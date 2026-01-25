use crate::USER_AGENT;
use crate::acme::error::ProtocolResult;
use crate::acme::object::Nonce;
use reqwest::{Certificate, ClientBuilder, Method, Request, Response};
use serde::Serialize;
use std::time::{Duration, SystemTime};
use tracing::warn;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const REPLAY_NONCE: &str = "Replay-Nonce";

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn try_new() -> ProtocolResult<Self> {
        Self::try_new_with_builder(ClientBuilder::new())
    }

    pub fn try_new_with_custom_roots(roots: Vec<Certificate>) -> ProtocolResult<Self> {
        let mut builder = ClientBuilder::new();
        for root_cert in roots {
            builder = builder.add_root_certificate(root_cert);
        }
        Self::try_new_with_builder(builder)
    }

    fn try_new_with_builder(client_builder: ClientBuilder) -> ProtocolResult<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        // RFC8555 Section 6.1, "clients SHOULD send an Accept-Language header field in
        // accordance with RFC7231"
        headers.insert(
            reqwest::header::ACCEPT_LANGUAGE,
            reqwest::header::HeaderValue::from_static("en"),
        );
        let client_builder = client_builder
            // RFC8555 Section 6, "Communications [...] are done over HTTPS [...]", except for test runs where we allow HTTP
            .https_only(!cfg!(test))
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .default_headers(headers)
            .http1_title_case_headers()
            .use_rustls_tls()
            // Make TRACE logs available for test or debug builds (still needs to be enabled separately)
            .connection_verbose(cfg!(any(test, debug_assertions)));
        Ok(Self {
            client: client_builder.build()?,
        })
    }

    pub fn extract_nonce(res: &Response) -> Option<Nonce> {
        res.headers()
            .get(REPLAY_NONCE)
            .and_then(|header| header.to_str().ok())
            .and_then(|nonce_value| Nonce::try_from(nonce_value.to_string()).ok())
    }

    pub fn extract_backoff(res: &Response) -> Option<SystemTime> {
        res.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|header| header.to_str().ok())
            .and_then(parse_retry_after)
    }

    pub fn extract_location(res: &Response) -> Option<Url> {
        res.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|header| header.to_str().ok())
            .and_then(|location_str| parse_url(res.url(), location_str))
    }

    pub fn extract_relation_links(res: &Response) -> Vec<RelationLink> {
        res.headers()
            .get_all(reqwest::header::LINK)
            .into_iter()
            .filter_map(|header| header.to_str().ok())
            .filter_map(|header_str| nom_rfc8288::complete::link_lenient(header_str).ok())
            .flat_map(IntoIterator::into_iter)
            .flatten()
            .filter_map(|link| {
                let url = parse_url(res.url(), link.url)?;
                if let Some(relation) = link.params.into_iter().find(|param| param.key == "rel") {
                    Some(RelationLink {
                        relation: relation.val?,
                        url,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    async fn execute(&self, req: Request) -> ProtocolResult<Response> {
        Ok(self.client.execute(req).await?)
    }

    pub async fn get(&self, url: Url) -> ProtocolResult<Response> {
        self.execute(Request::new(Method::GET, url)).await
    }

    pub async fn get_with_retry(
        &self,
        url: &Url,
        retries: usize,
        delay: Duration,
    ) -> ProtocolResult<Response> {
        let mut attempts = 0;
        loop {
            let response = self.execute(Request::new(Method::GET, url.clone())).await;
            match response {
                Ok(response) if response.status().is_server_error() && attempts < retries => {
                    warn!(
                        "Server error (status: {}) when sending GET request to {url}. Retrying...",
                        response.status()
                    );
                    attempts += 1;
                    tokio::time::sleep(delay).await;
                }
                Err(err) if attempts < retries => {
                    warn!("{:#}. Retrying...", anyhow::Error::from(err));
                    attempts += 1;
                    tokio::time::sleep(delay).await;
                }
                Ok(response) => return Ok(response),
                Err(err) => return Err(err),
            }
        }
    }

    pub async fn head(&self, url: Url) -> ProtocolResult<Response> {
        self.execute(Request::new(Method::HEAD, url)).await
    }

    pub async fn post<T: Serialize + 'static>(
        &self,
        url: Url,
        body: &T,
    ) -> ProtocolResult<Response> {
        let request_builder = self.client.post(url);
        // RFC8555 Section 6.2, "[clients] must have the Content-Type header field set
        // to "application/jose+json""
        let response = request_builder
            .header(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/jose+json"),
            )
            .json(&body)
            .send()
            .await?;
        Ok(response)
    }
}

fn parse_retry_after(retry_after: &str) -> Option<SystemTime> {
    // As per RFC9110, the Retry-After header either contains a value in seconds, or
    // a Date/Time string.
    if let Ok(seconds) = retry_after.parse::<u64>() {
        let timeout = Duration::from_secs(seconds);
        SystemTime::now().checked_add(timeout)
    } else {
        // Refer to RFC9110 Date/Time format parsing
        httpdate::parse_http_date(retry_after).ok()
    }
}

fn parse_url(base_url: &Url, raw_url: &str) -> Option<Url> {
    // As per RFC7231 (Location) and RFC8288 (Link), both the Link and Location header
    // may contain relative URLs as well as absolute URls. We need to ensure we parse both.
    // Fortunately, the Url crate already contains the logic for this.
    base_url.join(raw_url).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationLink {
    pub relation: String,
    pub url: Url,
}

#[cfg(test)]
pub mod test_helper {
    use mockito::{Mock, ServerGuard};
    use serde::Serialize;
    use url::Url;

    pub trait AbsoluteUrl {
        fn absolute_url(&self, path: &str) -> Url;
    }

    impl AbsoluteUrl for ServerGuard {
        fn absolute_url(&self, path: &str) -> Url {
            let base = self.url();
            Url::parse(&(base + path)).unwrap()
        }
    }

    pub trait MockJsonResponse {
        #[must_use]
        fn with_json_body<T: serde::Serialize>(self, body: &T) -> Self;
    }

    impl MockJsonResponse for Mock {
        fn with_json_body<T: Serialize>(self, body: &T) -> Self {
            let body = serde_json::to_vec(body).expect("JSON serialization failed");
            self.with_header("content-type", "application/json")
                .with_body(body)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helper::*;
    use super::*;
    use mockito::Server;
    use std::str::FromStr;
    use time::macros::datetime;

    #[test]
    fn test_try_new() {
        let _ = HttpClient::try_new().unwrap();
    }

    #[tokio::test]
    async fn test_sends_user_agent() {
        let mut server = Server::new_async().await;
        let head_mock = server
            .mock("HEAD", "/")
            .match_header("user-agent", USER_AGENT)
            .create_async()
            .await;
        let post_mock = server
            .mock("POST", "/")
            .match_header("user-agent", USER_AGENT)
            .create_async()
            .await;
        let get_mock = server
            .mock("GET", "/")
            .match_header("user-agent", USER_AGENT)
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        client
            .head(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        client
            .post(server.absolute_url(String::new().as_str()), &())
            .await
            .unwrap();
        client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();

        head_mock.assert_async().await;
        post_mock.assert_async().await;
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_sends_accept_language() {
        let mut server = Server::new_async().await;
        let head_mock = server
            .mock("HEAD", "/")
            .match_header("accept-language", "en")
            .create_async()
            .await;
        let post_mock = server
            .mock("POST", "/")
            .match_header("accept-language", "en")
            .create_async()
            .await;
        let get_mock = server
            .mock("GET", "/")
            .match_header("accept-language", "en")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        client
            .head(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        client
            .post(server.absolute_url(String::new().as_str()), &())
            .await
            .unwrap();
        client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();

        head_mock.assert_async().await;
        post_mock.assert_async().await;
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_post_sends_content_type() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("content-type", "application/jose+json")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        client
            .post(server.absolute_url(String::new().as_str()), &())
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_nonce() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("HEAD", "/")
            .with_header(REPLAY_NONCE, "nonceValue")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .head(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let nonce = HttpClient::extract_nonce(&response).expect("No nonce found");

        assert_eq!(nonce.to_string(), "nonceValue");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_nonce_with_invalid_nonce() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("HEAD", "/")
            .with_header(REPLAY_NONCE, "!invalid-nonce!")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .head(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let nonce = HttpClient::extract_nonce(&response);

        assert!(nonce.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_backoff_with_seconds() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_header("retry-after", "60")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let retry_after =
            HttpClient::extract_backoff(&response).expect("No retry after value or parsed");

        let backoff = retry_after.duration_since(SystemTime::now()).unwrap();
        let difference = backoff.abs_diff(Duration::from_secs(60));
        // Allow some leeway to account for a slow test or jumping clock
        assert!(
            difference < Duration::from_secs(3),
            "Time difference greater than 3s: {difference:?}"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_backoff_with_timestamp() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_header("retry-after", "Sun, 06 Nov 1994 08:49:37 GMT")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let retry_after =
            HttpClient::extract_backoff(&response).expect("No retry after value or parsed");

        assert_eq!(
            retry_after,
            SystemTime::from(datetime!(1994-11-06 08:49:37 UTC))
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_backoff_with_invalid_timestamp() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_header(
                "retry-after",
                "Well, what if there is no tomorrow? There wasn’t one today.",
            )
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let backoff = HttpClient::extract_backoff(&response);

        assert!(backoff.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_location() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_header("Location", "https://example.com/look-here")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .post(server.absolute_url(String::new().as_str()), &())
            .await
            .unwrap();
        let location = HttpClient::extract_location(&response).unwrap();

        assert_eq!(location.as_str(), "https://example.com/look-here");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_location_with_invalid_value() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_header("Location", "These aren’t the droids you’re looking for.")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .post(server.absolute_url(String::new().as_str()), &())
            .await
            .unwrap();
        let location = HttpClient::extract_location(&response);

        assert!(location.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_location_with_relative_url() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_header("Location", "/everything-is-relative")
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .post(server.absolute_url(String::new().as_str()), &())
            .await
            .unwrap();
        let location = HttpClient::extract_location(&response).unwrap();

        assert_eq!(location, server.absolute_url("/everything-is-relative"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_relation_links() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_header("Link",
                         r#"<https://example.com/TheBook/chapter2>; rel="previous"; title="previous chapter""#)
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let links = HttpClient::extract_relation_links(&response);

        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0],
            RelationLink {
                relation: "previous".to_string(),
                url: Url::parse("https://example.com/TheBook/chapter2").unwrap()
            }
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_extract_relation_links_with_complex_links() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_header("Link",
                         r#"</TheBook/chapter2>; rel="previous"; title*=UTF-8'de'letztes%20Kapitel,  </TheBook/chapter4>;    rel="next"; title*=UTF-8'de'n%c3%a4chstes%20Kapitel"#)
            .with_header("Link",
                         r#"<https://example.org/>;   rel="start https://example.net/relation/other""#)
            .create_async()
            .await;
        let client = HttpClient::try_new().unwrap();

        let response = client
            .get(server.absolute_url(String::new().as_str()))
            .await
            .unwrap();
        let links = HttpClient::extract_relation_links(&response);

        assert_eq!(links.len(), 3);
        let link = server.absolute_url("/TheBook/chapter2");
        assert_eq!(
            links[0],
            RelationLink {
                relation: "previous".to_string(),
                url: link
            }
        );
        let link = server.absolute_url("/TheBook/chapter4");
        assert_eq!(
            links[1],
            RelationLink {
                relation: "next".to_string(),
                url: link
            }
        );
        let link = Url::from_str("https://example.org/").unwrap();
        assert_eq!(
            links[2],
            RelationLink {
                relation: "start https://example.net/relation/other".to_string(),
                url: link
            }
        );
        mock.assert_async().await;
    }
}
