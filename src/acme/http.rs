use crate::acme::error::ProtocolResult;
use crate::acme::object::Nonce;
use reqwest::{Certificate, ClientBuilder, Method, Request, Response};
use serde::Serialize;
use std::time::{Duration, SystemTime};
use url::Url;

// As per RFC8555 Section 6.1, we should conform both to RFC 7525 and supply the name + version
// of our HTTP library.
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " reqwest/",
    env!("REQWEST_VERSION"),
    " ( +",
    env!("CARGO_PKG_REPOSITORY"),
    " )"
);
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

    pub fn try_new_with_custom_root(root: Certificate) -> ProtocolResult<Self> {
        let builder = ClientBuilder::new().add_root_certificate(root);
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
            .filter_map(|header_str| nom_rfc8288::complete::link(header_str).ok())
            .flat_map(std::iter::IntoIterator::into_iter)
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

    pub async fn head(&self, url: Url) -> ProtocolResult<Response> {
        self.execute(Request::new(Method::HEAD, url)).await
    }

    pub async fn post<T: Serialize + 'static>(&self, url: Url, body: &T) -> ProtocolResult<Response> {
        let request_builder = self.client.post(url);
        // RFC8555 Section 6.2, "[clients] must have the Content-Type header field set
        // to "application/jose+json""
        let request = request_builder
            .header(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/jose+json"),
            )
            .json(&body)
            .build()?;
        self.execute(request).await
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
    use httptest::http::Uri;
    use httptest::{ServerHandle, ServerPool};
    use url::Url;

    pub static SERVER_POOL: ServerPool = ServerPool::new(20);

    pub type Server = ServerHandle<'static>;

    // It's so annoying that the http crate and url crate don't interop by default...
    // Fortunately this is only a problem in test code.
    #[allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]
    pub fn uri_to_url(uri: Uri) -> Url {
        let uri_string = uri.to_string();
        Url::parse(&uri_string).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_helper::*;
    use super::*;
    use httptest::matchers::contains;
    use httptest::matchers::request::{headers, method_path};
    use httptest::responders::status_code;
    use httptest::Expectation;
    use std::str::FromStr;
    use time::macros::datetime;

    #[test]
    fn test_try_new() {
        let _ = HttpClient::try_new().unwrap();
    }

    #[tokio::test]
    async fn test_sends_user_agent() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(headers(contains(("user-agent", USER_AGENT))))
                .times(3)
                .respond_with(status_code(200)),
        );

        let client = HttpClient::try_new().unwrap();
        client.head(uri_to_url(server.url("/"))).await.unwrap();
        client.post(uri_to_url(server.url("/")), &()).await.unwrap();
        client.get(uri_to_url(server.url("/"))).await.unwrap();
    }

    #[tokio::test]
    async fn test_sends_accept_language() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(headers(contains(("accept-language", "en"))))
                .times(3)
                .respond_with(status_code(200)),
        );

        let client = HttpClient::try_new().unwrap();
        client.head(uri_to_url(server.url("/"))).await.unwrap();
        client.post(uri_to_url(server.url("/")), &()).await.unwrap();
        client.get(uri_to_url(server.url("/"))).await.unwrap();
    }

    #[tokio::test]
    async fn test_post_sends_content_type() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(headers(contains(("content-type", "application/jose+json"))))
                .respond_with(status_code(200)),
        );

        let client = HttpClient::try_new().unwrap();
        client.post(uri_to_url(server.url("/")), &()).await.unwrap();
    }

    #[tokio::test]
    async fn test_extract_nonce() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("HEAD", "/"))
                .respond_with(status_code(200).append_header(REPLAY_NONCE, "nonceValue")),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.head(uri_to_url(server.url("/"))).await.unwrap();
        let nonce = HttpClient::extract_nonce(&response).expect("No nonce found");
        assert_eq!(nonce.to_string(), "nonceValue");
    }

    #[tokio::test]
    async fn test_extract_nonce_with_invalid_nonce() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("HEAD", "/"))
                .respond_with(status_code(200).append_header(REPLAY_NONCE, "!invalid-nonce!")),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.head(uri_to_url(server.url("/"))).await.unwrap();
        assert!(HttpClient::extract_nonce(&response).is_none());
    }

    #[tokio::test]
    async fn test_extract_backoff_with_seconds() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("GET", "/"))
                .respond_with(status_code(200).append_header("retry-after", "60")),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.get(uri_to_url(server.url("/"))).await.unwrap();
        let retry_after = HttpClient::extract_backoff(&response).expect("No retry after value or parsed");
        let backoff = retry_after.duration_since(SystemTime::now()).unwrap();
        let difference = backoff.abs_diff(Duration::from_secs(60));
        // Allow some leeway to account for a slow test or jumping clock
        assert!(
            difference < Duration::from_secs(3),
            "Time difference greater than 3s: {difference:?}"
        );
    }

    #[tokio::test]
    async fn test_extract_backoff_with_timestamp() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("GET", "/"))
                .respond_with(status_code(200).append_header("retry-after", "Sun, 06 Nov 1994 08:49:37 GMT")),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.get(uri_to_url(server.url("/"))).await.unwrap();
        let retry_after = HttpClient::extract_backoff(&response).expect("No retry after value or parsed");
        assert_eq!(retry_after, SystemTime::from(datetime!(1994-11-06 08:49:37 UTC)));
    }

    #[tokio::test]
    async fn test_extract_backoff_with_invalid_timestamp() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("GET", "/")).respond_with(status_code(200).append_header(
                "retry-after",
                "Well, what if there is no tomorrow? There wasn’t one today.",
            )),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.get(uri_to_url(server.url("/"))).await.unwrap();
        assert!(HttpClient::extract_backoff(&response).is_none());
    }

    #[tokio::test]
    async fn test_extract_location() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("POST", "/"))
                .respond_with(status_code(201).append_header("Location", "https://example.com/look-here")),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.post(uri_to_url(server.url("/")), &()).await.unwrap();
        let location = HttpClient::extract_location(&response).unwrap();
        assert_eq!(location.as_str(), "https://example.com/look-here");
    }

    #[tokio::test]
    async fn test_extract_location_with_invalid_value() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("POST", "/")).respond_with(
                status_code(201).append_header("Location", "These aren’t the droids you’re looking for."),
            ),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.post(uri_to_url(server.url("/")), &()).await.unwrap();
        assert!(HttpClient::extract_location(&response).is_none());
    }

    #[tokio::test]
    async fn test_extract_location_with_relative_url() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("POST", "/"))
                .respond_with(status_code(201).append_header("Location", "/everything-is-relative")),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.post(uri_to_url(server.url("/")), &()).await.unwrap();
        let location = HttpClient::extract_location(&response).unwrap();
        assert_eq!(location.as_str(), server.url_str("/everything-is-relative"));
    }

    #[tokio::test]
    async fn test_extract_relation_links() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("GET", "/")).respond_with(status_code(200).append_header(
                "Link",
                r#"<https://example.com/TheBook/chapter2>; rel="previous"; title="previous chapter""#,
            )),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.get(uri_to_url(server.url("/"))).await.unwrap();
        let links = HttpClient::extract_relation_links(&response);
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0],
            RelationLink {
                relation: "previous".to_string(),
                url: Url::parse("https://example.com/TheBook/chapter2").unwrap()
            }
        );
    }

    #[tokio::test]
    async fn test_extract_relation_links_with_complex_links() {
        let server = SERVER_POOL.get_server();
        server.expect(
            Expectation::matching(method_path("GET", "/")).respond_with(status_code(200).append_header(
                "Link",
                r#"</TheBook/chapter2>; rel="previous"; title*=UTF-8'de'letztes%20Kapitel,  </TheBook/chapter4>;    rel="next"; title*=UTF-8'de'n%c3%a4chstes%20Kapitel"#,
            ).append_header("Link",
                            r#"<https://example.org/>;   rel="start https://example.net/relation/other""#)),
        );

        let client = HttpClient::try_new().unwrap();
        let response = client.get(uri_to_url(server.url("/"))).await.unwrap();
        let links = HttpClient::extract_relation_links(&response);
        assert_eq!(links.len(), 3);
        let link = uri_to_url(server.url("/TheBook/chapter2"));
        assert_eq!(
            links[0],
            RelationLink {
                relation: "previous".to_string(),
                url: link
            }
        );
        let link = uri_to_url(server.url("/TheBook/chapter4"));
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
    }
}
