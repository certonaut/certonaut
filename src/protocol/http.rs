use crate::protocol::error::ProtocolResult;
use crate::protocol::object::Nonce;
use reqwest::{Certificate, ClientBuilder, Method, Request, Response};
use serde::Serialize;
use std::time::Duration;
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

#[derive(Debug)]
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
            "Accept-Language",
            reqwest::header::HeaderValue::from_static("en"),
        );
        let client_builder = client_builder
            .https_only(true)
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .default_headers(headers)
            .connection_verbose(true);
        Ok(Self {
            client: client_builder.build()?,
        })
    }

    pub fn extract_nonce(res: &Response) -> Option<Nonce> {
        res.headers()
            .get("Replay-Nonce")
            .and_then(|header| header.to_str().ok())
            .and_then(|nonce_value| Nonce::try_from(nonce_value.to_string()).ok())
    }

    pub fn extract_backoff(res: &Response) -> Option<Duration> {
        res.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|header| header.to_str().ok())
            .and_then(|delay_str| delay_str.parse::<u64>().ok())
            .map(Duration::from_secs)
    }

    pub fn extract_location(res: &Response) -> Option<Url> {
        res.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|header| header.to_str().ok())
            .and_then(|location_str| Url::parse(location_str).ok())
    }

    pub fn extract_relation_links(res: &Response) -> Vec<RelationLink> {
        res.headers()
            .get_all(reqwest::header::LINK)
            .into_iter()
            .filter_map(|header| header.to_str().ok())
            .filter_map(|header_str| nom_rfc8288::complete::link(header_str).ok())
            .flat_map(|link_vec| link_vec.into_iter())
            .flatten()
            .filter_map(|link| {
                let url = Url::parse(link.url).ok()?;
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

    pub async fn post<T: Serialize>(&self, url: Url, body: &T) -> ProtocolResult<Response> {
        let request_builder = self.client.post(url);
        // RFC8555 Section 6.2, "[clients] must have the Content-Type header field set
        // to "application/jose+json"
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationLink {
    pub relation: String,
    pub url: Url,
}

// TODO: Unit test with mockall? (Assuming we add more logic here than a plain reqwest wrapper)
