use crate::acme::ACME_STAGING_URL;
use crate::rpc::service;
use crate::rpc::service::orbiter_server::Orbiter;
use tonic::{Request, Response, Status};

#[derive(Debug, Default)]
pub struct OrbiterService {}

#[tonic::async_trait]
impl Orbiter for OrbiterService {
    async fn get_config(
        &self,
        _request: Request<()>,
    ) -> Result<Response<service::Configuration>, Status> {
        todo!()
    }

    async fn set_config(
        &self,
        _request: Request<service::Configuration>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn list_certificate_authorities(
        &self,
        _request: Request<()>,
    ) -> Result<Response<service::ListCertificateAuthorityResponse>, Status> {
        // TODO: Persistent state from where?
        let letsencrypt = service::CertificateAuthority {
            id: 0,
            name: "Let's Encrypt".to_string(),
            acme_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            is_public: true,
            is_default: false,
            is_testing: false,
        };
        let staging = service::CertificateAuthority {
            id: 1,
            name: "Let's Encrypt Staging".to_string(),
            acme_url: ACME_STAGING_URL.to_string(),
            is_public: true,
            is_default: false,
            is_testing: true,
        };
        Ok(Response::new(service::ListCertificateAuthorityResponse {
            certificate_authorities: vec![letsencrypt, staging],
        }))
    }
}
