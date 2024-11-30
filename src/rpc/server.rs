use crate::daemon::OrbiterService;
use crate::rpc::service;
use crate::rpc::service::orbiter_server::Orbiter;
use crate::rpc::service::{CertificateAuthority, ListAccountRequest, ListAccountResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct OrbiterRPCService {
    service: Arc<OrbiterService>,
}

impl OrbiterRPCService {
    pub fn new(service: Arc<OrbiterService>) -> Self {
        Self { service }
    }
}

#[tonic::async_trait]
impl Orbiter for OrbiterRPCService {
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
        let ca_list = self.service.list_certificate_authorities().await;
        let ca_list = ca_list
            .iter()
            .map(|ca| ca.get_configuration())
            .map(|config| CertificateAuthority {
                id: config.identifier.to_string(),
                name: config.name.clone(),
                acme_url: config.acme_directory.to_string(),
                is_public: config.public,
                is_default: config.default,
                is_testing: config.testing,
            })
            .collect();
        Ok(Response::new(service::ListCertificateAuthorityResponse {
            certificate_authorities: ca_list,
        }))
    }

    async fn list_accounts(
        &self,
        request: Request<ListAccountRequest>,
    ) -> Result<Response<ListAccountResponse>, Status> {
        let request = request.into_inner();
        let accounts = self
            .service
            .list_accounts(&request.ca_id)
            .await
            .map_err(|anyhow| Status::not_found(anyhow.to_string()))?;
        let accounts = accounts
            .iter()
            .map(|account| {
                let config = account.get_config();
                service::Account {
                    id: config.identifier.clone(),
                    name: config.name.clone(),
                }
            })
            .collect::<Vec<_>>();
        Ok(Response::new(ListAccountResponse { accounts }))
    }
}
