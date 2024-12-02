use crate::daemon::OrbiterService;
use crate::rpc::service;
use crate::rpc::service::orbiter_server::Orbiter;
use crate::rpc::service::{
    Account, CertificateAuthority, ListAccountRequest, ListAccountResponse, Metadata,
    NewAccountRequest,
};
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
        let mut certificate_authorities = Vec::with_capacity(ca_list.len());
        for ca in ca_list {
            let lock = ca.read().await;
            let config = lock.build_configuration();
            let directory = &lock.get_directory().meta;
            let meta = directory.as_ref().map(|meta| Metadata {
                terms_of_service: meta.terms_of_service.as_ref().map(|url| url.to_string()),
                website: meta.website.as_ref().map(|url| url.to_string()),
                caa_identities: meta.caa_identities.clone(),
                external_account_required: meta.external_account_required,
            });
            certificate_authorities.push(CertificateAuthority {
                id: config.identifier.to_string(),
                name: config.name.clone(),
                acme_url: config.acme_directory.to_string(),
                is_public: config.public,
                is_default: config.default,
                is_testing: config.testing,
                metadata: meta,
            });
        }
        Ok(Response::new(service::ListCertificateAuthorityResponse {
            certificate_authorities,
        }))
    }

    async fn list_accounts(
        &self,
        request: Request<ListAccountRequest>,
    ) -> Result<Response<ListAccountResponse>, Status> {
        let request = request.into_inner();
        let accounts = self
            .service
            .list_account_configs(&request.ca_id)
            .await
            .map_err(|err| Status::not_found(format!("{err:#}")))?;
        let accounts = accounts
            .iter()
            .map(|config| Account {
                id: config.identifier.clone(),
                name: config.name.clone(),
            })
            .collect::<Vec<_>>();
        Ok(Response::new(ListAccountResponse { accounts }))
    }

    async fn create_account(
        &self,
        request: Request<NewAccountRequest>,
    ) -> Result<Response<Account>, Status> {
        let request = request.into_inner();
        let account = self
            .service
            .create_account(request)
            .await
            .map_err(|err| Status::failed_precondition(format!("{err:#}")))?;
        Ok(Response::new(Account {
            id: account.identifier.clone(),
            name: account.name.clone(),
        }))
    }
}
