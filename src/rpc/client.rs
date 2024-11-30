use crate::rpc::service::orbiter_client::OrbiterClient;
use crate::rpc::service::{Account, CertificateAuthority, ListAccountRequest};
use tonic::codegen::StdError;
use tonic::IntoRequest;

#[derive(Debug)]
pub struct RpcClient<T> {
    client: OrbiterClient<T>,
}

impl RpcClient<tonic::transport::Channel> {
    pub async fn try_new<D>(address: D) -> Result<Self, tonic::transport::Error>
    where
        D: TryInto<tonic::transport::Endpoint>,
        D::Error: Into<StdError>,
    {
        let client = OrbiterClient::connect(address).await?;
        Ok(Self { client })
    }

    pub async fn list_certificate_authorities(
        &mut self,
    ) -> Result<Vec<CertificateAuthority>, tonic::Status> {
        let request = ().into_request();
        let response = self.client.list_certificate_authorities(request).await?;
        Ok(response.into_inner().certificate_authorities)
    }

    pub async fn list_accounts(&mut self, ca_id: String) -> Result<Vec<Account>, tonic::Status> {
        let request = ListAccountRequest { ca_id }.into_request();
        let response = self.client.list_accounts(request).await?;
        Ok(response.into_inner().accounts)
    }
}
