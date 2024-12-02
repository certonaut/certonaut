use crate::rpc::service::orbiter_client::OrbiterClient;
use crate::rpc::service::{
    Account, CertificateAuthority, Keytype, ListAccountRequest, NewAccountRequest,
};
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

    pub async fn create_account(
        &mut self,
        ca_id: String,
        account_name: String,
        contacts: Vec<String>,
        tos: Option<bool>,
        key_type: Option<Keytype>,
    ) -> Result<Account, tonic::Status> {
        let request = NewAccountRequest {
            name: account_name,
            ca_id,
            contacts,
            terms_of_service_agreed: tos,
            key_type: key_type.map(|key_type| key_type.as_str_name().to_string()),
        }
        .into_request();
        let response = self.client.create_account(request).await?;
        Ok(response.into_inner())
    }
}
