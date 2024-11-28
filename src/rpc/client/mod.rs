use crate::rpc::service::orbiter_client::OrbiterClient;
use crate::rpc::service::CertificateAuthority;
use tonic::codegen::StdError;

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
        let request = tonic::Request::new(());
        let response = self.client.list_certificate_authorities(request).await?;
        Ok(response.into_inner().certificate_authorities)
    }
}
