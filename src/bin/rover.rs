use certonaut::rpc::client::RpcClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: Same as server
    let mut client = RpcClient::try_new("http://[::1]:50051").await?;
    let ca_list = client.list_certificate_authorities().await?;
    for ca in ca_list {
        println!("{ca:#?}")
    }
    Ok(())
}
