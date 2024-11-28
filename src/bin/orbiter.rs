use certonaut::rpc::server::OrbiterService;
use certonaut::rpc::service::orbiter_server::OrbiterServer;
use tonic::transport::Server;

// Idea: Have a fully-guided, step-by-step interactive default CLI interface, in addition
// to scripted/automated

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: Port configuration, Windows named pipes, Unix sockets, TLS
    let addr = "[::1]:50051".parse()?;
    let service = OrbiterService::default();
    Server::builder()
        .add_service(OrbiterServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}
