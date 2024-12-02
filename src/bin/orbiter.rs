use certonaut::daemon::OrbiterService;
use certonaut::rpc::server::OrbiterRPCService;
use certonaut::rpc::service::orbiter_server::OrbiterServer;
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: Port configuration, Windows named pipes, Unix sockets, TLS
    // TODO: Determine defaults for config, clap configurable
    let config = certonaut::config::load("orbiter.toml")?;
    let addr = config.rpc_address;
    let service = Arc::new(OrbiterService::load_from_config(config).await?);
    // TODO: Authentication such that not any local process can issue certs via orbiter
    let rpc_service = OrbiterRPCService::new(service);
    Server::builder()
        .add_service(OrbiterServer::new(rpc_service))
        .serve(addr)
        .await?;
    Ok(())
}
