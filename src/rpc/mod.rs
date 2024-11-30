pub mod client;
mod message;
pub mod server;

pub mod service {
    tonic::include_proto!("astrolink");
}
