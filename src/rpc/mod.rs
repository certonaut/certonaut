pub mod client;
pub mod server;
mod messages;

pub mod service {
    tonic::include_proto!("astrolink");
}