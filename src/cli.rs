use crate::crypto::asymmetric::{Curve, KeyType};
use crate::parse_duration;
use aws_lc_rs::rsa::KeySize;
use clap::{Args, Subcommand, ValueEnum};
use std::fmt::Display;
use std::time::Duration;
use strum::VariantArray;

#[derive(Debug, Args, Default)]
pub struct IssueCommand {
    /// ID of the CA to use
    #[clap(short, long)]
    pub ca: Option<String>,
    /// ID of the account to use
    #[clap(short, long)]
    pub account: Option<String>,
    /// Domain names to include in the certificate
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    pub domains: Option<Vec<String>>,
    /// The display name of the new certificate
    #[clap(long)]
    pub cert_name: Option<String>,
    #[clap(flatten)]
    pub advanced: AdvancedIssueConfiguration,
    /// The solver (authenticator) to solve the ACME challenges required for issuance
    #[clap(subcommand)]
    pub solver: Option<CommandLineSolverConfiguration>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct AdvancedIssueConfiguration {
    /// Type of key to use for the certificate
    #[clap(short, long)]
    pub key_type: Option<CommandLineKeyType>,
    /// ACME profile to use, if the CA offers ACME profile selection
    #[clap(short, long)]
    pub profile: Option<String>,
    /// Lifetime of the requested certificate, if supported by the CA
    #[clap(short, long, value_parser = parse_duration)]
    pub lifetime: Option<Duration>,
    /// Whether to reuse the same private key on each renewal, or rotate the key on each renewal
    #[clap(short, long)]
    pub reuse_key: bool,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, VariantArray)]
pub enum CommandLineKeyType {
    /// ECDSA with NIST P-256
    #[default]
    P256,
    /// ECDSA with NIST P-384
    P384,
    /// RSA (2048-bit key)
    Rsa2048,
    /// RSA (3072-bit key)
    Rsa3072,
    /// RSA (4096-bit key)
    Rsa4096,
    /// RSA (8192-bit key)
    Rsa8192,
}

impl Display for CommandLineKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enum_value = self.to_possible_value().unwrap(/* Infallible */);
        write!(f, "{}", enum_value.get_help().unwrap(/* Infallible */))
    }
}

impl From<CommandLineKeyType> for KeyType {
    fn from(key_type: CommandLineKeyType) -> Self {
        match key_type {
            CommandLineKeyType::P256 => KeyType::Ecdsa(Curve::P256),
            CommandLineKeyType::P384 => KeyType::Ecdsa(Curve::P384),
            CommandLineKeyType::Rsa2048 => KeyType::Rsa(KeySize::Rsa2048),
            CommandLineKeyType::Rsa3072 => KeyType::Rsa(KeySize::Rsa3072),
            CommandLineKeyType::Rsa4096 => KeyType::Rsa(KeySize::Rsa4096),
            CommandLineKeyType::Rsa8192 => KeyType::Rsa(KeySize::Rsa8192),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum CommandLineSolverConfiguration {
    /// This solver does not authenticate at all. It can be used when the user has already authorized out-of-band
    /// with the CA. Will cause failures otherwise.
    Nothing,
    /// Talks to a pebble-challtestsrv to solve HTTP-01 challenges. Only works with the Pebble Test CA.
    #[clap(name = "pebble-http")]
    Pebble,
}

#[derive(Debug, Args, Default)]
pub struct RenewCommand {}
