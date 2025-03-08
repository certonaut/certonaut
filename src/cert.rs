use crate::acme::object::Identifier;
use crate::crypto::{SHA256_LENGTH, sha256};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use std::net::IpAddr;
use tracing::warn;
use x509_parser::certificate::Validity;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::num_bigint::BigUint;

pub struct ParsedX509Certificate {
    pub serial: BigUint,
    pub subject: String,
    pub issuer: String,
    pub validity: Validity,
    pub subject_alternative_names: Vec<Identifier>,
    pub acme_renewal_identifier: Option<AcmeRenewalIdentifier>,
    pub subject_public_key_sha256: [u8; SHA256_LENGTH],
}

impl From<x509_parser::certificate::X509Certificate<'_>> for ParsedX509Certificate {
    fn from(cert: x509_parser::certificate::X509Certificate) -> ParsedX509Certificate {
        let serial = cert.serial.clone();
        let serial_base64 = BASE64_URL_SAFE_NO_PAD.encode(cert.raw_serial());
        let subject = cert.subject.to_string();
        let issuer = cert.issuer.to_string();
        let validity = cert.validity.clone();
        let mut subject_alternative_names = Vec::new();
        let subject_public_key_sha256 = sha256(cert.public_key().raw);
        let mut ari_aki = None;
        for extension in cert.extensions() {
            match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(_aki) => {
                    ari_aki = Some(BASE64_URL_SAFE_NO_PAD.encode(extension.value));
                }
                ParsedExtension::SubjectAlternativeName(san) => {
                    for general_name in &san.general_names {
                        match general_name {
                            GeneralName::DNSName(dns_name) => {
                                let id = Identifier::Dns {
                                    value: (*dns_name).to_string(),
                                };
                                subject_alternative_names.push(id);
                            }
                            GeneralName::IPAddress(ip_addr) => {
                                let ip_addr = *ip_addr;
                                warn!(
                                    "Found IP address in certificate, support for IP addr identifiers is WIP"
                                );
                                let parsed_ip_addr = ip_addr
                                    .try_into()
                                    .ok()
                                    .map(|ipv6_addr: [u8; 16]| IpAddr::from(ipv6_addr))
                                    .or_else(|| {
                                        ip_addr
                                            .try_into()
                                            .ok()
                                            .map(|ipv4_addr: [u8; 4]| IpAddr::from(ipv4_addr))
                                    });
                                match parsed_ip_addr {
                                    Some(ip_addr) => {
                                        // TODO: Properly parse into identifier
                                        let id = Identifier::from(ip_addr.to_string());
                                        subject_alternative_names.push(id);
                                    }
                                    None => {
                                        warn!(
                                            "Certificate contains invalid IP address {ip_addr:#?}"
                                        );
                                    }
                                }
                            }
                            unsupported => {
                                warn!(
                                    "Found unsupported general name {unsupported} in certificate"
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let acme_renewal_identifier = ari_aki.map(|aki| AcmeRenewalIdentifier {
            key_identifier_base64: aki,
            serial_base64,
        });
        Self {
            serial,
            subject,
            issuer,
            validity,
            subject_alternative_names,
            acme_renewal_identifier,
            subject_public_key_sha256,
        }
    }
}

pub struct AcmeRenewalIdentifier {
    pub key_identifier_base64: String,
    pub serial_base64: String,
}
