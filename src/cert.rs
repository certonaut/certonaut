use crate::acme::object::{AcmeRenewalIdentifier, Identifier};
use crate::crypto::{SHA256_LENGTH, sha256};
use anyhow::{Context, Error};
use rcgen::CertificateSigningRequest;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek};
use std::net::IpAddr;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing::warn;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::num_bigint::BigUint;

/// The maximum number of certificates we will parse in a PEM-array of certificates by default
const DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH: usize = 100;

// TODO: must-staple option
pub fn create_and_sign_csr(
    cert_key: &rcgen::KeyPair,
    identifiers: Vec<Identifier>,
) -> Result<CertificateSigningRequest, Error> {
    let mut cert_params = rcgen::CertificateParams::new(
        identifiers
            .into_iter()
            .map(Into::into)
            .collect::<Vec<String>>(),
    )
    .context("CSR generation failed")?;
    // Ensure the DN is empty
    cert_params.distinguished_name = rcgen::DistinguishedName::default();
    let csr = cert_params
        .serialize_request(cert_key)
        .context("Signing CSR failed")?;
    Ok(csr)
}

pub fn load_certificates_from_file<P: AsRef<Path>>(
    cert_file: P,
    limit: Option<usize>,
) -> anyhow::Result<Vec<ParsedX509Certificate>> {
    let cert_file = cert_file.as_ref();
    let cert_file_display = cert_file.display();
    let cert_file = File::open(cert_file).context(format!("Opening {cert_file_display} failed"))?;
    let reader = BufReader::new(cert_file);
    load_certificates_from_reader(reader, limit)
        .context(format!("Parsing certificate {cert_file_display} failed"))
}

pub fn load_certificates_from_memory<B: AsRef<[u8]>>(
    pem_bytes: B,
    limit: Option<usize>,
) -> anyhow::Result<Vec<ParsedX509Certificate>> {
    let reader = Cursor::new(pem_bytes);
    load_certificates_from_reader(reader, limit)
}

fn load_certificates_from_reader<R: BufRead + Seek>(
    reader: R,
    limit: Option<usize>,
) -> anyhow::Result<Vec<ParsedX509Certificate>> {
    let mut certificates = Vec::new();
    for pem in x509_parser::pem::Pem::iter_from_reader(reader)
        .take(limit.unwrap_or(DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH))
    {
        let pem = pem.context("Reading PEM block failed")?;
        let parser_x509 = pem
            .parse_x509()
            .context("Reading X509 structure: Decoding DER failed")?;
        certificates.push(parser_x509.into());
    }
    Ok(certificates)
}

pub async fn load_reqwest_certificates<'a, I: Iterator<Item = T>, T: AsRef<Path>>(
    files: I,
) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let mut certificates = Vec::with_capacity(files.size_hint().0);
    for cert_path in files {
        let cert_path = cert_path.as_ref();
        let cert_path_display = cert_path.display();
        let mut cert_file = tokio::fs::File::open(cert_path).await.context(format!(
            "Opening certificate file {cert_path_display} failed"
        ))?;
        let mut cert_data = Vec::new();
        cert_file
            .read_to_end(&mut cert_data)
            .await
            .context(format!(
                "Reading certificate file {cert_path_display} failed"
            ))?;
        let reqwest_cert = reqwest::Certificate::from_pem(&cert_data).context(format!(
            "Parsing certificate file PEM {cert_path_display} failed"
        ))?;
        certificates.push(reqwest_cert)
    }
    Ok(certificates)
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
        let subject = cert.subject.to_string();
        let issuer = cert.issuer.to_string();
        let validity = (&cert.validity).into();
        let mut subject_alternative_names = Vec::new();
        let subject_public_key_sha256 = sha256(cert.public_key().raw);
        let mut ari_aki = None;
        for extension in cert.extensions() {
            match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    // draft-ietf-acme-ari-08: The unique identifier is constructed by concatenating
                    // the base64url-encoding [RFC4648] of the keyIdentifier field of the certificate's
                    // Authority Key Identifier (AKI) [RFC5280] extension
                    if let Some(key_identifier) = &aki.key_identifier {
                        ari_aki = Some(key_identifier.0);
                    }
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
        let acme_renewal_identifier =
            ari_aki.map(|aki| AcmeRenewalIdentifier::new(aki, cert.raw_serial()));
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before: time::OffsetDateTime,
    pub not_after: time::OffsetDateTime,
}

impl Validity {
    pub fn time_to_expiration(&self) -> time::Duration {
        let now = time::OffsetDateTime::now_utc();
        self.not_after - now
    }
}

impl From<&x509_parser::certificate::Validity> for Validity {
    fn from(value: &x509_parser::certificate::Validity) -> Self {
        Self {
            not_before: value.not_before.to_datetime(),
            not_after: value.not_after.to_datetime(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Identifier;
    use crate::acme::object::AcmeRenewalIdentifier;
    use crate::cert::{ParsedX509Certificate, Validity, load_certificates_from_file};
    use std::path::Path;
    use std::str::FromStr;
    use time::macros::datetime;
    use x509_parser::num_bigint::BigUint;

    #[test]
    fn test_from_x509_cert() -> anyhow::Result<()> {
        let expected_cert = ParsedX509Certificate {
            serial: BigUint::from(0x12b4_3256_fcc5_16f3_u128),
            subject: String::new(),
            issuer: "CN=Pebble Intermediate CA 05e38a".to_string(),
            validity: Validity {
                not_before: datetime!(2025-03-21 16:57:27 UTC),
                not_after: datetime!(2025-03-21 17:27:27 UTC),
            },
            subject_alternative_names: ["extended.subdomain", "my.first.cert", "www.my.first.cert"]
                .into_iter()
                .map(|s| Identifier::from_str(s).unwrap())
                .map(Into::into)
                .collect(),
            acme_renewal_identifier: Some(AcmeRenewalIdentifier::new(
                &[
                    0xb8, 0xf4, 0xd9, 0xa8, 0x21, 0x57, 0xab, 0x41, 0x68, 0x2a, 0x14, 0xb3, 0x68,
                    0x69, 0xe7, 0xb8, 0x8f, 0x28, 0xa6, 0x19,
                ],
                &[0x12, 0xb4, 0x32, 0x56, 0xfc, 0xc5, 0x16, 0xf3],
            )),
            subject_public_key_sha256: [
                85, 97, 188, 156, 44, 163, 170, 229, 177, 52, 164, 166, 172, 109, 186, 177, 21,
                108, 85, 243, 203, 60, 7, 235, 145, 74, 167, 236, 87, 74, 88, 106,
            ],
        };
        let test_file = Path::new("./testdata/testcert.pem");
        let mut parsed_certs = load_certificates_from_file(test_file, Some(1))?;
        assert_eq!(parsed_certs.len(), 1);
        let actual_cert = parsed_certs.remove(0);

        assert_eq!(actual_cert, expected_cert);
        Ok(())
    }
}
