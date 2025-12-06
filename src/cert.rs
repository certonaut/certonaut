use crate::acme::object::{AcmeRenewalIdentifier, Identifier};
use crate::crypto::asymmetric::KeyPair;
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
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;

/// The maximum number of certificates we will parse in a PEM-array of certificates by default
const DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH: usize = 100;

// TODO: must-staple option
pub fn create_and_sign_csr(
    cert_key: &KeyPair,
    identifiers: Vec<Identifier>,
) -> Result<CertificateSigningRequest, Error> {
    let rcgen_keypair = cert_key.to_rcgen_keypair()?;
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
        .serialize_request(&rcgen_keypair)
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
    for pem in
        Pem::iter_from_reader(reader).take(limit.unwrap_or(DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH))
    {
        let pem = pem.context("Reading PEM block failed")?;
        let parsed_x509 = ParsedX509Certificate::try_from(pem.contents)?;
        certificates.push(parsed_x509);
    }
    Ok(certificates)
}

pub async fn load_reqwest_certificates<I: Iterator<Item = T>, T: AsRef<Path>>(
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
        certificates.push(reqwest_cert);
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
    pub raw_bytes: Vec<u8>,
}

impl TryFrom<Vec<u8>> for ParsedX509Certificate {
    type Error = Error;

    fn try_from(der_bytes: Vec<u8>) -> anyhow::Result<ParsedX509Certificate> {
        let (_extra_bytes, cert) = x509_parser::certificate::X509Certificate::from_der(&der_bytes)
            .context("Reading X.509 structure: Decoding DER failed")?;
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
                                        subject_alternative_names.push(ip_addr.into());
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
        Ok(Self {
            serial,
            subject,
            issuer,
            validity,
            subject_alternative_names,
            acme_renewal_identifier,
            subject_public_key_sha256,
            raw_bytes: der_bytes,
        })
    }
}

impl ParsedX509Certificate {
    pub fn as_der_bytes(&self) -> &[u8] {
        &self.raw_bytes
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
            raw_bytes: vec![
                0x30, 0x82, 0x02, 0x7b, 0x30, 0x82, 0x01, 0x63, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
                0x08, 0x12, 0xb4, 0x32, 0x56, 0xfc, 0xc5, 0x16, 0xf3, 0x30, 0x0d, 0x06, 0x09, 0x2a,
                0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x28, 0x31, 0x26,
                0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1d, 0x50, 0x65, 0x62, 0x62, 0x6c,
                0x65, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65,
                0x20, 0x43, 0x41, 0x20, 0x30, 0x35, 0x65, 0x33, 0x38, 0x61, 0x30, 0x1e, 0x17, 0x0d,
                0x32, 0x35, 0x30, 0x33, 0x32, 0x31, 0x31, 0x36, 0x35, 0x37, 0x32, 0x37, 0x5a, 0x17,
                0x0d, 0x32, 0x35, 0x30, 0x33, 0x32, 0x31, 0x31, 0x37, 0x32, 0x37, 0x32, 0x37, 0x5a,
                0x30, 0x00, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
                0x04, 0x48, 0x78, 0xc5, 0xac, 0xd5, 0xee, 0x0a, 0xc3, 0xd2, 0x6d, 0xe3, 0xcf, 0xc3,
                0x91, 0x01, 0x2b, 0x82, 0x2c, 0x45, 0xe6, 0x0b, 0x3b, 0xe3, 0x4f, 0xa0, 0xba, 0xe0,
                0xb2, 0x2a, 0xe1, 0xac, 0x50, 0xb5, 0x98, 0x87, 0xac, 0x2b, 0x9d, 0x9d, 0x82, 0xae,
                0xf4, 0xa4, 0x85, 0xa4, 0xcb, 0xfb, 0xd3, 0x1e, 0x97, 0x01, 0xb0, 0xc5, 0xf6, 0xad,
                0x3a, 0x3c, 0x2c, 0xbc, 0xe9, 0x47, 0x3b, 0x89, 0xdf, 0xa3, 0x81, 0x9b, 0x30, 0x81,
                0x98, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
                0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x0c, 0x06, 0x03,
                0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1f, 0x06, 0x03,
                0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb8, 0xf4, 0xd9, 0xa8, 0x21,
                0x57, 0xab, 0x41, 0x68, 0x2a, 0x14, 0xb3, 0x68, 0x69, 0xe7, 0xb8, 0x8f, 0x28, 0xa6,
                0x19, 0x30, 0x42, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x38, 0x30,
                0x36, 0x82, 0x12, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x2e, 0x73, 0x75,
                0x62, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x82, 0x0d, 0x6d, 0x79, 0x2e, 0x66, 0x69,
                0x72, 0x73, 0x74, 0x2e, 0x63, 0x65, 0x72, 0x74, 0x82, 0x11, 0x77, 0x77, 0x77, 0x2e,
                0x6d, 0x79, 0x2e, 0x66, 0x69, 0x72, 0x73, 0x74, 0x2e, 0x63, 0x65, 0x72, 0x74, 0x30,
                0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
                0x03, 0x82, 0x01, 0x01, 0x00, 0x08, 0x95, 0x67, 0xfc, 0x2f, 0x7c, 0x2d, 0xf9, 0xfa,
                0x87, 0x42, 0x94, 0xb9, 0x8d, 0xc5, 0xaf, 0xce, 0x44, 0xdd, 0x83, 0x5f, 0xc0, 0xd0,
                0xba, 0xdf, 0x59, 0x93, 0x48, 0x44, 0x07, 0x0d, 0x99, 0xfb, 0x24, 0x13, 0x7b, 0xff,
                0xd4, 0x82, 0x0b, 0x71, 0xe7, 0x04, 0xb1, 0x7d, 0x89, 0x1e, 0xab, 0xf4, 0x76, 0xf3,
                0xd3, 0x05, 0xc6, 0x9c, 0xf3, 0x78, 0x67, 0xd7, 0x73, 0xa7, 0xdd, 0xfd, 0x21, 0xe5,
                0xa9, 0x74, 0x3b, 0x47, 0x39, 0xe3, 0x31, 0xad, 0x42, 0xaa, 0xb8, 0x87, 0x40, 0xfa,
                0x63, 0x19, 0x14, 0x57, 0x39, 0xac, 0x14, 0xb5, 0x20, 0x78, 0x14, 0x1a, 0xbe, 0x77,
                0x2b, 0x62, 0x36, 0x63, 0xa3, 0x09, 0x01, 0xd2, 0xcd, 0xa2, 0x9e, 0x00, 0x27, 0x8d,
                0x1a, 0x0a, 0x62, 0x63, 0xc2, 0xf8, 0xf4, 0x33, 0xd3, 0x4a, 0x92, 0x53, 0x90, 0x0e,
                0x0b, 0xa6, 0x04, 0xbc, 0xc3, 0x13, 0xb4, 0xcf, 0x88, 0xe0, 0x35, 0x2a, 0x9c, 0x9c,
                0xbb, 0x52, 0x33, 0x44, 0xa6, 0xd4, 0x84, 0xf4, 0x29, 0xf8, 0x20, 0xac, 0xfc, 0x0a,
                0x30, 0x4d, 0xff, 0x68, 0x38, 0x64, 0xdb, 0xc9, 0x4c, 0xa7, 0x18, 0x41, 0x8e, 0x4a,
                0xfe, 0x8d, 0x05, 0x85, 0x6e, 0x7d, 0xd9, 0x04, 0xb0, 0xe6, 0xbe, 0x3f, 0xd4, 0xc9,
                0xc7, 0x22, 0x67, 0xb3, 0x02, 0xcf, 0x79, 0xed, 0xa3, 0x2d, 0x7f, 0xe1, 0x61, 0x31,
                0x29, 0x57, 0x0c, 0xab, 0x8e, 0x59, 0x00, 0x74, 0xf7, 0x0d, 0xc2, 0xd8, 0x39, 0xab,
                0xc5, 0xba, 0x6c, 0x91, 0x47, 0x72, 0xe1, 0x97, 0xd2, 0x49, 0xbe, 0xc5, 0x9f, 0xca,
                0x10, 0x70, 0x5c, 0xfe, 0xbc, 0xaf, 0x41, 0x12, 0x83, 0x6b, 0x1f, 0x97, 0xec, 0xd9,
                0x8c, 0x5e, 0xbc, 0xa7, 0x95, 0x9d, 0x02, 0x90, 0x8f, 0xeb, 0x38, 0x18, 0xe4, 0xc4,
                0xee, 0xb3, 0x5c, 0xc1, 0xe6, 0xc2, 0x70, 0x06, 0x45,
            ],
        };
        let test_file = Path::new("testdata/certs/testcert.pem");
        let mut parsed_certs = load_certificates_from_file(test_file, Some(1))?;
        assert_eq!(parsed_certs.len(), 1);
        let actual_cert = parsed_certs.remove(0);

        assert_eq!(actual_cert, expected_cert);
        Ok(())
    }
}
