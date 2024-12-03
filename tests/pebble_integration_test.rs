use anyhow::{anyhow, bail, Context};
use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::acme::object::{ChallengeStatus, InnerChallenge, NewOrderRequest, OrderStatus};
use certonaut::crypto::signing::KeyPair;
use certonaut::pebble::pebble_root;
use std::fs::File;
use url::Url;

const PEBBLE_URL: &str = "https://localhost:14000/dir";

#[tokio::test]
#[ignore]
async fn pebble_e2e_test() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let acme_url = Url::parse(PEBBLE_URL)?;
    let http_client = HttpClient::try_new_with_custom_root(pebble_root()?)?;
    let acme_client = AcmeClientBuilder::new(acme_url)
        .with_http_client(http_client)
        .try_build()
        .await?;
    let keypair = KeyPair::load_from_disk(File::open("testdata/account.key")?)?;
    let register_options = AccountRegisterOptions {
        key: keypair,
        contact: vec!["mailto:admin@example.org".parse()?],
        terms_of_service_agreed: Some(true),
    };
    let (jwk, account_url, account) = acme_client.register_account(register_options).await?;
    println!("{account_url}");
    let identifiers = vec!["example.com".to_string().into()];
    let (order_url, order) = acme_client
        .new_order(
            &jwk,
            &NewOrderRequest {
                identifiers: identifiers.clone(),
                not_before: None,
                not_after: None,
            },
        )
        .await?;
    println!("{order_url}");
    if order.status == OrderStatus::Pending {
        for auth_url in &order.authorizations {
            println!("{auth_url}");
            let auth = acme_client.get_authorization(&jwk, auth_url).await?;
            let challenge = auth
                .challenges
                .iter()
                .find(|challenge| matches!(challenge.inner_challenge, InnerChallenge::Http(_)))
                .ok_or(anyhow!("no HTTP challenge in authorization"))?;
            let token = match &challenge.inner_challenge {
                InnerChallenge::Http(challenge) => &challenge.token,
                InnerChallenge::Dns(challenge) => &challenge.token,
                InnerChallenge::Alpn(challenge) => &challenge.token,
                InnerChallenge::Unknown => bail!("unknown challenge"),
            };
            println!("token: {token}");
            let updated_challenge = acme_client.validate_challenge(&jwk, &challenge.url).await?;
            if updated_challenge.status != ChallengeStatus::Valid {
                bail!("Challenge not valid :(");
            }
        }
    }

    let updated_order = acme_client.get_order(&jwk, &order_url).await?;

    let finished_order = match updated_order.status {
        OrderStatus::Ready => {
            let cert_key = rcgen::KeyPair::generate().context("cert key generation failed")?;
            let cert_params = rcgen::CertificateParams::new(
                identifiers
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>(),
            )
            .context("CSR generation failed")?;
            let csr = cert_params
                .serialize_request(&cert_key)
                .context("Signing CSR failed")?;
            acme_client
                .finalize_order(&jwk, &updated_order, &csr)
                .await?
        }
        OrderStatus::Valid => updated_order,
        status => bail!("order has invalid status: {status:?}"),
    };

    if finished_order.status != OrderStatus::Valid {
        bail!("Order not valid :(");
    }

    let cert_url = finished_order
        .certificate
        .ok_or(anyhow!("Order certificate not found"))?;
    let downloaded_cert = acme_client.download_certificate(&jwk, &cert_url).await?;
    for pem in x509_parser::pem::Pem::iter_from_buffer(&downloaded_cert.pem) {
        let pem = pem.context("Reading next PEM block failed")?;
        let x509 = pem.parse_x509().context("X.509: decoding DER failed")?;
        println!("Parsed downloaded certificate!");
        let subject = x509.subject();
        println!("subject: {subject}");
        let serial = &x509.serial;
        println!("serial: {serial}");
        if let Some(san) = x509.subject_alternative_name()? {
            let san = san.value;
            for name in &san.general_names {
                println!("SAN: {name}");
            }
        }
        let issuer = x509.issuer();
        println!("issuer: {issuer}");
        let validity = x509.validity();
        let not_before = validity.not_before;
        let not_after = validity.not_after;
        println!("not before: {not_before}");
        println!("not after: {not_after}");
        println!();
    }
    let alternates = downloaded_cert.alternate_chains;
    println!("We could also have fetched these alternate chains:");
    for alternate in alternates {
        println!("{alternate}");
    }
    Ok(())
}
