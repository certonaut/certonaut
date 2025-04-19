use crate::dns::name::DnsName;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use tracing::warn;

const MAX_CNAME_CHAIN_LENGTH: usize = 10;

#[cfg_attr(test, faux::create)]
#[derive(Debug)]
pub struct Resolver {
    resolver: hickory_resolver::Resolver<TokioConnectionProvider>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

// impl block for new() functions outside of main impl block to avoid linter being confused by faux
impl Resolver {
    /// Create a new DNS resolver with default settings. The resolver will use the system configuration (`/etc/resolv.conf` or equivalent)
    /// if available, otherwise it falls back to a compiled-in default (currently Cloudflare DNS).
    pub fn new() -> Self {
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .unwrap_or_else(|e| {
                warn!("Failed to create DNS resolver using system configuration, using default servers instead: {e:#}");
                hickory_resolver::Resolver::builder_with_config(
                    ResolverConfig::cloudflare(),
                    TokioConnectionProvider::default(),
                )
            })
            .build();
        Self::__new(resolver)
    }

    /// Create a new DNS resolver using the provided nameservers for DNS resolution
    pub fn new_with_upstream(nameservers: NameServerConfigGroup) -> Self {
        let resolver = hickory_resolver::Resolver::builder_with_config(
            ResolverConfig::from_parts(None, Vec::new(), nameservers),
            TokioConnectionProvider::default(),
        )
        .build();
        Self::__new(resolver)
    }
}

#[cfg_attr(test, faux::methods)]
impl Resolver {
    // Helper function for faux
    #[inline]
    fn __new(resolver: hickory_resolver::Resolver<TokioConnectionProvider>) -> Self {
        Self { resolver }
    }

    // fn get_owned_resolver(&self) -> Arc<hickory_resolver::Resolver<TokioConnectionProvider>> {
    //     self.resolver.clone()
    // }

    pub async fn lookup_generic(
        &self,
        source: DnsName,
        rtype: RecordType,
    ) -> Result<Lookup, Error> {
        match self.resolver.lookup(source, rtype).await {
            Ok(lookup) => Ok(lookup),
            // Note: Order matters, because is_no_records_found includes is_nx_domain
            Err(e) if e.is_nx_domain() => Err(Error::NxDomain),
            Err(e) if e.is_no_records_found() => Err(Error::NoRecords(rtype)),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn resolve_cname_chain(&self, source: DnsName) -> Result<DnsName, Error> {
        let mut cname_lookups = 0;
        let mut current = source;
        let resolved = loop {
            cname_lookups += 1;
            if cname_lookups > MAX_CNAME_CHAIN_LENGTH {
                return Err(Error::CNameChainTooLong);
            }
            let lookup = match self
                .lookup_generic(current.clone(), RecordType::CNAME)
                .await
            {
                Ok(lookup) => lookup,
                Err(Error::NoRecords(_) | Error::NxDomain) => {
                    break current;
                }
                other_error => other_error?,
            };
            let new_source = lookup.record_iter().find_map(|record| {
                let record_name: DnsName = record.name().into();
                if let Some(cname) = record.data().as_cname() {
                    if record_name == current {
                        return Some((&cname.0).into());
                    }
                }
                None
            });
            match new_source {
                Some(new_source) if current == new_source => {
                    // CNAME that points to itself? Abort search, consider this the final result
                    break new_source;
                }
                Some(new_source) => {
                    // CNAME points to another name, continue search
                    current = new_source;
                }
                None => {
                    // No valid CNAME in lookup, consider this the final result
                    break current;
                }
            }
        };
        Ok(resolved)
    }
}

// impl reqwest::dns::Resolve for Resolver {
//     fn resolve(&self, name: reqwest::dns::Name) -> Resolving {
//         let resolver = self.get_owned_resolver();
//         async move {
//             let name: DnsName = name.try_into().context("invalid DNS name")?;
//             let lookup = resolver.lookup_ip(name).await?;
//             let addrs: reqwest::dns::Addrs =
//                 Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0)));
//             Ok(addrs)
//         }
//         .boxed()
//     }
// }

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the domain does not exist (NXDOMAIN)")]
    NxDomain,
    #[error("No DNS records found for RR type {0}")]
    NoRecords(RecordType),
    #[error("The domain name has too many CNAMEs (possible CNAME loop?)")]
    CNameChainTooLong,
    #[error("DNS resolution failed")]
    LookupFailure(#[from] hickory_resolver::ResolveError),
}

#[cfg(test)]
mod tests {
    use crate::dns::resolver::{Error, Resolver};
    use hickory_resolver::proto::rr::RecordType;
    use rstest::rstest;

    #[tokio::test]
    #[rstest]
    #[case("cname-1.test.certonaut.net.", "cname-3.test.certonaut.net.")]
    #[case("cname-1.test.certonaut.net", "cname-3.test.certonaut.net.")]
    #[case("cname-2.test.certonaut.net", "cname-3.test.certonaut.net.")]
    #[case("cname-2.test.certonaut.net.", "cname-3.test.certonaut.net.")]
    #[case("cname-3.test.certonaut.net.", "cname-3.test.certonaut.net.")]
    #[case("cname-3.test.certonaut.net", "cname-3.test.certonaut.net.")]
    #[case("nxdomain.test.certonaut.net", "nxdomain.test.certonaut.net.")]
    async fn test_resolve_cname_chain(#[case] source: &str, #[case] expected: &str) {
        let source = source.try_into().unwrap();
        let expected = expected.try_into().unwrap();
        let resolver = Resolver::new();

        let actual_cname = resolver.resolve_cname_chain(source).await.unwrap();

        assert_eq!(actual_cname, expected);
    }

    #[tokio::test]
    async fn test_lookup_generic() {
        let resolver = Resolver::new();

        let lookup = resolver
            .lookup_generic(
                "cname-3.test.certonaut.net".try_into().unwrap(),
                RecordType::TXT,
            )
            .await
            .unwrap();

        assert_eq!(lookup.records().len(), 2);
    }

    #[tokio::test]
    #[rstest]
    #[case("cname-3.test.certonaut.net.", RecordType::A)]
    #[case("cname-3.test.certonaut.net", RecordType::A)]
    async fn test_lookup_generic_with_no_records(
        #[case] name: &str,
        #[case] record_type: RecordType,
    ) {
        let resolver = Resolver::new();

        let lookup = resolver
            .lookup_generic(name.try_into().unwrap(), record_type)
            .await;

        assert!(
            matches!(lookup, Err(Error::NoRecords(RecordType::A))),
            "invalid lookup result: {lookup:?}"
        );
    }

    #[tokio::test]
    #[rstest]
    #[case("nxdomain.test.certonaut.net.", RecordType::TXT)]
    #[case("nxdomain.test.certonaut.net", RecordType::TXT)]
    async fn test_lookup_generic_with_nxdomain(
        #[case] name: &str,
        #[case] record_type: RecordType,
    ) {
        let resolver = Resolver::new();

        let lookup = resolver
            .lookup_generic(name.try_into().unwrap(), record_type)
            .await;

        assert!(
            matches!(lookup, Err(Error::NxDomain)),
            "invalid lookup result: {lookup:?}"
        );
    }
}
