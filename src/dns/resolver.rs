use crate::dns::name::DnsName;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use tracing::warn;

const MAX_CNAME_CHAIN_LENGTH: usize = 10;

pub struct Resolver {
    resolver: hickory_resolver::Resolver<TokioConnectionProvider>,
}

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
        Self { resolver }
    }

    async fn lookup_generic(&self, source: DnsName, rtype: RecordType) -> Result<Lookup, Error> {
        match self.resolver.lookup(source, rtype).await {
            Ok(lookup) => Ok(lookup),
            Err(e) if e.is_no_records_found() => Err(Error::NoRecords(rtype)),
            Err(e) if e.is_nx_domain() => Err(Error::NxDomain),
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
                Err(Error::NoRecords(_)) => {
                    break current;
                }
                other_error => other_error?,
            };
            let new_source = lookup.record_iter().find_map(|record| {
                let record_name: DnsName = record.name().into();
                if let Some(cname) = record.data().as_cname() {
                    if record_name.eq_ignore_root(&current) {
                        return Some((&cname.0).into());
                    }
                }
                None
            });
            match new_source {
                Some(new_source) if current.eq_ignore_root(&new_source) => {
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

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

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
    use crate::dns::resolver::Resolver;
    use rstest::rstest;

    #[tokio::test]
    #[rstest]
    #[case("cname-1.test.certonaut.net.", "cname-3.test.certonaut.net.")]
    #[case("cname-1.test.certonaut.net", "cname-3.test.certonaut.net.")]
    #[case("cname-2.test.certonaut.net", "cname-3.test.certonaut.net.")]
    #[case("cname-2.test.certonaut.net.", "cname-3.test.certonaut.net.")]
    #[case("cname-3.test.certonaut.net.", "cname-3.test.certonaut.net.")]
    #[case("cname-3.test.certonaut.net", "cname-3.test.certonaut.net")]
    async fn test_resolve_cname_chain(#[case] source: &str, #[case] expected: &str) {
        let source = source.try_into().unwrap();
        let expected = expected.try_into().unwrap();
        let resolver = Resolver::new();

        let actual_cname = resolver.resolve_cname_chain(source).await.unwrap();

        assert_eq!(actual_cname, expected);
    }
}
