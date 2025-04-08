use anyhow::bail;
use async_trait::async_trait;
use certonaut::dns::name::DnsName;
use hickory_resolver::Name;
use hickory_resolver::config::NameServerConfigGroup;
use hickory_resolver::proto::rr::{LowerName, RecordType};
use hickory_server::ServerFuture;
use hickory_server::authority::{
    AuthLookup, Authority, Catalog, LookupControlFlow, LookupObject, LookupOptions, MessageRequest,
    UpdateResult, ZoneType,
};
use hickory_server::proto::rr::rdata::{CNAME, SOA};
use hickory_server::proto::rr::{RData, Record};
use hickory_server::server::RequestInfo;
use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use hickory_server::store::in_memory::InMemoryAuthority;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use url::Url;

/// `StubDnsResolver` is a (test-only) DNS solver that combines local and forwarding lookups.
/// It can be "stubbed" with a local zone whose records can be added/removed dynamically.
/// Additionally, it forwards other queries to one or more remote (recursive) DNS servers.
///
/// While `StubDnsResolver` is not a recursive resolver, it does implement some basic
/// CNAME chasing to resolve `CNAME` records added in the local zone via the remote DNS server.
/// This is particularly useful for mocking ACME DNS-01 CNAME records.
///
/// It does **not** implement the DNS protocol correctly and must only be used for testing.
pub struct StubDnsResolver {
    server: ServerFuture<Catalog>,
    authority: Arc<StubAuthority>,
    listen_port: u16,
}

impl StubDnsResolver {
    /// Create a new resolver instance.
    ///
    /// # Arguments
    /// - `listen_port` - The port the resolver will listen on. Currently IPv4 UDP only (no TCP). Set to 0 to choose an arbitrary port.
    /// - `local_zone` - Zone name where local data can be added.
    /// - `forward_servers` - All queries will be forwarded to (at least one) forward server and the results are merged with the local zone.
    ///   Can be an empty list, in which case forwarding is implicitly disabled.
    pub async fn try_new(
        listen_port: u16,
        local_zone: Name,
        forward_servers: NameServerConfigGroup,
    ) -> anyhow::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            listen_port,
        )))
        .await?;
        let listen_port = socket.local_addr()?.port();
        let mut catalog = Catalog::default();
        let authority = Arc::new(StubAuthority::try_new(local_zone, forward_servers)?);
        catalog.upsert(LowerName::from(Name::root()), vec![authority.clone()]);
        let mut server = ServerFuture::new(catalog);
        server.register_socket(socket);
        Ok(Self {
            server,
            authority,
            listen_port,
        })
    }

    pub fn authority(&self) -> &StubAuthority {
        &self.authority
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn get_dns_url(&self, host_ip: IpAddr) -> Result<Url, url::ParseError> {
        Url::parse(&format!("dns://{host_ip}:{}", self.listen_port()))
    }
}

pub struct StubAuthority {
    local_authority: InMemoryAuthority,
    forwarding_authority: ForwardAuthority,
}

impl StubAuthority {
    fn try_new(local_zone: Name, upstream_dns: NameServerConfigGroup) -> anyhow::Result<Self> {
        let mut local_authority =
            InMemoryAuthority::empty(local_zone.clone(), ZoneType::Primary, false);
        local_authority.upsert_mut(
            Record::from_rdata(
                local_zone,
                60,
                RData::SOA(SOA::new(Name::root(), Name::root(), 0, 1, 1, 120, 60)),
            ),
            0,
        );
        let forwarding_authority = ForwardAuthority::builder_tokio(ForwardConfig {
            name_servers: upstream_dns,
            options: None,
        })
        .build()
        .map_err(anyhow::Error::msg)?;
        Ok(Self {
            local_authority,
            forwarding_authority,
        })
    }

    pub async fn add_record(&self, name: Name, record: RData) -> bool {
        self.local_authority
            .upsert(Record::from_rdata(name, 60, record), 0)
            .await
    }

    pub async fn add_cname(&self, name: DnsName, target: DnsName) -> anyhow::Result<()> {
        if self
            .add_record(name.into(), RData::CNAME(CNAME(target.into())))
            .await
        {
            Ok(())
        } else {
            bail!("Adding CNAME failed")
        }
    }

    pub async fn remove_record(&self, name: Name, record_type: RecordType) -> bool {
        self.local_authority
            .upsert(Record::update0(name, 60, record_type), 0)
            .await
    }

    fn extract_cname(
        result: &LookupControlFlow<<InMemoryAuthority as Authority>::Lookup>,
    ) -> Option<CNAME> {
        match result {
            LookupControlFlow::Continue(result) | LookupControlFlow::Break(result) => {
                match result {
                    Ok(result) => {
                        for record in result {
                            if let Some(cname) = record.data().as_cname() {
                                return Some(cname.clone());
                            }
                        }
                        None
                    }
                    Err(_) => None,
                }
            }
            LookupControlFlow::Skip => None,
        }
    }

    async fn chase_cname(
        &self,
        cname: &CNAME,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<<ForwardAuthority as Authority>::Lookup> {
        self.forwarding_authority
            .lookup(&LowerName::from(&cname.0), rtype, lookup_options)
            .await
    }

    fn merge_lookups(
        local_results: LookupControlFlow<<InMemoryAuthority as Authority>::Lookup>,
        forward_results: LookupControlFlow<<ForwardAuthority as Authority>::Lookup>,
    ) -> LookupControlFlow<StubLookup> {
        let control_flow = match (&local_results, &forward_results) {
            (LookupControlFlow::Continue(_), LookupControlFlow::Continue(_))
            | (&LookupControlFlow::Continue(_), &LookupControlFlow::Skip)
            | (&LookupControlFlow::Skip, &LookupControlFlow::Continue(_)) => {
                LookupControlFlow::<StubLookup, ()>::Continue(Ok(StubLookup::default()))
            }
            (LookupControlFlow::Skip, LookupControlFlow::Skip) => LookupControlFlow::Skip,
            (LookupControlFlow::Break(_), _) | (_, LookupControlFlow::Break(_)) => {
                LookupControlFlow::Break(Ok(StubLookup::default()))
            }
        };
        let local = match local_results {
            LookupControlFlow::Continue(result) | LookupControlFlow::Break(result) => result,
            LookupControlFlow::Skip => Ok(AuthLookup::default()),
        };
        let forward = match forward_results {
            LookupControlFlow::Continue(result) | LookupControlFlow::Break(result) => Some(result),
            LookupControlFlow::Skip => None,
        };
        let stub_result = match (local, forward) {
            (Err(local), Some(Err(_)) | None) => Err(local),
            (Err(_), Some(Ok(forward))) => Ok(StubLookup {
                local_lookup: AuthLookup::default(),
                forward_lookup: Some(forward),
            }),
            (Ok(local), Some(Ok(forward))) => Ok(StubLookup {
                local_lookup: local,
                forward_lookup: Some(forward),
            }),
            (Ok(local), None | Some(Err(_))) => Ok(StubLookup {
                local_lookup: local,
                forward_lookup: None,
            }),
        };
        match control_flow {
            LookupControlFlow::Continue(_) => LookupControlFlow::Continue(stub_result),
            LookupControlFlow::Break(_) => LookupControlFlow::Break(stub_result),
            LookupControlFlow::Skip => LookupControlFlow::Skip,
        }
    }

    fn merge_extra_lookups(
        stub_result: LookupControlFlow<StubLookup>,
        forward_results: LookupControlFlow<<ForwardAuthority as Authority>::Lookup>,
    ) -> LookupControlFlow<StubLookup> {
        let forward_result = match forward_results {
            LookupControlFlow::Continue(result) | LookupControlFlow::Break(result) => {
                match result {
                    Ok(result) => result,
                    Err(_) => {
                        return stub_result;
                    }
                }
            }
            LookupControlFlow::Skip => {
                return stub_result;
            }
        };
        match stub_result {
            LookupControlFlow::Continue(Ok(mut stub_result)) => match stub_result.forward_lookup {
                None => {
                    stub_result.forward_lookup = Some(forward_result);
                    LookupControlFlow::Continue(Ok(stub_result))
                }
                Some(mut existing_result) => {
                    existing_result
                        .0
                        .extend_records(forward_result.0.record_iter().cloned().collect());
                    stub_result.forward_lookup = Some(existing_result);
                    LookupControlFlow::Continue(Ok(stub_result))
                }
            },
            LookupControlFlow::Break(Ok(mut stub_result)) => match stub_result.forward_lookup {
                None => {
                    stub_result.forward_lookup = Some(forward_result);
                    LookupControlFlow::Break(Ok(stub_result))
                }
                Some(mut existing_result) => {
                    existing_result
                        .0
                        .extend_records(forward_result.0.record_iter().cloned().collect());
                    stub_result.forward_lookup = Some(existing_result);
                    LookupControlFlow::Break(Ok(stub_result))
                }
            },
            LookupControlFlow::Continue(Err(e)) => LookupControlFlow::Continue(Err(e)),
            LookupControlFlow::Break(Err(e)) => LookupControlFlow::Break(Err(e)),
            LookupControlFlow::Skip => LookupControlFlow::Skip,
        }
    }
}

#[derive(Default)]
pub struct StubLookup {
    local_lookup: <InMemoryAuthority as Authority>::Lookup,
    forward_lookup: Option<<ForwardAuthority as Authority>::Lookup>,
}

impl LookupObject for StubLookup {
    fn is_empty(&self) -> bool {
        self.local_lookup.is_empty()
            && self
                .forward_lookup
                .as_ref()
                .is_none_or(hickory_server::authority::LookupObject::is_empty)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        let iter: Box<dyn Iterator<Item = &'a Record> + Send + 'a> =
            Box::new(self.local_lookup.iter());
        if let Some(forward_lookup) = self.forward_lookup.as_ref() {
            Box::new(iter.chain(Box::new(forward_lookup.iter())))
        } else {
            iter
        }
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        // TODO: Should actually merge instead of returning just one
        LookupObject::take_additionals(&mut self.local_lookup).or_else(|| {
            self.forward_lookup
                .as_mut()
                .and_then(hickory_server::authority::LookupObject::take_additionals)
        })
    }
}

#[async_trait]
impl Authority for StubAuthority {
    type Lookup = StubLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.local_authority.update(update).await
    }

    fn origin(&self) -> &LowerName {
        self.local_authority.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let local_results = self
            .local_authority
            .lookup(name, rtype, lookup_options)
            .await;
        let forward_results = self
            .forwarding_authority
            .lookup(name, rtype, lookup_options)
            .await;
        let cname = Self::extract_cname(&local_results);
        let stub = Self::merge_lookups(local_results, forward_results);
        if let Some(cname) = cname {
            let extra_results = self.chase_cname(&cname, rtype, lookup_options).await;
            Self::merge_extra_lookups(stub, extra_results)
        } else {
            stub
        }
    }

    async fn search(
        &self,
        request: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let local_results = self
            .local_authority
            .search(request.clone(), lookup_options)
            .await;
        let forward_results = self
            .forwarding_authority
            .search(request.clone(), lookup_options)
            .await;
        let cname = Self::extract_cname(&local_results);
        let stub = Self::merge_lookups(local_results, forward_results);
        if let Some(cname) = cname {
            let extra_results = self
                .chase_cname(&cname, request.query.query_type(), lookup_options)
                .await;
            Self::merge_extra_lookups(stub, extra_results)
        } else {
            stub
        }
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let local_results = self
            .local_authority
            .get_nsec_records(name, lookup_options)
            .await;
        let forward_results = self
            .forwarding_authority
            .get_nsec_records(name, lookup_options)
            .await;
        Self::merge_lookups(local_results, forward_results)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::dns::StubDnsResolver;
    use certonaut::dns::name::DnsName;
    use hickory_resolver::config::NameServerConfigGroup;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::proto::rr::rdata::CNAME;
    use hickory_server::proto::rr::RData;
    use hickory_server::proto::rr::rdata::A;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_stub_dns_resolver_local_data_resolves() -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            0,
            DnsName::try_from("example.org")?.into(),
            NameServerConfigGroup::new(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                server.listen_port(),
                true,
            ),
        );
        let source_name = DnsName::try_from("local-zone-test-initial.example.org")?;
        let destination_name = DnsName::try_from("local-zone-test-destination.example.org")?;
        let authority = server.authority();
        authority
            .add_record(
                source_name.clone().into(),
                RData::CNAME(CNAME(destination_name.clone().into())),
            )
            .await;
        let resolved_name = resolver.resolve_cname_chain(source_name).await?;
        assert_eq!(resolved_name, destination_name);
        Ok(())
    }

    #[tokio::test]
    async fn test_stub_dns_resolver_local_data_removed() -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            0,
            DnsName::try_from("example.org")?.into(),
            NameServerConfigGroup::new(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                server.listen_port(),
                true,
            ),
        );
        let source_name = DnsName::try_from("local-zone-test.example.org")?;
        let destination_name = DnsName::try_from("somewhere-else.example.org")?;
        let authority = server.authority();
        authority
            .add_record(
                source_name.clone().into(),
                RData::CNAME(CNAME(destination_name.clone().into())),
            )
            .await;
        authority
            .remove_record(source_name.clone().into(), RecordType::CNAME)
            .await;
        let resolved_name = resolver.resolve_cname_chain(source_name.clone()).await?;
        assert_eq!(resolved_name, source_name);
        Ok(())
    }

    #[tokio::test]
    async fn test_stub_dns_resolver_local_data_forwards_cname() -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            0,
            DnsName::try_from("example.org")?.into(),
            NameServerConfigGroup::cloudflare(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                server.listen_port(),
                true,
            ),
        );
        let source_name = DnsName::try_from("initial-name-local-test.example.org")?;
        let destination_name = DnsName::try_from("cname-1.test.certonaut.net")?;
        let authority = server.authority();
        authority
            .add_record(
                source_name.clone().into(),
                RData::CNAME(CNAME(destination_name.clone().into())),
            )
            .await;
        // tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        let lookup = resolver
            .lookup_generic(source_name, RecordType::TXT)
            .await?;
        assert_eq!(
            lookup
                .records()
                .iter()
                .filter(|record| record.record_type() == RecordType::TXT)
                .count(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_stub_dns_resolver_when_local_zone_has_no_entries_returns_upstream()
    -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            0,
            DnsName::try_from("test.certonaut.net")?.into(),
            NameServerConfigGroup::cloudflare(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                server.listen_port(),
                true,
            ),
        );
        let source_name = DnsName::try_from("override.cname-1.test.certonaut.net")?;
        let parent_domain = DnsName::try_from("cname-1.test.certonaut.net")?;
        let authority = server.authority();
        authority
            .add_record(source_name.clone().into(), RData::A(A(Ipv4Addr::LOCALHOST)))
            .await;
        let lookup = resolver
            .lookup_generic(parent_domain, RecordType::CNAME)
            .await?;
        assert_eq!(lookup.records().iter().count(), 1);
        Ok(())
    }
}
