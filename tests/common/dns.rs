use anyhow::bail;
use async_trait::async_trait;
use certonaut::dns::name::DnsName;
use certonaut::url::Url;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig};
use hickory_server::Server;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::{CNAME, SOA};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType, TSigResponseContext};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
    ZoneHandler, ZoneType,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

/// Time a TCP client may stay idle before the stub server hangs up on it.
const TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Number of outgoing responses the stub server buffers per TCP connection.
const RESPONSE_BUFFER_SIZE: usize = 16;

/// Build a plaintext (UDP + TCP) nameserver configuration for each of `ips`, all using `port`.
pub fn nameservers_at_port(ips: &[IpAddr], port: u16) -> Vec<NameServerConfig> {
    ips.iter()
        .map(|&ip| {
            let connections = [ConnectionConfig::udp(), ConnectionConfig::tcp()]
                .into_iter()
                .map(|mut connection| {
                    connection.port = port;
                    connection
                })
                .collect();
            NameServerConfig::new(ip, true, connections)
        })
        .collect()
}

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
    authority: Arc<StubAuthority>,
    listen_addr: SocketAddr,
}

impl StubDnsResolver {
    /// Create a new resolver instance.
    ///
    /// # Arguments
    /// - `listen_addr` - The address tuple (IP + port) the resolver will listen on. Supports both UDP and TCP. Set port to 0 to choose an arbitrary port.
    /// - `local_zone` - Zone name where local data can be added.
    /// - `forward_servers` - All queries will be forwarded to (at least one) forward server and the results are merged with the local zone.
    ///   Can be an empty list, in which case forwarding is implicitly disabled.
    pub async fn try_new(
        listen_addr: SocketAddr,
        local_zone: Name,
        forward_servers: Vec<NameServerConfig>,
    ) -> anyhow::Result<Self> {
        let udp_socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        let listen_addr = udp_socket.local_addr()?;

        let tcp_listener = tokio::net::TcpListener::bind(listen_addr).await?;

        let mut catalog = Catalog::default();
        let authority = Arc::new(StubAuthority::try_new(local_zone, forward_servers)?);
        catalog.upsert(LowerName::from(Name::root()), vec![authority.clone()]);
        let mut server = Server::new(catalog);
        server.register_socket(udp_socket);
        server.register_listener(tcp_listener, TCP_REQUEST_TIMEOUT, RESPONSE_BUFFER_SIZE);

        tokio::spawn(async move {
            let _ = server.block_until_done().await;
        });

        Ok(Self {
            authority,
            listen_addr,
        })
    }

    pub fn authority(&self) -> &StubAuthority {
        &self.authority
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_addr.port()
    }

    pub fn get_dns_url(&self) -> Result<Url, url::ParseError> {
        Url::parse(&format!("dns://{}", self.listen_addr))
    }
}

pub struct StubAuthority {
    local_zone: Name,
    origin: LowerName,
    local_records: Mutex<Vec<Record>>,
    local_authority: RwLock<InMemoryZoneHandler>,
    forwarding_authority: ForwardZoneHandler,
}

impl StubAuthority {
    fn try_new(local_zone: Name, upstream_dns: Vec<NameServerConfig>) -> anyhow::Result<Self> {
        let local_authority = Self::build_zone(&local_zone, &[]);
        let forwarding_authority = ForwardZoneHandler::builder_tokio(ForwardConfig {
            name_servers: upstream_dns,
            options: None,
        })
        .build()
        .map_err(anyhow::Error::msg)?;
        Ok(Self {
            origin: LowerName::new(&local_zone),
            local_zone,
            local_records: Mutex::new(Vec::new()),
            local_authority: RwLock::new(local_authority),
            forwarding_authority,
        })
    }

    /// Create a local zone holding nothing but the mandatory SOA record and `records`.
    fn build_zone(local_zone: &Name, records: &[Record]) -> InMemoryZoneHandler {
        let mut zone =
            InMemoryZoneHandler::empty(local_zone.clone(), ZoneType::Primary, AxfrPolicy::Deny);
        zone.upsert_mut(
            Record::from_rdata(
                local_zone.clone(),
                60,
                RData::SOA(SOA::new(Name::root(), Name::root(), 0, 1, 1, 120, 60)),
            ),
            0,
        );
        for record in records {
            zone.upsert_mut(record.clone(), 0);
        }
        zone
    }

    pub async fn add_record(&self, name: Name, record: RData) -> bool {
        let record = Record::from_rdata(name, 60, record);
        self.local_records.lock().await.push(record.clone());
        self.local_authority.read().await.upsert(record, 0).await
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
        let mut records = self.local_records.lock().await;
        let before = records.len();
        records.retain(|record| record.name != name || record.record_type() != record_type);
        if records.len() == before {
            return false;
        }
        *self.local_authority.write().await = Self::build_zone(&self.local_zone, &records);
        true
    }

    fn extract_cname(result: &LookupControlFlow<AuthLookup>) -> Option<CNAME> {
        let (LookupControlFlow::Continue(Ok(result)) | LookupControlFlow::Break(Ok(result))) =
            result
        else {
            return None;
        };
        result.iter().find_map(|record| match &record.data {
            RData::CNAME(cname) => Some(cname.clone()),
            _ => None,
        })
    }

    async fn chase_cname(
        &self,
        cname: &CNAME,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.forwarding_authority
            .lookup(&LowerName::from(&cname.0), rtype, None, lookup_options)
            .await
    }

    /// Split a control flow value into "continue lookup?" and the response itself (`None` for `Skip`).
    fn split(
        result: LookupControlFlow<AuthLookup>,
    ) -> (bool, Option<Result<AuthLookup, LookupError>>) {
        match result {
            LookupControlFlow::Continue(result) => (false, Some(result)),
            LookupControlFlow::Break(result) => (true, Some(result)),
            LookupControlFlow::Skip => (false, None),
        }
    }

    /// Collect every record of a lookup, answers and additionals alike, into a flat list.
    ///
    /// The catalog drops the additional section for external (i.e. forwarding) zones, so anything
    /// the client should see has to end up in the answer section.
    fn all_records(lookup: &AuthLookup) -> Vec<Record> {
        let mut records: Vec<Record> = lookup.iter().cloned().collect();
        if let Some(additionals) = lookup.additionals() {
            records.extend(additionals.cloned());
        }
        records
    }

    /// Concatenate two lookups into a single answer section, dropping duplicate records.
    fn concat(first: &AuthLookup, second: &AuthLookup) -> AuthLookup {
        let mut records = Self::all_records(first);
        for record in Self::all_records(second) {
            if !records.contains(&record) {
                records.push(record);
            }
        }
        AuthLookup::answers(LookupRecords::Section(records), None)
    }

    /// Merge two lookup results into one.
    ///
    /// A successful lookup wins over a failed one; if both succeeded, their records are
    /// concatenated. `Break` from either side is preserved, and `Skip` is only returned if both
    /// sides skipped.
    fn merge_lookups(
        local_results: LookupControlFlow<AuthLookup>,
        forward_results: LookupControlFlow<AuthLookup>,
    ) -> LookupControlFlow<AuthLookup> {
        let (local_break, local) = Self::split(local_results);
        let (forward_break, forward) = Self::split(forward_results);
        let merged = match (local, forward) {
            (None, None) => return LookupControlFlow::Skip,
            (Some(Ok(local)), Some(Ok(forward))) => Ok(Self::concat(&local, &forward)),
            // Pass a lone lookup through untouched: for a forwarded one this preserves the
            // answer/authority/additional split that the catalog knows how to unpack.
            (Some(Ok(lookup)), _) | (_, Some(Ok(lookup))) => Ok(lookup),
            (Some(Err(local)), _) => Err(local),
            (None, Some(Err(forward))) => Err(forward),
        };
        if local_break || forward_break {
            LookupControlFlow::Break(merged)
        } else {
            LookupControlFlow::Continue(merged)
        }
    }
}

#[async_trait]
impl ZoneHandler for StubAuthority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        self.local_authority.read().await.update(update, now).await
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let local_results = self
            .local_authority
            .read()
            .await
            .lookup(name, rtype, request_info, lookup_options)
            .await;
        let forward_results = self
            .forwarding_authority
            .lookup(name, rtype, request_info, lookup_options)
            .await;
        let cname = Self::extract_cname(&local_results);
        let merged = Self::merge_lookups(local_results, forward_results);
        if let Some(cname) = cname {
            let extra_results = self.chase_cname(&cname, rtype, lookup_options).await;
            Self::merge_lookups(merged, extra_results)
        } else {
            merged
        }
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let rtype = match request.request_info() {
            Ok(request_info) => request_info.query.query_type(),
            Err(e) => return (LookupControlFlow::Break(Err(e)), None),
        };
        let (local_results, _) = self
            .local_authority
            .read()
            .await
            .search(request, lookup_options)
            .await;
        let (forward_results, _) = self
            .forwarding_authority
            .search(request, lookup_options)
            .await;
        let cname = Self::extract_cname(&local_results);
        let merged = Self::merge_lookups(local_results, forward_results);
        let merged = if let Some(cname) = cname {
            let extra_results = self.chase_cname(&cname, rtype, lookup_options).await;
            Self::merge_lookups(merged, extra_results)
        } else {
            merged
        };
        (merged, None)
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let local_results = self
            .local_authority
            .read()
            .await
            .nsec_records(name, lookup_options)
            .await;
        let forward_results = self
            .forwarding_authority
            .nsec_records(name, lookup_options)
            .await;
        Self::merge_lookups(local_results, forward_results)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::dns::{StubDnsResolver, nameservers_at_port};
    use certonaut::dns::name::DnsName;
    use hickory_resolver::config::CLOUDFLARE;
    use hickory_server::proto::rr::RData;
    use hickory_server::proto::rr::RecordType;
    use hickory_server::proto::rr::rdata::{A, CNAME};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_stub_dns_resolver_local_data_resolves() -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            "127.0.0.1:0".parse()?,
            DnsName::try_from("example.org")?.into(),
            Vec::new(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(nameservers_at_port(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            server.listen_port(),
        ))?;
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
            "127.0.0.1:0".parse()?,
            DnsName::try_from("example.org")?.into(),
            Vec::new(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(nameservers_at_port(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            server.listen_port(),
        ))?;
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
            "127.0.0.1:0".parse()?,
            DnsName::try_from("example.org")?.into(),
            CLOUDFLARE.udp_and_tcp().collect(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(nameservers_at_port(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            server.listen_port(),
        ))?;
        let source_name = DnsName::try_from("initial-name-local-test.example.org")?;
        let destination_name = DnsName::try_from("cname-1.test.certonaut.net")?;
        let authority = server.authority();
        authority
            .add_record(
                source_name.clone().into(),
                RData::CNAME(CNAME(destination_name.clone().into())),
            )
            .await;
        let lookup = resolver
            .lookup_generic(source_name, RecordType::TXT)
            .await?;
        assert_eq!(
            lookup
                .answers()
                .iter()
                .filter(|record| record.record_type() == RecordType::TXT)
                .count(),
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_stub_dns_resolver_local_data_combines_with_upstream() -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            "127.0.0.1:0".parse()?,
            DnsName::try_from("example.org")?.into(),
            CLOUDFLARE.udp_and_tcp().collect(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(nameservers_at_port(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            server.listen_port(),
        ))?;
        let source_name = DnsName::try_from("initial-name-local-test.example.org")?;
        let destination_name = DnsName::try_from("cname-3.test.certonaut.net")?;
        let authority = server.authority();
        authority
            .add_record(
                source_name.clone().into(),
                RData::CNAME(CNAME(destination_name.clone().into())),
            )
            .await;
        let lookup = resolver
            .lookup_generic(source_name, RecordType::TXT)
            .await?;
        assert_eq!(
            lookup
                .answers()
                .iter()
                .filter(|record| record.record_type() == RecordType::TXT)
                .count(),
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_stub_dns_resolver_when_local_zone_has_no_entries_returns_upstream()
    -> anyhow::Result<()> {
        let server = StubDnsResolver::try_new(
            "127.0.0.1:0".parse()?,
            DnsName::try_from("test.certonaut.net")?.into(),
            CLOUDFLARE.udp_and_tcp().collect(),
        )
        .await?;
        let resolver = certonaut::dns::resolver::Resolver::new_with_upstream(nameservers_at_port(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            server.listen_port(),
        ))?;
        let source_name = DnsName::try_from("override.cname-1.test.certonaut.net")?;
        let parent_domain = DnsName::try_from("cname-1.test.certonaut.net")?;
        let authority = server.authority();
        authority
            .add_record(source_name.clone().into(), RData::A(A(Ipv4Addr::LOCALHOST)))
            .await;
        let lookup = resolver
            .lookup_generic(parent_domain, RecordType::CNAME)
            .await?;
        assert_eq!(lookup.answers().iter().count(), 1);
        Ok(())
    }
}
