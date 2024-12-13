use crate::challenge_solver::HttpChallengeParameters;
use crate::CRATE_NAME;
use anyhow::{anyhow, Context};
use caps::{CapSet, Capability};
use futures::future;
use http::HeaderName;
use http_body_util::{Either, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags};
use std::fs::File;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{Arc, LazyLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

const MAX_OPEN_CONNECTIONS: usize = 200;

const MINIMUM_KERNEL_MAJOR: usize = 5;
const MINIMUM_KERNEL_MINOR: usize = 9;

mod port_mapper {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/port_mapper.skel.rs"));
}

static HOP_BY_HOP_HEADERS: LazyLock<Vec<HeaderName>> = LazyLock::new(|| {
    // We intentionally keep most of the hop-by-hop headers. While technically violating specification
    // we want to be as transparent as possible. We only remove headers where forwarding them
    // would create a connection issue or security problem.
    vec![
        http::header::CONNECTION,
        // TODO: Someone smuggling X-Forwarded-For via TRAILER header? Is that a thing?
        //        http::header::TRAILER,
        http::header::FORWARDED,
        // Below are nonstandard, but should be stripped anyway
        HeaderName::from_static("x-forwarded-for"), // Don't know if trustworthy or not, so strip
        HeaderName::from_static("x-forwarded-proto"),
        http::header::UPGRADE,
    ]
});

static SOLVER_LOCK: Mutex<()> = Mutex::const_new(());

fn load_bpf<'a, I>(challenge_port: u16, sockets: I) -> anyhow::Result<Link>
where
    I: Iterator<Item = &'a TcpListener>,
{
    let mut open_object = MaybeUninit::uninit();
    let skeleton_builder = port_mapper::PortMapperSkelBuilder::default();
    let open_skeleton = skeleton_builder
        .open(&mut open_object)
        .context("Initializing BPF program")?;
    open_skeleton.maps.rodata_data.CHALLENGE_PORT = u32::from(challenge_port);

    let skeleton = open_skeleton.load().context("Loading BPF program")?;
    for (idx, socket) in sockets.enumerate() {
        let idx = (idx as u32).to_ne_bytes();
        let fd = socket.as_raw_fd().to_ne_bytes();
        skeleton
            .maps
            .solver_socket
            .update(&idx, &fd, MapFlags::ANY)
            .context("Configuring BPF program")?;
    }

    // Assumes we're not running containerized, otherwise we won't get called for the challenge port
    let network_namespace = File::open("/proc/self/ns/net").context("Failed to load network namespace")?;
    let proxy_challenge_link = skeleton
        .progs
        .proxy_challenge
        .attach_netns(network_namespace.as_raw_fd())
        .context("Attaching BPF program to network namespace")?;
    Ok(proxy_challenge_link)
}

async fn http_handler(
    params: &HttpChallengeParameters,
    client_addr: SocketAddr,
    request: Request<hyper::body::Incoming>,
) -> anyhow::Result<Response<Either<Full<Bytes>, hyper::body::Incoming>>> {
    let path = request.uri().path();
    // This condition is slightly too broad as it will also answer with the challenge on paths like
    // /.well-known/acme-challenge/something/token, but it avoids string allocations for an exact match.
    if path.starts_with("/.well-known/acme-challenge/") && path.ends_with(params.token.as_str()) {
        Ok(Response::builder()
            .status(200)
            .header(http::header::SERVER, CRATE_NAME)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(Either::Left(Full::new(Bytes::from(
                params.key_authorization.to_string(),
            ))))?)
    } else {
        // Reverse proxy to the actual server
        proxy_http(client_addr, params.challenge_port, request)
            .await
            .map(|response| {
                let (mut parts, body) = response.into_parts();
                for hop_header in HOP_BY_HOP_HEADERS.iter() {
                    parts.headers.remove(hop_header);
                }
                Response::from_parts(parts, Either::Right(body))
            })
            .or_else(|e| {
                warn!("Forwarding failed: {e}");
                Ok(Response::builder()
                    .status(502)
                    .header(http::header::SERVER, CRATE_NAME)
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .body(Either::Left(Full::new(Bytes::from(
                        "Unable to forward request to HTTP server",
                    ))))?)
            })
    }
}

async fn proxy_http(
    client_addr: SocketAddr,
    challenge_port: u16,
    request: Request<hyper::body::Incoming>,
) -> anyhow::Result<Response<hyper::body::Incoming>> {
    // TODO: Reuse connections
    let stream = TcpStream::connect(("127.0.0.1", challenge_port)).await?;
    let io = TokioIo::new(stream);

    let max_headers = request.headers().len() + 10;

    let mut client_builder = hyper::client::conn::http1::Builder::new();
    client_builder.preserve_header_case(true).http09_responses(true);
    // For performance reasons, only set this field if it exceeds hyper's default
    if max_headers > 100 {
        client_builder.max_headers(max_headers);
    }
    let (mut sender, conn) = client_builder.handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            warn!("Connection failed: {err:#}");
        }
    });

    let mut req_builder = Request::builder().method(request.method()).uri(request.uri());

    for (header_name, header_value) in request.headers() {
        if HOP_BY_HOP_HEADERS.contains(header_name) {
            continue;
        }
        req_builder = req_builder.header(header_name, header_value);
    }

    let additional_hop_headers = request
        .headers()
        .get(http::header::CONNECTION)
        .and_then(|connection| connection.to_str().ok())
        .map(|connection| connection.split(','))
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|hop_header| {
            let lower = hop_header.to_lowercase();
            lower != "close" && lower != "keep-alive" && lower != "upgrade"
        })
        .collect::<Vec<&str>>();
    // Re-add the Connection header if it contains additional hop-by-hop headers
    if !additional_hop_headers.is_empty() {
        req_builder = req_builder.header(
            http::header::CONNECTION,
            "close, ".to_string() + &additional_hop_headers.join(", "),
        );
    }

    let client_ip = client_addr.ip().to_string();
    let client_port = client_addr.port();
    let client_forwarded_for = match client_addr.ip() {
        IpAddr::V4(v4) => format!("{v4}:{client_port}"),
        IpAddr::V6(v6) => format!(r#""[{v6}]:{client_port}""#),
    };
    req_builder = req_builder
        .header(
            http::header::FORWARDED,
            format!("for={client_forwarded_for};proto=http"),
        )
        .header("X-Forwarded-Proto", "http")
        .header("X-Forwarded-For", &client_ip);

    let request = req_builder.body(request.into_body())?;
    let res = sender.send_request(request).await?;
    Ok(res)
}

// TODO: Unsupported HTTP features
// - connection upgrade (HTTP websocket)
// - how does hyper handle Trailers & chunked transfers?

pub async fn deploy_challenge(
    params: HttpChallengeParameters,
    cancellation_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let guard = SOLVER_LOCK.lock().await;
    let challenge_port = params.challenge_port;
    // Note to self: The final solver needs to somehow lock to ensure that on parallel issuance, we don't
    // spawn multiple solvers at the same time that all fight for the socket redirection.

    // Dualstack sockets may not work if IPv6 is disabled, or if the platform sets ipv6-only flags by default
    let ipv4_solver = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("Binding local challenge solver socket failed (IPv4)")?;
    let sockets = match TcpListener::bind(("::1", 0)).await {
        Ok(ipv6_solver) => vec![ipv4_solver, ipv6_solver],
        Err(e) => {
            warn!("System does not seem to support IPv6, disabling challenge solver on IPv6: {e}");
            vec![ipv4_solver]
        }
    };
    // Our BPF program runs until the link is dropped, so keep it around while we need it.
    let link = load_bpf(challenge_port, sockets.iter()).context("Loading BPF program failed")?;
    // Limit the max number of open connections to avoid an FD-based DoS
    let connection_limiter = Arc::new(Semaphore::new(MAX_OPEN_CONNECTIONS));
    let params = Arc::new(params);

    Ok(task::spawn(async move {
        loop {
            let permit = connection_limiter
                .clone()
                .acquire_owned()
                .await
                .context("Connection Limiter failed")?;
            let accepts = sockets.iter().map(|socket| Box::pin(socket.accept()));
            let (client, client_addr) = tokio::select! {
                accept_result = future::select_ok(accepts) => {
                    match accept_result {
                        Ok(((client, client_addr), _)) => (client, client_addr),
                        Err(e) => {
                            error!("Failed to accept incoming connections for BPF challenge solver: {e}");
                            return Err(e.into());
                        }
                    }
                }
                () = cancellation_token.cancelled() => {
                    // TODO: Drain the accept queue before leaving
                    break;
                }
            };

            let io = TokioIo::new(client);

            let params = params.clone();
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .half_close(true)
                    .keep_alive(false)
                    .serve_connection(
                        io,
                        service_fn(|request| async { http_handler(&params, client_addr, request).await }),
                    )
                    .await
                {
                    error!("Error serving connection: {err}");
                }
                // Explicit drop to move the permit to this task
                drop(permit);
            });
        }
        // Explicit drop to move the link and guard to this task
        // Drop order matters: Disconnect the BPF program before allowing a new one
        drop(link);
        drop(guard);
        Ok(())
    }))
}

fn get_kernel_version() -> anyhow::Result<(usize, usize, usize)> {
    let kernel_version = std::fs::read_to_string("/proc/sys/kernel/osrelease").context("Reading os-release")?;
    let mut parts = kernel_version.split('.');
    let major = parts
        .next()
        .and_then(|major| major.parse::<usize>().ok())
        .ok_or(anyhow!("Failed to parse kernel version"))?;
    let minor = parts
        .next()
        .and_then(|minor| minor.parse::<usize>().ok())
        .ok_or(anyhow!("Failed to parse kernel version"))?;
    let patch = parts
        .next()
        .and_then(|patch| patch.parse::<usize>().ok())
        .ok_or(anyhow!("Failed to parse kernel version"))?;
    Ok((major, minor, patch))
}

pub fn is_supported() -> bool {
    let (major, minor, _patch) = match get_kernel_version() {
        Ok(version) => version,
        Err(e) => {
            warn!("Failed to determine kernel version, assuming system does not support magic-solver: {e:#}");
            return false;
        }
    };
    if major < MINIMUM_KERNEL_MAJOR {
        debug!("Kernel is way too old to support required BPF features (want {MINIMUM_KERNEL_MAJOR}.x, got {major}.x)");
        return false;
    }
    if major == MINIMUM_KERNEL_MAJOR && minor < MINIMUM_KERNEL_MINOR {
        debug!("Kernel is slightly too old to support required BPF features (want {MINIMUM_KERNEL_MAJOR}.{MINIMUM_KERNEL_MINOR}, got {major}.{minor})");
        return false;
    }

    // Kernel is new enough to support BPF features, check permissions
    let capabilities = caps::read(None, CapSet::Effective).unwrap_or_default();
    if !capabilities.contains(&Capability::CAP_BPF) || !capabilities.contains(&Capability::CAP_NET_ADMIN) {
        debug!("Process lacks privileges to manipulate the network stack with BPF");
        return false;
    }
    // All looks good, assume OK
    true
}

#[cfg(test)]
mod tests {
    // TODO
}
