//! The loopback address test servers bind, chosen so paused-clock tests see loopback I/O in step with the clock.
//!
//! A `start_paused` tokio runtime auto-advances its clock whenever it parks and one zero-timeout I/O poll finds
//! nothing ready. Tests that talk to a [`crate::MockInferenceServer`] under a paused clock therefore assume every
//! loopback connect and write is visible to the very next poll. Native Linux `lo` delivers in the sending syscall,
//! so that holds. WSL2 `networkingMode=mirrored` routes `127.0.0.0/8` through the `loopback0` virtual NIC
//! (policy routing table 127), so IPv4 loopback I/O lands about 150-350 µs later and is never ready on that poll.
//! The paused clock then jumps to the next timer (reqwest's 10 s `connect_timeout`, a backoff, the test's own
//! deadline) and the request fails with `tcp connect error: deadline has elapsed`. `::1` stays on `lo` there.
//!
//! The same WSL2 path never refuses a connect to a closed IPv4 loopback port either: no RST comes back, so the
//! connect hangs until the client's timeout (10 s for the sampler) instead of failing at once as it does on `lo`.
//!
//! [`loopback_ip`] keeps `127.0.0.1` wherever it behaves like `lo` and falls back to `::1` only where it does not.
//! [`refused_loopback_url`] is the closed-port counterpart for tests that need a request to fail fast.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

/// Candidates in preference order: `127.0.0.1` first, so hosts where it already works see no change.
const CANDIDATES: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
];

/// Rounds per candidate; one failed round disqualifies it (a flaky path must not win over a reliable one).
const PROBE_ROUNDS: usize = 3;

/// The loopback address a paused-clock test can reach a local server on, probed once per process.
///
/// Falls back to `127.0.0.1` when no candidate is synchronous; [`paused_clock_loopback_io_is_synchronous`]
/// then reports the host as unable to run paused-clock network tests.
pub fn loopback_ip() -> IpAddr {
    static CHOSEN: OnceLock<IpAddr> = OnceLock::new();
    *CHOSEN.get_or_init(|| select_loopback(&CANDIDATES, paused_clock_loopback_io_is_synchronous))
}

/// The first candidate `is_synchronous` accepts, else the first candidate.
pub(crate) fn select_loopback(
    candidates: &[IpAddr],
    is_synchronous: impl Fn(IpAddr) -> bool,
) -> IpAddr {
    candidates
        .iter()
        .copied()
        .find(|ip| is_synchronous(*ip))
        .unwrap_or(candidates[0])
}

/// An `http://` origin on [`loopback_ip`] where nothing listens: a request to it is refused at once.
///
/// One port per process, held bound (never listening) for the life of the process, so no other socket can take
/// it: a port that is merely released can be re-bound by a concurrent test and then accept instead of refuse.
pub fn refused_loopback_url() -> String {
    static RESERVED: OnceLock<(tokio::net::TcpSocket, SocketAddr)> = OnceLock::new();
    let (_socket, addr) = RESERVED
        .get_or_init(|| closed_port(loopback_ip()).expect("reserve a closed loopback port"));
    format!("http://{addr}")
}

/// A socket bound to an ephemeral port on `ip` and never put in the listening state; connects to it are refused
/// while the caller holds it. It does not set `SO_REUSEADDR`, so no other socket can bind the port meanwhile.
fn closed_port(ip: IpAddr) -> std::io::Result<(tokio::net::TcpSocket, SocketAddr)> {
    let socket = match ip {
        IpAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        IpAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(ip, 0))?;
    let addr = socket.local_addr()?;
    Ok((socket, addr))
}

/// Whether `ip` behaves like native `lo` on a paused clock with a 10 s timer pending: a connect plus a one-byte
/// reply completes, and a connect to a closed port is refused, both before the timer.
///
/// This is the exact shape that fails on an asynchronous loopback: the auto-advance fires the timer while the
/// I/O is still in flight. Every one of [`PROBE_ROUNDS`] must pass. `false` when `ip` cannot be bound.
///
/// It checks that the exchange beats the timer, not that the clock stood still: on a synchronous loopback the
/// clock still jumps to the timer, but the I/O is ready in the same poll and `timeout` polls it first. That is the
/// exact property the suites rely on.
pub fn paused_clock_loopback_io_is_synchronous(ip: IpAddr) -> bool {
    // Its own OS thread: the caller may already be inside a runtime, where `block_on` panics.
    std::thread::spawn(move || (0..PROBE_ROUNDS).all(|_| probe_round(ip)))
        .join()
        .unwrap_or(false)
}

fn probe_round(ip: IpAddr) -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
    else {
        return false;
    };
    rt.block_on(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let Ok(listener) = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0)).await else {
            return false;
        };
        let Ok(addr) = listener.local_addr() else {
            return false;
        };
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"k").await;
                let mut hold = [0u8; 1];
                let _ = stream.read(&mut hold).await;
            }
        });
        let exchange = async {
            let mut client = tokio::net::TcpStream::connect(addr).await?;
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await?;
            Ok::<_, std::io::Error>(byte)
        };
        let ok = matches!(
            tokio::time::timeout(Duration::from_secs(10), exchange).await,
            Ok(Ok(b)) if &b == b"k"
        );
        server.abort();
        let Ok((_held, closed)) = closed_port(ip) else {
            return false;
        };
        let refused = matches!(
            tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(closed)).await,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused
        );
        ok && refused
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    #[test]
    fn keeps_ipv4_loopback_when_it_is_synchronous() {
        assert_eq!(select_loopback(&CANDIDATES, |_| true), V4);
    }

    /// The WSL2 mirrored-networking shape: IPv4 loopback is routed through a NIC, `::1` is not.
    #[test]
    fn falls_back_to_ipv6_loopback_when_ipv4_is_asynchronous() {
        assert_eq!(select_loopback(&CANDIDATES, |ip| ip == V6), V6);
    }

    #[test]
    fn keeps_ipv4_loopback_when_no_candidate_is_synchronous() {
        assert_eq!(select_loopback(&CANDIDATES, |_| false), V4);
    }

    #[test]
    fn an_unbindable_address_is_not_synchronous() {
        // TEST-NET-1 is never a local address, so the bind fails and the probe must say no rather than panic.
        assert!(!paused_clock_loopback_io_is_synchronous(IpAddr::V4(
            Ipv4Addr::new(192, 0, 2, 1)
        )));
    }

    /// Host check: the closed-port URL refuses at once on the real clock (the laziness debug-mode tests rely on it).
    #[test]
    fn the_refused_loopback_url_refuses_at_once() {
        let url = refused_loopback_url();
        let addr: SocketAddr = url
            .trim_start_matches("http://")
            .parse()
            .expect("socket address");
        let started = std::time::Instant::now();
        let err = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .expect_err("nothing listens there");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "{url}: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{url} took {:?}",
            started.elapsed()
        );
    }

    /// Host check, not a unit test: the chosen address must actually carry paused-clock I/O on this machine.
    /// On a host where neither loopback family is synchronous this fails here, by name, instead of as dozens of
    /// `deadline has elapsed` failures in the shell's turn-loop suites.
    #[test]
    fn the_chosen_loopback_carries_paused_clock_io() {
        let ip = loopback_ip();
        assert!(
            paused_clock_loopback_io_is_synchronous(ip),
            "{ip} loopback I/O is not visible to a zero-timeout poll on this host, and neither is any other \
             candidate; paused-clock network tests cannot run here (run them in a private network namespace)"
        );
    }
}
