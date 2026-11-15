use fuigo_sandbox::WebsiteOrigin;
use fuigo_sandbox::command::CommandTag;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{ConnectionError, ProxyError, write_all_idle, write_committed_idle};
use crate::idle::IdleDeadline;
use crate::metrics::ProxyOutcome;
use crate::request::{ParsedRequest, strict_connect_authority};
use crate::tls::read_client_hello;
use crate::{ProxyIo, ProxyState};

pub(crate) async fn handle<S: ProxyIo>(
    client: &mut S,
    request: ParsedRequest,
    mut buffered: Vec<u8>,
    state: &ProxyState,
    call: Option<&CommandTag>,
) -> Result<(), ConnectionError> {
    let options = &state.options;
    let framing = request.framing().map_err(ConnectionError::Precommit)?;
    if framing.is_some() {
        return Err(ConnectionError::Precommit(ProxyError::Malformed));
    }
    let authority =
        strict_connect_authority(&request.target).map_err(ConnectionError::Precommit)?;
    if let Some(host) = request
        .single_header("host")
        .map_err(ConnectionError::Precommit)?
        && strict_connect_authority(host).map_err(ConnectionError::Precommit)? != authority
    {
        return Err(ConnectionError::Precommit(ProxyError::Malformed));
    }
    let origin = WebsiteOrigin::parse(&format!("https://{authority}"))
        .map_err(|_| ConnectionError::Precommit(ProxyError::Malformed))?;
    state
        .admit(&origin, call, client, &mut buffered)
        .await
        .map_err(ConnectionError::from_admit)?;
    let addresses = crate::resolve_public(&origin, options)
        .await
        .map_err(ConnectionError::Precommit)?;
    let mut upstream = tokio::time::timeout(
        options.connect_timeout,
        options.connector.connect(&addresses),
    )
    .await
    .map_err(|_| ConnectionError::Precommit(ProxyError::Timeout))?
    .map_err(|_| ConnectionError::Precommit(ProxyError::Connect))?;

    write_committed_idle(
        client,
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        options.request_timeout,
    )
    .await?;

    let hello_timeout = options.tls_hello_timeout.min(options.request_timeout);
    let prefix = read_client_hello(
        client,
        buffered,
        options.max_tls_client_hello_bytes,
        hello_timeout,
        &origin,
    )
    .await
    .map_err(ConnectionError::Committed)?;
    write_all_idle(&mut upstream, &prefix, options.request_timeout)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut => ConnectionError::Committed(ProxyError::Timeout),
            _ => ConnectionError::Committed(ProxyError::Connect),
        })?;
    match relay(client, &mut upstream, options.tunnel_idle_timeout).await {
        Ok(()) => {
            state.metrics.record(ProxyOutcome::Ok);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            state.metrics.record(ProxyOutcome::Ok);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            Err(ConnectionError::Committed(ProxyError::Timeout))
        }
        Err(_) => Err(ConnectionError::Committed(ProxyError::Connect)),
    }
}

/// Copies both ways until both sides finish, ending the tunnel when neither direction has moved
/// a byte for `idle`. A byte counts when it is read or when the other side takes it, so a side
/// that stops reading cannot hold the tunnel open, even after the other direction has finished.
async fn relay<A, B>(a: &mut A, b: &mut B, idle: Duration) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let clock = Instant::now();
    let last_activity = AtomicU64::new(0);
    let up = pump(&mut a_read, &mut b_write, IdleDeadline::new(idle, clock, &last_activity));
    let down = pump(&mut b_read, &mut a_write, IdleDeadline::new(idle, clock, &last_activity));
    tokio::try_join!(up, down).map(|_| ())
}

async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut deadline: IdleDeadline<'_>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let count = deadline.read(reader, &mut buffer).await?;
        if count == 0 {
            // This side is done: pass the end on and let the other direction finish.
            deadline.shutdown(writer).await;
            return Ok(());
        }
        deadline.write_all(writer, &buffer[..count]).await?;
    }
}
