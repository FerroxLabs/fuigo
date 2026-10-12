//! Connection core of the unix inbox (Fuigo 1.0.25, packet 8c): one hello each way, ONE operation, ONE reply,
//! close (S3.2). Generic over a byte stream; no socket is opened here.
//!
//! Frames reuse the audited leader code: [`FrameReader::with_limit`] checks the 4-byte prefix against
//! [`MAX_FRAME_BYTES`] before its buffer grows (and is cancel-safe), and [`write_frame_limited`] caps writes.
//! Deadlines: every write 5 s, the whole exchange 10 s on both sides (so a peer that sends one byte per second
//! is dropped). No error or log line here carries peer-supplied bytes: decode errors are mapped to unit variants.
// Inert until packet 8d (the inbox accept loop and the dialer) calls these; no caller exists outside tests.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::future::Future;
use std::io;
use std::time::Duration;

use fuigo_peer::limits::MAX_FRAME_BYTES;
use fuigo_peer::{
    Address, BoundedId, DeliveryOutcome, Envelope, Hello, HostId, NoticeKind, Op, ReasonText, Reply, SessionRow,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::leader::protocol::{FrameReader, ProtocolError, write_frame_limited};

/// Longest a single write may take.
pub(crate) const WRITE_DEADLINE: Duration = Duration::from_secs(5);
/// Longest a whole exchange may take, on either side.
pub(crate) const EXCHANGE_DEADLINE: Duration = Duration::from_secs(10);
/// The fixed `unavailable` reason for a protocol version mismatch.
pub(crate) const REASON_VERSION: &str = "protocol version mismatch";
/// The fixed `unavailable` reason when the host produced a reply that does not validate.
pub(crate) const REASON_HOST: &str = "host could not answer";

const FRAME_CAP: u32 = MAX_FRAME_BYTES as u32;

/// Why a connection ended without a reply. Fixed text only: nothing a peer sent is ever in here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnError {
    /// A single write took longer than [`WRITE_DEADLINE`].
    WriteTimeout,
    /// The exchange took longer than [`EXCHANGE_DEADLINE`].
    ExchangeTimeout,
    /// The peer closed before a whole frame arrived.
    Closed,
    /// A length prefix (or our own reply) is over the frame cap.
    FrameTooLarge,
    /// A frame did not decode as the expected type.
    Decode,
    /// A decoded value failed its checks (page range, reply rows).
    Invalid,
    /// The peer speaks another protocol version. Never a reason to reap a locator row.
    VersionMismatch,
    /// The peer's hello names another host than the one dialled. The caller uses this for the reap decision.
    HostMismatch,
    /// The reply is not the kind the operation asks for.
    UnexpectedReply,
    /// Stream failure (kind only).
    Io(io::ErrorKind),
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WriteTimeout => "write deadline exceeded",
            Self::ExchangeTimeout => "exchange deadline exceeded",
            Self::Closed => "connection closed",
            Self::FrameTooLarge => "frame over the cap",
            Self::Decode => "frame did not decode",
            Self::Invalid => "value failed its checks",
            Self::VersionMismatch => "protocol version mismatch",
            Self::HostMismatch => "host id mismatch",
            Self::UnexpectedReply => "unexpected reply kind",
            Self::Io(_) => "stream error",
        })
    }
}

impl std::error::Error for ConnError {}

impl From<ProtocolError> for ConnError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::Io(e) => Self::Io(e.kind()),
            // The leader's text names its own 64 MiB cap and the peer's number: map, never display.
            ProtocolError::MessageTooLarge(_) => Self::FrameTooLarge,
            ProtocolError::InvalidJson(_) => Self::Decode,
            ProtocolError::ConnectionClosed => Self::Closed,
        }
    }
}

/// What the receiving host does for each operation. The futures are `Send` so 8d can spawn the connection.
pub(crate) trait InboxHost {
    /// One page of sessions and whether more follow.
    fn list(&self, page: u32) -> impl Future<Output = (Vec<SessionRow>, bool)> + Send;
    /// Deliver a validated envelope.
    fn send(&self, to: Address, envelope: Envelope) -> impl Future<Output = DeliveryOutcome> + Send;
    /// `send` with the wire's `watch` field (S9.1): also arm an idle watch; an EMPTY body with `watch` is a watch only. A host
    /// without watches answers `send`'s outcome (a plain send) or `unavailable` for a watch.
    fn send_watched(&self, to: Address, envelope: Envelope, watch: bool) -> impl Future<Output = DeliveryOutcome> + Send;
    /// Record a delivery notice; the reply carries nothing.
    fn notice(&self, message_id: BoundedId, kind: NoticeKind) -> impl Future<Output = ()> + Send;
    /// Called once with the host id from the peer's hello, before any operation is read (8d: the consistency check
    /// that `envelope.from` names the same host; not a security claim). Default: ignore.
    fn peer_hello(&self, _host: &HostId) {}
}

async fn write_msg<W: AsyncWrite + Unpin, T: serde::Serialize>(w: &mut W, msg: &T) -> Result<(), ConnError> {
    let bytes = serde_json::to_vec(msg).map_err(|_| ConnError::Invalid)?;
    match timeout(WRITE_DEADLINE, write_frame_limited(w, &bytes, FRAME_CAP)).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(ConnError::WriteTimeout),
    }
}

async fn read_msg<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    r: &mut FrameReader<R>,
) -> Result<T, ConnError> {
    let frame = r.read_frame().await?;
    serde_json::from_slice(&frame).map_err(|_| ConnError::Decode)
}

/// How long a finished exchange may spend in `close`. The reply is already written, so this only bounds how long a
/// connection permit is held after the work is done (it was the full 5 s write deadline).
const CLOSE_DEADLINE: Duration = Duration::from_millis(250);

/// Best-effort close; the connection is over either way.
async fn close<W: AsyncWrite + Unpin>(w: &mut W) {
    let _ = timeout(CLOSE_DEADLINE, w.shutdown()).await;
}

fn unavailable(reason: &str) -> Result<Reply, ConnError> {
    Ok(Reply::Unavailable { reason: ReasonText::new(reason).map_err(|_| ConnError::Invalid)? })
}

/// Serve exactly one operation on `stream`, then close. The peer's version must be exactly ours, else it gets
/// `unavailable` and the host is never called. A second operation is never read.
pub(crate) async fn serve_one<S, H>(stream: S, our: Hello, host: &H) -> Result<(), ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: InboxHost,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = FrameReader::with_limit(rd, FRAME_CAP);
    let result = match timeout(EXCHANGE_DEADLINE, serve_inner(&mut rd, &mut wr, our, host)).await {
        Ok(r) => r,
        Err(_) => return Err(ConnError::ExchangeTimeout),
    };
    close(&mut wr).await;
    result
}

async fn serve_inner<R, W, H>(rd: &mut FrameReader<R>, wr: &mut W, our: Hello, host: &H) -> Result<(), ConnError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: InboxHost,
{
    let theirs: Hello = read_msg(rd).await?;
    write_msg(wr, &our).await?;
    if !theirs.version_matches() || theirs.version != our.version {
        write_msg(wr, &unavailable(REASON_VERSION)?).await?;
        return Err(ConnError::VersionMismatch);
    }
    // Only a peer of our version is recorded.
    host.peer_hello(&theirs.host_id);
    let op: Op = read_msg(rd).await?;
    op.validate().map_err(|_| ConnError::Invalid)?;
    let reply = match op {
        Op::List { page } => {
            let (rows, more) = host.list(page).await;
            let reply = Reply::List { rows, more };
            if reply.validate().is_ok() { reply } else { unavailable(REASON_HOST)? }
        }
        Op::Send { to, envelope, watch } => Reply::Send { outcome: host.send_watched(to, envelope, watch).await },
        Op::Notice { message_id, kind } => {
            host.notice(message_id, kind).await;
            Reply::Notice {}
        }
    };
    write_msg(wr, &reply).await
}

/// Client side: hello, check the version and that the server is `expect_host`, send `op`, read one reply, close.
pub(crate) async fn exchange<S>(stream: S, our: Hello, expect_host: &HostId, op: Op) -> Result<Reply, ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    op.validate().map_err(|_| ConnError::Invalid)?;
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = FrameReader::with_limit(rd, FRAME_CAP);
    let result = match timeout(EXCHANGE_DEADLINE, exchange_inner(&mut rd, &mut wr, our, expect_host, op)).await {
        Ok(r) => r,
        Err(_) => return Err(ConnError::ExchangeTimeout),
    };
    close(&mut wr).await;
    result
}

async fn exchange_inner<R, W>(
    rd: &mut FrameReader<R>,
    wr: &mut W,
    our: Hello,
    expect_host: &HostId,
    op: Op,
) -> Result<Reply, ConnError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_msg(wr, &our).await?;
    let theirs: Hello = read_msg(rd).await?;
    if theirs.version != our.version {
        return Err(ConnError::VersionMismatch);
    }
    if &theirs.host_id != expect_host {
        return Err(ConnError::HostMismatch);
    }
    write_msg(wr, &op).await?;
    let reply: Reply = read_msg(rd).await?;
    reply.validate().map_err(|_| ConnError::Invalid)?;
    let kind_ok = matches!(
        (&op, &reply),
        (_, Reply::Unavailable { .. })
            | (Op::List { .. }, Reply::List { .. })
            | (Op::Send { .. }, Reply::Send { .. })
            | (Op::Notice { .. }, Reply::Notice {})
    );
    if kind_ok { Ok(reply) } else { Err(ConnError::UnexpectedReply) }
}

/// Client side, reaping probe (8d): hello each way and nothing more. Returns the peer's hello (the caller compares
/// the version and the host id), or why none arrived. The server sees a close where it would read an operation.
pub(crate) async fn probe<S>(stream: S, our: Hello) -> Result<Hello, ConnError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = FrameReader::with_limit(rd, FRAME_CAP);
    let result = match timeout(EXCHANGE_DEADLINE, async {
        write_msg(&mut wr, &our).await?;
        read_msg::<_, Hello>(&mut rd).await
    })
    .await
    {
        Ok(r) => r,
        Err(_) => return Err(ConnError::ExchangeTimeout),
    };
    close(&mut wr).await;
    result
}
