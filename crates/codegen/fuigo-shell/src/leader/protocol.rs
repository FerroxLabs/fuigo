use std::io;
use std::path::PathBuf;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cpu_profile::{ControlError, ProfileArtifactFormat};

const MAX_MESSAGE_SIZE: u32 = 64 * 1024 * 1024;
const FRAME_HEADER_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Message too large: {0} bytes (max: {MAX_MESSAGE_SIZE})")]
    MessageTooLarge(u32),
    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("Connection closed")]
    ConnectionClosed,
}

/// One-shot frame read. NOT cancel-safe (`read_exact` drops what it read when its future is dropped): never use it
/// inside `select!` or under a timeout whose expiry leaves the stream in use; use [`FrameReader`] there.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::ConnectionClosed);
        }
        Err(e) => return Err(ProtocolError::Io(e)),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(len));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Reads length-prefixed frames into a buffer that outlives each read, so [`FrameReader::read_frame`] and
/// [`FrameReader::read_message`] are cancel-safe: when another `select!` branch (an outbound write, a timer) wins
/// mid-frame, the bytes already read stay in `buf` for the next call instead of being dropped, which used to
/// desynchronize the stream (P161, ported from upstream). Use one `FrameReader` for the whole connection: the buffer
/// can already hold the start of the next frame, so a second reader over the same stream would lose bytes.
pub(crate) struct FrameReader<R> {
    reader: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        FrameReader {
            reader,
            buf: BytesMut::new(),
        }
    }

    /// Cancel-safe: the only await is `read_buf`, which either appends to `buf` or reads nothing.
    pub(crate) async fn read_frame(&mut self) -> Result<Vec<u8>, ProtocolError> {
        loop {
            if let Some(frame) = self.take_frame()? {
                return Ok(frame);
            }
            if self.reader.read_buf(&mut self.buf).await? == 0 {
                // Matches `read_frame`: EOF inside the length prefix is a close, inside a body an error.
                return Err(if self.buf.len() < FRAME_HEADER_LEN {
                    ProtocolError::ConnectionClosed
                } else {
                    ProtocolError::Io(io::ErrorKind::UnexpectedEof.into())
                });
            }
        }
    }

    /// Cancel-safe: decoding happens only after a whole frame has been taken out of the buffer.
    pub(crate) async fn read_message<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<T, ProtocolError> {
        let data = self.read_frame().await?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// Takes one complete frame out of the buffer, if it holds one. The size cap is checked from the prefix alone.
    fn take_frame(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        let Some(header) = self.buf.first_chunk::<FRAME_HEADER_LEN>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*header);
        if len > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge(len));
        }
        let frame_len = FRAME_HEADER_LEN + len as usize;
        if self.buf.len() < frame_len {
            self.buf.reserve(frame_len - self.buf.len());
            return Ok(None);
        }
        self.buf.advance(FRAME_HEADER_LEN);
        Ok(Some(self.buf.split_to(len as usize).to_vec()))
    }
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), ProtocolError> {
    let len = data.len() as u32;
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(len));
    }

    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// One-shot message read over `read_frame`; NOT cancel-safe, see there. Leader loops use `FrameReader` instead.
pub async fn read_message<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let data = read_frame(reader).await?;
    Ok(serde_json::from_slice(&data)?)
}

pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let data = serde_json::to_vec(msg)?;
    write_frame(writer, &data).await
}

/// Unique identifier assigned to each client connecting to the leader server.
/// IDs are monotonically increasing and wrap around at u64::MAX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(pub u64);

impl ClientId {
    /// Generate a new unique client ID from an atomic counter that wraps at u64::MAX.
    /// Collisions would need 2^64 IDs, which never happens in practice.
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        // Use wrapping_add to handle overflow gracefully
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(if id == 0 {
            COUNTER.fetch_add(1, Ordering::Relaxed)
        } else {
            id
        })
    }
}

impl Default for ClientId {
    fn default() -> Self {
        Self::new()
    }
}

/// Client mode determines how the leader handles communication for this client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMode {
    /// Headless mode (fuigo agent, fuigo agent headless): the leader connects to the websocket relay once and forwards messages.
    Headless,
    /// Stdio mode (fuigo agent stdio, fuigo -p): the client sends and receives ACP messages directly via local IPC.
    Stdio,
}

pub const LEADER_PROTOCOL_VERSION: u32 = 1;

/// Client capabilities reported during registration.
/// The leader uses them to customize behavior per client, such as injecting settings into session requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientCapabilities {
    /// Auto-approve all tool executions without confirmation (YOLO mode).
    /// When true, the leader will inject `yoloMode: true` into session/new requests.
    #[serde(default)]
    pub yolo_mode: bool,

    /// Classifier permission mode (auto).
    /// When true and not yolo, the leader injects `autoMode: true` into session/new and session/load `_meta`.
    #[serde(default)]
    pub auto_mode: bool,

    /// Default model ID to use for new sessions.
    /// When set, the leader injects `modelId` into session/new requests that don't already specify one.
    #[serde(default)]
    pub default_model: Option<String>,

    /// Client binary version (e.g., "0.1.150").
    /// The leader logs a warning when this differs from its own version, which happens after client auto-updates.
    #[serde(default)]
    pub client_version: Option<String>,

    /// Whether this client has advertised `fuigo/codeNavigation.enabled`.
    /// When true, the leader injects `codeNavEnabled: true` into `session/new` and `session/load` requests.
    /// The agent can then gate code-nav startup per client rather than reading shared last-initialized state.
    #[serde(default)]
    pub code_nav_enabled: bool,

    /// Whether the client handles terminal ACP messages (create, output, kill, etc.).
    /// When true, the leader injects `clientTerminal: true` into `session/new` and `session/load`.
    /// The agent then routes terminal commands to the client via ACP instead of running them locally.
    /// Per-client so a TUI (`terminal: false`) and a web client (`terminal: true`) sharing the same leader get independent routing.
    #[serde(default)]
    pub terminal: bool,

    /// Whether the client handles filesystem ACP read/write messages.
    /// Same per-client isolation rationale as `terminal`.
    #[serde(default)]
    pub fs_read: bool,
    #[serde(default)]
    pub fs_write: bool,

    /// P125: whether the client wants the leader's relay-refusal state on every registration: the refusal when the
    /// leader refuses its relay, and an explicit "cleared" when it does not, so a client that reconnects reconciles
    /// whatever it cached. Without it the client is told only of a refusal.
    #[serde(default)]
    pub relay_refusal_state: bool,

    /// Whether this client will draw a status row (`fuigo/statusLine`).
    /// When true, the leader injects `clientStatusLine: true`.
    /// The agent then builds the payload for a client that asked, not for whichever one started the process.
    /// The flag it sets is per session, so other subscribers of a shared session receive the payload too.
    #[serde(default)]
    pub status_line: bool,

    /// Whether this client wants live `user_message_chunk` during a prompt (`fuigo/userMessageEcho`).
    /// When true, the leader injects `clientUserMessageEcho: true` so the answer travels with the session.
    #[serde(default)]
    pub user_message_echo: bool,

    /// P142: whether this client shows the leader's one-off process notices ([`LEADER_NOTICE_METHOD`]). The leader
    /// runs the agent, so a notice the agent prints (an old memory folder it did not move, uploads it withheld) goes
    /// to `~/.fuigo/leader.log`, which nobody reads; the leader sends each one, once, to the clients that ask. A client
    /// that does not ask (a raw ACP client, an older Fuigo) is sent none, and the notice waits for one that does.
    #[serde(default)]
    pub leader_notices: bool,
}

/// P142: the extension notification that carries one leader process notice (`params.message`, the text as it was
/// printed). It has the ACP `_` prefix, so the client decoder delivers it as the `fuigo/leader/notice` extension.
pub const LEADER_NOTICE_METHOD: &str = "_fuigo/leader/notice";

/// P142: the JSON-RPC line of a [`LEADER_NOTICE_METHOD`] notification for `message`.
pub fn leader_notice_payload(message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": LEADER_NOTICE_METHOD,
        "params": { "message": message },
    })
    .to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LeaderCapabilities {
    #[serde(default)]
    pub control_v1: bool,
    #[serde(default)]
    pub runtime_cpu_profile: bool,
    #[serde(default)]
    pub profile_formats: Vec<ProfileArtifactFormat>,
    #[serde(default)]
    pub workspace_exposure: bool,
    /// Whether the leader supports [`ControlCommand::RelaunchForUpdate`], a disruptive relaunch onto a freshly-installed binary driven by `fuigo update`.
    /// Old leaders default to `false`, so a new client falls back to advising a manual restart.
    #[serde(default)]
    pub relaunch_v1: bool,
    /// Whether the leader supports [`ControlCommand::StopForDowngrade`] (P124): `fuigo update` asks a leader that is newer than the
    /// binary it just installed to stop, so an explicit downgrade is not silently served by the newer leader.
    /// Old leaders default to `false`.
    #[serde(default)]
    pub downgrade_stop_v1: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlCommand {
    GetLeaderInfo,
    CpuProfileStatus,
    StartCpuProfile {
        #[serde(default)]
        output: Option<String>,
        #[serde(default)]
        frequency_hz: Option<i32>,
    },
    StopCpuProfile,
    WorkspaceStart {
        #[serde(default)]
        hub_url: Option<String>,
        cwd: String,
    },
    WorkspacePause,
    WorkspaceResume,
    WorkspaceStop,
    WorkspaceStatus,
    /// Ask the leader to relaunch onto a freshly-installed binary (driven by `fuigo update`).
    /// The leader stops admitting new turns, waits a bounded grace period for in-flight turns, and flushes session state.
    /// It then exits with [`ShutdownReason::AutoUpdate`] so connected clients reconnect onto the new binary and restore sessions via `session/load`.
    ///
    /// `to_version` is the version `fuigo update` just installed; the leader declines if it already runs that version or newer.
    RelaunchForUpdate {
        to_version: String,
    },
    /// Ask the leader to stop after an EXPLICIT downgrade (P124): `fuigo update --version X` or `--force` installed `to_version`,
    /// which is strictly older than the leader. Same drain and exit as [`ControlCommand::RelaunchForUpdate`] (clients reconnect and
    /// the next connect spawns a leader from the installed binary); acked with `Relaunching`, declined with `RelaunchDeclined`
    /// unless the leader is strictly newer than `to_version`. The ordinary relaunch keeps its never-downgrade guard.
    StopForDowngrade {
        to_version: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlPayload {
    LeaderInfo {
        pid: u32,
        socket_path: PathBuf,
        lock_path: PathBuf,
        ws_url_suffix: String,
        leader_protocol_version: u32,
        leader_binary_version: String,
        profiling_supported: bool,
        profiling_compiled_in: bool,
        cpu_profile_active: bool,
        #[serde(default)]
        cpu_profile_stopping: bool,
        profile_started_at: Option<String>,
        profile_formats: Vec<ProfileArtifactFormat>,
    },
    CpuProfileStatus {
        active: bool,
        #[serde(default)]
        stopping: bool,
        started_at: Option<String>,
        svg_path: Option<PathBuf>,
        frequency_hz: Option<i32>,
    },
    CpuProfileStarted {
        pid: u32,
        svg_path: PathBuf,
        frequency_hz: i32,
        started_at: String,
    },
    CpuProfileStopped {
        pid: u32,
        svg_path: PathBuf,
        started_at: String,
        stopped_at: String,
    },
    WorkspaceStatus {
        state: String,
        #[serde(default)]
        hub_url: Option<String>,
        #[serde(default)]
        cwd: Option<String>,
        uptime_ms: u64,
        active_tool_calls: u32,
        #[serde(default)]
        sessions: Vec<String>,
        pid: u32,
    },
    /// Ack for [`ControlCommand::RelaunchForUpdate`]: the leader accepted the request and will exit after a bounded grace period of `grace_ms`.
    Relaunching {
        from_version: String,
        to_version: String,
        grace_ms: u64,
    },
    /// Response to [`ControlCommand::RelaunchForUpdate`] when the leader will not relaunch.
    /// E.g. it is already running `to_version` or newer, or a relaunch is already in progress.
    RelaunchDeclined { reason: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Register {
        client_type: String,
        mode: ClientMode,
        #[serde(default)]
        capabilities: ClientCapabilities,
    },
    Acp {
        payload: String,
    },
    Control {
        request_id: String,
        command: ControlCommand,
    },
    Ping,
    Disconnect,
}

/// Reason for a planned leader shutdown, sent with [`ServerMessage::ShuttingDown`].
///
/// ## Runtime status
///
/// | Variant | Emitted today? | Notes |
/// |---------|---------------|-------|
/// | `AutoUpdate` | **Yes** — when `run_auto_update_checker` triggers shutdown | |
/// | `Manual` | **Yes** — default for SIGTERM, test cancellation, all other paths | |
/// | `IdleTimeout` | **No** — reserved for a future idle-timeout feature | |
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownReason {
    /// Leader is shutting down to install a downloaded binary auto-update.
    /// Clients should reconnect immediately via `connect_or_spawn`; the new binary is picked up automatically.
    AutoUpdate,
    /// Reserved for a future idle-timeout feature (no active clients for a configurable duration).
    /// **Not emitted in the current implementation.**
    IdleTimeout,
    /// Unspecified or externally-triggered shutdown (SIGTERM, programmatic cancel, etc.).
    Manual,
}

/// Old leaders that predate `ready` are already initialised, so default to `true`.
fn default_ready() -> bool {
    true
}

/// New fields must use `#[serde(default)]`; the leader and client can run different binary versions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Registration confirmation.
    ///
    /// `ready` indicates whether the leader has already completed its startup (auth and model prefetch).
    /// When `ready = false` the client **must** wait for a subsequent [`LeaderReady`](Self::LeaderReady) message before sending any ACP traffic.
    /// The server holds the connection open until the leader is ready.
    Registered {
        client_id: u64,
        /// Whether the leader is fully initialised and ready to forward ACP traffic.
        #[serde(default = "default_ready")]
        ready: bool,
        #[serde(default)]
        leader_protocol_version: Option<u32>,
        #[serde(default)]
        leader_binary_version: Option<String>,
        #[serde(default)]
        leader_capabilities: Option<LeaderCapabilities>,
    },
    Acp {
        payload: String,
    },
    ControlResult {
        request_id: String,
        result: Result<ControlPayload, ControlError>,
    },
    Pong,
    Error {
        code: i32,
        message: String,
    },
    /// Advance notice of a planned shutdown.
    /// Sent before [`Shutdown`](Self::Shutdown) to give clients time to prepare for reconnection.
    ///
    /// Clients should treat this as a signal that [`Shutdown`](Self::Shutdown) is imminent and prepare their reconnection handlers (e.g. show a banner).
    ShuttingDown {
        reason: ShutdownReason,
        /// Milliseconds until the actual [`Shutdown`](Self::Shutdown) message.
        ///
        /// **Currently always `0`**: the server sends `Shutdown` immediately after `ShuttingDown` with no intervening sleep.
        /// Clients must not rely on this field providing a real grace window.
        /// Treat `ShuttingDown` as an imminent `Shutdown` regardless of this value.
        delay_ms: u64,
    },
    Shutdown,
    /// Sent by the server after a `Registered { ready: false }` once the leader finishes initialising.
    /// The client should treat this as the signal that ACP traffic will now be forwarded correctly.
    LeaderReady,
}

/// Extension methods injected into the agent, named as the agent matches them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::EnumIter)]
pub(crate) enum InternalMethod {
    AuthCleared,
    EvictSessions,
    ReloadAllMcpServers,
    ReloadModels,
    ReloadModelsCache,
    ReloadProjectMcpServers,
    ReloadSkills,
    ReloadWorkflows,
}

impl InternalMethod {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::AuthCleared => "fuigo/internal/auth_cleared",
            Self::EvictSessions => "fuigo/internal/evict_sessions",
            Self::ReloadAllMcpServers => "fuigo/internal/reload_all_mcp_servers",
            Self::ReloadModels => "fuigo/internal/reload_models",
            Self::ReloadModelsCache => "fuigo/internal/reload_models_cache",
            Self::ReloadProjectMcpServers => "fuigo/internal/reload_project_mcp_servers",
            Self::ReloadSkills => "fuigo/internal/reload_skills",
            Self::ReloadWorkflows => "fuigo/internal/reload_workflows",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        use strum::IntoEnumIterator;

        Self::iter().find(|method| method.name() == name)
    }

    /// The decoder routes a custom method to `ext_method` or `ext_notification` only when it carries the `_` prefix, and rejects the bare name.
    fn wire_name(self) -> String {
        format!("_{}", self.name())
    }
}

/// Not newline-terminated: the `acp_tx` forwarding loop appends the terminator.
pub(crate) fn internal_notification(method: InternalMethod, params: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": method.wire_name(),
        "params": params,
    })
    .to_string()
}

/// Newline-terminated for direct injection.
pub(crate) fn internal_request_line(
    id: &str,
    method: InternalMethod,
    params: serde_json::Value,
) -> String {
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method.wire_name(),
        "params": params,
    });
    format!("{msg}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let data = b"hello world";

        write_frame(&mut client, data).await.unwrap();
        let received = read_frame(&mut server).await.unwrap();

        assert_eq!(received, data);
    }

    fn encode_frame(data: &[u8]) -> Vec<u8> {
        let mut frame = (data.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(data);
        frame
    }

    /// P161 (U6): a read cancelled mid-frame (a `select!` timer wins after part of the frame arrived) must leave the
    /// partial frame for the next read, which then delivers that frame and the one after it intact.
    /// Covers every split point: inside the length prefix, exactly after it, and inside the body.
    /// `read_frame` over `read_exact` drops the consumed bytes and desynchronizes the stream.
    #[tokio::test(start_paused = true)]
    async fn frame_reader_survives_timer_cancellation_at_every_split_point() {
        let data = b"hello world";
        let frame = encode_frame(data);
        for split in 1..frame.len() {
            let (mut client, server) = duplex(1024);
            let mut reader = FrameReader::new(server);
            let (head, tail) = frame.split_at(split);
            client.write_all(head).await.unwrap();
            tokio::select! {
                biased;
                res = reader.read_frame() => {
                    panic!("split {split}: a partial frame must not complete a read: {res:?}")
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            client.write_all(tail).await.unwrap();
            write_frame(&mut client, b"next").await.unwrap();

            let first = tokio::time::timeout(Duration::from_secs(5), reader.read_frame()).await;
            assert!(
                matches!(&first, Ok(Ok(got)) if got.as_slice() == data),
                "split {split}: the cancelled frame must be delivered whole, got {first:?}"
            );
            let second = tokio::time::timeout(Duration::from_secs(5), reader.read_frame()).await;
            assert!(
                matches!(&second, Ok(Ok(got)) if got.as_slice() == b"next"),
                "split {split}: the stream must stay in sync for the next frame, got {second:?}"
            );
        }
    }

    /// Same as above, at the message layer the leader loops use: a cancelled `read_message` loses nothing.
    #[tokio::test(start_paused = true)]
    async fn frame_reader_message_survives_cancellation_between_header_and_body() {
        let first_msg = ClientMessage::Acp {
            payload: r#"{"jsonrpc":"2.0","method":"a","id":1}"#.into(),
        };
        let frame = encode_frame(&serde_json::to_vec(&first_msg).unwrap());
        let (mut client, server) = duplex(1024);
        let mut reader = FrameReader::new(server);
        // The whole prefix and part of the body: the header read completed before the timer won.
        let (head, tail) = frame.split_at(FRAME_HEADER_LEN + 3);
        client.write_all(head).await.unwrap();
        tokio::select! {
            biased;
            res = reader.read_message::<ClientMessage>() => panic!("partial frame completed: {res:?}"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        client.write_all(tail).await.unwrap();
        write_message(&mut client, &ClientMessage::Ping).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(5), reader.read_message::<ClientMessage>())
            .await;
        assert!(
            matches!(&got, Ok(Ok(ClientMessage::Acp { payload })) if payload.contains(r#""method":"a""#)),
            "got {got:?}"
        );
        let got = tokio::time::timeout(Duration::from_secs(5), reader.read_message::<ClientMessage>())
            .await;
        assert!(matches!(got, Ok(Ok(ClientMessage::Ping))), "got {got:?}");
    }

    /// Frames that arrive in one write are all delivered, in order, even when one read pulls in several.
    #[tokio::test]
    async fn frame_reader_delivers_coalesced_frames_in_order() {
        let (mut client, server) = duplex(4096);
        let mut reader = FrameReader::new(server);
        let mut wire = Vec::new();
        for i in 0..10 {
            wire.extend_from_slice(&encode_frame(format!("message {i}").as_bytes()));
        }
        wire.extend_from_slice(&encode_frame(b""));
        client.write_all(&wire).await.unwrap();
        drop(client);
        for i in 0..10 {
            assert_eq!(
                reader.read_frame().await.unwrap(),
                format!("message {i}").as_bytes()
            );
        }
        assert!(reader.read_frame().await.unwrap().is_empty());
        assert!(matches!(
            reader.read_frame().await,
            Err(ProtocolError::ConnectionClosed)
        ));
    }

    /// Ported from upstream: EOF inside the length prefix is a close (as `read_frame`), inside a body an error.
    #[tokio::test]
    async fn frame_reader_eof_in_prefix_is_a_close_and_in_body_an_error() {
        let (client, server) = duplex(64);
        drop(client);
        let mut reader = FrameReader::new(server);
        assert!(matches!(
            reader.read_frame().await,
            Err(ProtocolError::ConnectionClosed)
        ));

        let (mut client, server) = duplex(64);
        client.write_all(&[0, 0]).await.unwrap();
        drop(client);
        let mut reader = FrameReader::new(server);
        assert!(matches!(
            reader.read_frame().await,
            Err(ProtocolError::ConnectionClosed)
        ));

        let (mut client, server) = duplex(64);
        client.write_all(&8u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        drop(client);
        let mut reader = FrameReader::new(server);
        assert!(matches!(
            reader.read_frame().await,
            Err(ProtocolError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    /// Ported from upstream: the size cap is enforced from the prefix alone, before any body byte arrives.
    #[tokio::test]
    async fn frame_reader_rejects_an_oversized_prefix() {
        let (mut client, server) = duplex(64);
        client
            .write_all(&(MAX_MESSAGE_SIZE + 1).to_be_bytes())
            .await
            .unwrap();
        let mut reader = FrameReader::new(server);
        // `client` stays open: a reader that accepted the prefix would wait for a body forever, so bound the wait.
        let got = tokio::time::timeout(Duration::from_secs(5), reader.read_frame()).await;
        assert!(
            matches!(got, Ok(Err(ProtocolError::MessageTooLarge(len))) if len == MAX_MESSAGE_SIZE + 1),
            "an oversized prefix must be rejected before any body arrives, got {got:?}"
        );
        drop(client);

        // Exactly the cap is accepted as a length (the body is then awaited, not rejected).
        let (mut client, server) = duplex(64);
        client
            .write_all(&MAX_MESSAGE_SIZE.to_be_bytes())
            .await
            .unwrap();
        drop(client);
        let mut reader = FrameReader::new(server);
        assert!(matches!(
            reader.read_frame().await,
            Err(ProtocolError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn message_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let msg = ClientMessage::Register {
            client_type: "test".into(),
            mode: ClientMode::Stdio,
            capabilities: ClientCapabilities::default(),
        };

        write_message(&mut client, &msg).await.unwrap();
        let received: ClientMessage = read_message(&mut server).await.unwrap();

        match received {
            ClientMessage::Register {
                client_type, mode, ..
            } => {
                assert_eq!(client_type, "test");
                assert_eq!(mode, ClientMode::Stdio);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[tokio::test]
    async fn control_message_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let msg = ClientMessage::Control {
            request_id: "req-1".into(),
            command: ControlCommand::StartCpuProfile {
                output: Some("/tmp/profile.folded".into()),
                frequency_hz: Some(250),
            },
        };

        write_message(&mut client, &msg).await.unwrap();
        let received: ClientMessage = read_message(&mut server).await.unwrap();

        assert!(matches!(
            received,
            ClientMessage::Control {
                request_id,
                command: ControlCommand::StartCpuProfile {
                    output: Some(output),
                    frequency_hz: Some(250),
                },
            } if request_id == "req-1" && output == "/tmp/profile.folded"
        ));
    }

    #[tokio::test]
    async fn connection_closed_on_eof() {
        let (client, mut server) = duplex(1024);
        drop(client);

        match read_frame(&mut server).await {
            Err(ProtocolError::ConnectionClosed) => {}
            other => panic!("expected ConnectionClosed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_oversized_messages() {
        let (mut client, mut server) = duplex(1024);

        // Write a length header claiming a huge message
        client
            .write_all(&(MAX_MESSAGE_SIZE + 1).to_be_bytes())
            .await
            .unwrap();

        match read_frame(&mut server).await {
            Err(ProtocolError::MessageTooLarge(size)) => {
                assert_eq!(size, MAX_MESSAGE_SIZE + 1);
            }
            other => panic!("expected MessageTooLarge, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn multiple_frames_in_sequence() {
        let (mut client, mut server) = duplex(4096);

        for i in 0..10 {
            let data = format!("message {}", i);
            write_frame(&mut client, data.as_bytes()).await.unwrap();
        }
        drop(client);

        for i in 0..10 {
            let received = read_frame(&mut server).await.unwrap();
            assert_eq!(received, format!("message {}", i).as_bytes());
        }
    }

    #[test]
    fn registered_serde_compatibility_without_optional_metadata() {
        let json = r#"{"type":"registered","client_id":7}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();

        assert!(matches!(
            msg,
            ServerMessage::Registered {
                client_id: 7,
                // `ready` defaults to `true` via `default_ready()`: old leaders that predate the field are already initialised
                ready: true,
                leader_protocol_version: None,
                leader_binary_version: None,
                leader_capabilities: None,
            }
        ));
    }

    #[test]
    fn registered_serde_compatibility_with_all_optional_metadata() {
        let msg = ServerMessage::Registered {
            client_id: 7,
            ready: true,
            leader_protocol_version: Some(LEADER_PROTOCOL_VERSION),
            leader_binary_version: Some("1.2.3".into()),
            leader_capabilities: Some(LeaderCapabilities {
                control_v1: true,
                runtime_cpu_profile: true,
                profile_formats: vec![ProfileArtifactFormat::Svg],
                workspace_exposure: true,
                relaunch_v1: true,
                downgrade_stop_v1: true,
            }),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: ServerMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            ServerMessage::Registered {
                client_id: 7,
                ready: true,
                leader_protocol_version: Some(LEADER_PROTOCOL_VERSION),
                leader_binary_version: Some(_),
                leader_capabilities: Some(LeaderCapabilities {
                    control_v1: true,
                    runtime_cpu_profile: true,
                    profile_formats,
                    workspace_exposure: true,
                    relaunch_v1: true,
                downgrade_stop_v1: true,
                }),
            } if profile_formats == vec![ProfileArtifactFormat::Svg]
        ));
    }

    #[test]
    fn profile_artifact_format_serde_names_are_stable() {
        // Wire compat contract: `svg` must stay decodable (old leaders advertise it)
        // `folded` is the name new binaries will start advertising once the fleet can decode it
        // Renaming either variant breaks the Registered handshake across version skew
        assert_eq!(
            serde_json::to_string(&ProfileArtifactFormat::Svg).unwrap(),
            "\"svg\""
        );
        assert_eq!(
            serde_json::to_string(&ProfileArtifactFormat::Folded).unwrap(),
            "\"folded\""
        );
        let decoded: ProfileArtifactFormat = serde_json::from_str("\"svg\"").unwrap();
        assert_eq!(decoded, ProfileArtifactFormat::Svg);
    }

    #[test]
    fn control_payload_serde_defaults_new_stopping_flags() {
        let leader_info_json = r#"{
            "type":"leader_info",
            "pid":123,
            "socket_path":"/tmp/leader.sock",
            "lock_path":"/tmp/leader.lock",
            "ws_url_suffix":"suffix",
            "leader_protocol_version":1,
            "leader_binary_version":"1.2.3",
            "profiling_supported":true,
            "profiling_compiled_in":true,
            "cpu_profile_active":false,
            "profile_started_at":null,
            "profile_formats":["svg"]
        }"#;
        let status_json = r#"{
            "type":"cpu_profile_status",
            "active":false,
            "started_at":null,
            "svg_path":null,
            "frequency_hz":null
        }"#;

        let leader_info: ControlPayload = serde_json::from_str(leader_info_json).unwrap();
        let status: ControlPayload = serde_json::from_str(status_json).unwrap();

        assert!(matches!(
            leader_info,
            ControlPayload::LeaderInfo {
                cpu_profile_active: false,
                cpu_profile_stopping: false,
                profile_started_at: None,
                ..
            }
        ));
        assert!(matches!(
            status,
            ControlPayload::CpuProfileStatus {
                active: false,
                stopping: false,
                started_at: None,
                svg_path: None,
                frequency_hz: None,
            }
        ));
    }

    #[tokio::test]
    async fn workspace_control_command_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let msg = ClientMessage::Control {
            request_id: "ws-1".into(),
            command: ControlCommand::WorkspaceStart {
                hub_url: Some("wss://hub.example/v1/tools".into()),
                cwd: "/home/u/proj".into(),
            },
        };

        write_message(&mut client, &msg).await.unwrap();
        let received: ClientMessage = read_message(&mut server).await.unwrap();

        assert!(matches!(
            received,
            ClientMessage::Control {
                request_id,
                command: ControlCommand::WorkspaceStart { hub_url: Some(url), cwd },
            } if request_id == "ws-1"
                && url == "wss://hub.example/v1/tools"
                && cwd == "/home/u/proj"
        ));
    }

    #[test]
    fn workspace_status_payload_roundtrip() {
        let payload = ControlPayload::WorkspaceStatus {
            state: "running".into(),
            hub_url: Some("wss://hub.example/v1/tools".into()),
            cwd: Some("/home/u/proj".into()),
            uptime_ms: 4200,
            active_tool_calls: 2,
            sessions: vec!["fuigo-a".into(), "fuigo-b".into()],
            pid: 4242,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: ControlPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, payload);
        assert!(json.contains("\"type\":\"workspace_status\""));
    }

    #[test]
    fn workspace_status_payload_defaults_optional_fields() {
        let json = r#"{"type":"workspace_status","state":"none","uptime_ms":0,"active_tool_calls":0,"pid":1}"#;
        let decoded: ControlPayload = serde_json::from_str(json).unwrap();
        assert!(matches!(
            decoded,
            ControlPayload::WorkspaceStatus {
                state,
                hub_url: None,
                cwd: None,
                sessions,
                ..
            } if state == "none" && sessions.is_empty()
        ));
    }

    #[test]
    fn workspace_exposure_capability_defaults_false() {
        let json = r#"{"control_v1":true,"runtime_cpu_profile":false,"profile_formats":[]}"#;
        let caps: LeaderCapabilities = serde_json::from_str(json).unwrap();
        assert!(!caps.workspace_exposure);
    }

    #[test]
    fn client_id_is_unique() {
        let ids: Vec<_> = (0..100).map(|_| ClientId::new()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().map(|c| c.0).collect();
        assert_eq!(unique.len(), 100);
    }

    // --- ShuttingDown / ShutdownReason tests ---

    #[tokio::test]
    async fn shutting_down_message_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let msg = ServerMessage::ShuttingDown {
            reason: ShutdownReason::AutoUpdate,
            delay_ms: 2000,
        };

        write_message(&mut client, &msg).await.unwrap();
        let received: ServerMessage = read_message(&mut server).await.unwrap();

        match received {
            ServerMessage::ShuttingDown { reason, delay_ms } => {
                assert_eq!(reason, ShutdownReason::AutoUpdate);
                assert_eq!(delay_ms, 2000);
            }
            _ => panic!("Expected ShuttingDown, got {:?}", received),
        }
    }

    #[test]
    fn every_internal_method_carries_the_routable_prefix() {
        use strum::IntoEnumIterator;

        for method in InternalMethod::iter() {
            for line in [
                internal_notification(method, serde_json::json!({})),
                internal_request_line("id", method, serde_json::json!({})),
            ] {
                let json: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
                assert_eq!(
                    json["method"].as_str().and_then(|m| m.strip_prefix('_')),
                    Some(method.name()),
                    "unroutable wire method: {line}"
                );
            }
        }
    }

    #[test]
    fn shutdown_reason_variants_serialize_correctly() {
        let auto = serde_json::to_string(&ShutdownReason::AutoUpdate).unwrap();
        assert_eq!(auto, "\"auto_update\"");

        let idle = serde_json::to_string(&ShutdownReason::IdleTimeout).unwrap();
        assert_eq!(idle, "\"idle_timeout\"");

        let manual = serde_json::to_string(&ShutdownReason::Manual).unwrap();
        assert_eq!(manual, "\"manual\"");

        // Verify deserialization
        let parsed: ShutdownReason = serde_json::from_str("\"auto_update\"").unwrap();
        assert_eq!(parsed, ShutdownReason::AutoUpdate);
    }
}
