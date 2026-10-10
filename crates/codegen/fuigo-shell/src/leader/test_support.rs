//! In-crate fake leaders for exercising how the client handles a misbehaving leader (hung, half-framed, wrong-versioned).
//! These are wire shapes the real `spawn_leader_server` can never produce.
//!
//! All stalls wait on `cancel.cancelled().await`, never on a timer.
//! `#[tokio::test(start_paused = true)]` auto-advance can therefore jump the client-side timeouts under test without waking the fake.
use super::protocol::{
    ClientMessage, LEADER_PROTOCOL_VERSION, LeaderCapabilities, ServerMessage, read_message,
    write_message,
};
use std::fs;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
/// Version metadata a fake leader reports in `Registered`.
pub(crate) struct FakeVersions {
    pub(crate) protocol_version: Option<u32>,
    pub(crate) binary_version: Option<String>,
}
impl FakeVersions {
    /// The versions a same-build real leader would report (`run_leader` stamps `fuigo_version::VERSION` into its metadata).
    pub(crate) fn current() -> Self {
        Self {
            protocol_version: Some(LEADER_PROTOCOL_VERSION),
            binary_version: Some(fuigo_version::VERSION.to_string()),
        }
    }
}
/// `LeaderCapabilities` has no `Default` (serde-only defaults), so fakes build their capabilities through this helper.
pub(crate) fn fake_caps(control_v1: bool, relaunch_v1: bool) -> LeaderCapabilities {
    LeaderCapabilities {
        control_v1,
        runtime_cpu_profile: false,
        profile_formats: Vec::new(),
        workspace_exposure: false,
        relaunch_v1,
        downgrade_stop_v1: false,
    }
}
/// Wire behavior of a [`spawn_fake_leader`] instance.
pub(crate) enum FakeLeaderBehavior {
    /// Well-formed: `Registered { ready: true }` with the given metadata, then idle until cancelled.
    /// Backs the discovery and adopt/evict tests.
    /// Skewed metadata (wrong protocol version, stale binary version) comes from passing an explicit [`FakeVersions`]; there is no dedicated variant.
    Normal {
        versions: FakeVersions,
        caps: LeaderCapabilities,
    },
    /// Accepts the connection but never sends anything (hung pre-`Registered`).
    SilentAfterAccept,
    /// Like `Normal`, but every client is served on its own task, so a client that connects, drops and connects again
    /// (a retry loop) is served every time instead of the second one queueing behind the first.
    NormalPerClient {
        versions: FakeVersions,
        caps: LeaderCapabilities,
    },
    /// `Registered { ready: false }`, then never sends `LeaderReady`.
    ReadyFalseForever,
    /// Writes only `bytes` (< 4) of the 4-byte length prefix, then stalls.
    PartialFrame { bytes: usize },
    /// Valid length prefix followed by a non-JSON body.
    GarbageFrame,
    /// Well-formed `Registered { ready: true }`, then closes the connection.
    CloseAfterRegister,
    /// P161: a short `Registered { ready: false }`, `LeaderReady` and an ACP frame carrying `payload`, all in ONE write,
    /// then idle. The client's first buffered read pulls in the start of the later frames during registration, so the
    /// ACP payload only arrives if the same reader (and its buffer) carries over into the client's read loop.
    CoalescedRegisterReadyAcp { payload: String },
    /// A current-version, `control_v1` leader that answers every `GetLeaderInfo` with `claimed_pid` in the payload (a lie or a
    /// squatter's choice), whatever process really serves the pipe. Each client is served on its own task.
    ClaimsPid { claimed_pid: u32 },
}
/// Handle for a running fake leader; cancelling stops the accept loop and any held-open connections, and removes the socket.
pub(crate) struct FakeLeaderHandle {
    cancel: CancellationToken,
}
impl FakeLeaderHandle {
    pub(crate) fn cancel(&self) {
        self.cancel.cancel();
    }
}
/// Bind a fake leader at `socket_path` behaving per `behavior`.
///
/// Returns once the listener is bound (readiness signalled via oneshot, no fixed startup sleep), so callers can connect immediately.
/// Serves clients sequentially: the point of a fake is wire shape, not concurrency.
pub(crate) async fn spawn_fake_leader(
    socket_path: PathBuf,
    behavior: FakeLeaderBehavior,
) -> FakeLeaderHandle {
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = fs::remove_file(&socket_path);
        let listener = match super::transport::LeaderListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(_) => return,
        };
        let _ = ready_tx.send(());
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                accept_result = listener.accept() => {
                    let Ok((stream, _)) = accept_result else {
                        break;
                    };
                    if let FakeLeaderBehavior::ClaimsPid { claimed_pid } = &behavior {
                        let claimed_pid = *claimed_pid;
                        let cancel = cancel_clone.clone();
                        tokio::spawn(async move { serve_claims_pid(stream, claimed_pid, &cancel).await });
                        continue;
                    }
                    if let FakeLeaderBehavior::NormalPerClient { versions, caps } = &behavior {
                        let as_normal = FakeLeaderBehavior::Normal {
                            versions: FakeVersions {
                                protocol_version: versions.protocol_version,
                                binary_version: versions.binary_version.clone(),
                            },
                            caps: caps.clone(),
                        };
                        let cancel = cancel_clone.clone();
                        tokio::spawn(async move { serve_client(stream, &as_normal, &cancel).await });
                        continue;
                    }
                    serve_client(stream, &behavior, &cancel_clone).await;
                }
            }
        }
        let _ = fs::remove_file(&socket_path);
    });
    let _ = ready_rx.await;
    FakeLeaderHandle { cancel }
}
async fn serve_client(
    stream: super::transport::LeaderStream,
    behavior: &FakeLeaderBehavior,
    cancel: &CancellationToken,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    /// A `Registered` with `client_id: 1` and the given shape.
    fn registered(
        ready: bool,
        versions: &FakeVersions,
        caps: &LeaderCapabilities,
    ) -> ServerMessage {
        ServerMessage::Registered {
            client_id: 1,
            ready,
            leader_protocol_version: versions.protocol_version,
            leader_binary_version: versions.binary_version.clone(),
            leader_capabilities: Some(caps.clone()),
        }
    }
    match behavior {
        FakeLeaderBehavior::SilentAfterAccept => {
            cancel.cancelled().await;
        }
        FakeLeaderBehavior::PartialFrame { bytes } => {
            let prefix = 1024u32.to_be_bytes();
            let n = (*bytes).min(prefix.len());
            let _ = writer.write_all(&prefix[..n]).await;
            let _ = writer.flush().await;
            cancel.cancelled().await;
        }
        FakeLeaderBehavior::GarbageFrame => {
            let body = b"this is not json";
            let _ = writer.write_all(&(body.len() as u32).to_be_bytes()).await;
            let _ = writer.write_all(body).await;
            let _ = writer.flush().await;
            cancel.cancelled().await;
        }
        FakeLeaderBehavior::Normal { versions, caps } => {
            let register: Result<ClientMessage, _> = read_message(&mut reader).await;
            if register.is_err() {
                return;
            }
            let _ = write_message(&mut writer, &registered(true, versions, caps)).await;
            cancel.cancelled().await;
        }
        // Reached only through the concurrent path in `spawn_fake_leader`, which serves it as `Normal`.
        FakeLeaderBehavior::NormalPerClient { .. } => {
            cancel.cancelled().await;
        }
        FakeLeaderBehavior::ReadyFalseForever => {
            let register: Result<ClientMessage, _> = read_message(&mut reader).await;
            if register.is_err() {
                return;
            }
            let _ = write_message(
                &mut writer,
                &registered(false, &FakeVersions::current(), &fake_caps(true, false)),
            )
            .await;
            cancel.cancelled().await;
        }
        FakeLeaderBehavior::CoalescedRegisterReadyAcp { payload } => {
            let register: Result<ClientMessage, _> = read_message(&mut reader).await;
            if register.is_err() {
                return;
            }
            let mut wire = Vec::new();
            let bodies = [
                // Deliberately minimal (the optional metadata defaults), so it is shorter than one buffered read.
                br#"{"type":"registered","client_id":1,"ready":false}"#.to_vec(),
                serde_json::to_vec(&ServerMessage::LeaderReady).unwrap(),
                serde_json::to_vec(&ServerMessage::Acp {
                    payload: payload.clone(),
                })
                .unwrap(),
            ];
            for body in bodies {
                wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
                wire.extend_from_slice(&body);
            }
            let _ = writer.write_all(&wire).await;
            let _ = writer.flush().await;
            cancel.cancelled().await;
        }
        // Reached only through the concurrent path in `spawn_fake_leader`.
        FakeLeaderBehavior::ClaimsPid { .. } => {
            cancel.cancelled().await;
        }
        FakeLeaderBehavior::CloseAfterRegister => {
            let register: Result<ClientMessage, _> = read_message(&mut reader).await;
            if register.is_err() {
                return;
            }
            let _ = write_message(
                &mut writer,
                &registered(true, &FakeVersions::current(), &fake_caps(true, false)),
            )
            .await;
        }
    }
}

/// Serve one client of [`FakeLeaderBehavior::ClaimsPid`]: register, then answer `GetLeaderInfo` with `claimed_pid`.
async fn serve_claims_pid(
    stream: super::transport::LeaderStream,
    claimed_pid: u32,
    cancel: &CancellationToken,
) {
    use super::protocol::{ControlCommand, ControlPayload};
    let (mut reader, mut writer) = tokio::io::split(stream);
    let register: Result<ClientMessage, _> = read_message(&mut reader).await;
    if register.is_err() {
        return;
    }
    let registered = ServerMessage::Registered {
        client_id: 1,
        ready: true,
        leader_protocol_version: Some(LEADER_PROTOCOL_VERSION),
        leader_binary_version: Some(fuigo_version::VERSION.to_string()),
        leader_capabilities: Some(fake_caps(true, false)),
    };
    if write_message(&mut writer, &registered).await.is_err() {
        return;
    }
    loop {
        let message: Result<ClientMessage, _> = tokio::select! {
            _ = cancel.cancelled() => return,
            message = read_message(&mut reader) => message,
        };
        let Ok(message) = message else { return };
        if let ClientMessage::Control { request_id, command: ControlCommand::GetLeaderInfo } = message {
            let info = ControlPayload::LeaderInfo {
                pid: claimed_pid,
                socket_path: PathBuf::new(),
                lock_path: PathBuf::new(),
                ws_url_suffix: String::new(),
                leader_protocol_version: LEADER_PROTOCOL_VERSION,
                leader_binary_version: fuigo_version::VERSION.to_string(),
                profiling_supported: false,
                profiling_compiled_in: false,
                cpu_profile_active: false,
                cpu_profile_stopping: false,
                profile_started_at: None,
                profile_formats: Vec::new(),
            };
            let reply = ServerMessage::ControlResult { request_id, result: Ok(info) };
            if write_message(&mut writer, &reply).await.is_err() {
                return;
            }
        }
    }
}
