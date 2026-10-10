//! Leader-follower IPC architecture for fuigo-shell.
//!
//! This module implements a single-leader-per-machine architecture where one leader
//! process manages the agent state while multiple clients (TUI, IDE extensions, headless)
//! communicate via Unix domain sockets.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        Leader Process                        │
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │                      Agent (MvpAgent)                    ││
//! │  │   - Shared state across all clients                      ││
//! │  │   - Persists to ~/.fuigo/                                 ││
//! │  └─────────────────────────────────────────────────────────┘│
//! │                           ▲                                  │
//! │                           │ ACP                              │
//! │  ┌────────────────────────┴────────────────────────────────┐│
//! │  │                   IPC Server (Unix Socket)               ││
//! │  │   - Routes messages between clients and agent            ││
//! │  │   - Namespaces request IDs to avoid collisions           ││
//! │  │   - Tracks session ownership for routing                 ││
//! │  └────────────────────────┬────────────────────────────────┘│
//! └───────────────────────────┼──────────────────────────────────┘
//!                             │ IPC (Unix socket at ~/.fuigo/leader.sock)
//!         ┌───────────────────┼───────────────────┐
//!         ▼                   ▼                   ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │   TUI Client  │   │  IDE Extension │   │ Headless CLI  │
//! │   (stdio)     │   │   (stdio)      │   │  (websocket)  │
//! └───────────────┘   └───────────────┘   └───────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use fuigo_shell::leader::{connect_or_spawn, ClientCapabilities, ClientMode};
//!
//! // Connect to existing leader or spawn a new one
//! let caps = ClientCapabilities {
//!     yolo_mode: true,
//!     default_model: Some("grok-3-fast".to_string()),
//! };
//! let conn = connect_or_spawn("my-client", ClientMode::Stdio, &env_urls, caps).await?;
//!
//! // Send/receive ACP messages
//! conn.send(r#"{"jsonrpc":"2.0","method":"test","id":1}"#.to_string())?;
//! if let Some(response) = conn.recv().await {
//!     println!("Got response: {}", response);
//! }
//! ```
mod act_on;
mod client;
#[cfg(feature = "test-support")]
pub mod in_process;
mod lock;
mod peer_check;
#[cfg(all(test, windows))]
mod starter_identity_tests;
mod peer_auth;
#[cfg(all(test, windows))]
mod peer_auth_tests;
pub mod protocol;
mod server;
#[cfg(test)]
pub(crate) mod test_support;
mod transport;
use crate::env::FuigoBuildEnvironment;
pub use client::{ClientError, DisconnectReason, LeaderClient, LeaderRegistration};
pub use lock::{
    LEADER_SOCKET_ENV, LeaderLock, LockError, compute_ws_url_suffix, lock_path_for_ws_url,
    lock_path_for_ws_url_in, socket_path_for_ws_url, socket_path_for_ws_url_in,
    ws_url_suffix_from_paths,
};
pub use protocol::{
    ClientCapabilities, ClientId, ClientMode, ControlCommand, ControlPayload, LEADER_NOTICE_METHOD,
    LEADER_PROTOCOL_VERSION, LeaderCapabilities, ShutdownReason, leader_notice_payload,
};
use serde::{Deserialize, Serialize};
pub use server::{
    LeaderServerControlState, LeaderServerMetadata, RelayRefusalBoard, ServerError, ServerHandle, run_leader_server,
    spawn_leader_server,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
pub use transport::listener_is_ready;
const SPAWN_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const SPAWN_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Passed by [`spawn_leader_subprocess`] to every auto-spawned leader; its
/// absence in argv marks an externally supervised daemon (never reclaim).
const RELAY_ON_DEMAND_FLAG: &str = "--relay-on-demand";
/// Same source the leader reports, so adoption compares versions like-for-like.
const CLIENT_LEADER_VERSION: &str = fuigo_version::VERSION;
/// Max wait for an evicted leader to exit before force-killing (relaunch drain ~5s).
const EVICT_WAIT_TIMEOUT: Duration = Duration::from_secs(8);
/// How long the SAME live fuigo flock-holder may stay unconnectable before
/// `connect_or_spawn` treats it as a "zombie leader" and evicts it.
const ZOMBIE_EVICT_DEADLINE: Duration = Duration::from_secs(30);
/// How long `connect_or_spawn` keeps asking a too-old leader that holds the lock to vacate before it gives up.
/// Same kind and size as [`ZOMBIE_EVICT_DEADLINE`]; it must exceed the leader's own relaunch grace (10 s).
const VACATE_WAIT_TIMEOUT: Duration = ZOMBIE_EVICT_DEADLINE;
/// Whether `leader_version` is a strictly-older parseable semver than `baseline`.
/// Unparseable versions (e.g. dev `"unknown"`) return `false`, so they are left alone.
pub fn leader_is_older_than(leader_version: &str, baseline: &str) -> bool {
    match (
        semver::Version::parse(leader_version),
        semver::Version::parse(baseline),
    ) {
        (Ok(leader), Ok(baseline)) => leader < baseline,
        _ => false,
    }
}
/// Evict a discovered leader only if it runs a strictly-older parseable version than this client.
/// A newer client replaces an older leader, never the reverse, so the machine converges to the newest version without thrash.
/// A missing or unparseable version keeps the leader.
fn should_evict(leader_version: Option<&str>, client_version: &str) -> bool {
    leader_version.is_some_and(|v| leader_is_older_than(v, client_version))
}
/// Whether `leader_version` is a strictly-newer parseable semver than `baseline` (P124).
/// Unparseable versions (e.g. dev `"unknown"`) return `false`, like [`leader_is_older_than`].
pub fn leader_is_newer_than(leader_version: &str, baseline: &str) -> bool {
    match (
        semver::Version::parse(leader_version),
        semver::Version::parse(baseline),
    ) {
        (Ok(leader), Ok(baseline)) => leader > baseline,
        _ => false,
    }
}
/// The message a client prints when it adopts a leader that runs a strictly newer Fuigo than the client (P124).
/// `None` when the leader is the same, older, unversioned or unparseable (nothing to say).
///
/// A client never evicts a newer leader (that would thrash machines running two versions), so before this it simply
/// served a session from the newer binary without saying so, which is what an explicit downgrade looked like.
pub fn newer_leader_notice(leader_version: Option<&str>, client_version: &str) -> Option<String> {
    let leader_version = leader_version.filter(|v| leader_is_newer_than(v, client_version))?;
    Some(format!(
        "Fuigo {client_version} is connected to a shared background session (the leader) that runs the newer Fuigo \
         {leader_version}, so it behaves like {leader_version}, not {client_version}. If you went back to \
         {client_version} on purpose, run `fuigo leader kill` and start Fuigo again."
    ))
}
/// The notice last announced by [`note_adopted_leader`]; reconnects adopt the same leader again and must not repeat it.
static LAST_NEWER_LEADER_NOTICE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// Tell the user, once per distinct message, that the leader this client just adopted is newer than the client (P124).
fn note_adopted_leader(conn: &LeaderConnection) {
    let leader_version = conn.registration().leader_binary_version.as_deref();
    let Some(text) = newer_leader_notice(leader_version, CLIENT_LEADER_VERSION).or_else(|| {
        stale_client_notice(
            leader_version,
            installed_version_for_eviction().as_deref(),
            CLIENT_LEADER_VERSION,
            &crate::util::fuigo_home::fuigo_home().join("bin").join(managed_fuigo_bin_name()),
        )
    }) else {
        return;
    };
    let Ok(mut last) = LAST_NEWER_LEADER_NOTICE.lock() else {
        return;
    };
    if last.as_deref() == Some(text.as_str()) {
        return;
    }
    warn!(
        leader_version = ?conn.registration().leader_binary_version,
        client_version = CLIENT_LEADER_VERSION,
        "Adopted a leader whose version differs from this client (newer leader, or the installed older one a newer client keeps)"
    );
    fuigo_file_utils::destination_gate::announce_notice(&text);
    *last = Some(text);
}
/// What became of one leader asked to stop after an explicit downgrade (P124).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DowngradeStopResult {
    /// The leader accepted and will exit after its bounded grace period; clients reconnect.
    Stopping { from_version: String },
    /// The leader was left running: it is not newer than the installed version, or a relaunch is already in progress.
    Declined(String),
    /// The leader is newer but predates `StopForDowngrade`: the user must run `fuigo leader kill`.
    Unsupported { leader_version: String },
    /// The leader could not be reached or answered with an error.
    Unreachable(String),
}
/// Ask the leader on `socket_path` to stop because `installed_version` (strictly older than the leader) was just installed
/// by an explicit downgrade (P124). The version handshake: the leader's registered version is checked here, and the leader
/// checks it again authoritatively, so a leader that is not strictly newer is never signalled or stopped.
pub async fn stop_leader_for_downgrade(
    socket_path: PathBuf,
    installed_version: &str,
) -> DowngradeStopResult {
    let client = match LeaderClient::connect(
        socket_path,
        "fuigo-pager-update",
        ClientMode::Stdio,
        ClientCapabilities::default(),
    )
    .await
    {
        Ok(client) => client,
        Err(e) => return DowngradeStopResult::Unreachable(e.to_string()),
    };
    let leader_version = client.registration().leader_binary_version.clone();
    let result = match leader_version {
        Some(version) if leader_is_newer_than(&version, installed_version) => {
            if !client.registration().supports_downgrade_stop() {
                DowngradeStopResult::Unsupported {
                    leader_version: version,
                }
            } else {
                match client
                    .send_control(ControlCommand::StopForDowngrade {
                        to_version: installed_version.to_string(),
                    })
                    .await
                {
                    Ok(Ok(ControlPayload::Relaunching { from_version, .. })) => {
                        DowngradeStopResult::Stopping { from_version }
                    }
                    Ok(Ok(ControlPayload::RelaunchDeclined { reason })) => {
                        DowngradeStopResult::Declined(reason)
                    }
                    Ok(Ok(other)) => {
                        DowngradeStopResult::Unreachable(format!("unexpected answer {other:?}"))
                    }
                    Ok(Err(e)) => DowngradeStopResult::Unreachable(e.message),
                    Err(e) => DowngradeStopResult::Unreachable(e.to_string()),
                }
            }
        }
        Some(version) => DowngradeStopResult::Declined(format!(
            "leader version {version} is not newer than {installed_version}"
        )),
        None => DowngradeStopResult::Declined("leader reports no version".to_string()),
    };
    client.cancel();
    result
}
/// Whether a `fuigo update` that installed `installed` while this process ran `running` was an explicit downgrade (P124 r1 #2):
/// the user asked for a version (`--version X` or `--force`) and what was installed is strictly older than what ran.
/// An ordinary update, or one that installed nothing ("Already up to date"), is never a downgrade, so it never stops a leader.
pub fn is_explicit_downgrade(explicit_request: bool, installed: &str, running: &str) -> bool {
    explicit_request && leader_is_older_than(installed, running)
}
/// Leader versions that are STILL below this process's version floor after it spawned a leader itself (P124 r2 #1, r3 #1).
/// The managed binary is the one that produced them, so evicting such a version again only respawns the same version.
/// Without this, clients still running a newer binary after an explicit downgrade evict each other's leaders in turn (Astra P110 r2 #1).
/// Learned ONLY from a completed spawn: merely discovering a stale leader (even repeatedly) never records anything, so an
/// ordinary version-floor replacement is unchanged.
static FUTILE_EVICTIONS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
/// Whether `leader_version` IS the version installed on disk while this client is newer than that install (P129).
/// Then the client itself is the stale binary: a respawn runs the managed (installed) binary, which is the leader's own version,
/// so evicting only churns it (one eviction per fresh process after an explicit downgrade, e2e residue a3).
/// An unknown or unparseable install is never matched, which keeps the plain P124 behaviour.
fn leader_is_installed_and_client_is_stale(
    leader_version: &str,
    installed_version: Option<&str>,
    client_version: &str,
) -> bool {
    let Some(installed) = installed_version else {
        return false;
    };
    match (
        semver::Version::parse(leader_version),
        semver::Version::parse(installed),
    ) {
        (Ok(leader), Ok(installed_parsed)) => {
            leader == installed_parsed && leader_is_older_than(installed, client_version)
        }
        _ => false,
    }
}
/// The version of the managed binary a leader spawn from this process would run (P129), or `None` when that is not knowable.
/// Same source as `fuigo update`'s disk probe (the target name of the `<fuigo_home>/bin/fuigo` symlink), and only for a managed
/// client (`current_exe` under `fuigo_home`, the case where [`resolve_binary_impl`] spawns through that symlink). A dev or out-of-tree
/// binary spawns itself, so there is no "installed" version to defer to. A dangling or unparseable link yields `None`.
pub fn managed_installed_version(fuigo_home: &Path, current_exe: Option<&Path>) -> Option<String> {
    #[cfg(unix)]
    {
        let exe = current_exe?;
        if !path_is_under(exe, fuigo_home) {
            return None;
        }
        let managed_bin = fuigo_home.join("bin").join(managed_fuigo_bin_name());
        let target = std::fs::read_link(&managed_bin).ok()?;
        std::fs::metadata(&managed_bin).ok()?;
        version_from_versioned_binary_name(target.file_name()?.to_str()?, "fuigo")
    }
    #[cfg(not(unix))]
    {
        let _ = (fuigo_home, current_exe);
        None
    }
}
/// Everything between the `{bin_prefix}-` prefix and the first platform-OS component is the version, validated as semver.
/// Handles `fuigo-0.1.150-macos-aarch64` and the npm layout `fuigo-0.1.150`; pre-releases parse whole. Unknown layouts give `None`.
/// The single place that understands the versioned-binary naming; `fuigo-update` delegates to it.
pub fn version_from_versioned_binary_name(name: &str, bin_prefix: &str) -> Option<String> {
    const PLATFORM_OS: &[&str] = &["macos", "linux", "darwin", "windows"];
    let suffix = name.strip_prefix(bin_prefix)?.strip_prefix('-')?;
    let parts: Vec<&str> = suffix.split('-').collect();
    let platform_start = parts
        .iter()
        .position(|p| PLATFORM_OS.contains(p))
        .unwrap_or(parts.len());
    let ver_str = parts[..platform_start].join("-");
    semver::Version::parse(&ver_str).ok()?;
    Some(ver_str)
}
/// Whether to evict the leader running `leader_version`: it is below the floor ([`should_evict`]), its version was not found futile,
/// and it is not the installed version that this (newer, stale) client would only respawn (P129).
/// Pure: a decision never changes the record.
fn evict_decision(
    leader_version: Option<&str>,
    client_version: &str,
    installed_version: Option<&str>,
    futile: &std::sync::Mutex<Vec<String>>,
) -> bool {
    let Some(version) = leader_version.filter(|v| should_evict(Some(v), client_version)) else {
        return false;
    };
    if leader_is_installed_and_client_is_stale(version, installed_version, client_version) {
        return false;
    }
    futile
        .lock()
        .is_ok_and(|futile| !futile.iter().any(|v| v == version))
}
/// The notice a newer-than-installed client prints when it keeps (does not evict) the installed-version leader (P129).
/// `None` unless the leader is the installed version and the client is newer than it.
pub fn stale_client_notice(
    leader_version: Option<&str>,
    installed_version: Option<&str>,
    client_version: &str,
    managed_bin: &Path,
) -> Option<String> {
    let leader_version = leader_version?;
    if !leader_is_installed_and_client_is_stale(leader_version, installed_version, client_version) {
        return None;
    }
    let managed = managed_bin.display();
    Some(format!(
        "This Fuigo ({client_version}) is newer than the installed Fuigo {leader_version}, so it is using the shared background \
         session (the leader) of {leader_version} instead of replacing it, and behaves like {leader_version}. \
         To run the installed version, start `{managed}` (the `fuigo` on your PATH may be a different install); to use {client_version}, run `fuigo update --version {client_version}`."
    ))
}
/// Remember that a leader this process spawned runs `leader_version`, if that is still below the floor.
fn remember_futile(
    leader_version: Option<&str>,
    client_version: &str,
    futile: &std::sync::Mutex<Vec<String>>,
) {
    let Some(version) = leader_version.filter(|v| should_evict(Some(v), client_version)) else {
        return;
    };
    if let Ok(mut futile) = futile.lock()
        && !futile.iter().any(|v| v == version)
    {
        futile.push(version.to_string());
    }
}
/// [`evict_decision`] for a live connection against the process-wide record.
fn evict_leader_conn(conn: &LeaderConnection) -> bool {
    evict_decision(
        conn.registration().leader_binary_version.as_deref(),
        CLIENT_LEADER_VERSION,
        installed_version_for_eviction().as_deref(),
        &FUTILE_EVICTIONS,
    )
}
/// [`managed_installed_version`] for this process.
fn installed_version_for_eviction() -> Option<String> {
    managed_installed_version(
        &crate::util::fuigo_home::fuigo_home(),
        std::env::current_exe().ok().as_deref(),
    )
}
/// A leader this client just spawned that is still below its floor: the installed binary is that old, so never evict that version again.
fn note_spawned_leader(conn: &LeaderConnection) {
    remember_futile(
        conn.registration().leader_binary_version.as_deref(),
        CLIENT_LEADER_VERSION,
        &FUTILE_EVICTIONS,
    );
}
/// Base delay between reconnection attempts.
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(1);
/// Maximum delay between reconnection attempts (caps exponential backoff).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
/// Maximum reconnection attempts for bounded mode (headless/`fuigo -p`).
/// TUI mode uses unlimited retries controlled by a cancellation token.
const RECONNECT_MAX_ATTEMPTS_BOUNDED: u32 = 5;
/// Environment URLs to pass to the leader subprocess.
/// These are resolved from the environment (--dev flag) before spawning.
#[derive(Debug, Clone)]
pub struct LeaderEnvUrls {
    pub fuigo_ws_url: String,
    pub fuigo_ws_origin: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderDiscoveryState {
    Reachable,
    Stale,
    Unreachable,
    UnsupportedProtocol,
    Ambiguous,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderTargetErrorCode {
    LeaderNotFound,
    SocketUnreachable,
    PidVerificationFailed,
    UnsupportedProtocol,
    AmbiguousTarget,
}
impl std::fmt::Display for LeaderTargetErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::LeaderNotFound => "leader_not_found",
            Self::SocketUnreachable => "socket_unreachable",
            Self::PidVerificationFailed => "pid_verification_failed",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::AmbiguousTarget => "ambiguous_target",
        };
        f.write_str(code)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct LeaderTargetError {
    pub code: LeaderTargetErrorCode,
    pub message: String,
}
impl LeaderTargetError {
    fn new(code: LeaderTargetErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveLeaderInfo {
    pub pid: u32,
    pub socket_path: PathBuf,
    pub lock_path: PathBuf,
    pub ws_url_suffix: String,
    pub leader_protocol_version: u32,
    pub leader_binary_version: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderDescriptor {
    pub pid_from_lock: Option<u32>,
    pub lock_path: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub ws_url_suffix: String,
    pub classification: LeaderDiscoveryState,
    pub environment: Option<FuigoBuildEnvironment>,
    pub live_info: Option<LiveLeaderInfo>,
    pub target_error: Option<LeaderTargetErrorCode>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderTargetSelection {
    pub descriptor: LeaderDescriptor,
}
impl LeaderTargetSelection {
    pub fn socket_path(&self) -> Option<&Path> {
        self.descriptor.socket_path.as_deref()
    }
    pub fn lock_path(&self) -> Option<&Path> {
        self.descriptor.lock_path.as_deref()
    }
    pub fn ws_url_suffix(&self) -> &str {
        &self.descriptor.ws_url_suffix
    }
    pub fn live_info(&self) -> Option<&LiveLeaderInfo> {
        self.descriptor.live_info.as_ref()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderTarget {
    Environment(FuigoBuildEnvironment),
    WsUrl(String),
    Pid(u32),
}
fn known_environment_for_ws_url(ws_url: &str) -> Option<FuigoBuildEnvironment> {
    let environments: &[FuigoBuildEnvironment] = &[FuigoBuildEnvironment::Production];
    environments
        .iter()
        .copied()
        .find(|environment| environment.relay_ws_url() == ws_url)
}
fn environment_target_matches_descriptor(
    environment: FuigoBuildEnvironment,
    descriptor: &LeaderDescriptor,
) -> bool {
    descriptor.environment == Some(environment)
}
fn ws_url_target_matches_descriptor(ws_url: &str, descriptor: &LeaderDescriptor) -> bool {
    descriptor.ws_url_suffix == compute_ws_url_suffix(ws_url)
}
fn known_environment_for_suffix(ws_url_suffix: &str) -> Option<FuigoBuildEnvironment> {
    let environments: &[FuigoBuildEnvironment] = &[FuigoBuildEnvironment::Production];
    environments
        .iter()
        .copied()
        .find(|environment| compute_ws_url_suffix(&environment.relay_ws_url()) == ws_url_suffix)
}
fn build_live_leader_info(payload: ControlPayload) -> Result<LiveLeaderInfo, LeaderTargetError> {
    match payload {
        ControlPayload::LeaderInfo {
            pid,
            socket_path,
            lock_path,
            ws_url_suffix,
            leader_protocol_version,
            leader_binary_version,
            ..
        } => Ok(LiveLeaderInfo {
            pid,
            socket_path,
            lock_path,
            ws_url_suffix,
            leader_protocol_version,
            leader_binary_version,
        }),
        _ => Err(LeaderTargetError::new(
            LeaderTargetErrorCode::UnsupportedProtocol,
            "leader returned an unexpected control payload for GetLeaderInfo",
        )),
    }
}
async fn fetch_live_leader_info(socket_path: &Path) -> Result<LiveLeaderInfo, LeaderTargetError> {
    let client = LeaderClient::connect(
        socket_path.to_path_buf(),
        "fuigo-leader-discovery",
        ClientMode::Stdio,
        ClientCapabilities::default(),
    )
    .await
    .map_err(|error| {
        LeaderTargetError::new(
            LeaderTargetErrorCode::SocketUnreachable,
            format!(
                "failed to connect to leader socket {}: {}",
                socket_path.display(),
                error
            ),
        )
    })?;
    let result = async {
        let registration = client.registration();
        let protocol_version = registration.leader_protocol_version.ok_or_else(|| {
            LeaderTargetError::new(
                LeaderTargetErrorCode::UnsupportedProtocol,
                format!(
                    "leader at {} did not advertise a control protocol version",
                    socket_path.display()
                ),
            )
        })?;
        if protocol_version < LEADER_PROTOCOL_VERSION {
            return Err(LeaderTargetError::new(
                LeaderTargetErrorCode::UnsupportedProtocol,
                format!(
                    "leader at {} uses unsupported protocol version {}",
                    socket_path.display(),
                    protocol_version
                ),
            ));
        }
        let control_v1 = registration
            .leader_capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.control_v1);
        if !control_v1 {
            return Err(LeaderTargetError::new(
                LeaderTargetErrorCode::UnsupportedProtocol,
                format!(
                    "leader at {} does not advertise control_v1 support",
                    socket_path.display()
                ),
            ));
        }
        let payload = client
            .send_control(ControlCommand::GetLeaderInfo)
            .await
            .map_err(|error| {
                LeaderTargetError::new(
                    LeaderTargetErrorCode::SocketUnreachable,
                    format!(
                        "failed to query live leader info from {}: {}",
                        socket_path.display(),
                        error
                    ),
                )
            })?
            .map_err(|error| {
                LeaderTargetError::new(
                    LeaderTargetErrorCode::UnsupportedProtocol,
                    format!(
                        "leader at {} rejected GetLeaderInfo: {}",
                        socket_path.display(),
                        error
                    ),
                )
            })?;
        build_live_leader_info(payload)
    }
    .await;
    client.cancel();
    result
}
fn descriptor_from_paths(
    lock_path: Option<PathBuf>,
    socket_path: Option<PathBuf>,
    pid_from_lock: Option<u32>,
    live_info: Option<LiveLeaderInfo>,
    classification: LeaderDiscoveryState,
    target_error: Option<LeaderTargetErrorCode>,
) -> LeaderDescriptor {
    let ws_url_suffix =
        live_info
            .as_ref()
            .map(|info| info.ws_url_suffix.clone())
            .or_else(|| {
                lock_path.as_deref().zip(socket_path.as_deref()).and_then(
                    |(lock_path, socket_path)| ws_url_suffix_from_paths(lock_path, socket_path),
                )
            })
            .or_else(|| {
                lock_path
                    .as_deref()
                    .and_then(|path| path.file_name()?.to_str())
                    .and_then(|name| name.strip_prefix("leader"))
                    .and_then(|name| name.strip_suffix(".lock"))
                    .map(str::to_string)
            })
            .or_else(|| {
                socket_path
                    .as_deref()
                    .and_then(|path| path.file_name()?.to_str())
                    .and_then(|name| name.strip_prefix("leader"))
                    .and_then(|name| name.strip_suffix(".sock"))
                    .map(str::to_string)
            })
            .unwrap_or_default();
    let environment = known_environment_for_suffix(&ws_url_suffix);
    LeaderDescriptor {
        pid_from_lock,
        lock_path,
        socket_path,
        ws_url_suffix,
        classification,
        environment,
        live_info,
        target_error,
    }
}
/// Whether a live leader's endpoint is a file in fuigo home. On Unix it is the `leader*.sock` Unix domain socket. On
/// Windows the transport is a named pipe whose name is derived from the socket PATH (`transport::path_to_pipe_name`), and
/// no file is ever created at that path (P145).
const LEADER_ENDPOINT_IS_FILE: bool = !cfg!(windows);
async fn discover_leaders_in(root: &Path) -> Vec<LeaderDescriptor> {
    discover_leaders_in_with(root, LEADER_ENDPOINT_IS_FILE).await
}
/// [`discover_leaders_in`] with the endpoint kind injected, so the Windows rule runs in the Linux tests.
///
/// With a file endpoint, a lock and a socket file are paired by suffix (a lock alone is Stale). Without one (Windows),
/// discovery used to see only `leader.lock`, classify every leader Stale and never ask it anything, so `fuigo leader
/// list` showed a live leader as "PID ? (Stale)" (its PID is unreadable too: the leader holds a mandatory lock on the
/// file) and `fuigo leader info` found no reachable leader (P145). Now each lock is paired with the socket path its
/// leader binds (the sibling `.sock`, the pairing `lock_path_for_socket` defines) and the leader is asked over the
/// pipe; only a leader that does not answer is Stale.
async fn discover_leaders_in_with(root: &Path, endpoint_is_file: bool) -> Vec<LeaderDescriptor> {
    let mut candidates: std::collections::BTreeMap<String, (Option<PathBuf>, Option<PathBuf>)> =
        std::collections::BTreeMap::new();
    let Ok(read_dir) = fs::read_dir(root) else {
        return Vec::new();
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let file_name = file_name.to_string();
        if let Some(suffix) = file_name
            .strip_prefix("leader")
            .and_then(|name| name.strip_suffix(".lock"))
        {
            candidates.entry(suffix.to_string()).or_default().0 = Some(path);
            continue;
        }
        if endpoint_is_file
            && let Some(suffix) = file_name
                .strip_prefix("leader")
                .and_then(|name| name.strip_suffix(".sock"))
        {
            candidates.entry(suffix.to_string()).or_default().1 = Some(path);
        }
    }
    let mut entries = Vec::new();
    for (_suffix, (lock_path, socket_path)) in candidates {
        let pid_from_lock = lock_path
            .as_deref()
            .and_then(LeaderLock::read_pid_from_path);
        if let (Some(lock_path), None) = (&lock_path, &socket_path)
            && let Some(derived) = derived_endpoint_for_lock(lock_path, endpoint_is_file)
        {
            let lock_path = lock_path.clone();
            entries.push(match fetch_live_leader_info(&derived).await {
                Ok(live_info) => descriptor_from_paths(
                    Some(lock_path),
                    Some(derived),
                    pid_from_lock,
                    Some(live_info),
                    LeaderDiscoveryState::Reachable,
                    None,
                ),
                // Nothing answers on the pipe: the same verdict a lock without a socket file gets on Unix.
                Err(error) if error.code == LeaderTargetErrorCode::SocketUnreachable => descriptor_from_paths(
                    Some(lock_path),
                    None,
                    pid_from_lock,
                    None,
                    LeaderDiscoveryState::Stale,
                    None,
                ),
                Err(error) if error.code == LeaderTargetErrorCode::UnsupportedProtocol => descriptor_from_paths(
                    Some(lock_path),
                    Some(derived),
                    pid_from_lock,
                    None,
                    LeaderDiscoveryState::UnsupportedProtocol,
                    Some(LeaderTargetErrorCode::UnsupportedProtocol),
                ),
                Err(error) => descriptor_from_paths(
                    Some(lock_path),
                    Some(derived),
                    pid_from_lock,
                    None,
                    LeaderDiscoveryState::Ambiguous,
                    Some(error.code),
                ),
            });
            continue;
        }
        match (lock_path.clone(), socket_path.clone()) {
            (Some(lock_path), None) => entries.push(descriptor_from_paths(
                Some(lock_path),
                None,
                pid_from_lock,
                None,
                LeaderDiscoveryState::Stale,
                None,
            )),
            (None, Some(socket_path)) => match fetch_live_leader_info(&socket_path).await {
                Ok(live_info) => entries.push(descriptor_from_paths(
                    None,
                    Some(socket_path),
                    None,
                    Some(live_info),
                    LeaderDiscoveryState::Reachable,
                    None,
                )),
                Err(error) if error.code == LeaderTargetErrorCode::SocketUnreachable => {
                    entries.push(descriptor_from_paths(
                        None,
                        Some(socket_path),
                        None,
                        None,
                        LeaderDiscoveryState::Unreachable,
                        Some(LeaderTargetErrorCode::SocketUnreachable),
                    ));
                }
                Err(error) if error.code == LeaderTargetErrorCode::UnsupportedProtocol => {
                    entries.push(descriptor_from_paths(
                        None,
                        Some(socket_path),
                        None,
                        None,
                        LeaderDiscoveryState::UnsupportedProtocol,
                        Some(LeaderTargetErrorCode::UnsupportedProtocol),
                    ));
                }
                Err(error) => entries.push(descriptor_from_paths(
                    None,
                    Some(socket_path),
                    None,
                    None,
                    LeaderDiscoveryState::Ambiguous,
                    Some(error.code),
                )),
            },
            (Some(lock_path), Some(socket_path)) => {
                match fetch_live_leader_info(&socket_path).await {
                    Ok(live_info) => entries.push(descriptor_from_paths(
                        Some(lock_path),
                        Some(socket_path),
                        pid_from_lock,
                        Some(live_info),
                        LeaderDiscoveryState::Reachable,
                        None,
                    )),
                    Err(error) if error.code == LeaderTargetErrorCode::SocketUnreachable => {
                        entries.push(descriptor_from_paths(
                            Some(lock_path),
                            Some(socket_path),
                            pid_from_lock,
                            None,
                            LeaderDiscoveryState::Unreachable,
                            Some(LeaderTargetErrorCode::SocketUnreachable),
                        ));
                    }
                    Err(error) if error.code == LeaderTargetErrorCode::UnsupportedProtocol => {
                        entries.push(descriptor_from_paths(
                            Some(lock_path),
                            Some(socket_path),
                            pid_from_lock,
                            None,
                            LeaderDiscoveryState::UnsupportedProtocol,
                            Some(LeaderTargetErrorCode::UnsupportedProtocol),
                        ));
                    }
                    Err(error) => entries.push(descriptor_from_paths(
                        Some(lock_path),
                        Some(socket_path),
                        pid_from_lock,
                        None,
                        LeaderDiscoveryState::Ambiguous,
                        Some(error.code),
                    )),
                }
            }
            (None, None) => {}
        }
    }
    entries.sort_by(|left, right| {
        left.ws_url_suffix
            .cmp(&right.ws_url_suffix)
            .then_with(|| left.lock_path.cmp(&right.lock_path))
            .then_with(|| left.socket_path.cmp(&right.socket_path))
    });
    entries
}
/// The endpoint path a lock's leader binds when that endpoint is not a file (Windows named pipe): the sibling `.sock`
/// path, from which the transport derives the pipe name. `None` with file endpoints, where the file itself is scanned.
fn derived_endpoint_for_lock(lock_path: &Path, endpoint_is_file: bool) -> Option<PathBuf> {
    (!endpoint_is_file).then(|| lock_path.with_extension("sock"))
}
pub async fn discover_leaders() -> Vec<LeaderDescriptor> {
    discover_leaders_in(&crate::util::fuigo_home::fuigo_home()).await
}
/// (pid, leader_binary_version) of socket-verified (Reachable) leaders; a
/// stale-lock-only descriptor is skipped (its `pid_from_lock` may be recycled).
fn reachable_leader_pids(leaders: &[LeaderDescriptor]) -> Vec<(u32, String)> {
    leaders
        .iter()
        .filter_map(|d| {
            d.live_info
                .as_ref()
                .map(|li| (li.pid, li.leader_binary_version.clone()))
        })
        .collect()
}
/// True when the leader was auto-spawned by an interactive client (argv has
/// [`RELAY_ON_DEMAND_FLAG`]). Externally supervised daemons (systemd, devbox
/// supervisors) lack it; killing them drops the host's relay agent, so an
/// unreadable cmdline also counts as not reclaimable.
fn is_policy_reclaimable_leader(pid: u32) -> bool {
    crate::util::process_cmdline_args(pid)
        .is_some_and(|args| args.iter().any(|arg| arg == RELAY_ON_DEMAND_FLAG))
}
/// Best-effort, time-boxed kill of reachable leaders, reclaiming a leader still running after leader mode was disabled by policy (`reason`).
/// Skips leaders not auto-spawned by interactive clients ([`is_policy_reclaimable_leader`]).
/// Emits unified_log (captured in unified.jsonl) so operators can attribute eviction kills; the `tracing` lines are kept for local debug.
/// Errors are logged, never fatal.
#[tracing::instrument(level = "debug", skip_all)]
pub async fn kill_stale_reachable_leaders(reason: &'static str) {
    let targets = reachable_leader_pids(&discover_leaders().await);
    let discovered = targets.len();
    crate::unified_log::info(
        "leader.startup_kill.begin",
        None,
        Some(serde_json::json!({ "reason": reason, "discovered": discovered })),
    );
    let mut killed = 0usize;
    let mut failed = 0usize;
    let mut skipped_supervised = 0usize;
    let timed_out = tokio::time::timeout(Duration::from_secs(5), async {
        for (pid, dead_leader_ver) in &targets {
            if !is_policy_reclaimable_leader(*pid) {
                skipped_supervised += 1;
                info!(pid = *pid, "skipping externally supervised leader");
                crate::unified_log::info(
                    "leader.startup_kill.skipped_supervised",
                    None,
                    Some(serde_json::json!({
                        "pid": *pid,
                        "leader_ver": dead_leader_ver,
                        "reason": reason,
                    })),
                );
                continue;
            }
            match crate::util::kill_process_by_pid(*pid) {
                Ok(()) => {
                    killed += 1;
                    info!(pid = *pid, "killed stale reachable leader");
                    crate::unified_log::warn(
                        "leader.startup_kill.killed",
                        None,
                        Some(serde_json::json!({
                            "pid": *pid,
                            "dead_leader_ver": dead_leader_ver,
                            "reason": reason,
                            "killer_ver": fuigo_version::VERSION,
                        })),
                    );
                }
                Err(e) => {
                    failed += 1;
                    warn!(pid = *pid, error = %e, "failed to kill stale leader");
                    crate::unified_log::warn(
                        "leader.startup_kill.failed",
                        None,
                        Some(serde_json::json!({
                            "pid": *pid,
                            "dead_leader_ver": dead_leader_ver,
                            "error": e.to_string(),
                        })),
                    );
                }
            }
        }
    })
    .await
    .is_err();
    crate::unified_log::info(
        "leader.startup_kill.done",
        None,
        Some(serde_json::json!({
            "reason": reason,
            "discovered": discovered,
            "killed": killed,
            "failed": failed,
            "skipped_supervised": skipped_supervised,
            "timed_out": timed_out,
        })),
    );
}
fn resolve_target_from_descriptors(
    target: LeaderTarget,
    leaders: Vec<LeaderDescriptor>,
) -> Result<LeaderTargetSelection, LeaderTargetError> {
    match target {
        LeaderTarget::Environment(environment) => {
            let ws_url = environment.relay_ws_url();
            let environment_note = environment
                .indicator()
                .map(str::to_string)
                .unwrap_or_else(|| ws_url.clone());
            let matching: Vec<_> = leaders
                .into_iter()
                .filter(|descriptor| environment_target_matches_descriptor(environment, descriptor))
                .collect();
            let reachable: Vec<_> = matching
                .iter()
                .filter(|descriptor| descriptor.classification == LeaderDiscoveryState::Reachable)
                .cloned()
                .collect();
            if reachable.len() == 1 {
                let Some(descriptor) = reachable.into_iter().next() else {
                    return Err(LeaderTargetError::new(
                        LeaderTargetErrorCode::LeaderNotFound,
                        format!("no reachable leader found for target {}", environment_note),
                    ));
                };
                return Ok(LeaderTargetSelection { descriptor });
            }
            if reachable.len() > 1 {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::AmbiguousTarget,
                    format!(
                        "multiple leader candidates matched target {}",
                        environment_note
                    ),
                ));
            }
            if matching.iter().any(|descriptor| {
                descriptor.target_error == Some(LeaderTargetErrorCode::UnsupportedProtocol)
            }) {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::UnsupportedProtocol,
                    format!(
                        "leader target for {} exists but does not support control_v1",
                        ws_url
                    ),
                ));
            }
            if matching.iter().any(|descriptor| {
                descriptor.target_error == Some(LeaderTargetErrorCode::SocketUnreachable)
            }) {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::SocketUnreachable,
                    format!("leader target for {} has an unreachable socket", ws_url),
                ));
            }
            Err(LeaderTargetError::new(
                LeaderTargetErrorCode::LeaderNotFound,
                format!("no reachable leader found for target {}", environment_note),
            ))
        }
        LeaderTarget::WsUrl(ws_url) => {
            let environment_note = known_environment_for_ws_url(&ws_url)
                .and_then(|environment| environment.indicator().map(str::to_string))
                .unwrap_or_else(|| ws_url.clone());
            let matching: Vec<_> = leaders
                .into_iter()
                .filter(|descriptor| ws_url_target_matches_descriptor(&ws_url, descriptor))
                .collect();
            let reachable: Vec<_> = matching
                .iter()
                .filter(|descriptor| descriptor.classification == LeaderDiscoveryState::Reachable)
                .cloned()
                .collect();
            if reachable.len() == 1 {
                let Some(descriptor) = reachable.into_iter().next() else {
                    return Err(LeaderTargetError::new(
                        LeaderTargetErrorCode::LeaderNotFound,
                        format!("no reachable leader found for target {}", environment_note),
                    ));
                };
                return Ok(LeaderTargetSelection { descriptor });
            }
            if reachable.len() > 1 {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::AmbiguousTarget,
                    format!(
                        "multiple leader candidates matched target {}",
                        environment_note
                    ),
                ));
            }
            if matching.iter().any(|descriptor| {
                descriptor.target_error == Some(LeaderTargetErrorCode::UnsupportedProtocol)
            }) {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::UnsupportedProtocol,
                    format!(
                        "leader target for {} exists but does not support control_v1",
                        ws_url
                    ),
                ));
            }
            if matching.iter().any(|descriptor| {
                descriptor.target_error == Some(LeaderTargetErrorCode::SocketUnreachable)
            }) {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::SocketUnreachable,
                    format!("leader target for {} has an unreachable socket", ws_url),
                ));
            }
            Err(LeaderTargetError::new(
                LeaderTargetErrorCode::LeaderNotFound,
                format!("no reachable leader found for target {}", environment_note),
            ))
        }
        LeaderTarget::Pid(pid) => {
            let matching: Vec<_> = leaders
                .into_iter()
                .filter(|descriptor| {
                    descriptor.pid_from_lock == Some(pid)
                        || descriptor
                            .live_info
                            .as_ref()
                            .is_some_and(|info| info.pid == pid)
                })
                .collect();
            if matching.is_empty() {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::LeaderNotFound,
                    format!("no leader candidate found for pid {}", pid),
                ));
            }
            let reachable: Vec<_> = matching
                .iter()
                .filter(|descriptor| descriptor.classification == LeaderDiscoveryState::Reachable)
                .cloned()
                .collect();
            if reachable.len() != 1 {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::PidVerificationFailed,
                    format!(
                        "pid {} did not resolve to exactly one reachable leader candidate",
                        pid
                    ),
                ));
            }
            let Some(descriptor) = reachable.into_iter().next() else {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::PidVerificationFailed,
                    format!(
                        "pid {} did not resolve to a reachable leader candidate",
                        pid
                    ),
                ));
            };
            let live_pid = descriptor.live_info.as_ref().map(|info| info.pid);
            if live_pid != Some(pid) {
                return Err(LeaderTargetError::new(
                    LeaderTargetErrorCode::PidVerificationFailed,
                    format!(
                        "leader pid verification failed: lock file recorded {:?}, live leader reported {:?}",
                        descriptor.pid_from_lock, live_pid
                    ),
                ));
            }
            Ok(LeaderTargetSelection { descriptor })
        }
    }
}
pub async fn resolve_leader_target(
    target: LeaderTarget,
) -> Result<LeaderTargetSelection, LeaderTargetError> {
    let leaders = discover_leaders().await;
    resolve_target_from_descriptors(target, leaders)
}
impl From<&crate::auth::FuigoComConfig> for LeaderEnvUrls {
    fn from(c: &crate::auth::FuigoComConfig) -> Self {
        Self {
            fuigo_ws_url: c.fuigo_ws_url.clone(),
            fuigo_ws_origin: c.fuigo_ws_origin.clone(),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Lock error: {0}")]
    Lock(#[from] LockError),
    #[error("Client error: {0}")]
    Client(#[from] ClientError),
    #[error("Server error: {0}")]
    Server(#[from] ServerError),
    #[error("Failed to spawn leader: {0}")]
    SpawnFailed(String),
    #[error("Timeout waiting for leader to start")]
    Timeout,
    #[error("Reconnection cancelled")]
    Cancelled,
    #[error(
        "leader mode is unavailable under sandbox profile '{0}': the leader is a \
         separate, shared process this client cannot prove is confined by that \
         profile, so tools are not guaranteed to stay inside it. Disable the \
         profile at the source that selected it (CLI, env, config, or a managed \
         requirement)"
    )]
    SandboxConfinement(&'static str),
}
/// Handle for a connection to the leader process.
///
/// Provides send/receive methods for ACP message payloads.
/// The connection is automatically cleaned up when dropped.
pub struct LeaderConnection {
    client: LeaderClient,
}
impl LeaderConnection {
    /// Send an ACP message payload to the leader.
    ///
    /// The payload should be a valid JSON-RPC message. Request IDs will be
    /// namespaced by the leader to avoid collisions with other clients.
    pub fn send(&self, payload: String) -> Result<(), ConnectionError> {
        self.client.send(payload).map_err(ConnectionError::Client)
    }
    /// Send a leader control request over the existing IPC connection.
    ///
    /// This forwards the same capability-aware control requests as [`LeaderClient`],
    /// so callers using the public `connect_or_spawn` facade can issue process-level
    /// commands without reimplementing leader discovery or socket selection.
    pub async fn send_control(
        &self,
        command: ControlCommand,
    ) -> Result<Result<ControlPayload, crate::cpu_profile::ControlError>, ConnectionError> {
        self.client
            .send_control(command)
            .await
            .map_err(ConnectionError::Client)
    }
    /// Windows: the OS-reported pid of the server end of this connection's pipe.
    #[cfg(windows)]
    pub(crate) fn os_server_pid(&self) -> Option<u32> {
        self.client.os_server_pid()
    }
    /// Windows: the OS-reported pid of the server end of this connection's pipe, asked again now.
    #[cfg(windows)]
    pub(crate) fn os_server_pid_now(&self) -> Option<u32> {
        self.client.os_server_pid_now()
    }
    /// Returns the negotiated registration metadata for this connection.
    pub fn registration(&self) -> &LeaderRegistration {
        self.client.registration()
    }
    /// Receive the next ACP message from the leader.
    ///
    /// Returns `None` if the connection is closed.
    pub async fn recv(&mut self) -> Option<String> {
        self.client.recv().await
    }
    /// Returns a receiver for the most recent `ShuttingDown` reason sent by the
    /// server before a planned shutdown.
    ///
    /// - `None`: no `ShuttingDown` message received yet (still connected or
    ///   connection ended without a planned shutdown announcement).
    /// - `Some(AutoUpdate)`: leader is restarting to install a binary update;
    ///   safe to reconnect immediately via `connect_or_spawn`.
    /// - `Some(Manual)`: deliberately stopped or unspecified shutdown.
    ///
    /// This is the primary entry point for first-party callers (TUI bridge,
    /// headless path, reconnection logic) because `connect_or_spawn` returns
    /// `LeaderConnection`, not `LeaderClient` directly.
    pub fn shutting_down_reason(&self) -> watch::Receiver<Option<protocol::ShutdownReason>> {
        self.client.shutting_down_reason()
    }
    /// Decompose this connection into raw channels.
    ///
    /// Useful for integration with other async code that needs direct channel access.
    pub fn into_channels(
        self,
    ) -> (
        mpsc::UnboundedSender<String>,
        mpsc::UnboundedReceiver<String>,
    ) {
        self.client.into_channels()
    }
    /// Decompose into raw channels plus the disconnect reason receiver.
    ///
    /// Like [`into_channels()`](Self::into_channels) but also returns a
    /// [`watch::Receiver<DisconnectReason>`] so the caller can observe
    /// why the connection ended (e.g., `LeaderShutdown` vs `ConnectionLost`).
    pub(crate) fn into_channels_with_disconnect(
        self,
    ) -> (
        mpsc::UnboundedSender<String>,
        mpsc::UnboundedReceiver<String>,
        watch::Receiver<DisconnectReason>,
    ) {
        self.client.into_channels_with_disconnect()
    }
}
/// Status of a reconnection attempt, observable by callers (e.g., TUI banner).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connected to the leader.
    ///
    /// `generation` is 0 for the initial connection and increments on every
    /// successful reconnect. Observers compare it against the last generation
    /// they handled, so a fast `Reconnecting -> Connected` flip coalesced by
    /// the watch channel still registers as a reconnect.
    Connected { generation: u64 },
    /// Attempting to reconnect (includes current attempt number).
    Reconnecting { attempt: u32 },
    /// Reconnection failed permanently.
    Failed { error: String },
}
/// Controls how many reconnection attempts are made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectPolicy {
    /// Retry indefinitely until the cancellation token fires.
    /// Suitable for interactive TUI sessions where the user expects persistence.
    Unbounded,
    /// Retry up to a fixed number of attempts, then fail.
    /// Suitable for headless/`fuigo -p` where hanging forever is unacceptable.
    Bounded { max_attempts: u32 },
}
impl ReconnectPolicy {
    /// Default bounded policy for headless/non-interactive modes.
    pub fn bounded() -> Self {
        Self::Bounded {
            max_attempts: RECONNECT_MAX_ATTEMPTS_BOUNDED,
        }
    }
    /// Default unbounded policy for interactive TUI mode.
    pub fn unbounded() -> Self {
        Self::Unbounded
    }
}
/// Holds the parameters needed to reconnect to a leader process.
///
/// Does **not** own the live channels; the caller (bridge) owns those directly
/// and swaps them on reconnect. This matches how `connect_or_spawn()` followed by
/// `conn.into_channels()` works in `run_via_leader()`.
///
/// # Usage
///
/// ```ignore
/// let (status_tx, status_rx) = LeaderReconnector::status_channel();
/// let reconnector = LeaderReconnector::new(
///     "fuigo-tui", ClientMode::Stdio, env_urls, caps, status_tx,
/// );
///
/// // When connection dies:
/// let (new_tx, new_rx, _disconnect_rx) = reconnector.reconnect(
///     ReconnectPolicy::unbounded(), &cancel,
/// ).await?;
/// // ... install new_tx/new_rx, then:
/// reconnector.notify_connected();
/// ```
pub struct LeaderReconnector {
    client_type: String,
    mode: ClientMode,
    env_urls: LeaderEnvUrls,
    capabilities: ClientCapabilities,
    status_tx: watch::Sender<ConnectionStatus>,
    /// Generation [`notify_connected`](Self::notify_connected) publishes next.
    /// Starts at 1: generation 0 is the initial connection, pre-seeded by [`status_channel`](Self::status_channel).
    /// Atomic because `notify_connected` takes `&self`.
    next_generation: std::sync::atomic::AtomicU64,
}
impl LeaderReconnector {
    /// Create a new reconnector with the given connection parameters.
    ///
    /// The `status_tx` channel is used to broadcast reconnection status to observers (e.g., TUI banner).
    pub fn new(
        client_type: impl Into<String>,
        mode: ClientMode,
        env_urls: LeaderEnvUrls,
        capabilities: ClientCapabilities,
        status_tx: watch::Sender<ConnectionStatus>,
    ) -> Self {
        Self {
            client_type: client_type.into(),
            mode,
            env_urls,
            capabilities,
            status_tx,
            next_generation: std::sync::atomic::AtomicU64::new(1),
        }
    }
    /// Publish `ConnectionStatus::Connected` with the next reconnect generation.
    ///
    /// Deliberately NOT called by [`reconnect`](Self::reconnect): the caller must first install the fresh channels it returned, then notify,
    /// so an observer that reacts to `Connected` by sending requests cannot race the channel swap and write into the dead pre-reconnect sender.
    pub fn notify_connected(&self) {
        let generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = self
            .status_tx
            .send(ConnectionStatus::Connected { generation });
    }
    /// Attempt to reconnect to the leader (or spawn a new one).
    ///
    /// Returns fresh `(tx, rx, disconnect_rx)` on success.
    /// The caller is responsible for swapping these into its local state, calling [`notify_connected`](Self::notify_connected),
    /// and replaying initialization (e.g., `initialize` + `session/load`).
    ///
    /// The `disconnect_rx` allows the caller to observe *why* the new connection ends (e.g., `LeaderShutdown` vs `ConnectionLost`),
    /// preserving that signal across reconnection cycles.
    ///
    /// Uses exponential backoff, doubling from 1s up to a 30s cap.
    ///
    /// # Retry policy
    ///
    /// - [`ReconnectPolicy::Unbounded`]: retries until `cancel` fires (for TUI).
    /// - [`ReconnectPolicy::Bounded`]: retries up to `max_attempts`, then returns an error.
    pub async fn reconnect(
        &self,
        policy: ReconnectPolicy,
        cancel: &CancellationToken,
    ) -> Result<
        (
            mpsc::UnboundedSender<String>,
            mpsc::UnboundedReceiver<String>,
            watch::Receiver<DisconnectReason>,
        ),
        ConnectionError,
    > {
        self.reconnect_with(policy, cancel, || {
            connect_or_spawn(
                &self.client_type,
                self.mode,
                &self.env_urls,
                self.capabilities.clone(),
            )
        })
        .await
    }
    async fn reconnect_with<F, Fut>(
        &self,
        policy: ReconnectPolicy,
        cancel: &CancellationToken,
        mut connect_attempt: F,
    ) -> Result<
        (
            mpsc::UnboundedSender<String>,
            mpsc::UnboundedReceiver<String>,
            watch::Receiver<DisconnectReason>,
        ),
        ConnectionError,
    >
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<LeaderConnection, ConnectionError>>,
    {
        let mut attempt: u32 = 0;
        let mut delay = RECONNECT_BASE_DELAY;
        loop {
            if cancel.is_cancelled() {
                let _ = self.status_tx.send(ConnectionStatus::Failed {
                    error: "Cancelled".into(),
                });
                return Err(ConnectionError::Cancelled);
            }
            attempt += 1;
            let _ = self
                .status_tx
                .send(ConnectionStatus::Reconnecting { attempt });
            info!(
                attempt,
                delay_ms = delay.as_millis(),
                "Attempting to reconnect to leader"
            );
            match connect_attempt().await {
                Ok(conn) => {
                    info!(attempt, "Reconnected to leader");
                    return Ok(conn.into_channels_with_disconnect());
                }
                Err(e) if is_terminal_refusal(&e) => {
                    warn!(attempt, error = %e, "Reconnection refused (terminal)");
                    let _ = self.status_tx.send(ConnectionStatus::Failed {
                        error: e.to_string(),
                    });
                    return Err(e);
                }
                Err(e) => {
                    warn!(attempt, error = %e, "Reconnection attempt failed");
                    if let ReconnectPolicy::Bounded { max_attempts } = policy
                        && attempt >= max_attempts
                    {
                        let error_msg = format!("Failed after {} attempts: {}", max_attempts, e);
                        let _ = self.status_tx.send(ConnectionStatus::Failed {
                            error: error_msg.clone(),
                        });
                        return Err(ConnectionError::SpawnFailed(error_msg));
                    }
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = self.status_tx.send(ConnectionStatus::Failed {
                        error: "Cancelled".into(),
                    });
                    return Err(ConnectionError::Cancelled);
                }
                _ = tokio::time::sleep(delay) => {}
            }
            delay = std::cmp::min(delay * 2, RECONNECT_MAX_DELAY);
        }
    }
    /// Create a `watch` channel pair for connection status.
    ///
    /// Returns `(tx, rx)` initialized to the pre-reconnect `Connected { generation: 0 }` state.
    /// Pass `tx` to [`LeaderReconnector::new()`], keep `rx` for observing status.
    pub fn status_channel() -> (
        watch::Sender<ConnectionStatus>,
        watch::Receiver<ConnectionStatus>,
    ) {
        watch::channel(ConnectionStatus::Connected { generation: 0 })
    }
}
/// Poll until the eviction target is no longer alive or `timeout` elapses (liveness through the target's own handle on Windows).
async fn wait_for_exit(target: &act_on::ActTarget, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if !target.is_alive() {
            return;
        }
        tokio::time::sleep(SPAWN_POLL_INTERVAL).await;
    }
    debug!(
        pid = target.pid(),
        "Evicted leader still alive after grace; reclaiming socket anyway"
    );
}
/// Poll until `pid` is no longer alive or `timeout` elapses.
async fn wait_for_pid_exit(pid: u32, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if !crate::util::is_process_alive(pid) {
            return;
        }
        tokio::time::sleep(SPAWN_POLL_INTERVAL).await;
    }
    debug!(
        pid,
        "Evicted leader still alive after grace; reclaiming socket anyway"
    );
}
/// Whether the leader on `conn` is below this client's version floor (see [`should_evict`]).
#[cfg(test)]
fn should_evict_conn(conn: &LeaderConnection) -> bool {
    should_evict(
        conn.registration().leader_binary_version.as_deref(),
        CLIENT_LEADER_VERSION,
    )
}
/// Ask a stale leader to vacate so it releases the flock: graceful `RelaunchForUpdate` if relaunch-capable (the leader dedupes concurrent requests
/// and re-checks the directional guard, so this is idempotent and never downgrades), else SIGTERM its pid.
/// Best-effort and non-waiting; the caller retries the spawn loop, where the replacement is created under the flock.
async fn request_leader_vacate(conn: &LeaderConnection, target: Option<&act_on::ActTarget>) {
    let pid = target.map(act_on::ActTarget::pid);
    let leader_version = conn.registration().leader_binary_version.clone();
    let (method, outcome) = if conn.registration().supports_relaunch() {
        let outcome = match conn
            .send_control(ControlCommand::RelaunchForUpdate {
                to_version: CLIENT_LEADER_VERSION.to_string(),
            })
            .await
        {
            Ok(Ok(ControlPayload::Relaunching { .. })) => "accepted",
            Ok(Ok(ControlPayload::RelaunchDeclined { .. })) => "declined",
            Ok(Ok(_)) | Ok(Err(_)) => "send_failed",
            Err(e) => {
                debug!(error = %e, "Relaunch request to stale leader failed");
                "send_failed"
            }
        };
        ("relaunch", outcome)
    } else {
        let outcome = match target {
            Some(target) => match target.terminate() {
                Ok(()) => "signaled",
                Err(e) => {
                    warn!(error = %e, pid = target.pid(), "Failed to signal stale leader to exit");
                    "signal_failed"
                }
            },
            None => "signal_failed",
        };
        ("sigterm", outcome)
    };
    fuigo_telemetry::unified_log::warn(
        "leader.evict.vacate_requested",
        None,
        Some(serde_json::json!({
            "method": method,
            "outcome": outcome,
            "leader_pid": pid,
            "leader_version": leader_version,
            "client_version": CLIENT_LEADER_VERSION,
        })),
    );
}
/// Longest wait for the leader's own answer to `GetLeaderInfo` when its pid is wanted.
const LEADER_PID_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// The pid the leader REPORTS about itself over the pipe. Windows display and telemetry only: whoever serves the pipe wrote
/// it, so it is never passed to a signal or a kill (see [`leader_target_to_act_on`]).
async fn leader_pid_reported_over_pipe(conn: &LeaderConnection) -> Option<u32> {
    let answer = tokio::time::timeout(
        LEADER_PID_QUERY_TIMEOUT,
        conn.send_control(ControlCommand::GetLeaderInfo),
    )
    .await
    .ok()?;
    match answer {
        Ok(Ok(ControlPayload::LeaderInfo { pid, .. })) => Some(pid),
        _ => None,
    }
}
/// The pid of the live leader on `conn` TO SHOW (telemetry, logs). Windows: the leader's own claim over the pipe, `None` when it
/// gives none. Elsewhere: the pid in the lock file, exactly as before. Never use it to signal or kill.
async fn leader_pid_to_show(conn: &LeaderConnection, lock: &LeaderLock) -> Option<u32> {
    if cfg!(windows) {
        leader_pid_reported_over_pipe(conn).await
    } else {
        lock.read_pid()
    }
}
/// The leader process an eviction may signal or terminate, or `None` (then nothing is signalled; the caller behaves as when no
/// pid is known). Windows: the OS-reported owner of the server end of `conn`'s own pipe, kept only if its image is a Fuigo binary,
/// as an open handle that is also the handle the kill goes through. Elsewhere: the pid in the lock file, as before.
async fn leader_target_to_act_on(conn: &LeaderConnection, lock: &LeaderLock) -> Option<act_on::ActTarget> {
    #[cfg(windows)]
    {
        let _ = lock;
        // The pid recorded at connect is re-asked right before the process is opened; any failure or change means no action.
        let pid = act_on::pid_to_act_on(conn.os_server_pid(), conn.os_server_pid_now());
        match pid.and_then(act_on::ActTarget::from_os_server_pid) {
            Some(target) => Some(target),
            None => {
                warn!("Not signalling the pipe's leader: the OS server pid is unknown, gone, or not a Fuigo process");
                None
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = conn;
        lock.read_pid().map(act_on::ActTarget::from_lock_pid)
    }
}
/// What `fuigo leader kill` may do for one discovered leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderKillPlan {
    /// Windows: connect and act only on the OS-reported owner of that connection's pipe ([`kill_leader_by_connection`]).
    ViaPipeConnection,
    /// Elsewhere: terminate this pid (the verified live pid, else the lock-file pid), as before.
    ByPid(u32),
    /// Nothing is terminated: the process cannot be identified safely.
    CannotIdentify,
}
/// The kill decision. On Windows a pid from a pipe payload or a lock file is never terminated: only a leader that answered
/// over the pipe (`pipe_answers`) is acted on, through its own connection. Elsewhere the pid is used unchanged.
pub fn leader_kill_plan(windows: bool, pipe_answers: bool, pid: Option<u32>) -> LeaderKillPlan {
    match (windows, pipe_answers, pid) {
        (true, true, _) => LeaderKillPlan::ViaPipeConnection,
        (true, false, _) => LeaderKillPlan::CannotIdentify,
        (false, _, Some(pid)) => LeaderKillPlan::ByPid(pid),
        (false, _, None) => LeaderKillPlan::CannotIdentify,
    }
}
/// Result of [`kill_leader_by_connection`].
#[cfg(windows)]
#[derive(Debug)]
pub enum KillByConnection {
    Killed(u32),
    /// Nothing answered on the pipe.
    NotAnswering,
    /// The pipe's owner could not be established, is not a Fuigo program, or changed: nothing was terminated.
    Refused,
    Failed(String),
}
/// Windows: connect to the leader at `socket_path` and terminate the process the OS reports as serving that connection's
/// pipe, only if it is a Fuigo image (same handle for check and kill). No pid from a payload or a lock file is used.
#[cfg(windows)]
pub async fn kill_leader_by_connection(socket_path: &Path) -> KillByConnection {
    let connect = LeaderClient::connect(
        socket_path.to_path_buf(),
        "fuigo-pager-leader-cli",
        ClientMode::Stdio,
        ClientCapabilities::default(),
    );
    let client = match tokio::time::timeout(Duration::from_secs(10), connect).await {
        Ok(Ok(client)) => client,
        Ok(Err(ClientError::PeerRefused)) => return KillByConnection::Refused,
        Ok(Err(_)) | Err(_) => return KillByConnection::NotAnswering,
    };
    let pid = act_on::pid_to_act_on(client.os_server_pid(), client.os_server_pid_now());
    let Some(target) = pid.and_then(act_on::ActTarget::from_os_server_pid) else {
        return KillByConnection::Refused;
    };
    match target.terminate() {
        Ok(()) => KillByConnection::Killed(target.pid()),
        Err(e) => KillByConnection::Failed(e.to_string()),
    }
}
/// Evict a below-floor leader that holds the socket but NOT the flock (the caller
/// MUST hold the flock, so this teardown is serialized against other clients).
/// Signals it to vacate, waits for the pid to exit, then re-sends SIGTERM if it
/// overran the grace window, so the caller can reclaim the socket and respawn.
async fn evict_leader(conn: LeaderConnection, lock: &LeaderLock) {
    let target = leader_target_to_act_on(&conn, lock).await;
    let pid = target.as_ref().map(act_on::ActTarget::pid);
    let leader_version = conn.registration().leader_binary_version.clone();
    request_leader_vacate(&conn, target.as_ref()).await;
    drop(conn);
    let wait_start = std::time::Instant::now();
    let outcome = if let Some(target) = target.as_ref() {
        wait_for_exit(target, EVICT_WAIT_TIMEOUT).await;
        if !target.is_alive() {
            "exited"
        } else if let Err(e) = target.terminate() {
            warn!(error = %e, pid = target.pid(), "Failed to re-signal (SIGTERM) stale leader");
            "timed_out"
        } else {
            wait_for_exit(target, EVICT_WAIT_TIMEOUT).await;
            if target.is_alive() {
                "timed_out"
            } else {
                "resignaled_sigterm"
            }
        }
    } else {
        "exited"
    };
    fuigo_telemetry::unified_log::warn(
        "leader.evict.completed",
        None,
        Some(serde_json::json!({
            "outcome": outcome,
            "leader_pid": pid,
            "leader_version": leader_version,
            "client_version": CLIENT_LEADER_VERSION,
            "waited_ms": wait_start.elapsed().as_millis() as u64,
        })),
    );
}
/// PID-keyed timer state: the holder PID being timed and when we first saw it live-but-unconnectable.
type ZombieTimer = Option<(u32, Instant)>;
/// Decision produced by [`zombie_evict_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZombieAction {
    /// Not a zombie candidate this round; timer cleared.
    Clear,
    /// A live fuigo holder is still unconnectable; timer (re)armed, keep waiting.
    Wait,
    /// The SAME holder PID has been unconnectable for the full deadline, so evict it.
    Evict { pid: u32, waited: Duration },
}
/// Pure decision for the zombie-eviction net. The timer is keyed to the PID so a
/// timer accrued against an old zombie can never evict a freshly-spawned leader.
fn zombie_evict_decision(
    holder: Option<u32>,
    now: Instant,
    deadline: Duration,
    timer: &mut ZombieTimer,
) -> ZombieAction {
    let Some(pid) = holder else {
        *timer = None;
        return ZombieAction::Clear;
    };
    match *timer {
        Some((tracked_pid, since)) if tracked_pid == pid => {
            let waited = now.saturating_duration_since(since);
            if waited >= deadline {
                *timer = None;
                ZombieAction::Evict { pid, waited }
            } else {
                ZombieAction::Wait
            }
        }
        _ => {
            *timer = Some((pid, now));
            ZombieAction::Wait
        }
    }
}
/// The live *fuigo* PID that ACTUALLY holds the flock on the lock file, if any.
/// `None` for a dead / non-fuigo PID, OR when the file PID can't be confirmed to be the real flock holder,
/// so the auto-kill zombie net never SIGKILLs a process that does not hold the flock (a stale-but-live PID left in `leader.lock`,
/// or a brief spawner that held the flock without rewriting the file).
/// Uses the stricter (name-matching) fuigo check since this drives the auto-kill path.
///
/// Linux confirms the holder via `/proc/locks`.
/// macOS/BSD have no `/proc/locks`, so the holder is unconfirmable and this returns `None` (eviction skipped),
/// accepting that a genuine zombie there is not auto-killed.
fn live_fuigo_lock_holder(lock: &LeaderLock) -> Option<u32> {
    let file_pid = lock.read_pid()?;
    let pid = evictable_holder(file_pid, confirmed_flock_holder(lock.lock_path()))?;
    (crate::util::is_process_alive(pid) && crate::util::is_fuigo_process_strict(pid)).then_some(pid)
}
/// Safety gate: a file PID is evictable only when the confirmed flock `holder` is
/// known AND equals it. An unknown holder, or a file PID that differs from the real
/// holder, is NOT evictable. Pure so the "do not evict" invariant is unit-testable.
fn evictable_holder(file_pid: u32, holder: Option<u32>) -> Option<u32> {
    match holder {
        Some(h) if h == file_pid => Some(file_pid),
        _ => None,
    }
}
/// PID that actually holds the exclusive flock on the lock file, or `None` when it can't be determined.
/// Linux reads `/proc/locks`; other platforms lack that interface,
/// so the holder is unknowable there and we return `None` (callers must not auto-kill a PID they can't confirm holds the flock).
fn confirmed_flock_holder(lock_path: &Path) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        flock_holder_pid(lock_path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = lock_path;
        None
    }
}
/// The flock-holder PID for `lock_path` per `/proc/locks`: stat the path for its
/// device:inode, then find the matching `FLOCK`/`WRITE` (fs2's exclusive lock)
/// entry. Linux-only.
#[cfg(target_os = "linux")]
fn flock_holder_pid(lock_path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(lock_path).ok()?;
    let proc_locks = std::fs::read_to_string("/proc/locks").ok()?;
    let (major, minor) = glibc_dev_major_minor(meta.dev());
    parse_flock_holder(&proc_locks, major, minor, meta.ino())
}
/// Decode a glibc 64-bit `dev_t` into (major, minor), the same bit layout glibc's `gnu_dev_major`/`gnu_dev_minor` use,
/// matching the numbers the kernel prints in `/proc/locks`.
/// (libc 0.2 dropped `major`/`minor` for the gnu target.)
/// Pure, so it and the parser below compile and test on all hosts even though only Linux consumes them.
#[cfg(any(target_os = "linux", test))]
fn glibc_dev_major_minor(dev: u64) -> (u64, u64) {
    let major = ((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32);
    let minor = (dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0fff_fff0_0000) >> 12);
    (major, minor)
}
/// Parse `/proc/locks` for the PID holding an exclusive `flock` on the file identified by `major:minor:inode`.
/// Skips blocked waiters (lines whose second field is `->`, which does not hold the lock and shifts the field layout).
/// Returns `None` if no matching `FLOCK`/`WRITE` holder is present.
/// Pure (parses a string) so it is unit-testable without real kernel locks.
#[cfg(any(target_os = "linux", test))]
fn parse_flock_holder(proc_locks: &str, major: u64, minor: u64, inode: u64) -> Option<u32> {
    for line in proc_locks.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.get(1) == Some(&"->") {
            continue;
        }
        if f.len() < 6 || f[1] != "FLOCK" || f[3] != "WRITE" {
            continue;
        }
        let mut dev_inode = f[5].split(':');
        let (Some(maj), Some(min), Some(ino)) =
            (dev_inode.next(), dev_inode.next(), dev_inode.next())
        else {
            continue;
        };
        let (Ok(maj), Ok(min), Ok(ino)) = (
            u64::from_str_radix(maj, 16),
            u64::from_str_radix(min, 16),
            ino.parse::<u64>(),
        ) else {
            continue;
        };
        if maj == major && min == minor && ino == inode {
            return f[4].parse::<u32>().ok();
        }
    }
    None
}
/// Max zombie-eviction attempts against the SAME PID before `connect_or_spawn`
/// surfaces an error instead of looping forever.
const MAX_ZOMBIE_EVICT_ATTEMPTS: u32 = 3;
/// Max times `connect_or_spawn` will self-spawn a leader that fails to become connectable before surfacing an error.
/// Bounds a persistent spawn/bind failure (bad socket-dir perms, exec fault in `run_leader`) that would otherwise
/// re-fork every `SPAWN_WAIT_TIMEOUT` forever; still allows the intended single-retry after a transient same-version sibling race.
const MAX_SELF_SPAWN_ATTEMPTS: u32 = 3;
/// Records an eviction attempt against `pid`; returns `false` once the per-PID budget is exhausted.
/// Attempts reset when the target PID changes.
fn register_evict_attempt(state: &mut Option<(u32, u32)>, pid: u32, max_attempts: u32) -> bool {
    let count = match *state {
        Some((tracked, n)) if tracked == pid => n + 1,
        _ => 1,
    };
    *state = Some((pid, count));
    count <= max_attempts
}
/// A connect-level failure: never became connectable (`Timeout`) or the socket
/// file exists but refuses connections (`Connect`, e.g. ECONNREFUSED against a
/// stale socket / dead IPC task). Both drive the zombie net. Registration- and
/// protocol-level errors mean the socket ANSWERED and must surface instead.
fn is_connect_level_failure(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::Timeout | ConnectionError::Client(ClientError::Connect(_, _))
    )
}
/// Policy refusals that can never succeed on reconnect retry (not zombie-evictable).
fn is_terminal_refusal(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::SandboxConfinement(_) | ConnectionError::Client(ClientError::PeerRefused)
    )
}
/// Evict a suspected zombie leader (holds the flock but is not connectable).
/// SIGTERM, wait, then escalate to SIGKILL if it overran the grace window.
async fn evict_zombie_leader(pid: u32, sock_path: &Path, waited: Duration) {
    use crate::util::KillSignal;
    warn!(
        pid,
        socket = %sock_path.display(),
        "Suspected zombie leader (holds lock, not connectable past deadline); evicting"
    );
    if let Err(e) = crate::util::kill_process_with_signal(pid, KillSignal::Term) {
        warn!(error = %e, pid, "Failed to SIGTERM suspected zombie leader");
    }
    wait_for_pid_exit(pid, EVICT_WAIT_TIMEOUT).await;
    let outcome = if !crate::util::is_process_alive(pid) {
        "exited"
    } else if let Err(e) = crate::util::kill_process_with_signal(pid, KillSignal::Kill) {
        warn!(error = %e, pid, "Failed to SIGKILL suspected zombie leader");
        "sigkill_failed"
    } else {
        wait_for_pid_exit(pid, EVICT_WAIT_TIMEOUT).await;
        if crate::util::is_process_alive(pid) {
            "survived_sigkill"
        } else {
            "sigkilled"
        }
    };
    fuigo_telemetry::unified_log::warn(
        "leader.zombie.evicted",
        None,
        Some(serde_json::json!({
            "zombie_pid": pid,
            "socket_path": sock_path.display().to_string(),
            "outcome": outcome,
            "client_version": CLIENT_LEADER_VERSION,
            "waited_ms": waited.as_millis() as u64,
        })),
    );
}
/// Connect to existing leader or spawn a new one.
///
/// Uses OS-level file locking (flock) to coordinate:
/// 1. Try to connect to existing socket (fast path)
/// 2. If connection fails, try to acquire exclusive lock
/// 3. If lock acquired, we are responsible for spawning the leader
/// 4. If lock not acquired, another process is leader/spawning; wait and retry
///
/// The `env_urls.fuigo_ws_url` determines which leader instance to connect to.
/// Different WS URLs get different leader processes (via hashed socket paths).
///
/// # Arguments
///
/// * `client_type`: Identifier for the client type (e.g., "fuigo-tui", "vscode")
/// * `mode`: Communication mode (Stdio or Headless)
/// * `env_urls`: Environment URLs for the leader subprocess
/// * `capabilities`: Client capabilities (e.g., yolo_mode) to register with the leader
pub async fn connect_or_spawn(
    client_type: &str,
    mode: ClientMode,
    env_urls: &LeaderEnvUrls,
    capabilities: ClientCapabilities,
) -> Result<LeaderConnection, ConnectionError> {
    connect_or_spawn_with_vacate_budget(
        client_type,
        mode,
        env_urls,
        capabilities,
        VACATE_WAIT_TIMEOUT,
    )
    .await
}
/// [`connect_or_spawn`] with the vacate budget injected, so a test can reach the bound without waiting out the real one.
async fn connect_or_spawn_with_vacate_budget(
    client_type: &str,
    mode: ClientMode,
    env_urls: &LeaderEnvUrls,
    capabilities: ClientCapabilities,
    vacate_budget: Duration,
) -> Result<LeaderConnection, ConnectionError> {
    if let Some(profile) = fuigo_sandbox::requested_confinement_profile() {
        return Err(ConnectionError::SandboxConfinement(profile));
    }
    let start = std::time::Instant::now();
    let mut lock = LeaderLock::new(&env_urls.fuigo_ws_url);
    let sock_path = lock.socket_path().clone();
    let mut replacing_stale = false;
    if crate::leader::transport::listener_is_ready(&sock_path) {
        let skip_connect = if let Some(pid) = lock.read_pid() {
            if crate::util::is_process_alive(pid) {
                debug!(pid, "Leader PID is alive, attempting connection");
                false
            } else {
                debug!(pid, "Leader PID is dead, skipping socket connect");
                true
            }
        } else {
            debug!("Socket exists but no PID in lock, attempting connection");
            false
        };
        if !skip_connect {
            match connect_to_leader(&sock_path, client_type, mode, capabilities.clone()).await {
                Ok(conn) => {
                    if !evict_leader_conn(&conn) {
                        note_adopted_leader(&conn);
                        info!(
                            elapsed_ms = start.elapsed().as_millis() as u64,
                            "Adopted leader"
                        );
                        return Ok(conn);
                    }
                    drop(conn);
                    replacing_stale = true;
                }
                Err(e) => {
                    debug!(error = %e, "Connection to existing socket failed");
                }
            }
        }
    }
    let mut zombie_timer: ZombieTimer = None;
    let mut evict_attempts: Option<(u32, u32)> = None;
    let mut self_spawn_attempts: u32 = 0;
    let mut vacate_since: Option<std::time::Instant> = None;
    loop {
        match lock.try_acquire() {
            Ok(true) => {
                // Windows: the lock file cannot be read while a live process holds it, and a dead leader leaves no pipe, so an
                // answering pipe is the proof of life. Elsewhere the pid in the file is checked first, as before.
                if crate::leader::transport::listener_is_ready(&sock_path)
                    && (cfg!(windows) || lock.read_pid().is_some_and(crate::util::is_process_alive))
                    && let Ok(conn) =
                        connect_to_leader(&sock_path, client_type, mode, capabilities.clone()).await
                {
                    if !evict_leader_conn(&conn) {
                        note_adopted_leader(&conn);
                        let leader_pid = leader_pid_to_show(&conn, &lock).await;
                        if let Err(e) = lock.release() {
                            warn!(error = %e, "Failed to release lock after adopting leader");
                        }
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        info!(
                            elapsed_ms,
                            "Adopted sibling-spawned leader after eviction race"
                        );
                        fuigo_telemetry::unified_log::info(
                            "leader.spawn.sibling_adopted",
                            None,
                            Some(serde_json::json!({
                                "leader_pid": leader_pid,
                                "leader_version": conn
                                    .registration()
                                    .leader_binary_version
                                    .as_deref(),
                                "client_version": CLIENT_LEADER_VERSION,
                                "elapsed_ms": elapsed_ms,
                            })),
                        );
                        return Ok(conn);
                    }
                    evict_leader(conn, &lock).await;
                    replacing_stale = true;
                }
                info!("Acquired lock, spawning leader subprocess");
                if let Err(e) = lock.release() {
                    warn!(error = %e, "Failed to release lock before spawning leader");
                }
                spawn_leader_subprocess(env_urls)?;
                let conn = match wait_for_socket_connectable(
                    &sock_path,
                    client_type,
                    mode,
                    capabilities.clone(),
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(ConnectionError::Timeout) => {
                        self_spawn_attempts += 1;
                        if self_spawn_attempts >= MAX_SELF_SPAWN_ATTEMPTS {
                            return Err(ConnectionError::SpawnFailed(format!(
                                "spawned leader did not become connectable after \
                                 {MAX_SELF_SPAWN_ATTEMPTS} attempts"
                            )));
                        }
                        debug!(
                            attempt = self_spawn_attempts,
                            "Spawned leader not connectable yet, retrying"
                        );
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                note_spawned_leader(&conn);
                let elapsed_ms = start.elapsed().as_millis() as u64;
                info!(elapsed_ms, "Spawned and connected to leader");
                if replacing_stale {
                    fuigo_telemetry::unified_log::info(
                        "leader.spawn.replacement",
                        None,
                        Some(serde_json::json!({
                            "reason": "version_floor",
                            "client_version": CLIENT_LEADER_VERSION,
                            "elapsed_ms": elapsed_ms,
                        })),
                    );
                }
                return Ok(conn);
            }
            Ok(false) => {
                debug!("Lock held by another process, probing socket connectability");
            }
            Err(e) => {
                return Err(e.into());
            }
        }
        match wait_for_socket_connectable(&sock_path, client_type, mode, capabilities.clone()).await
        {
            Ok(conn) => {
                zombie_timer = None;
                if !evict_leader_conn(&conn) {
                    note_adopted_leader(&conn);
                    info!(
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "Adopted leader"
                    );
                    return Ok(conn);
                }
                let since = *vacate_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() >= vacate_budget {
                    // Nothing asked of the old leader made it let go of the lock (it does not advertise `relaunch_v1`
                    // and no signal reached it, or it ignores the signal): stop asking instead of looping forever.
                    return Err(ConnectionError::SpawnFailed(format!(
                        "could not replace the old Fuigo leader (version {}) that holds the lock: it did not exit \
                         within {} seconds. Close the other Fuigo windows and try again.",
                        fuigo_tty_utils::untrusted(
                            conn.registration()
                                .leader_binary_version
                                .as_deref()
                                .unwrap_or("unknown")
                        ),
                        vacate_budget.as_secs()
                    )));
                }
                let leader_target = leader_target_to_act_on(&conn, &lock).await;
                request_leader_vacate(&conn, leader_target.as_ref()).await;
                drop(conn);
                replacing_stale = true;
                tokio::time::sleep(SPAWN_POLL_INTERVAL).await;
                continue;
            }
            Err(e) if is_connect_level_failure(&e) => {
                let holder = live_fuigo_lock_holder(&lock);
                match zombie_evict_decision(
                    holder,
                    Instant::now(),
                    ZOMBIE_EVICT_DEADLINE,
                    &mut zombie_timer,
                ) {
                    ZombieAction::Evict { pid, waited } => {
                        if !register_evict_attempt(
                            &mut evict_attempts,
                            pid,
                            MAX_ZOMBIE_EVICT_ATTEMPTS,
                        ) {
                            return Err(ConnectionError::SpawnFailed(format!(
                                "zombie leader pid {pid} could not be evicted after \
                                 {MAX_ZOMBIE_EVICT_ATTEMPTS} attempts"
                            )));
                        }
                        evict_zombie_leader(pid, &sock_path, waited).await;
                        continue;
                    }
                    ZombieAction::Wait => {
                        debug!("Flock-holder not connectable yet, waiting");
                        continue;
                    }
                    ZombieAction::Clear => {
                        debug!("Timeout waiting for socket, retrying lock acquisition");
                        continue;
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}
/// Resolve the binary to spawn as the leader subprocess.
///
/// For a **managed install** — the running binary lives under `fuigo_home`
/// (e.g. `~/.fuigo/...`) — prefer the managed `~/.fuigo/bin/fuigo` symlink. After an
/// auto-update or `fuigo update` atomically swaps that symlink, `current_exe()` still resolves (via `/proc/self/exe` on Linux) to the *old* versioned
/// target, so spawning it would relaunch the stale binary.
/// The symlink always points to the freshly-installed version.
/// This mirrors `fuigo_update::auto_update::resolve_restart_exe`.
///
/// For a **dev / out-of-tree binary** (`cargo run`, integration tests, installs not under `fuigo_home`),
/// keep `current_exe()` so the spawned leader matches the calling binary.
///
/// Falls back to `~/.fuigo/bin/fuigo` only when `current_exe()` is unavailable.
fn resolve_exe_for_spawn() -> Result<std::path::PathBuf, ConnectionError> {
    resolve_binary_with_home(&crate::util::fuigo_home::fuigo_home())
}
fn resolve_binary_with_home(fuigo_home: &Path) -> Result<std::path::PathBuf, ConnectionError> {
    resolve_binary_impl(fuigo_home, std::env::current_exe().ok())
}
/// Binary file name for the managed fuigo install (`fuigo` / `fuigo.exe`).
fn managed_fuigo_bin_name() -> &'static str {
    if cfg!(windows) { "fuigo.exe" } else { "fuigo" }
}
/// Core leader-binary resolution with the current-exe path injected, for testability.
fn resolve_binary_impl(
    fuigo_home: &Path,
    current_exe: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, ConnectionError> {
    let managed_bin = fuigo_home.join("bin").join(managed_fuigo_bin_name());
    if let Some(ref exe) = current_exe
        && path_is_under(exe, fuigo_home)
        && managed_bin.exists()
    {
        return Ok(managed_bin);
    }
    if let Some(exe) = current_exe {
        return Ok(exe);
    }
    if managed_bin.exists() {
        return Ok(managed_bin);
    }
    Err(ConnectionError::SpawnFailed(
        "could not determine binary path for leader spawn".into(),
    ))
}
/// Whether `path` is located within `dir`, canonicalizing both where possible so symlinked / relative paths compare correctly.
fn path_is_under(path: &Path, dir: &Path) -> bool {
    let path = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    path.starts_with(&dir)
}
/// Win32 creation flags for the leader daemon, which outlives the client that
/// spawns it.
///
/// - `CREATE_NO_WINDOW`: the leader does not attach to the spawning client's
///   console; it gets its own console with no window. Without it the leader
///   shares the client's console and is terminated along with every other
///   process on it when that console closes (the terminal window is closed, or
///   its console host exits). Matches every other Windows spawn
///   (`fuigo_tty_utils::detach_command`). It does not shield the leader from
///   an explicit process-tree kill of the client (`taskkill /PID <client> /T
///   /F`), which follows parent/child links, not consoles.
/// - `CREATE_NEW_PROCESS_GROUP`: a Ctrl+C / Ctrl+Break in the client's group
///   does not reach the leader.
/// - Never `DETACHED_PROCESS`: it breaks stdio inheritance for grandchildren.
#[cfg(any(windows, test))]
fn leader_creation_flags() -> u32 {
    use fuigo_tty_utils::win32_creation_flags::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
    CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
}
/// Create the leader process from `cmd` (program, arguments, environment and
/// stdio already set), detached from the client: its own process group on
/// Unix, [`leader_creation_flags`] on Windows.
///
/// The one place the leader process is created, so the `leader_spawn_*` tests
/// that spawn through it pin what the real spawn does.
fn spawn_leader_process(mut cmd: Command) -> std::io::Result<std::process::Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(leader_creation_flags());
    }
    // The leader is a daemon that deliberately outlives the client; the caller
    // reaps it on a waiter thread.
    #[allow(clippy::disallowed_methods)]
    cmd.spawn()
}
fn spawn_leader_subprocess(env_urls: &LeaderEnvUrls) -> Result<u32, ConnectionError> {
    let exe = resolve_exe_for_spawn()?;
    let mut cmd = Command::new(exe);
    cmd.arg("agent").arg("leader");
    cmd.arg("--no-exit-on-disconnect");
    cmd.arg(RELAY_ON_DEMAND_FLAG);
    cmd.arg("--fuigo-ws-url").arg(&env_urls.fuigo_ws_url);
    cmd.arg("--fuigo-ws-origin").arg(&env_urls.fuigo_ws_origin);
    if let Some(socket) = std::env::var_os(crate::leader::LEADER_SOCKET_ENV) {
        cmd.env(crate::leader::LEADER_SOCKET_ENV, socket);
    }
    for key in [
        "FUIGO_DEBUG_LOG",
        "FUIGO_HOOKS_LOG",
        "FUIGO_LOG_SAMPLING",
        "FUIGO_INSTRUMENTATION",
    ] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    let log_path = crate::util::fuigo_home::fuigo_home().join("leader.log");
    match std::fs::File::create(&log_path) {
        Ok(log_file) => {
            info!("Leader stderr → log file");
            cmd.stderr(std::process::Stdio::from(log_file));
        }
        Err(e) => {
            warn!(error = %e, "Failed to create leader log file, using /dev/null");
            cmd.stderr(std::process::Stdio::null());
        }
    }
    let leader_log = std::env::var("FUIGO_LEADER_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "fuigo_shell=info,fuigo_acp_lib=warn,fuigo_mcp=warn".into());
    cmd.env("RUST_LOG", leader_log);
    let mut child =
        spawn_leader_process(cmd).map_err(|e| ConnectionError::SpawnFailed(e.to_string()))?;
    let pid = child.id();
    info!(pid, "Spawned leader subprocess");
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}
async fn connect_to_leader(
    sock_path: &Path,
    client_type: &str,
    mode: ClientMode,
    capabilities: ClientCapabilities,
) -> Result<LeaderConnection, ConnectionError> {
    let client =
        LeaderClient::connect(sock_path.to_path_buf(), client_type, mode, capabilities).await?;
    Ok(LeaderConnection { client })
}
/// Wait for socket to appear and successfully connect.
///
/// Polls the socket path until it becomes connectable or timeout is reached.
/// Uses exponential backoff starting from SPAWN_POLL_INTERVAL.
pub(crate) async fn wait_for_socket_connectable(
    sock_path: &Path,
    client_type: &str,
    mode: ClientMode,
    capabilities: ClientCapabilities,
) -> Result<LeaderConnection, ConnectionError> {
    let deadline = tokio::time::Instant::now() + SPAWN_WAIT_TIMEOUT;
    let mut last_error = None;
    while tokio::time::Instant::now() < deadline {
        if crate::leader::transport::listener_is_ready(sock_path) {
            match connect_to_leader(sock_path, client_type, mode, capabilities.clone()).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    debug!(error = %e, "Connection attempt failed, retrying");
                    last_error = Some(e);
                }
            }
        }
        tokio::time::sleep(SPAWN_POLL_INTERVAL).await;
    }
    match last_error {
        Some(e) => Err(e),
        None => Err(ConnectionError::Timeout),
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn g_leader_kill_never_terminates_a_pid_from_a_payload_or_lock_file_on_windows() {
        // Windows: only a leader that answered on the pipe is acted on, through its own connection.
        assert_eq!(leader_kill_plan(true, true, Some(4242)), LeaderKillPlan::ViaPipeConnection);
        assert_eq!(leader_kill_plan(true, false, Some(4242)), LeaderKillPlan::CannotIdentify);
        assert_eq!(leader_kill_plan(true, false, None), LeaderKillPlan::CannotIdentify);
        // Elsewhere: unchanged.
        assert_eq!(leader_kill_plan(false, true, Some(4242)), LeaderKillPlan::ByPid(4242));
        assert_eq!(leader_kill_plan(false, false, Some(4242)), LeaderKillPlan::ByPid(4242));
        assert_eq!(leader_kill_plan(false, false, None), LeaderKillPlan::CannotIdentify);
    }
    use super::*;
    use crate::leader::test_support::{
        FakeLeaderBehavior, FakeVersions, fake_caps, spawn_fake_leader,
    };
    use std::fs;
    use tempfile::TempDir;
    const TEST_DEADLINE: Duration = Duration::from_secs(30);
    /// No live fuigo holder yields `Clear`, and any pending timer is reset.
    #[test]
    fn zombie_decision_clears_when_no_holder() {
        let mut timer: ZombieTimer = Some((100, Instant::now()));
        assert_eq!(
            zombie_evict_decision(None, Instant::now(), TEST_DEADLINE, &mut timer),
            ZombieAction::Clear
        );
        assert_eq!(timer, None, "timer must be cleared when there is no holder");
    }
    /// First sighting of a holder arms the timer and waits (never evicts).
    #[test]
    fn zombie_decision_arms_timer_on_first_sighting() {
        let mut timer: ZombieTimer = None;
        let t0 = Instant::now();
        assert_eq!(
            zombie_evict_decision(Some(100), t0, TEST_DEADLINE, &mut timer),
            ZombieAction::Wait
        );
        assert_eq!(timer, Some((100, t0)));
    }
    /// The SAME holder is evicted only after staying unconnectable for the deadline.
    #[test]
    fn zombie_decision_evicts_same_pid_after_deadline() {
        let mut timer: ZombieTimer = None;
        let t0 = Instant::now();
        assert_eq!(
            zombie_evict_decision(Some(100), t0, TEST_DEADLINE, &mut timer),
            ZombieAction::Wait
        );
        let t_mid = t0 + Duration::from_secs(29);
        assert_eq!(
            zombie_evict_decision(Some(100), t_mid, TEST_DEADLINE, &mut timer),
            ZombieAction::Wait
        );
        let t_end = t0 + Duration::from_secs(30);
        assert_eq!(
            zombie_evict_decision(Some(100), t_end, TEST_DEADLINE, &mut timer),
            ZombieAction::Evict {
                pid: 100,
                waited: Duration::from_secs(30),
            }
        );
        assert_eq!(timer, None);
    }
    /// A holder PID change re-keys the timer, so time accrued against an old zombie can never evict a fresh leader.
    #[test]
    fn zombie_decision_resets_timer_when_pid_changes() {
        let mut timer: ZombieTimer = None;
        let t0 = Instant::now();
        assert_eq!(
            zombie_evict_decision(Some(100), t0, TEST_DEADLINE, &mut timer),
            ZombieAction::Wait
        );
        let t1 = t0 + Duration::from_secs(40);
        assert_eq!(
            zombie_evict_decision(Some(200), t1, TEST_DEADLINE, &mut timer),
            ZombieAction::Wait
        );
        assert_eq!(timer, Some((200, t1)), "timer must re-key to the new PID");
        let t2 = t1 + Duration::from_secs(1);
        assert_eq!(
            zombie_evict_decision(None, t2, TEST_DEADLINE, &mut timer),
            ZombieAction::Clear
        );
        assert_eq!(timer, None);
    }
    /// Eviction safety gate: a file PID is evictable only when the confirmed flock
    /// holder is known AND equals it. An unknown holder or a mismatch is not evicted.
    #[test]
    fn evictable_holder_requires_confirmed_matching_holder() {
        assert_eq!(evictable_holder(100, Some(100)), Some(100));
        assert_eq!(evictable_holder(100, Some(200)), None);
        assert_eq!(evictable_holder(100, None), None);
    }
    /// glibc `dev_t` decode matches the logical major:minor the kernel prints.
    /// makedev(253, 1) is 0xfd01, which decodes back to (253, 1).
    #[test]
    fn glibc_dev_major_minor_decodes_makedev() {
        assert_eq!(glibc_dev_major_minor(0xfd01), (253, 1));
        assert_eq!(glibc_dev_major_minor(0), (0, 0));
    }
    /// `/proc/locks` parsing: match an exclusive FLOCK holder by device:inode and
    /// return its PID; skip waiters, POSIX locks, and non-matching dev/inode.
    #[test]
    fn parse_flock_holder_matches_dev_inode_and_pid() {
        let sample = "\
1: POSIX  ADVISORY  WRITE 111 fd:01:2000 0 EOF
2: FLOCK  ADVISORY  WRITE 592 fd:01:1000 0 EOF
3: FLOCK  ADVISORY  WRITE 700 fd:01:3000 0 EOF
";
        assert_eq!(parse_flock_holder(sample, 253, 1, 1000), Some(592));
        assert_eq!(parse_flock_holder(sample, 253, 1, 9999), None);
        assert_eq!(parse_flock_holder(sample, 8, 1, 1000), None);
    }
    /// Blocked waiters (`->`) do not hold the lock and shift the field layout, so they must be skipped even when their dev:inode matches.
    #[test]
    fn parse_flock_holder_skips_waiters() {
        let sample = "\
1: FLOCK  ADVISORY  WRITE 592 fd:01:1000 0 EOF
1: -> FLOCK ADVISORY WRITE 800 fd:01:1000 0 EOF
";
        assert_eq!(parse_flock_holder(sample, 253, 1, 1000), Some(592));
    }
    /// A stale-but-live PID in the lock file, one that differs from the real flock holder,
    /// is classified "do not evict" end-to-end through the parse and gate helpers.
    #[test]
    fn stale_file_pid_not_matching_holder_is_not_evictable() {
        let sample = "1: FLOCK  ADVISORY  WRITE 592 fd:01:1000 0 EOF\n";
        let holder = parse_flock_holder(sample, 253, 1, 1000);
        assert_eq!(holder, Some(592));
        assert_eq!(evictable_holder(12345, holder), None);
    }
    /// Connect-level failures (timeout / connection-refused) drive the zombie net; registration/protocol errors (socket answered) surface instead.
    #[test]
    fn connect_level_failure_classification() {
        use std::io::{Error, ErrorKind};
        assert!(is_connect_level_failure(&ConnectionError::Timeout));
        assert!(is_connect_level_failure(&ConnectionError::Client(
            ClientError::Connect(3, Error::from(ErrorKind::ConnectionRefused))
        )));
        assert!(!is_connect_level_failure(&ConnectionError::Client(
            ClientError::Registration("rejected".into())
        )));
        assert!(!is_connect_level_failure(&ConnectionError::Client(
            ClientError::ConnectionClosed
        )));
        assert!(!is_connect_level_failure(
            &ConnectionError::SandboxConfinement("strict")
        ));
    }
    #[test]
    fn terminal_refusal_classification() {
        assert!(is_terminal_refusal(&ConnectionError::SandboxConfinement(
            "strict"
        )));
        assert!(!is_terminal_refusal(&ConnectionError::Timeout));
        assert!(!is_terminal_refusal(&ConnectionError::SpawnFailed(
            "boom".into()
        )));
        assert!(!is_terminal_refusal(&ConnectionError::Cancelled));
    }
    /// Per-PID eviction budget: allows `max` attempts, then denies; a PID change resets the counter so a fresh zombie gets its own budget.
    #[test]
    fn register_evict_attempt_bounds_per_pid() {
        let mut state: Option<(u32, u32)> = None;
        assert!(register_evict_attempt(&mut state, 100, 3));
        assert!(register_evict_attempt(&mut state, 100, 3));
        assert!(register_evict_attempt(&mut state, 100, 3));
        assert!(!register_evict_attempt(&mut state, 100, 3));
        assert!(register_evict_attempt(&mut state, 200, 3));
        assert_eq!(state, Some((200, 1)));
    }
    /// `live_fuigo_lock_holder` returns `None` for a missing or dead PID, so the zombie net never times/kills a recycled or unrelated PID.
    #[test]
    fn live_fuigo_lock_holder_none_for_missing_or_dead_pid() {
        let temp = TempDir::new().unwrap();
        let lock = LeaderLock::from_paths(
            temp.path().join("leader.lock"),
            temp.path().join("leader.sock"),
        );
        assert_eq!(live_fuigo_lock_holder(&lock), None);
        fs::write(lock.lock_path(), "4000000000").unwrap();
        assert_eq!(live_fuigo_lock_holder(&lock), None);
    }
    #[test]
    fn reachable_leader_pids_skips_stale_locks() {
        let reachable = LeaderDescriptor {
            pid_from_lock: Some(111),
            lock_path: None,
            socket_path: None,
            ws_url_suffix: String::new(),
            classification: LeaderDiscoveryState::Reachable,
            environment: None,
            live_info: Some(LiveLeaderInfo {
                pid: 222,
                socket_path: PathBuf::new(),
                lock_path: PathBuf::new(),
                ws_url_suffix: String::new(),
                leader_protocol_version: 0,
                leader_binary_version: "0.2.52".to_string(),
            }),
            target_error: None,
        };
        let stale = LeaderDescriptor {
            pid_from_lock: Some(333),
            lock_path: None,
            socket_path: None,
            ws_url_suffix: String::new(),
            classification: LeaderDiscoveryState::Stale,
            environment: None,
            live_info: None,
            target_error: None,
        };
        assert_eq!(
            reachable_leader_pids(&[reachable, stale]),
            vec![(222, "0.2.52".to_string())]
        );
    }
    /// Killed on drop so children don't outlive a failed assertion.
    #[cfg(unix)]
    struct SpawnedChild(std::process::Child);
    #[cfg(unix)]
    impl Drop for SpawnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[cfg(unix)]
    #[test]
    fn policy_reclaim_requires_client_spawn_marker() {
        let spawn = |args: &[&str]| {
            let mut cmd = std::process::Command::new("sh");
            cmd.args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            fuigo_tty_utils::detach_std_command(&mut cmd);
            SpawnedChild(cmd.spawn().expect("spawn test child"))
        };
        let marked = spawn(&["-c", "sleep 30; true", "sh", RELAY_ON_DEMAND_FLAG]);
        let unmarked = spawn(&["-c", "sleep 30; true", "sh"]);
        assert!(is_policy_reclaimable_leader(marked.0.id()));
        assert!(!is_policy_reclaimable_leader(unmarked.0.id()));
        let mut vanished = spawn(&["-c", "true", "sh"]);
        let _ = vanished.0.kill();
        let _ = vanished.0.wait();
        assert!(!is_policy_reclaimable_leader(vanished.0.id()));
    }
    #[test]
    fn leader_is_older_than_directional() {
        assert!(leader_is_older_than("0.1.0", "0.2.0"));
        assert!(leader_is_older_than("0.1.219", "0.1.220"));
        assert!(leader_is_older_than("0.1.220-alpha.1", "0.1.220"));
        assert!(leader_is_older_than("0.1.9", "0.1.10"));
        assert!(!leader_is_older_than("0.1.10", "0.1.9"));
        assert!(!leader_is_older_than("0.2.0", "0.1.0"));
        assert!(!leader_is_older_than("0.2.0", "0.2.0"));
        assert!(!leader_is_older_than("unknown", "0.2.0"));
        assert!(!leader_is_older_than("0.1.0", "not-a-version"));
    }
    /// Evicted only when strictly older than the client (anti-thrash).
    #[test]
    fn should_evict_only_strictly_older_leaders() {
        let client = "0.1.220";
        assert!(!should_evict(None, client));
        assert!(should_evict(Some("0.1.219"), client));
        assert!(should_evict(Some("0.1.9"), "0.1.10"));
        assert!(!should_evict(Some("0.1.220"), client));
        assert!(!should_evict(Some("0.1.221"), client));
        assert!(!should_evict(Some("0.1.219"), "0.1.218"));
        assert!(should_evict(Some("0.1.218"), "0.1.219"));
        assert!(!should_evict(Some("unknown"), client));
    }
    /// Under-lock eviction decision for the concurrent-clients race: against one stale leader, only clients strictly newer than it evict;
    /// same-or-older clients keep it.
    /// With flock mutual exclusion (lock.rs `try_acquire_fails_when_held`) and eviction running only under the flock,
    /// this yields exactly one client that evicts and spawns, so no split-brain.
    #[test]
    fn concurrent_clients_only_newer_evict_same_stale_leader() {
        let stale_leader = "0.1.219";
        assert!(should_evict(Some(stale_leader), "0.1.220"));
        assert!(should_evict(Some(stale_leader), "0.2.0"));
        assert!(!should_evict(Some(stale_leader), stale_leader));
        assert!(!should_evict(Some(stale_leader), "0.1.200"));
    }
    #[tokio::test]
    async fn wait_for_pid_exit_returns_immediately_for_dead_pid() {
        let start = tokio::time::Instant::now();
        wait_for_pid_exit(4_000_000_000, Duration::from_secs(30)).await;
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[tokio::test(start_paused = true)]
    async fn wait_for_pid_exit_honors_timeout_for_live_pid() {
        let timeout = Duration::from_secs(8);
        let start = tokio::time::Instant::now();
        wait_for_pid_exit(std::process::id(), timeout).await;
        assert!(start.elapsed() >= timeout);
    }
    /// A leader that accepts but never registers must return a hard timeout error.
    /// Today there is no eviction/respawn fallback on this path, so every client adopting the hung leader parks and then errors.
    #[tokio::test(start_paused = true)]
    async fn connect_to_hung_leader_times_out_with_no_fallback() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("hung.sock");
        let fake =
            spawn_fake_leader(sock_path.clone(), FakeLeaderBehavior::SilentAfterAccept).await;
        let result = connect_to_leader(
            &sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await;
        let Err(err) = result else {
            panic!("a silent leader must not yield a connection");
        };
        assert!(
            matches!(err, ConnectionError::Client(ClientError::Timeout(_))),
            "expected registration timeout, got {err:?}"
        );
        fake.cancel();
    }
    /// Reconnect attempts against a hung leader exhaust the bounded policy and publish `Failed`;
    /// the reconnector never falls back to evicting the hung leader and spawning a healthy one.
    #[tokio::test(start_paused = true)]
    async fn reconnect_against_hung_leader_exhausts_attempts_without_respawn() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("hung.sock");
        let fake =
            spawn_fake_leader(sock_path.clone(), FakeLeaderBehavior::SilentAfterAccept).await;
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        let (status_tx, mut status_rx) = LeaderReconnector::status_channel();
        let reconnector = LeaderReconnector::new(
            "test",
            ClientMode::Stdio,
            env_urls,
            ClientCapabilities::default(),
            status_tx,
        );
        let cancel = CancellationToken::new();
        let sock = sock_path.clone();
        let result = reconnector
            .reconnect_with(
                ReconnectPolicy::Bounded { max_attempts: 2 },
                &cancel,
                || {
                    connect_to_leader(
                        &sock,
                        "test",
                        ClientMode::Stdio,
                        ClientCapabilities::default(),
                    )
                },
            )
            .await;
        assert!(result.is_err(), "hung leader must exhaust bounded attempts");
        assert!(
            matches!(
                status_rx.borrow_and_update().clone(),
                ConnectionStatus::Failed { .. }
            ),
            "status must land on Failed after exhaustion"
        );
        fake.cancel();
    }
    /// P124: a client older than its leader says so; same, older, unversioned and unparseable leaders say nothing.
    #[test]
    fn newer_leader_notice_names_both_versions_and_the_remedy() {
        let text = newer_leader_notice(Some("1.0.22"), "1.0.21").expect("a newer leader is announced");
        assert!(text.contains("1.0.22") && text.contains("1.0.21"), "{text}");
        assert!(text.contains("fuigo leader kill"), "{text}");
        assert!(!text.contains('\u{2014}'), "{text}");
        for quiet in [Some("1.0.21"), Some("1.0.20"), Some("unknown"), None] {
            assert_eq!(newer_leader_notice(quiet, "1.0.21"), None, "{quiet:?}");
        }
        assert_eq!(newer_leader_notice(Some("1.0.22"), "unknown"), None);
        assert_eq!(newer_leader_notice(Some("1.0.22-rc1"), "1.0.22"), None);
        assert!(newer_leader_notice(Some("1.0.22"), "1.0.22-rc1").is_some());
    }
    /// P124: adopting a leader that runs a newer Fuigo than this client prints the notice; adopting a same-version leader prints nothing.
    #[tokio::test]
    #[serial_test::serial(FUIGO_LEADER_SOCKET)]
    async fn connect_or_spawn_announces_an_adopted_newer_leader() {
        let client: semver::Version = CLIENT_LEADER_VERSION
            .parse()
            .expect("CLIENT_LEADER_VERSION parses as semver");
        let newer = format!("{}.{}.{}", client.major, client.minor, client.patch + 7);
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid/p124-adopt".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        for (version, expect_notice) in [
            (newer.clone(), true),
            (CLIENT_LEADER_VERSION.to_string(), false),
        ] {
            let temp = TempDir::new().unwrap();
            let sock_path = temp.path().join("leader.sock");
            let fake = spawn_fake_leader(
                sock_path.clone(),
                FakeLeaderBehavior::Normal {
                    versions: FakeVersions {
                        protocol_version: Some(LEADER_PROTOCOL_VERSION),
                        binary_version: Some(version.clone()),
                    },
                    caps: fake_caps(true, false),
                },
            )
            .await;
            // SAFETY: serialised on FUIGO_LEADER_SOCKET; restored below.
            unsafe { std::env::set_var(LEADER_SOCKET_ENV, &sock_path) };
            let before = fuigo_file_utils::destination_gate::withheld_notices().len();
            let conn = connect_or_spawn(
                "test",
                ClientMode::Stdio,
                &env_urls,
                ClientCapabilities::default(),
            )
            .await
            .expect("adopts the fake leader");
            unsafe { std::env::remove_var(LEADER_SOCKET_ENV) };
            let announced: Vec<String> = fuigo_file_utils::destination_gate::withheld_notices()
                .into_iter()
                .skip(before)
                .filter(|n| n.contains("leader"))
                .collect();
            assert_eq!(announced.len(), usize::from(expect_notice), "{version}: {announced:?}");
            if expect_notice {
                assert!(announced[0].contains(&version), "{announced:?}");
            }
            drop(conn);
            fake.cancel();
        }
    }
    /// The pid the eviction acts on (signals or terminates), taken from `conn` and `lock` by the production rule.
    async fn act_on_pid_of(conn: &LeaderConnection, lock: &LeaderLock) -> Option<u32> {
        leader_target_to_act_on(conn, lock).await.map(|target| target.pid())
    }
    /// Packet 2 round 2 (audit HIGH): on Windows the pid inside the `GetLeaderInfo` payload comes from whoever serves the pipe
    /// and must never be acted on. The fake claims pid 7777; the process that really serves the pipe is this test process.
    #[cfg(windows)]
    #[tokio::test]
    #[serial_test::serial(FUIGO_LEADER_SOCKET)]
    async fn the_pid_from_the_pipe_payload_is_never_the_pid_to_act_on() {
        const CLAIMED: u32 = 7777;
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("leader-r2.sock");
        let fake = spawn_fake_leader(
            sock_path.clone(),
            FakeLeaderBehavior::ClaimsPid { claimed_pid: CLAIMED },
        )
        .await;
        let lock = LeaderLock::from_paths(sock_path.with_extension("lock"), sock_path.clone());
        let conn = connect_to_leader(&sock_path, "test", ClientMode::Stdio, ClientCapabilities::default())
            .await
            .expect("connect to the fake");
        let acted = act_on_pid_of(&conn, &lock).await;
        fake.cancel();
        assert_ne!(acted, Some(CLAIMED), "the payload pid must never be acted on");
        assert_eq!(acted, Some(std::process::id()), "the pid to act on is the OS pid of the pipe server");
    }
    /// Packet 2: a too-old leader that holds the lock, does not advertise `relaunch_v1` and never vacates must not keep the
    /// client in the vacate loop forever: the call returns the "could not replace" error once the budget is spent.
    #[tokio::test]
    #[serial_test::serial(FUIGO_LEADER_SOCKET)]
    async fn a_too_old_leader_that_never_vacates_ends_in_an_error_within_the_budget() {
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid/p2-vacate".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("leader.sock");
        let fake = spawn_fake_leader(
            sock_path.clone(),
            FakeLeaderBehavior::NormalPerClient {
                versions: FakeVersions {
                    protocol_version: Some(LEADER_PROTOCOL_VERSION),
                    binary_version: Some("0.0.0-p2-vacate".to_string()),
                },
                caps: fake_caps(false, false),
            },
        )
        .await;
        // Another holder of the lock: the fake never lets go of it.
        let mut holder = LeaderLock::from_paths(sock_path.with_extension("lock"), sock_path.clone());
        assert!(holder.try_acquire().unwrap(), "the test holds the lock");
        // SAFETY: serialised on FUIGO_LEADER_SOCKET; restored below.
        unsafe { std::env::set_var(LEADER_SOCKET_ENV, &sock_path) };
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            connect_or_spawn_with_vacate_budget(
                "test",
                ClientMode::Stdio,
                &env_urls,
                ClientCapabilities::default(),
                Duration::from_secs(2),
            ),
        )
        .await;
        unsafe { std::env::remove_var(LEADER_SOCKET_ENV) };
        let elapsed = started.elapsed();
        fake.cancel();
        let outcome = outcome.expect("the vacate loop must end within the budget, not spin");
        match outcome {
            Err(ConnectionError::SpawnFailed(message)) => {
                assert!(message.contains("0.0.0-p2-vacate"), "{message}");
                assert!(message.contains("Close the other Fuigo windows"), "{message}");
            }
            Err(other) => panic!("wrong error: {other}"),
            Ok(_) => panic!("must not adopt a too-old leader"),
        }
        assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
        drop(holder);
    }
    /// P124 r1 #2: only an explicit request that installed something strictly older than the running binary is a downgrade.
    #[test]
    fn explicit_downgrade_needs_an_explicit_request_and_a_lower_installed_version() {
        assert!(is_explicit_downgrade(true, "1.0.20", "1.0.21"));
        assert!(!is_explicit_downgrade(false, "1.0.20", "1.0.21"), "an ordinary update is never a downgrade");
        assert!(!is_explicit_downgrade(true, "1.0.21", "1.0.21"), "'Already up to date' installed nothing");
        assert!(!is_explicit_downgrade(true, "1.0.22", "1.0.21"), "an upgrade is not a downgrade");
        assert!(!is_explicit_downgrade(true, "unknown", "1.0.21"));
        assert!(!is_explicit_downgrade(true, "1.0.20", "unknown"));
    }
    /// P124 r2 #1, r3 #1: only a SPAWNED leader still below the floor is remembered; discovering a stale leader, however often,
    /// never records anything, so ordinary replacement of an older leader is unchanged.
    #[test]
    fn only_a_spawned_leader_still_below_the_floor_is_remembered() {
        let futile = std::sync::Mutex::new(Vec::new());
        assert!(evict_decision(Some("1.0.20"), "1.0.21", None, &futile));
        for keep in [Some("1.0.21"), Some("1.0.22"), Some("unknown"), None] {
            assert!(!evict_decision(keep, "1.0.21", None, &futile), "{keep:?}");
        }
        // Meeting the same stale leader again and again (the existing-leader path) still evicts it.
        for _ in 0..5 {
            assert!(evict_decision(Some("1.0.20"), "1.0.21", None, &futile));
        }
        remember_futile(Some("1.0.22"), "1.0.21", &futile);
        remember_futile(None, "1.0.21", &futile);
        assert!(futile.lock().unwrap().is_empty());
        remember_futile(Some("1.0.20"), "1.0.21", &futile);
        assert!(!evict_decision(Some("1.0.20"), "1.0.21", None, &futile));
        assert!(evict_decision(Some("1.0.19"), "1.0.21", None, &futile));
    }
    /// P124 r3 #1 against a live registration: meeting a lower leader evicts it every time until a spawn of ours leaves it running.
    #[tokio::test]
    async fn a_lower_leader_is_evicted_until_a_spawn_leaves_it_running() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("lower.sock");
        let fake = spawn_fake_leader(
            sock_path.clone(),
            FakeLeaderBehavior::Normal {
                versions: FakeVersions {
                    protocol_version: Some(LEADER_PROTOCOL_VERSION),
                    binary_version: Some("0.0.0-p124-futile".to_string()),
                },
                caps: fake_caps(true, true),
            },
        )
        .await;
        let conn = connect_to_leader(&sock_path, "test", ClientMode::Stdio, ClientCapabilities::default())
            .await
            .unwrap();
        for _ in 0..3 {
            assert!(evict_leader_conn(&conn), "discovery alone never makes eviction futile");
        }
        note_spawned_leader(&conn);
        assert!(!evict_leader_conn(&conn), "a spawn that left it running makes eviction futile");
        drop(conn);
        fake.cancel();
    }
    /// P129: a newer client does not evict the leader that IS the installed (lower) version; ordinary upgrades still replace an older leader.
    #[test]
    fn a_stale_client_keeps_the_installed_version_leader() {
        let futile = std::sync::Mutex::new(Vec::new());
        // client 1.0.21 (stale), installed 1.0.20 == leader: keep, however often it is met.
        for _ in 0..3 {
            assert!(!evict_decision(Some("1.0.20"), "1.0.21", Some("1.0.20"), &futile));
        }
        // ordinary upgrade: installed is the client's version, the leader is older: evict.
        assert!(evict_decision(Some("1.0.20"), "1.0.21", Some("1.0.21"), &futile));
        // installed newer than the client, leader older: evict.
        assert!(evict_decision(Some("1.0.20"), "1.0.21", Some("1.0.22"), &futile));
        // leader older than the installed version: it is not the installed one, evict.
        assert!(evict_decision(Some("1.0.19"), "1.0.21", Some("1.0.20"), &futile));
        // installed unknown or unparseable: P124 behaviour.
        assert!(evict_decision(Some("1.0.20"), "1.0.21", None, &futile));
        assert!(evict_decision(Some("1.0.20"), "1.0.21", Some("latest"), &futile));
        // prerelease versions compare as semver
        assert!(!evict_decision(Some("1.0.21-e2e.1"), "1.0.21-e2e.2", Some("1.0.21-e2e.1"), &futile));
        assert!(evict_decision(Some("1.0.21-e2e.1"), "1.0.21-e2e.2", Some("1.0.21-e2e.2"), &futile));
    }
    /// P129: the stale-client notice names the installed version and how to run it; it is silent in every other case.
    #[test]
    fn stale_client_notice_names_installed_version_and_remedy() {
        let text = stale_client_notice(Some("1.0.20"), Some("1.0.20"), "1.0.21", Path::new("/h/.fuigo/bin/fuigo")).expect("stale client is told");
        assert!(text.contains("1.0.20") && text.contains("1.0.21") && text.contains("/h/.fuigo/bin/fuigo"), "{text}");
        assert_eq!(stale_client_notice(Some("1.0.20"), Some("1.0.21"), "1.0.21", Path::new("/x")), None);
        assert_eq!(stale_client_notice(Some("1.0.20"), None, "1.0.21", Path::new("/x")), None);
        assert_eq!(stale_client_notice(None, Some("1.0.20"), "1.0.21", Path::new("/x")), None);
        assert_eq!(stale_client_notice(Some("1.0.21"), Some("1.0.21"), "1.0.21", Path::new("/x")), None);
    }
    /// P129: the installed version comes from the managed symlink for a managed client only.
    #[cfg(unix)]
    #[test]
    fn managed_installed_version_reads_the_symlink_of_a_managed_client() {
        let temp = TempDir::new().unwrap();
        let home = temp.path();
        std::fs::create_dir_all(home.join("bin")).unwrap();
        std::fs::create_dir_all(home.join("versions")).unwrap();
        let exe_a = home.join("versions").join("fuigo-1.0.21-e2e.2");
        let exe_b = home.join("versions").join("fuigo-1.0.21-e2e.1");
        std::fs::write(&exe_a, "a").unwrap();
        assert_eq!(managed_installed_version(home, Some(&exe_a)), None, "no symlink yet");
        std::fs::write(&exe_b, "b").unwrap();
        std::os::unix::fs::symlink(&exe_b, home.join("bin").join("fuigo")).unwrap();
        assert_eq!(managed_installed_version(home, Some(&exe_a)).as_deref(), Some("1.0.21-e2e.1"));
        let outside = TempDir::new().unwrap();
        assert_eq!(managed_installed_version(home, Some(&outside.path().join("fuigo"))), None, "dev binary: no installed version");
        assert_eq!(managed_installed_version(home, None), None);
        std::fs::remove_file(&exe_b).unwrap();
        assert_eq!(managed_installed_version(home, Some(&exe_a)), None, "dangling link");
    }
    /// P129 against a live registration: a lower leader that is the installed version is kept even before any spawn of ours.
    #[tokio::test]
    async fn a_live_installed_version_leader_is_not_evicted_by_a_newer_client() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("installed.sock");
        let fake = spawn_fake_leader(
            sock_path.clone(),
            FakeLeaderBehavior::Normal {
                versions: FakeVersions {
                    protocol_version: Some(LEADER_PROTOCOL_VERSION),
                    binary_version: Some("0.0.0-p129-installed".to_string()),
                },
                caps: fake_caps(true, true),
            },
        )
        .await;
        let conn = connect_to_leader(&sock_path, "test", ClientMode::Stdio, ClientCapabilities::default())
            .await
            .unwrap();
        let version = conn.registration().leader_binary_version.clone();
        let futile = std::sync::Mutex::new(Vec::new());
        assert!(evict_decision(version.as_deref(), "0.0.1", None, &futile), "unknown install: P124 evicts");
        assert!(
            !evict_decision(version.as_deref(), "0.0.1", Some("0.0.0-p129-installed"), &futile),
            "the leader is the installed version: the client is stale"
        );
        drop(conn);
        fake.cancel();
    }
    /// P124: the newer-than test is the exact mirror of [`leader_is_older_than`].
    #[test]
    fn leader_is_newer_than_is_strict_and_parseable_only() {
        assert!(leader_is_newer_than("1.0.22", "1.0.21"));
        assert!(!leader_is_newer_than("1.0.21", "1.0.21"));
        assert!(!leader_is_newer_than("1.0.20", "1.0.21"));
        assert!(!leader_is_newer_than("unknown", "1.0.21"));
        assert!(!leader_is_newer_than("1.0.22", "unknown"));
    }
    /// Version-floor decision against a live registration: only a strictly older parseable leader version trips eviction;
    /// dev/`unknown` and missing versions are kept (anti-thrash, both directions).
    ///
    /// Fake versions are derived RELATIVE to the runtime `CLIENT_LEADER_VERSION` (cargo builds see the crate version,
    /// bazel fastbuild sees the unstamped `0.0.0`), with each expectation following structurally from how the case was constructed,
    /// never from re-running the comparison under test.
    #[tokio::test]
    async fn should_evict_conn_decides_from_live_fake_registrations() {
        let client: semver::Version = CLIENT_LEADER_VERSION
            .parse()
            .expect("CLIENT_LEADER_VERSION parses as semver");
        let newer = format!("{}.{}.{}", client.major, client.minor, client.patch + 1);
        let older = if client.patch > 0 {
            Some(format!(
                "{}.{}.{}",
                client.major,
                client.minor,
                client.patch - 1
            ))
        } else if client.minor > 0 {
            Some(format!("{}.{}.0", client.major, client.minor - 1))
        } else if client.major > 0 {
            Some(format!("{}.0.0", client.major - 1))
        } else if client.pre.is_empty() {
            Some(format!(
                "{}.{}.{}-0",
                client.major, client.minor, client.patch
            ))
        } else {
            None
        };
        let mut cases: Vec<(Option<String>, bool)> = vec![
            // Same version as this client: keep
            (Some(CLIENT_LEADER_VERSION.to_string()), false),
            // Newer than this client: keep (never downgrade)
            (Some(newer), false),
            // Dev build reports "unknown": keep (unparseable is left alone)
            (Some("unknown".to_string()), false),
            // Legacy leader without version metadata: keep (safe fallback)
            (None, false),
        ];
        if let Some(older) = older {
            cases.push((Some(older), true));
        }
        for (i, (binary_version, expect_evict)) in cases.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let sock_path = temp.path().join(format!("evict-{i}.sock"));
            let versions = FakeVersions {
                protocol_version: Some(LEADER_PROTOCOL_VERSION),
                binary_version: binary_version.clone(),
            };
            let fake = spawn_fake_leader(
                sock_path.clone(),
                FakeLeaderBehavior::Normal {
                    versions,
                    caps: fake_caps(true, false),
                },
            )
            .await;
            let conn = connect_to_leader(
                &sock_path,
                "test",
                ClientMode::Stdio,
                ClientCapabilities::default(),
            )
            .await
            .unwrap();
            assert_eq!(
                should_evict_conn(&conn),
                expect_evict,
                "leader version {binary_version:?} vs client {CLIENT_LEADER_VERSION}"
            );
            drop(conn);
            fake.cancel();
        }
    }
    /// A leader that closes right after `Registered` still yields a usable registration (version metadata for the eviction decision);
    /// the disconnect is observed afterwards, not during connect.
    #[tokio::test]
    async fn close_after_register_still_exposes_registration_metadata() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("close.sock");
        let fake =
            spawn_fake_leader(sock_path.clone(), FakeLeaderBehavior::CloseAfterRegister).await;
        let conn = connect_to_leader(
            &sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            conn.registration().leader_binary_version.as_deref(),
            Some(CLIENT_LEADER_VERSION)
        );
        assert!(!should_evict_conn(&conn));
        fake.cancel();
    }
    #[tokio::test]
    async fn spawn_server_and_connect() {
        use protocol::ClientMode;
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("test.sock");
        let handle = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = LeaderClient::connect(
            sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        client.cancel();
        handle.cancel.cancel();
    }
    #[test]
    fn reconnect_policy_bounded_default() {
        let policy = ReconnectPolicy::bounded();
        assert_eq!(
            policy,
            ReconnectPolicy::Bounded {
                max_attempts: RECONNECT_MAX_ATTEMPTS_BOUNDED
            }
        );
    }
    #[test]
    fn reconnect_policy_unbounded() {
        let policy = ReconnectPolicy::unbounded();
        assert_eq!(policy, ReconnectPolicy::Unbounded);
    }
    #[test]
    fn status_channel_initial_value() {
        let (_tx, rx) = LeaderReconnector::status_channel();
        assert_eq!(*rx.borrow(), ConnectionStatus::Connected { generation: 0 });
    }
    /// Each `notify_connected` publishes a strictly increasing generation,
    /// so an observer that only sees the latest watch value still detects every reconnect (including a coalesced `Reconnecting -> Connected` flip).
    #[test]
    fn notify_connected_increments_generation() {
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        let (status_tx, status_rx) = LeaderReconnector::status_channel();
        let reconnector = LeaderReconnector::new(
            "test",
            ClientMode::Stdio,
            env_urls,
            ClientCapabilities::default(),
            status_tx,
        );
        reconnector.notify_connected();
        assert_eq!(
            *status_rx.borrow(),
            ConnectionStatus::Connected { generation: 1 }
        );
        reconnector.notify_connected();
        assert_eq!(
            *status_rx.borrow(),
            ConnectionStatus::Connected { generation: 2 }
        );
    }
    /// A successful `reconnect_with` must NOT publish `Connected` itself: the caller installs the new channels first, then calls `notify_connected`.
    /// Publishing early lets an observer send requests into the dead pre-reconnect channel.
    #[tokio::test]
    async fn reconnect_with_does_not_publish_connected_before_swap() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("test.sock");
        let handle = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        let (status_tx, mut status_rx) = LeaderReconnector::status_channel();
        let reconnector = LeaderReconnector::new(
            "test",
            ClientMode::Stdio,
            env_urls,
            ClientCapabilities::default(),
            status_tx,
        );
        let _ = status_rx.borrow_and_update();
        let cancel = CancellationToken::new();
        let sock = sock_path.clone();
        let result = reconnector
            .reconnect_with(ReconnectPolicy::bounded(), &cancel, || {
                connect_to_leader(
                    &sock,
                    "test",
                    ClientMode::Stdio,
                    ClientCapabilities::default(),
                )
            })
            .await;
        assert!(result.is_ok(), "reconnect should succeed");
        assert_eq!(
            status_rx.borrow_and_update().clone(),
            ConnectionStatus::Reconnecting { attempt: 1 }
        );
        assert!(
            !status_rx.has_changed().unwrap(),
            "Connected must not be published before notify_connected()"
        );
        reconnector.notify_connected();
        assert_eq!(
            status_rx.borrow_and_update().clone(),
            ConnectionStatus::Connected { generation: 1 }
        );
        handle.cancel.cancel();
    }
    #[tokio::test]
    async fn reconnector_bounded_fails_after_max_attempts() {
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        let (status_tx, mut status_rx) = LeaderReconnector::status_channel();
        let reconnector = LeaderReconnector::new(
            "test",
            ClientMode::Stdio,
            env_urls,
            ClientCapabilities::default(),
            status_tx,
        );
        let cancel = CancellationToken::new();
        let policy = ReconnectPolicy::Bounded { max_attempts: 2 };
        let mut attempts = 0;
        let result = reconnector
            .reconnect_with(policy, &cancel, || {
                attempts += 1;
                async move {
                    Err(ConnectionError::SpawnFailed(format!(
                        "synthetic failure #{attempts}"
                    )))
                }
            })
            .await;
        assert!(result.is_err(), "Should fail after 2 attempts");
        let status = status_rx.borrow_and_update().clone();
        assert!(
            matches!(status, ConnectionStatus::Failed { .. }),
            "Expected Failed status, got {:?}",
            status
        );
    }
    #[tokio::test]
    async fn reconnector_cancelled_returns_error() {
        let env_urls = LeaderEnvUrls {
            fuigo_ws_url: "wss://test.invalid".into(),
            fuigo_ws_origin: "https://test.invalid".into(),
        };
        let (status_tx, _status_rx) = LeaderReconnector::status_channel();
        let reconnector = LeaderReconnector::new(
            "test",
            ClientMode::Stdio,
            env_urls,
            ClientCapabilities::default(),
            status_tx,
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = reconnector
            .reconnect(ReconnectPolicy::unbounded(), &cancel)
            .await;
        assert!(result.is_err(), "Should fail when cancelled");
    }
    #[tokio::test]
    async fn reconnector_succeeds_when_server_exists() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("test.sock");
        let handle = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (status_tx, status_rx) = LeaderReconnector::status_channel();
        let conn = connect_to_leader(
            &sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let _ = status_tx.send(ConnectionStatus::Connected { generation: 1 });
        assert_eq!(
            *status_rx.borrow(),
            ConnectionStatus::Connected { generation: 1 }
        );
        let (tx, _rx) = conn.into_channels();
        assert!(
            tx.send(r#"{"jsonrpc":"2.0","method":"test","id":1}"#.into())
                .is_ok()
        );
        handle.cancel.cancel();
    }
    #[tokio::test]
    async fn reconnector_status_transitions_on_failure_then_success() {
        let (status_tx, mut status_rx) = LeaderReconnector::status_channel();
        assert_eq!(
            *status_rx.borrow(),
            ConnectionStatus::Connected { generation: 0 }
        );
        let _ = status_tx.send(ConnectionStatus::Reconnecting { attempt: 1 });
        assert!(status_rx.has_changed().unwrap());
        let status = status_rx.borrow_and_update().clone();
        assert_eq!(status, ConnectionStatus::Reconnecting { attempt: 1 });
        let _ = status_tx.send(ConnectionStatus::Reconnecting { attempt: 2 });
        let status = status_rx.borrow_and_update().clone();
        assert_eq!(status, ConnectionStatus::Reconnecting { attempt: 2 });
        let _ = status_tx.send(ConnectionStatus::Connected { generation: 1 });
        let status = status_rx.borrow_and_update().clone();
        assert_eq!(status, ConnectionStatus::Connected { generation: 1 });
    }
    #[tokio::test]
    async fn reconnect_to_new_server_after_old_dies() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("test.sock");
        let handle_a = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client_a = LeaderClient::connect(
            sock_path.clone(),
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let (tx_a, _rx_a) = client_a.into_channels();
        assert!(
            tx_a.send(r#"{"jsonrpc":"2.0","method":"test","id":1}"#.into())
                .is_ok()
        );
        handle_a.cancel.cancel();
        for _ in 0..50 {
            if tx_a.send("probe".into()).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            tx_a.send("dead".into()).is_err(),
            "Old channel should be dead after server kill"
        );
        let _ = std::fs::remove_file(&sock_path);
        let handle_b = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client_b = LeaderClient::connect(
            sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let (tx_b, _rx_b) = client_b.into_channels();
        assert!(
            tx_b.send(r#"{"jsonrpc":"2.0","method":"test","id":2}"#.into())
                .is_ok()
        );
        handle_b.cancel.cancel();
    }
    #[tokio::test]
    async fn double_reconnect_server_a_dies_b_dies_c_works() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("test.sock");
        let handle_a = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client_a = LeaderClient::connect(
            sock_path.clone(),
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let mut disconnect_rx_a = client_a.disconnect_reason();
        let (tx_a, _rx_a) = client_a.into_channels();
        assert!(
            tx_a.send(r#"{"jsonrpc":"2.0","method":"test","id":1}"#.into())
                .is_ok()
        );
        handle_a.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), disconnect_rx_a.changed()).await;
        let reason_a = disconnect_rx_a.borrow().clone();
        assert!(
            reason_a == DisconnectReason::LeaderShutdown
                || reason_a == DisconnectReason::ConnectionLost,
            "First disconnect: expected LeaderShutdown or ConnectionLost, got {:?}",
            reason_a
        );
        let _ = std::fs::remove_file(&sock_path);
        let handle_b = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client_b = LeaderClient::connect(
            sock_path.clone(),
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let mut disconnect_rx_b = client_b.disconnect_reason();
        let (tx_b, _rx_b) = client_b.into_channels();
        assert!(
            tx_b.send(r#"{"jsonrpc":"2.0","method":"test","id":2}"#.into())
                .is_ok()
        );
        handle_b.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), disconnect_rx_b.changed()).await;
        let reason_b = disconnect_rx_b.borrow().clone();
        assert!(
            reason_b == DisconnectReason::LeaderShutdown
                || reason_b == DisconnectReason::ConnectionLost,
            "Second disconnect: expected LeaderShutdown or ConnectionLost, got {:?}",
            reason_b
        );
        let _ = std::fs::remove_file(&sock_path);
        let handle_c = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client_c = LeaderClient::connect(
            sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let disconnect_rx_c = client_c.disconnect_reason();
        let (tx_c, _rx_c) = client_c.into_channels();
        assert!(
            tx_c.send(r#"{"jsonrpc":"2.0","method":"test","id":3}"#.into())
                .is_ok()
        );
        assert_eq!(*disconnect_rx_c.borrow(), DisconnectReason::Connected);
        handle_c.cancel.cancel();
    }
    #[test]
    fn resolve_binary_prefers_current_exe() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("fuigo"), "fake-binary").unwrap();
        let result = resolve_binary_with_home(temp.path()).unwrap();
        let current = std::env::current_exe().unwrap();
        assert_eq!(result, current);
    }
    #[test]
    fn resolve_binary_succeeds_without_managed_bin() {
        let temp = TempDir::new().unwrap();
        let result = resolve_binary_with_home(temp.path()).unwrap();
        assert!(result.exists());
    }
    #[cfg(unix)]
    #[test]
    fn resolve_binary_prefers_current_exe_over_symlink() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let target_v2 = bin_dir.join("fuigo-v2");
        std::fs::write(&target_v2, "new-binary").unwrap();
        std::os::unix::fs::symlink(&target_v2, bin_dir.join("fuigo")).unwrap();
        let result = resolve_binary_with_home(temp.path()).unwrap();
        let current = std::env::current_exe().unwrap();
        assert_eq!(result, current);
    }
    #[cfg(unix)]
    #[test]
    fn resolve_binary_prefers_managed_symlink_for_managed_install() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let new_target = bin_dir.join("fuigo-v2");
        std::fs::write(&new_target, "new-binary").unwrap();
        let managed = bin_dir.join("fuigo");
        std::os::unix::fs::symlink(&new_target, &managed).unwrap();
        let stale_target = bin_dir.join("fuigo-v1");
        std::fs::write(&stale_target, "old-binary").unwrap();
        let result = resolve_binary_impl(temp.path(), Some(stale_target)).unwrap();
        assert_eq!(result, managed);
    }
    #[test]
    fn resolve_binary_prefers_current_exe_for_out_of_tree_install() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join(managed_fuigo_bin_name()), "managed").unwrap();
        let dev_exe = std::env::current_exe().unwrap();
        let result = resolve_binary_impl(temp.path(), Some(dev_exe.clone())).unwrap();
        assert_eq!(result, dev_exe);
    }
    #[test]
    fn resolve_binary_falls_back_to_managed_when_no_current_exe() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let managed = bin_dir.join(managed_fuigo_bin_name());
        std::fs::write(&managed, "managed").unwrap();
        let result = resolve_binary_impl(temp.path(), None).unwrap();
        assert_eq!(result, managed);
    }
    #[test]
    fn pid_check_identifies_dead_leader() {
        let temp = TempDir::new().unwrap();
        let lock_path = temp.path().join("leader.lock");
        fs::write(&lock_path, "4000000000").unwrap();
        let pid = LeaderLock::read_pid_from_path(&lock_path);
        assert_eq!(pid, Some(4_000_000_000));
        assert!(!crate::util::is_process_alive(4_000_000_000));
        fs::write(&lock_path, format!("{}", std::process::id())).unwrap();
        let pid = LeaderLock::read_pid_from_path(&lock_path).unwrap();
        assert_eq!(pid, std::process::id());
        assert!(crate::util::is_process_alive(pid));
    }
    /// P145: with a named-pipe endpoint (Windows) there is no `leader.sock` file. A live leader must be found through its
    /// lock (Reachable, with the PID it reports), not listed "PID ? (Stale)"; a lock nobody answers for stays Stale.
    /// Run here with the endpoint kind injected; the `.sock` file the Unix test server creates is ignored by the scan
    /// in that mode, so only the lock-derived endpoint can find the leader.
    #[tokio::test]
    async fn p145_a_pipe_endpoint_leader_is_found_through_its_lock() {
        let temp = TempDir::new().unwrap();
        let lock_path = temp.path().join("leader.lock");
        fs::write(&lock_path, "").unwrap();
        let found = discover_leaders_in_with(temp.path(), false).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].classification, LeaderDiscoveryState::Stale, "nobody answers: Stale");
        assert_eq!(found[0].socket_path, None);

        let handle = spawn_leader_server(temp.path().join("leader.sock")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let found = discover_leaders_in_with(temp.path(), false).await;
        assert_eq!(found.len(), 1, "one leader, not a lock entry plus a socket entry: {found:?}");
        assert_eq!(found[0].classification, LeaderDiscoveryState::Reachable, "{found:?}");
        assert_eq!(found[0].lock_path.as_deref(), Some(lock_path.as_path()));
        assert_eq!(found[0].socket_path.as_deref(), Some(temp.path().join("leader.sock").as_path()));
        assert_eq!(found[0].live_info.as_ref().map(|i| i.pid), Some(std::process::id()));
        assert_eq!(reachable_leader_pids(&found).len(), 1);
        handle.cancel.cancel();
    }
    #[test]
    fn p145_derived_endpoint_only_without_a_file_endpoint() {
        let lock = Path::new("/h/.fuigo/leader-ab12.lock");
        assert_eq!(derived_endpoint_for_lock(lock, true), None);
        assert_eq!(
            derived_endpoint_for_lock(lock, false).as_deref(),
            Some(Path::new("/h/.fuigo/leader-ab12.sock"))
        );
    }
    #[tokio::test]
    async fn pid_alive_and_server_reachable_allows_connection() {
        let temp = TempDir::new().unwrap();
        let sock_path = temp.path().join("leader.sock");
        let lock_path = temp.path().join("leader.lock");
        let handle = spawn_leader_server(sock_path.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        fs::write(&lock_path, format!("{}", std::process::id())).unwrap();
        let pid = LeaderLock::read_pid_from_path(&lock_path).unwrap();
        assert!(crate::util::is_process_alive(pid));
        let conn = connect_to_leader(
            &sock_path,
            "test",
            ClientMode::Stdio,
            ClientCapabilities::default(),
        )
        .await
        .unwrap();
        let (tx, _rx) = conn.into_channels();
        assert!(
            tx.send(r#"{"jsonrpc":"2.0","method":"test","id":1}"#.into())
                .is_ok()
        );
        handle.cancel.cancel();
    }
    /// The leader is a daemon that outlives the client that spawned it, so on
    /// Windows it must not attach to that client's console (closing the
    /// console would terminate it): it requests no console window, keeps its
    /// own process group, and never uses `DETACHED_PROCESS`.
    #[test]
    fn leader_spawn_flags_request_no_console_window_and_a_new_group() {
        use fuigo_tty_utils::win32_creation_flags::{
            CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS,
        };
        let flags = leader_creation_flags();
        assert_eq!(
            flags & CREATE_NO_WINDOW,
            CREATE_NO_WINDOW,
            "leader creation flags {flags:#010x} lack CREATE_NO_WINDOW: the leader attaches \
             to the client's console and is terminated when that console closes"
        );
        assert_eq!(
            flags & CREATE_NEW_PROCESS_GROUP,
            CREATE_NEW_PROCESS_GROUP,
            "leader creation flags {flags:#010x} lack CREATE_NEW_PROCESS_GROUP"
        );
        assert_eq!(
            flags & DETACHED_PROCESS,
            0,
            "DETACHED_PROCESS breaks stdio inheritance for the leader's grandchildren"
        );
        assert_eq!(flags, CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(windows)]
    #[test]
    fn leader_spawn_flags_match_the_windows_crate() {
        use windows::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        assert_eq!(
            leader_creation_flags(),
            (CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW).0
        );
    }

    /// Env marker for [`leader_spawn_console_probe_entry`].
    #[cfg(windows)]
    const LEADER_CONSOLE_PROBE_ENV: &str = "__FUIGO_SHELL_LEADER_CONSOLE_PROBE";

    /// Probe process for [`leader_spawn_gets_its_own_windowless_console`]:
    /// reports whether it has a console window and which processes share its
    /// console.
    #[cfg(windows)]
    #[test]
    fn leader_spawn_console_probe_entry() {
        use windows::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
        if std::env::var_os(LEADER_CONSOLE_PROBE_ENV).is_none() {
            return; // skip when not spawned as the probe
        }
        let mut pids = [0u32; 64];
        // SAFETY: plain FFI calls; `pids` is a live buffer of the length passed.
        let (attached, window) = unsafe { (GetConsoleProcessList(&mut pids), GetConsoleWindow()) };
        // A count above the buffer length leaves it unfilled; report the count.
        let processes = match pids.get(..attached as usize) {
            Some(listed) => listed
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
            None => format!("more-than-{}", pids.len()),
        };
        println!(
            "leader-console-probe window={} console-processes={processes} end",
            !window.0.is_null()
        );
    }

    /// Spawned through the real leader spawn path, a process must get its own
    /// console with no window: attached to no other process's console (that
    /// console closing would terminate it) and showing no window. With the
    /// pre-fix flags (`CREATE_NEW_PROCESS_GROUP` alone) it shares the
    /// spawner's console on Windows; under Wine, which never reports a console
    /// window, it has no console at all. Both fail the process-list assertion.
    #[cfg(windows)]
    #[test]
    fn leader_spawn_gets_its_own_windowless_console() {
        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = Command::new(exe);
        cmd.args([
            "--exact",
            "leader::tests::leader_spawn_console_probe_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(LEADER_CONSOLE_PROBE_ENV, "1")
        .env_remove("TEST_SHARD_INDEX")
        .env_remove("TEST_TOTAL_SHARDS")
        .env_remove("TEST_SHARD_STATUS_FILE")
        .env_remove("TESTBRIDGE_TEST_ONLY")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
        let child =
            spawn_leader_process(cmd).expect("spawn the probe through the leader spawn path");
        let pid = child.id();
        let output = child
            .wait_with_output()
            .expect("wait for the console probe");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "console probe failed ({}); stdout: {stdout}",
            output.status
        );
        let report = stdout
            .split("leader-console-probe ")
            .nth(1)
            .and_then(|rest| rest.split(" end").next())
            .unwrap_or_else(|| panic!("no console probe report; stdout: {stdout}"));
        let field = |key: &str| {
            report
                .split_whitespace()
                .find_map(|pair| pair.strip_prefix(key))
                .unwrap_or_else(|| panic!("probe report lacks {key}: {report}"))
                .to_owned()
        };
        assert_eq!(
            field("console-processes="),
            pid.to_string(),
            "the leader (pid {pid}) is not alone on a console of its own (console processes: \
             {report}; empty = no console): a leader on its client's console is terminated \
             when that console closes"
        );
        assert_eq!(
            field("window="),
            "false",
            "the leader's console has a window ({report})"
        );
    }
}
