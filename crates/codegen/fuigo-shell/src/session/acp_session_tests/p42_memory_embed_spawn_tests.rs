//! P42: the startup memory reindex seeded by `spawn_session_actor` never carries the session token to a
//! destination that may not receive it.
//!
//! These tests go through the real spawn path (`spawn_session_on_thread` -> `spawn_session_actor`), with memory
//! enabled, API embeddings configured, and a `MEMORY.md` present so the startup reindex has chunks to embed. The
//! sampler's base URL is a loopback listener (refused by `session_may_reach`) that records the `Authorization`
//! header of every request, including `POST <base_url>/embeddings`.
//!
//! * The positive control spawns with a BYOK-style key the `AuthManager` never held: it must arrive at
//!   `/embeddings`, which proves the reindex really embeds over the wire (so the negative is not vacuous).
//! * The negative spawns with the `AuthManager`'s own (valid OIDC) session token: it must never arrive at
//!   `/embeddings`. Replacing `memory_embed_api_key(..)` at the spawn call site with
//!   `sampling_config.api_key.clone()` makes it fail.
//!
//! Each test re-runs itself in a fresh process (`fresh_process_home`) because the wire harness installs proxy and
//! CA variables that latch when the first HTTP client is built.
use super::*;
use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};
use crate::test_support::session_wire::{Observed, SessionWire, token_arrived};
use std::sync::Arc;

const TOKEN: &str = "p42-memory-embed-session-token-3b9e";
const BYOK: &str = "p42-memory-embed-byok-key-5e0b";
const MODEL: &str = "p42-memory-embed-model";
const MODULE: &str = "session::acp_session::p42_memory_embed_spawn_tests::";

fn child(test: &str) -> bool {
    fuigo_test_support::env::fresh_process_home(&format!("{MODULE}{test}")).is_some()
}

fn run(f: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f);
}

/// An `AuthManager` holding `TOKEN` as a valid OIDC session credential.
fn manager() -> (tempfile::TempDir, Arc<AuthManager>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let am = Arc::new(AuthManager::new(dir.path(), FuigoComConfig::default()));
    am.hot_swap(FuigoAuth {
        key: TOKEN.into(),
        auth_mode: AuthMode::Oidc,
        refresh_token: Some("rt".into()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        ..FuigoAuth::test_default()
    });
    (dir, am)
}

/// Fixture facts the tests rely on; a wrong fixture fails loudly instead of passing vacuously.
fn preconditions(am: &AuthManager, base_url: &str) {
    crate::agent::config::Config::install_test_trusted_origins();
    assert!(
        !crate::auth::session_delivery::session_may_reach(base_url),
        "fixture: the loopback embeddings destination must be refused"
    );
    assert!(am.is_session_bearer(TOKEN), "fixture: TOKEN is the manager's session bearer");
    assert!(!am.is_session_bearer(BYOK), "fixture: BYOK is not a session bearer");
}

/// Memory on, API embeddings on, a flat root holding a `MEMORY.md` the startup reindex chunks and embeds.
fn memory_config(root: &std::path::Path) -> crate::config::MemoryConfig {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("MEMORY.md"),
        "# Project notes\n\nThe build box is the only place cargo runs for this project.\n\n\
         Prefer small focused commits with a clear subject line.\n",
    )
    .unwrap();
    let mut mc = crate::config::MemoryConfig {
        enabled: true,
        global_enabled: false,
        root_dir_override: Some(root.to_path_buf()),
        flat_memory_root: true,
        ..Default::default()
    };
    mc.embedding.provider = "api".to_string();
    mc.embedding.model = Some("p42-embedding-model".to_string());
    mc.embedding.dimensions = 8;
    mc
}

/// Everything the spawned session needs kept alive for the duration of the test.
struct Spawned {
    _handle: SessionHandle,
    _thread: SessionThread,
    _gateway_rx: tokio::sync::mpsc::UnboundedReceiver<crate::test_support::lsp_runtime::GatewayOut>,
    _persistence_rx: tokio::sync::mpsc::UnboundedReceiver<PersistenceMsg>,
    _permission_rx: tokio::sync::mpsc::UnboundedReceiver<PermissionEvent>,
}

/// Spawn a primary session through `spawn_session_on_thread` whose sampler targets `base_url` with `api_key`.
async fn spawn_session(
    id: &str,
    cwd: &std::path::Path,
    base_url: &str,
    api_key: &str,
    am: Arc<AuthManager>,
    memory: crate::config::MemoryConfig,
) -> Spawned {
    let session_info = SessionInfo {
        id: acp::SessionId::new(id.to_string()),
        cwd: cwd.to_string_lossy().into_owned(),
    };
    let _ = crate::util::fuigo_home::ensure_sessions_cwd_dir(&session_info.cwd);
    std::fs::create_dir_all(crate::session::persistence::session_dir(&session_info)).unwrap();

    let (gateway, gateway_rx) = crate::test_support::lsp_runtime::test_gateway_with_receiver();
    let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
    let persistence = PersistenceHandle::from_sender_for_test(persistence_tx);

    let cwd_abs = fuigo_paths::AbsPathBuf::new(cwd.to_path_buf()).expect("absolute cwd");
    let fs = Arc::new(fuigo_workspace::file_system::LocalFs::new(cwd.to_path_buf()));
    let terminal = Arc::new(crate::terminal::TerminalRunner::new(
        Arc::new(gateway.clone()),
        session_info.id.clone(),
    ));
    let tool_ctx = ToolContext::new(
        cwd_abs,
        Some(gateway.clone()),
        Some(session_info.id.clone()),
        fs,
        terminal,
        fuigo_hunk_tracker::HunkTrackerHandle::noop(),
    );

    let sampling_config = SamplingConfig {
        api_key: Some(api_key.to_string()),
        base_url: base_url.to_string(),
        model: MODEL.to_string(),
        max_retries: Some(0),
        ..Default::default()
    };
    let credentials = fuigo_chat_state::Credentials {
        api_key: Some(api_key.to_string()),
        auth_type: if api_key == TOKEN {
            fuigo_chat_state::AuthType::SessionToken
        } else {
            fuigo_chat_state::AuthType::ApiKey
        },
        ..Default::default()
    };

    let (handle, permission_rx, _system_prompt, thread) = spawn_session_on_thread(
        session_info,
        gateway,
        sampling_config,
        credentials,
        crate::agent::auth_method::new_shared_auth_method_id(Some(acp::AuthMethodId::new(
            "cached_token",
        ))),
        Some(am),
        None,
        tool_ctx,
        vec![],
        Default::default(),
        Default::default(),
        None,
        Vec::new(),
        true,
        false,
        None,
        persistence,
        Vec::new(),
        None,
        None,
        0,
        crate::session::StartupHints {
            non_interactive: true,
            skip_git_status: true,
            ..Default::default()
        },
        fuigo_workspace::permission::ClientType::Generic,
        85,
        fuigo_agent::DEFAULT_SYSTEM_PROMPT_LABEL.to_string(),
        fuigo_chat_state::CompactionMode::default(),
        false,
        Default::default(),
        false,
        None,
        None,
        Arc::new(parking_lot::Mutex::new(CodebaseIndexManager::new())),
        false,
        fs_watch::FsWatchCapabilities::none(),
        crate::session::notifications::SessionClientCaps::new(false, true),
        None,
        None,
        None,
        None,
        false,
        false,
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        AgentDefinition::default_fuigo_build(),
        None,
        SkillsConfig::default(),
        Some(Vec::new()),
        CompatConfig::default(),
        false,
        None,
        None,
        None,
        Vec::new(),
        None,
        Some(memory),
        false,
        Default::default(),
        crate::session::managed_mcp::ManagedMcpStateHandle::default(),
        String::new(),
        acp::ModelId::new(MODEL),
        false,
        false,
        None,
        600,
        Some(0),
        1,
        None,
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        true,
        false,
        false,
        false,
        false,
        fuigo_tools::implementations::fuigo_build::task::MAX_SUBAGENT_DEPTH,
        crate::session::workflow::host_service::DEFAULT_WORKFLOW_MAX_CONCURRENT_AGENTS,
        fuigo_tools::media_gen_limits::MediaGenBatchLimits::default(),
        false,
        Default::default(),
        None,
        std::collections::HashMap::new(),
        Vec::new(),
        fuigo_agent::prompt::context::PromptAudience::Primary,
        None,
        None,
        true,
        false,
        false,
        false,
        Default::default(),
        None,
        None,
        Default::default(),
        None,
        None,
        None,
        crate::test_support::TEST_MODEL.to_owned(),
        None,
        fuigo_workspace::WorkspaceOps::for_test(),
        vec![],
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )
    .await
    .expect("session spawns");
    Spawned {
        _handle: handle,
        _thread: thread,
        _gateway_rx: gateway_rx,
        _persistence_rx: persistence_rx,
        _permission_rx: permission_rx,
    }
}

fn embeddings(seen: &[Observed]) -> Vec<&Observed> {
    seen.iter().filter(|o| o.target.ends_with("/embeddings")).collect()
}

/// Wait until the startup reindex has written chunks for `root` (the step right before it embeds).
async fn wait_for_reindexed_chunks(cwd: &std::path::Path, root: &std::path::Path) -> usize {
    let storage = crate::session::memory::MemoryStorage::new_flat(cwd, root);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let n = storage.total_chunk_count();
        if n > 0 || std::time::Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Collect everything the wire records over `window`, stopping early once `done` holds.
async fn collect(
    wire: &mut SessionWire,
    window: std::time::Duration,
    done: impl Fn(&[Observed]) -> bool,
) -> Vec<Observed> {
    let deadline = std::time::Instant::now() + window;
    let mut seen = Vec::new();
    loop {
        seen.extend(wire.observed().await);
        if done(&seen) || std::time::Instant::now() >= deadline {
            return seen;
        }
    }
}

/// Positive control: a non-session (BYOK-style) key at the same refused loopback destination IS sent by the
/// spawn-time memory reindex to `/embeddings`. Proves the reindex embeds over the wire, so the negative test's
/// "no session token at /embeddings" cannot be the vacuous result of "no embeddings request".
#[test]
fn p42_spawn_memory_reindex_sends_non_session_key_to_embeddings() {
    if !child("p42_spawn_memory_reindex_sends_non_session_key_to_embeddings") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        let (_auth_dir, am) = manager();
        let base_url = wire.loopback_url();
        preconditions(&am, &base_url);
        let cwd = tempfile::tempdir().unwrap();
        let root = cwd.path().join("p42-memory");
        let memory = memory_config(&root);
        let _session = spawn_session(
            "p42-memory-embed-byok",
            cwd.path(),
            &base_url,
            BYOK,
            am,
            memory,
        )
        .await;
        assert!(
            wait_for_reindexed_chunks(cwd.path(), &root).await > 0,
            "the startup reindex must index MEMORY.md"
        );
        let seen = collect(&mut wire, std::time::Duration::from_secs(15), |seen| {
            embeddings(seen)
                .iter()
                .any(|o| o.authorization.as_deref().is_some_and(|a| a.contains(BYOK)))
        })
        .await;
        let embeds = embeddings(&seen);
        assert!(
            embeds
                .iter()
                .any(|o| o.authorization.as_deref().is_some_and(|a| a.contains(BYOK))),
            "the spawn-time memory reindex must POST /embeddings with the non-session key: {seen:?}"
        );
        assert!(
            !token_arrived(&seen, TOKEN),
            "the session token must not appear anywhere at the loopback destination: {seen:?}"
        );
    });
}

/// The session token held by the `AuthManager`, seeded into the spawn sampler for a destination that may not
/// receive it, never reaches `<base_url>/embeddings` through the spawn-time memory reindex.
#[test]
fn p42_spawn_memory_reindex_withholds_session_token_from_refused_embeddings() {
    if !child("p42_spawn_memory_reindex_withholds_session_token_from_refused_embeddings") {
        return;
    }
    run(async {
        let mut wire = SessionWire::start().await;
        let (_auth_dir, am) = manager();
        let base_url = wire.loopback_url();
        preconditions(&am, &base_url);
        let cwd = tempfile::tempdir().unwrap();
        let root = cwd.path().join("p42-memory");
        let memory = memory_config(&root);
        let _session = spawn_session(
            "p42-memory-embed-session",
            cwd.path(),
            &base_url,
            TOKEN,
            am,
            memory,
        )
        .await;
        // The reindex must have run (chunks written); embedding follows immediately, so a leaked token would be on
        // the wire within the window below (the positive control shows the same path delivers a key here).
        assert!(
            wait_for_reindexed_chunks(cwd.path(), &root).await > 0,
            "the startup reindex must index MEMORY.md"
        );
        let seen = collect(&mut wire, std::time::Duration::from_secs(4), |seen| {
            !embeddings(seen).is_empty()
        })
        .await;
        let embeds = embeddings(&seen);
        assert!(
            !embeds
                .iter()
                .any(|o| o.authorization.as_deref().is_some_and(|a| a.contains(TOKEN))),
            "the session token reached a refused /embeddings destination via the spawn-time memory reindex: {embeds:?}"
        );
    });
}
