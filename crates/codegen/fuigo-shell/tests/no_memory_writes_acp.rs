//! P53: `--no-memory` must stop memory WRITES, not just withhold the memory tools.
//!
//! Murage launches Fuigo with `--no-memory` (Contract E.1) because Murage owns persistent memory. The P00
//! conformance harness proves the model is not offered `memory_*` tools. This file proves the harder claim:
//! with every memory feature switched on in config AND `FUIGO_MEMORY=1` in the environment, the REAL
//! `fuigo` binary driven over ACP creates, modifies and deletes nothing that is memory, through a normal
//! turn, an explicit `/flush`, `/dream` and `/memory on`, the `fuigo/memory/*` extension methods, a
//! compaction, a session close (the session-end memory save), a restart, a session resume, an idle
//! period and the process-memory trace.
//!
//! Two agents run the identical scenario, each against its own sandbox and mock endpoint:
//! * the SUBJECT is spawned with `--no-memory`;
//! * the CONTROL is spawned without it. It is the positive control of the detector: it must write the
//!   memory store, a flush log for every trigger, a dream, a session-end log and a memtrace file,
//!   garbage-collect a planted orphan and offer `memory_*` tools. Otherwise a green subject run would
//!   prove nothing.
//!
//! Detection is a before/after snapshot of the whole sandbox root (HOME, FUIGO_HOME, TMPDIR) and of the
//! project directory, comparing kind, length, mtime and a content hash. A touch, a rewrite and a delete
//! all count, and a file created and removed inside one directory still moves that directory's mtime.
//! It reads the persistent end state: a file created and removed in a directory that was itself created
//! and removed in between is not seen. Inspection errors fail the test rather than reading as "empty".
//!
//! The project directory is NOT under the system temp dir: `MemoryStorage` treats a temp-dir cwd as
//! ephemeral and silently skips every daily-log write there, which would blind the control to flush,
//! session-end and dream writes. A planted `MEMORY.md` and an orphan `tmp*` workspace directory (the
//! shape memory garbage collection removes) are the canaries.
//!
//! Phase 1 keeps the idle flush off (one hour) so every explicit trigger runs alone and each flush log
//! is attributable to its trigger. Phase 2 restarts the agent in the same sandbox with a 2 s idle flush,
//! resumes the session and goes quiet, so the `interval` log can only come from the idle flush.
//!
//! Out of reach of this harness, and covered by code trace and unit tests only (see the P53 receipt):
//! * the 30 s startup dream timer (the explicit `/dream` reaches the same code);
//! * the leader-mode config hot reload (Murage runs `--no-leader`, which has no config watcher);
//! * embeddings: the provider only gets credentials for a first-party base URL, which the loopback mock
//!   is not, so no embedding request is ever sent, with or without the flag;
//! * the per-turn `memory.tar.gz` upload: it needs a session registry, which needs first-party OIDC
//!   auth, and this harness authenticates with an API key. `upload::memory::tests` covers the decision.
//!
//! Needs a built `fuigo` binary: `FUIGO_BINARY`, else a local `fuigo-pager` build (`fuigo_binary()`).
//! The binary's path, size and digest are logged so a stale binary is visible in the log.
// Test, bench or example code: its prints reach a harness or a developer, never a user, so the
// workspace print deny (R077) is waived here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use fuigo_test_support::sse::chat_completions_reasoning_then_tool_call_events;
use fuigo_test_support::{
    FuigoStdioClient, InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer,
    ScriptedResponse, TestSandbox, fuigo_binary, scaled,
};
use serde_json::json;
use tokio::task::LocalSet;

/// Appears in the user prompts and in every model reply. A memory flush, dream or session log built
/// from this conversation would carry it.
const SENTINEL: &str = "P53-NOMEM-SENTINEL";
/// The fixed model reply: a valid memory document (has a `##` header), so a flush or dream that
/// runs is ACCEPTED and written rather than rejected. The main-turn reply is the same text.
/// Long enough (over 500 chars) to pass the compaction summary floor, so a compaction on either side succeeds.
const REPLY: &str = "## P53-NOMEM-SENTINEL durable fact\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n\
- the project builds with sentinel-p53 and every build step is recorded here for later sessions\n";
const CANARY_BODY: &str = "# Pre-existing global memory\n- p53 canary, must never change\n";
/// Murage's leading argv, minus the flag under test.
const MURAGE_LEADING: &[&str] = &["--permission-mode", "default"];
/// Env both agents get, hostile on purpose: `FUIGO_MEMORY=1` tries to force memory on, an inherited
/// `FUIGO_MEMTRACE=1` tries to force the process-memory trace on, and the memtrace interval is the
/// sampler's minimum so its first file appears within the run. `--no-memory` must beat all of it.
const AGENT_ENV: &[(&str, &str)] = &[
    ("FUIGO_MEMORY", "1"),
    ("FUIGO_MEMTRACE", "1"),
    ("FUIGO_MEMTRACE_INTERVAL_SECS", "5"),
];
/// Every memory feature on, as hostile as the config allows: a flush on every compaction (threshold
/// headroom larger than any window), dream with no gates, session-end save, watcher on. `{IDLE}` is the idle-flush period, in seconds.
const HOSTILE_CONFIG: &str = r#"
[memory]
enabled = true

[memory.session]
save_on_end = true

[memory.watcher]
enabled = true

[memory.dream]
enabled = true
min_hours = 0
min_sessions = 0
check_interval_secs = 1

[compaction.memory_flush]
enabled = true
soft_threshold_tokens = 100000000
idle_timeout_secs = {IDLE}
"#;
const IDLE_PHASE1_SECS: u64 = 3600;
const IDLE_PHASE2_SECS: u64 = 2;
/// Quiet time in phase 2: the 2 s idle timer fires at least once, with room for a loaded host.
const IDLE_WINDOW: Duration = Duration::from_secs(8);
/// After a session close or a compaction, the memory work it triggers runs detached; give it time.
const SETTLE: Duration = Duration::from_secs(3);

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Dir { mtime_ns: u128 },
    File { len: u64, mtime_ns: u128, hash: u64 },
    Other,
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn mtime_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .unwrap_or_else(|e| panic!("cannot read an mtime: {e}"))
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// A path that vanished between listing and inspection (a lock file, a temp file) is not an error;
/// anything else is, because a silent skip would read as "nothing changed".
fn inspect<T>(what: &Path, result: std::io::Result<T>) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("snapshot cannot inspect {}: {e}", what.display()),
    }
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Kind>) {
    let Some(entries) = inspect(dir, std::fs::read_dir(dir)) else { return };
    for entry in entries {
        let Some(entry) = inspect(dir, entry) else { continue };
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let Some(meta) = inspect(&path, std::fs::symlink_metadata(&path)) else { continue };
        if meta.is_dir() {
            out.insert(rel, Kind::Dir { mtime_ns: mtime_ns(&meta) });
            walk(root, &path, out);
        } else if meta.is_file() {
            let Some(bytes) = inspect(&path, std::fs::read(&path)) else { continue };
            out.insert(
                rel,
                Kind::File { len: meta.len(), mtime_ns: mtime_ns(&meta), hash: hash_bytes(&bytes) },
            );
        } else {
            out.insert(rel, Kind::Other);
        }
    }
}

/// The sandbox root and the project directory, the project's paths prefixed `project/`.
fn snapshot_all(root: &Path, project: &Path) -> BTreeMap<String, Kind> {
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    let mut proj = BTreeMap::new();
    walk(project, project, &mut proj);
    out.extend(proj.into_iter().map(|(k, v)| (format!("project/{k}"), v)));
    out
}

/// Paths created, modified or deleted between two snapshots, each tagged with what happened.
fn diff(before: &BTreeMap<String, Kind>, after: &BTreeMap<String, Kind>) -> Vec<String> {
    let mut changed = Vec::new();
    for (path, kind) in after {
        match before.get(path) {
            None => changed.push(format!("created  {path}")),
            Some(old) if old != kind => changed.push(format!("modified {path}")),
            Some(_) => {}
        }
    }
    for path in before.keys() {
        if !after.contains_key(path) {
            changed.push(format!("deleted  {path}"));
        }
    }
    changed
}

/// Whether a changed path is memory by name: the memory store, its index, the dream lock and
/// consolidation marker, flush and session logs, embeddings, and the process-memory trace.
fn is_memory_path(entry: &str) -> bool {
    let path = entry
        .split_once(' ')
        .map_or(entry, |(_, p)| p.trim())
        .to_lowercase();
    // The user guide the agent installs on first run has a chapter named `13-memory.md`; it is
    // documentation. Session persistence directories are named after the project path, which a
    // developer's checkout may put anything in.
    if path.contains("/docs/user-guide/") || path.starts_with("home/.fuigo/sessions/") {
        return false;
    }
    ["memory", "memtrace", "dream", "consolidat", "index.sqlite", "embedding"]
        .iter()
        .any(|needle| path.contains(needle))
}

struct Outcome {
    /// Every changed path, whatever it is.
    changed: Vec<String>,
    /// The subset that is memory.
    memory_changed: Vec<String>,
    /// `x-fuigo-req-id` of every flush or dream model request that reached the mock.
    memory_requests: Vec<String>,
    /// Whether any chat request offered a `memory_*` tool.
    memory_tools_offered: bool,
    /// The `fuigo/memory/rewrite` reply: `Ok`, or the error's JSON-RPC code and message.
    rewrite: Result<(), (i64, String)>,
    /// Chat requests that carry the note-formatter system prompt (the rewrite's model call).
    rewrite_requests: usize,
    /// Which of the planted canaries survived untouched.
    canary_intact: bool,
    orphan_dir_survived: bool,
    /// Some `.md` under a `memory/` tree contains the conversation sentinel.
    sentinel_in_memory_logs: bool,
    /// A workspace `MEMORY.md` (not the planted one) carries the sentinel: dream consolidated and wrote.
    consolidated_memory_has_sentinel: bool,
    stderr: String,
}

/// A project directory outside the system temp dir, so memory is not treated as ephemeral.
fn project_dir() -> tempfile::TempDir {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&base).expect("target tmpdir");
    let dir = tempfile::Builder::new()
        .prefix("p53-project-")
        .tempdir_in(&base)
        .expect("project dir");
    let canonical = canonical(dir.path());
    let temp = canonical_of_temp();
    assert!(
        !canonical.starts_with(&temp)
            && !canonical.starts_with("/tmp")
            && !canonical.starts_with("/var/tmp")
            && !canonical.starts_with("/private/tmp"),
        "project dir {} is under the system temp dir, so memory treats it as ephemeral and the control \
         cannot see daily-log writes; point CARGO_TARGET_DIR outside the temp dir",
        canonical.display()
    );
    dir
}

fn canonical(path: &Path) -> std::path::PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn canonical_of_temp() -> std::path::PathBuf {
    canonical(&std::env::temp_dir())
}

/// Log which binary is under test: path, size and a digest, so a stale binary is visible in the log
/// (`fuigo_binary()` returns an existing binary without rebuilding it).
fn log_binary_identity() {
    use std::hash::{Hash, Hasher};
    let bin = fuigo_binary();
    let bytes = std::fs::read(&bin).unwrap_or_default();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    eprintln!(
        "[p53] FUIGO_BINARY={:?} resolved={} bytes={} hash={:016x}",
        std::env::var_os("FUIGO_BINARY"),
        bin.display(),
        bytes.len(),
        hasher.finish()
    );
}

/// An extension call with a deadline, so a stalled handler fails the test instead of hanging the gate.
async fn ext(
    client: &FuigoStdioClient,
    method: &str,
    params: serde_json::Value,
) -> agent_client_protocol::Result<agent_client_protocol::ExtResponse> {
    tokio::time::timeout(scaled(Duration::from_secs(60)), client.ext_method(method, params))
        .await
        .unwrap_or_else(|_| panic!("{method} timed out\nstderr:\n{}", client.stderr()))
}

fn config_with_idle(idle_secs: u64) -> String {
    HOSTILE_CONFIG.replace("{IDLE}", &idle_secs.to_string())
}

async fn scenario(no_memory: bool) -> Outcome {
    let server = MockInferenceServer::start().await.expect("start mock");
    server.set_response(REPLY);
    let sandbox = TestSandbox::new();
    let project = project_dir();
    let cwd = project.path().to_path_buf();
    std::fs::write(cwd.join("README.md"), "# p53 project\n").expect("project file");
    let fuigo_home = sandbox.fuigo_home().to_path_buf();
    let memory_root = fuigo_home.join("memory");
    std::fs::write(fuigo_home.join("config.toml"), config_with_idle(IDLE_PHASE1_SECS))
        .expect("write config");
    std::fs::create_dir_all(&memory_root).expect("memory root");
    std::fs::write(memory_root.join("MEMORY.md"), CANARY_BODY).expect("plant canary");
    let orphan = memory_root.join("tmp-p53-orphan");
    std::fs::create_dir_all(&orphan).expect("plant orphan");
    let root = sandbox.root().to_path_buf();
    let before = snapshot_all(&root, &cwd);

    let mut leading: Vec<&str> = MURAGE_LEADING.to_vec();
    if no_memory {
        leading.push("--no-memory");
    }

    // ---- phase 1: every explicit trigger, one at a time -------------------------------------------
    let mut client =
        FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, AGENT_ENV, &leading)
            .await;
    client.initialize_with_timeout().await;
    let session = client.create_session_with_timeout(&cwd).await;
    let sid = session.to_string();
    for turn in 0..3 {
        let text = format!("{SENTINEL} turn {turn}: {}", "context padding words ".repeat(200));
        let reply = client.prompt_with_timeout(&session, &text).await;
        assert!(reply.is_ok(), "turn {turn} failed: {reply:?}\n{}", client.stderr());
    }
    // The explicit memory entry points. Under `--no-memory` these may be refused or ignored; they
    // must never write. Their results are not asserted, only their effects.
    for slash in ["/flush", "/memory on", "/memory", "/dream"] {
        let _ = client.prompt_with_timeout(&session, slash).await;
    }
    let _ = ext(&client, "fuigo/memory/flush", json!({ "session_id": sid })).await;
    let rewrite = ext(
        &client,
        "fuigo/memory/rewrite",
        json!({ "sessionId": sid, "rawText": SENTINEL, "contextSummary": SENTINEL }),
    )
    .await;
    // Dream consolidates OTHER sessions' logs, so it needs a second session in the same project that
    // finds the first one's flush logs.
    let second = client.create_session_with_timeout(&cwd).await;
    let _ = client
        .prompt_with_timeout(&second, &format!("{SENTINEL} second session"))
        .await;
    let _ = client.prompt_with_timeout(&second, "/dream").await;
    // Compaction last: its memory flush runs detached. The compaction and the turn after it are NOT
    // memory features, so they must succeed on both sides: a failure on one side would otherwise let
    // that side skip the memory work and still look clean (or look different from the control).
    ext(
        &client,
        "fuigo/compact_conversation",
        json!({ "session_id": sid, "user_context": "keep the sentinel" }),
    )
    .await
    .unwrap_or_else(|e| panic!("compaction failed (no_memory={no_memory}): {e:?}\n{}", client.stderr()));
    let reply = client
        .prompt_with_timeout(&session, &format!("{SENTINEL} after compaction"))
        .await;
    assert!(reply.is_ok(), "turn after compaction failed (no_memory={no_memory}): {reply:?}");
    tokio::time::sleep(scaled(SETTLE)).await;
    // Close both sessions: that is what runs the session-end memory save (a SIGTERM does not).
    for closing in [&second, &session] {
        ext(&client, "fuigo/session/close", json!({ "sessionId": closing.to_string() }))
            .await
            .unwrap_or_else(|e| panic!("session close failed (no_memory={no_memory}): {e:?}"));
    }
    tokio::time::sleep(scaled(SETTLE)).await;
    let _ = client.close().await;
    let mut stderr = client.stderr();
    let sandbox = client.take_sandbox();

    // ---- phase 2: restart in the same sandbox, resume, go quiet --------------------------------------
    std::fs::write(fuigo_home.join("config.toml"), config_with_idle(IDLE_PHASE2_SECS))
        .expect("rewrite config");
    let mut client =
        FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, AGENT_ENV, &leading)
            .await;
    client.initialize_with_timeout().await;
    client.load_session_with_timeout(&session, &cwd).await;
    let reply = client
        .prompt_with_timeout(&session, &format!("{SENTINEL} after resume"))
        .await;
    assert!(reply.is_ok(), "turn after resume failed (no_memory={no_memory}): {reply:?}");
    tokio::time::sleep(scaled(IDLE_WINDOW)).await;
    ext(&client, "fuigo/session/close", json!({ "sessionId": sid }))
        .await
        .unwrap_or_else(|e| panic!("session close after resume failed (no_memory={no_memory}): {e:?}"));
    tokio::time::sleep(scaled(SETTLE)).await;
    let _ = client.close().await;
    stderr.push_str(&client.stderr());
    let sandbox = client.take_sandbox();
    assert_eq!(root, sandbox.root());

    let after = snapshot_all(&root, &cwd);
    let changed = diff(&before, &after);
    let memory_changed: Vec<String> = changed.iter().filter(|c| is_memory_path(c)).cloned().collect();
    let requests = server.requests();
    let memory_requests: Vec<String> = requests
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter_map(|r| r.header("x-fuigo-req-id").map(str::to_owned))
        .filter(|id| id.starts_with("fuigo-flush-") || id.starts_with("fuigo-dream-"))
        .collect();
    let rewrite_requests = requests
        .iter()
        .filter(|r| r.body.as_ref().is_some_and(|b| b.to_string().contains("memory note formatter")))
        .count();
    let rewrite = rewrite.map(|_| ()).map_err(|e| {
        let v = serde_json::to_value(&e).unwrap_or_default();
        // The typed detail (kind + reason) rides in `data`; the top-level message is the generic JSON-RPC text.
        (v["code"].as_i64().unwrap_or_default(), format!("{} {}", v["message"], v["data"]))
    });
    let memory_tools_offered = requests
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter_map(|r| r.body.as_ref().and_then(|b| b["tools"].as_array()).cloned())
        .flatten()
        .any(|t| {
            t["function"]["name"]
                .as_str()
                .is_some_and(|n| n.starts_with("memory_"))
        });
    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    for r in &requests {
        *histogram.entry(r.path.clone()).or_default() += 1;
    }
    let canary_rel = memory_root
        .join("MEMORY.md")
        .strip_prefix(&root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    let canary_intact = before.get(&canary_rel) == after.get(&canary_rel)
        && std::fs::read_to_string(memory_root.join("MEMORY.md")).is_ok_and(|b| b == CANARY_BODY);
    let orphan_dir_survived = orphan.is_dir();
    let sentinel_in_memory_logs = after.keys().any(|k| {
        k.contains("memory/") && k.ends_with(".md") && !k.contains("/docs/") && {
            std::fs::read_to_string(root.join(k)).is_ok_and(|b| b.contains(SENTINEL))
        }
    });
    let consolidated_memory_has_sentinel = after.keys().any(|k| {
        k.contains("memory/") && k.ends_with("/MEMORY.md") && *k != canary_rel && {
            std::fs::read_to_string(root.join(k)).is_ok_and(|b| b.contains(SENTINEL))
        }
    });
    eprintln!(
        "[p53] no_memory={no_memory} changed={} memory_changed={} memory_requests={} \
         memory_tools_offered={memory_tools_offered}",
        changed.len(),
        memory_changed.len(),
        memory_requests.len(),
    );
    eprintln!("[p53] no_memory={no_memory} request paths: {histogram:?}");
    for c in &memory_changed {
        eprintln!("[p53] no_memory={no_memory}   MEMORY {c}");
    }
    for r in &memory_requests {
        eprintln!("[p53] no_memory={no_memory}   REQUEST {r}");
    }
    Outcome {
        changed,
        memory_changed,
        memory_requests,
        memory_tools_offered,
        rewrite,
        rewrite_requests,
        canary_intact,
        orphan_dir_survived,
        sentinel_in_memory_logs,
        consolidated_memory_has_sentinel,
        stderr,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn no_memory_writes_nothing_and_the_control_proves_the_detector_sees_memory() {
    log_binary_identity();
    let local = LocalSet::new();
    let (subject, control) = local
        .run_until(async { tokio::join!(scenario(true), scenario(false)) })
        .await;

    // Positive control first: with the flag absent the same scenario DOES write memory. If this
    // fails the harness cannot see memory writes and the subject result below is meaningless.
    assert!(
        !control.memory_changed.is_empty(),
        "CONTROL wrote no memory file: the detector is blind.\nchanged: {:#?}\nstderr:\n{}",
        control.changed,
        control.stderr
    );
    let wrote = |needle: &str| control.memory_changed.iter().any(|c| c.contains(needle));
    assert!(wrote("/index.sqlite"), "CONTROL created no memory index: {:#?}", control.memory_changed);
    // Dream committed: the consolidation marker exists and the workspace MEMORY.md carries the
    // consolidated conversation (the empty template `ensure_initialized` writes would not).
    assert!(wrote("/.dream-consolidated"), "CONTROL committed no dream marker: {:#?}", control.memory_changed);
    assert!(
        control.consolidated_memory_has_sentinel,
        "CONTROL's dream wrote no consolidated MEMORY.md: {:#?}",
        control.memory_changed
    );
    // Every flush trigger wrote a log under its own name: idle (`interval`, phase 2 only), compaction,
    // `/flush` and the `fuigo/memory/flush` extension (`user_requested`).
    for trigger in ["interval", "pre_compaction", "slash_command", "user_requested"] {
        assert!(
            control
                .memory_changed
                .iter()
                .any(|c| c.contains("/sessions/") && c.contains(&format!("-{trigger}-"))),
            "CONTROL never wrote a `{trigger}` flush log: {:#?}",
            control.memory_changed
        );
    }
    // The session-end save names its log after the first user query, not after a flush trigger.
    assert!(
        control.memory_changed.iter().any(|c| c.contains("/sessions/")
            && c.contains("p53-nomem")
            && !["interval", "pre_compaction", "slash_command", "user_requested"]
                .iter()
                .any(|t| c.contains(&format!("-{t}-")))),
        "CONTROL wrote no session-end log: {:#?}",
        control.memory_changed
    );
    assert!(
        control.memory_requests.iter().any(|id| id.starts_with("fuigo-dream-")),
        "CONTROL never reached the dream model call: {:?}",
        control.memory_requests
    );
    assert!(
        control.sentinel_in_memory_logs,
        "CONTROL's memory logs do not carry the conversation sentinel: the flush did not write this conversation"
    );
    assert!(
        !control.orphan_dir_survived,
        "CONTROL did not garbage-collect the planted orphan: the gc write path was not exercised"
    );
    assert!(wrote("memtrace"), "CONTROL wrote no memtrace file: {:#?}", control.memory_changed);
    assert!(control.memory_tools_offered, "CONTROL was not offered memory_* tools");
    assert_eq!(control.rewrite, Ok(()), "CONTROL's fuigo/memory/rewrite failed");
    assert!(control.rewrite_requests > 0, "CONTROL's rewrite never reached the model");

    // The claim. Subject: nothing memory-like changed, the canaries are untouched, and no flush
    // or dream model call was even made.
    assert!(
        subject.memory_changed.is_empty(),
        "--no-memory still wrote memory: {:#?}\nall changes: {:#?}\nstderr:\n{}",
        subject.memory_changed,
        subject.changed,
        subject.stderr
    );
    assert!(subject.canary_intact, "--no-memory modified the planted MEMORY.md");
    assert!(subject.orphan_dir_survived, "--no-memory garbage-collected memory directories");
    assert!(
        subject.memory_requests.is_empty(),
        "--no-memory still made memory model requests: {:?}",
        subject.memory_requests
    );
    assert!(!subject.memory_tools_offered, "--no-memory still offered memory_* tools");
    // `fuigo/memory/rewrite` is refused with a typed invalid-request error and never calls the model.
    let (code, message) = subject.rewrite.clone().expect_err("--no-memory must refuse fuigo/memory/rewrite");
    assert_eq!(code, -32600, "refusal is an invalid-request error: {message}");
    assert!(message.contains("memory is not enabled"), "refusal names the reason: {message}");
    assert_eq!(subject.rewrite_requests, 0, "--no-memory still sent the note to the model");
}

// ---------------------------------------------------------------------------------------------
// The startup dream timer, with its 30 s delay made controllable.
// ---------------------------------------------------------------------------------------------

/// Env for the two startup-dream phases: the startup timer delay is the test seam, and the periodic dream check
/// is pushed far out so ONLY the startup timer can start a dream.
const STARTUP_DREAM_CONFIG: &str = r#"
[memory]
enabled = true

[memory.dream]
enabled = true
min_hours = 0
min_sessions = 0
check_interval_secs = 3600

[compaction.memory_flush]
enabled = true
soft_threshold_tokens = 100000000
idle_timeout_secs = 3600
"#;

/// Two agent runs in one sandbox. Run 1 (startup delay an hour) leaves a flush log from session one. Run 2 (startup
/// delay 2 s) opens a NEW session and goes quiet: the only thing that can start a dream is the startup timer, because
/// no `/dream` is ever sent and the periodic check is an hour out. Returns the number of dream model requests seen
/// in run 2 and the paths of memory files changed.
async fn startup_dream_scenario(no_memory: bool) -> (usize, Vec<String>) {
    let server = MockInferenceServer::start().await.expect("start mock");
    server.set_response(REPLY);
    let sandbox = TestSandbox::new();
    let project = project_dir();
    let cwd = project.path().to_path_buf();
    std::fs::write(cwd.join("README.md"), "# p53 project\n").expect("project file");
    std::fs::write(sandbox.fuigo_home().join("config.toml"), STARTUP_DREAM_CONFIG).expect("config");
    let mut leading: Vec<&str> = MURAGE_LEADING.to_vec();
    if no_memory {
        leading.push("--no-memory");
    }
    let env_run1: Vec<(&str, &str)> = vec![("FUIGO_MEMORY", "1"), ("FUIGO_MEMORY_DREAM_STARTUP_SECS", "3600")];
    let env_run2: Vec<(&str, &str)> = vec![("FUIGO_MEMORY", "1"), ("FUIGO_MEMORY_DREAM_STARTUP_SECS", "2")];

    let mut client =
        FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, &env_run1, &leading).await;
    client.initialize_with_timeout().await;
    let first = client.create_session_with_timeout(&cwd).await;
    let reply = client.prompt_with_timeout(&first, &format!("{SENTINEL} run one")).await;
    assert!(reply.is_ok(), "run-one turn failed: {reply:?}");
    let _ = client.prompt_with_timeout(&first, "/flush").await;
    tokio::time::sleep(scaled(SETTLE)).await;
    let _ = client.close().await;
    let sandbox = client.take_sandbox();
    let root = sandbox.root().to_path_buf();
    let dreams_before = dream_requests(&server);
    assert_eq!(dreams_before, 0, "no dream may run in run one (no_memory={no_memory})");
    let before = snapshot_all(&root, &cwd);

    let mut client =
        FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, &env_run2, &leading).await;
    client.initialize_with_timeout().await;
    let second = client.create_session_with_timeout(&cwd).await;
    let reply = client.prompt_with_timeout(&second, &format!("{SENTINEL} run two")).await;
    assert!(reply.is_ok(), "run-two turn failed: {reply:?}");
    tokio::time::sleep(scaled(IDLE_WINDOW)).await;
    let _ = client.close().await;
    let sandbox = client.take_sandbox();
    let after = snapshot_all(sandbox.root(), &cwd);
    let memory_changed: Vec<String> =
        diff(&before, &after).into_iter().filter(|c| is_memory_path(c)).collect();
    (dream_requests(&server), memory_changed)
}

fn dream_requests(server: &MockInferenceServer) -> usize {
    server
        .requests()
        .iter()
        .filter(|r| r.path == "/v1/chat/completions")
        .filter_map(|r| r.header("x-fuigo-req-id").map(str::to_owned))
        .filter(|id| id.starts_with("fuigo-dream-"))
        .count()
}

#[tokio::test(flavor = "current_thread")]
async fn no_memory_stops_the_startup_dream_timer() {
    log_binary_identity();
    let local = LocalSet::new();
    let ((subject_dreams, subject_changed), (control_dreams, control_changed)) = local
        .run_until(async { tokio::join!(startup_dream_scenario(true), startup_dream_scenario(false)) })
        .await;
    // Positive control: with the flag absent the startup timer alone starts a dream.
    assert!(
        control_dreams > 0,
        "CONTROL's startup dream timer never started a dream: the test cannot see the timer. changed: {control_changed:#?}"
    );
    assert_eq!(subject_dreams, 0, "--no-memory still ran the startup dream timer");
    assert!(subject_changed.is_empty(), "--no-memory wrote memory in run two: {subject_changed:#?}");
}

// ---------------------------------------------------------------------------------------------
// Agent memory: a subagent whose definition says `memory: user`.
// ---------------------------------------------------------------------------------------------

const AGENT_MEMORY_CANARY: &str = "P53-AGENT-MEMORY-CANARY";
const MEMORY_AGENT: &str = "p53-memagent";
/// Text only the child agent's own system prompt contains.
const CHILD_PROMPT_MARKER: &str = "You are the P53 agent.";

struct AgentMemoryOutcome {
    /// Memory-looking paths that changed.
    memory_changed: Vec<String>,
    /// Chat requests whose body carries the planted agent-memory text.
    requests_with_canary: usize,
    /// Chat requests that carry the child agent's own system prompt: proves the child actually ran.
    child_requests: usize,
    canary_intact: bool,
    stderr: String,
}

async fn agent_memory_scenario(no_memory: bool) -> AgentMemoryOutcome {
    let server = MockInferenceServer::start().await.expect("start mock");
    server.set_response(REPLY);
    // The parent's first foreground request spawns the memory agent; everything after falls through
    // to the fixed reply.
    let args = json!({
        "description": "p53 agent-memory child",
        "prompt": "say hello",
        "subagent_type": MEMORY_AGENT,
    });
    let spawn = server.expect_response(
        "p53-spawn-memory-agent",
        InferenceRequestMatcher::foreground(InferenceEndpoint::ChatCompletions),
        ScriptedResponse::sse(chat_completions_reasoning_then_tool_call_events(
            "spawn",
            "call_p53_spawn",
            "spawn_subagent",
            &args.to_string(),
            "test-model",
        )),
    );
    let sandbox = TestSandbox::new();
    let project = project_dir();
    let cwd = project.path().to_path_buf();
    std::fs::write(cwd.join("README.md"), "# p53 project\n").expect("project file");
    let fuigo_home = sandbox.fuigo_home().to_path_buf();
    std::fs::create_dir_all(fuigo_home.join("agents")).expect("agents dir");
    std::fs::write(
        fuigo_home.join(format!("agents/{MEMORY_AGENT}.md")),
        format!(
            "---\nname: {MEMORY_AGENT}\ndescription: P53 agent with persistent memory\nmemory: user\n---\nYou are the P53 agent.\n"
        ),
    )
    .expect("agent definition");
    let agent_memory = fuigo_home.join("agent-memory").join(MEMORY_AGENT);
    std::fs::create_dir_all(&agent_memory).expect("agent memory dir");
    let canary_file = agent_memory.join("MEMORY.md");
    let canary_body = format!("# agent notes\n- {AGENT_MEMORY_CANARY}\n");
    std::fs::write(&canary_file, &canary_body).expect("plant agent memory");
    let root = sandbox.root().to_path_buf();
    let before = snapshot_all(&root, &cwd);

    let mut leading: Vec<&str> = MURAGE_LEADING.to_vec();
    if no_memory {
        leading.push("--no-memory");
    }
    let mut client =
        FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, AGENT_ENV, &leading)
            .await;
    client.initialize_with_timeout().await;
    let session = client.create_session_with_timeout(&cwd).await;
    let reply = tokio::time::timeout(
        scaled(Duration::from_secs(120)),
        client.prompt(&session, "run the p53 memory agent"),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the spawning turn timed out (no_memory={no_memory}); mock saw {:?}\n{}",
            server.requests().iter().map(|r| r.path.clone()).collect::<Vec<_>>(),
            client.stderr()
        )
    });
    assert!(reply.is_ok(), "the spawning turn failed: {reply:?}\n{}", client.stderr());
    tokio::time::sleep(scaled(SETTLE)).await;
    let _ = client.close().await;
    let stderr = client.stderr();
    let sandbox = client.take_sandbox();
    assert_eq!(root, sandbox.root());
    assert!(spawn.is_satisfied(), "the scripted spawn_subagent reply was never claimed\n{stderr}");

    let after = snapshot_all(&root, &cwd);
    let changed = diff(&before, &after);
    let memory_changed: Vec<String> = changed.iter().filter(|c| is_memory_path(c)).cloned().collect();
    let requests = server.requests();
    let chat: Vec<_> = requests.iter().filter(|r| r.path == "/v1/chat/completions").collect();
    let requests_with_canary = chat
        .iter()
        .filter(|r| r.body.as_ref().is_some_and(|b| b.to_string().contains(AGENT_MEMORY_CANARY)))
        .count();
    let child_requests = chat
        .iter()
        .filter(|r| r.body.as_ref().is_some_and(|b| b.to_string().contains(CHILD_PROMPT_MARKER)))
        .count();
    let child_tools: Vec<String> = chat
        .iter()
        .filter(|r| r.body.as_ref().is_some_and(|b| b.to_string().contains(CHILD_PROMPT_MARKER)))
        .filter_map(|r| r.body.as_ref().and_then(|b| b["tools"].as_array()).cloned())
        .flatten()
        .filter_map(|t| t["function"]["name"].as_str().map(str::to_owned))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    eprintln!(
        "[p53] agent-memory no_memory={no_memory} chat_requests={} child_requests={child_requests} \
         with_canary={requests_with_canary} child_tools={child_tools:?} memory_changed={memory_changed:?}",
        chat.len()
    );
    AgentMemoryOutcome {
        memory_changed,
        requests_with_canary,
        child_requests,
        canary_intact: std::fs::read_to_string(&canary_file).is_ok_and(|b| b == canary_body),
        stderr,
    }
}

/// `--no-memory` must not hand a subagent persistent agent memory either: the child's prompt must not
/// carry the agent's MEMORY.md, and (with the child given no memory write tools) nothing under the
/// agent-memory directory may change. The control, without the flag, must carry the canary.
#[tokio::test(flavor = "current_thread")]
async fn no_memory_withholds_agent_memory_from_subagents() {
    log_binary_identity();
    let local = LocalSet::new();
    let (subject, control) = local
        .run_until(async { tokio::join!(agent_memory_scenario(true), agent_memory_scenario(false)) })
        .await;
    assert!(control.child_requests > 0, "CONTROL never ran the child: {}", control.stderr);
    assert!(
        control.requests_with_canary > 0,
        "CONTROL's child never saw its agent memory, so the memory agent was not wired:\n{}",
        control.stderr
    );
    assert!(
        subject.child_requests > 0,
        "SUBJECT never ran the child, so its missing agent memory proves nothing: {}",
        subject.stderr
    );
    assert_eq!(
        subject.requests_with_canary, 0,
        "--no-memory still injected the agent's MEMORY.md into a subagent prompt"
    );
    assert!(subject.canary_intact, "--no-memory modified the agent's MEMORY.md");
    assert!(
        subject.memory_changed.is_empty(),
        "--no-memory still wrote agent memory: {:#?}",
        subject.memory_changed
    );
}

// ---------------------------------------------------------------------------------------------
// A memory note is decided by the shell at write time (`fuigo/memory/save_note`).
// ---------------------------------------------------------------------------------------------

const NOTE_ONE: &str = "P53 note one: the deploy needs the staging flag";
const NOTE_TWO: &str = "P53 note two: written after memory is back on";
const NOTE_REFUSED: &str = "P53 note refused: memory is off";

/// The workspace `MEMORY.md` the shell would write, if one exists: any `memory/<workspace>/MEMORY.md`.
fn workspace_memory_file(root: &Path) -> Option<String> {
    let snap = snapshot_all(root, root.join("nonexistent-project").as_path());
    snap.keys()
        .find(|k| k.starts_with("home/.fuigo/memory/") && k.ends_with("/MEMORY.md") && k.matches('/').count() == 4)
        .and_then(|k| std::fs::read_to_string(root.join(k)).ok())
}

async fn save_note(
    client: &FuigoStdioClient,
    session: &agent_client_protocol::SessionId,
    text: &str,
) -> Result<(), (i64, String)> {
    ext(client, "fuigo/memory/save_note", json!({ "sessionId": session.to_string(), "text": text }))
        .await
        .map(|_| ())
        .map_err(|e| {
            let v = serde_json::to_value(&e).unwrap_or_default();
            (v["code"].as_i64().unwrap_or_default(), format!("{} {}", v["message"], v["data"]))
        })
}

/// One agent, one session. The client holds NO memory state of its own: it never reads an available-commands update,
/// which is exactly a pager whose first update was dropped, or whose cache went stale after another client acted.
async fn note_scenario(no_memory: bool) -> (Vec<Result<(), (i64, String)>>, Vec<Option<String>>, Vec<String>) {
    let server = MockInferenceServer::start().await.expect("start mock");
    server.set_response(REPLY);
    let sandbox = TestSandbox::new();
    let project = project_dir();
    let cwd = project.path().to_path_buf();
    std::fs::write(cwd.join("README.md"), "# p53 project\n").expect("project file");
    std::fs::write(sandbox.fuigo_home().join("config.toml"), config_with_idle(IDLE_PHASE1_SECS)).expect("config");
    let root = sandbox.root().to_path_buf();
    let before = snapshot_all(&root, &cwd);
    let mut leading: Vec<&str> = MURAGE_LEADING.to_vec();
    if no_memory {
        leading.push("--no-memory");
    }
    let mut client =
        FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, AGENT_ENV, &leading).await;
    client.initialize_with_timeout().await;
    let session = client.create_session_with_timeout(&cwd).await;
    let reply = client.prompt_with_timeout(&session, &format!("{SENTINEL} note scenario")).await;
    assert!(reply.is_ok(), "turn failed: {reply:?}");

    let mut results = Vec::new();
    let mut files = Vec::new();
    // 1. The first note, with memory on (control) or off (subject).
    results.push(save_note(&client, &session, NOTE_ONE).await);
    files.push(workspace_memory_file(&root));
    // 2. "Another client turns memory off": any client's /memory off reaches the same session. The note this client
    //    saves next carries whatever it believed before, and must be refused.
    let _ = client.prompt_with_timeout(&session, "/memory off").await;
    results.push(save_note(&client, &session, NOTE_REFUSED).await);
    files.push(workspace_memory_file(&root));
    // 3. Back on: the note works again, so the refusal was the live state, not a latch.
    let _ = client.prompt_with_timeout(&session, "/memory on").await;
    results.push(save_note(&client, &session, NOTE_TWO).await);
    files.push(workspace_memory_file(&root));
    let _ = client.close().await;
    let sandbox = client.take_sandbox();
    let after = snapshot_all(sandbox.root(), &cwd);
    let memory_changed: Vec<String> = diff(&before, &after).into_iter().filter(|c| is_memory_path(c)).collect();
    (results, files, memory_changed)
}

#[tokio::test(flavor = "current_thread")]
async fn a_memory_note_is_decided_by_the_shell_at_write_time() {
    log_binary_identity();
    let local = LocalSet::new();
    let ((subject, subject_files, subject_changed), (control, control_files, _)) = local
        .run_until(async { tokio::join!(note_scenario(true), note_scenario(false)) })
        .await;

    // CONTROL (memory on): the note is saved with no client-side state at all (the unreported case); after
    // `/memory off` the same call is refused and the file is unchanged; after `/memory on` it saves again.
    assert_eq!(control[0], Ok(()), "a note with memory on and nothing reported must save");
    assert!(control_files[0].as_deref().is_some_and(|f| f.contains(NOTE_ONE)), "note one is in MEMORY.md");
    let (code, message) = control[1].clone().expect_err("a note after /memory off must be refused");
    assert_eq!(code, -32600, "typed invalid-request refusal: {message}");
    assert!(message.contains("memory is not enabled"), "refusal names the reason: {message}");
    assert_eq!(control_files[1], control_files[0], "the refused note wrote nothing");
    assert!(
        !control_files[1].as_deref().unwrap_or_default().contains(NOTE_REFUSED),
        "the refused note is not in MEMORY.md"
    );
    assert_eq!(control[2], Ok(()), "after /memory on the note saves again");
    let last = control_files[2].as_deref().unwrap_or_default();
    assert!(last.contains(NOTE_ONE) && last.contains(NOTE_TWO) && !last.contains(NOTE_REFUSED), "{last}");

    // SUBJECT (--no-memory): every note is refused and nothing memory-shaped is created.
    for (i, r) in subject.iter().enumerate() {
        let (code, message) = r.clone().expect_err("--no-memory refuses every note");
        assert_eq!(code, -32600, "note {i}: {message}");
    }
    assert!(subject_files.iter().all(Option::is_none), "no MEMORY.md under --no-memory: {subject_files:?}");
    assert!(subject_changed.is_empty(), "--no-memory wrote memory for a note: {subject_changed:#?}");
}

/// A note racing `/memory off` is either written entirely (the save returned `Ok` and the note is in `MEMORY.md`) or
/// refused entirely (the save returned an error and the note is not): never written after a refusal, never `Ok` without a
/// write. The check and the append run with no `.await` between them on the session's single thread, so a toggle cannot
/// land in the middle; this test would catch a regression that moved the append off that thread.
#[tokio::test(flavor = "current_thread")]
async fn a_memory_note_racing_memory_off_is_all_or_nothing() {
    log_binary_identity();
    let local = LocalSet::new();
    local
        .run_until(async {
            let server = MockInferenceServer::start().await.expect("start mock");
            server.set_response(REPLY);
            let sandbox = TestSandbox::new();
            let project = project_dir();
            let cwd = project.path().to_path_buf();
            std::fs::write(cwd.join("README.md"), "# p53 project\n").expect("project file");
            std::fs::write(sandbox.fuigo_home().join("config.toml"), config_with_idle(IDLE_PHASE1_SECS))
                .expect("config");
            let root = sandbox.root().to_path_buf();
            let mut client =
                FuigoStdioClient::spawn_with_sandbox_env_and_args(&server, &cwd, sandbox, AGENT_ENV, MURAGE_LEADING)
                    .await;
            client.initialize_with_timeout().await;
            let session = client.create_session_with_timeout(&cwd).await;
            let reply = client.prompt_with_timeout(&session, &format!("{SENTINEL} race")).await;
            assert!(reply.is_ok(), "turn failed: {reply:?}");
            let (mut written, mut refused) = (0, 0);
            for i in 0..8 {
                let note = format!("P53 race note {i}");
                let (saved, _) = tokio::join!(
                    save_note(&client, &session, &note),
                    client.prompt_with_timeout(&session, "/memory off")
                );
                let file = workspace_memory_file(&root).unwrap_or_default();
                match saved {
                    Ok(()) => {
                        written += 1;
                        assert!(file.contains(&note), "save said Ok but the note is not in MEMORY.md (round {i})");
                    }
                    Err((code, message)) => {
                        refused += 1;
                        assert_eq!(code, -32600, "{message}");
                        assert!(!file.contains(&note), "save was refused but the note was written (round {i})");
                    }
                }
                let _ = client.prompt_with_timeout(&session, "/memory on").await;
            }
            eprintln!("[p53] race: written={written} refused={refused}");
            let _ = client.close().await;
        })
        .await;
}
