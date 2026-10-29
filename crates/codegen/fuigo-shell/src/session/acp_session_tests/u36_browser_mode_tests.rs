//! u36 (item b): browser mode is in-memory state on the plan tracker and an overlay on the outgoing request. Leaving it
//! gives back the session's own head byte-for-byte, the client is told the true mode, approvals never move, and a head
//! 1.0.35 stored while browsing is repaired once at load and at cross-compaction rewind.
//!
//! Wire tests read the request from the mock inference server; mode-id tests use the bare support actor.

use super::*;
use crate::session::browser_mode::{OVERLAY_OPEN, browser_body, is_legacy_browser_head};
use fuigo_sampling_types::ConversationItem;

const HEAD: &str = "U36-SYS-HEAD: the session's own instructions.";
const OVERLAY_MARK: &str = "<!-- session-mode: browser_use -->";

fn browsing_head(stored: &str) -> String {
    format!("{stored}{OVERLAY_OPEN}{}", browser_body())
}

/// Every string in a JSON value that contains `needle`.
fn strings_containing(value: &serde_json::Value, needle: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if s.contains(needle) => out.push(s.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| strings_containing(v, needle, out)),
        serde_json::Value::Object(map) => map.values().for_each(|v| strings_containing(v, needle, out)),
        _ => {}
    }
}

/// The System head the last request carried, read from the wire.
#[track_caller]
fn last_request_head(server: &MockInferenceServer, stored_prefix: &str) -> String {
    let bodies = server.request_bodies();
    let body = bodies.last().expect("a request was sent");
    let mut found = Vec::new();
    strings_containing(body, stored_prefix, &mut found);
    assert_eq!(found.len(), 1, "exactly one wire string carries the head: {found:?}");
    found.remove(0)
}

async fn stored_head(actor: &SessionActor) -> String {
    match actor.chat_state_handle.get_conversation().await.first() {
        Some(ConversationItem::System(sys)) => sys.content.to_string(),
        other => panic!("no stored System head: {other:?}"),
    }
}

/// Everything browser mode must leave alone: permission mode, always-approve, the auto classifier, the session edit
/// grant and peer influence, folder trust for the cwd, the always-approve lock, and the session's agent.
#[derive(Debug, PartialEq)]
struct Authority {
    effective_mode: fuigo_workspace::permission::types::EffectivePermissionMode,
    yolo: bool,
    auto: bool,
    llm_classifier: bool,
    edit_grant: bool,
    peer_influenced: bool,
    trusted: bool,
    yolo_lock: Option<String>,
    agent_type: Option<String>,
}

fn authority(actor: &SessionActor) -> Authority {
    let p = &actor.permissions;
    Authority {
        effective_mode: p.effective_mode(),
        yolo: p.is_yolo_mode(),
        auto: p.is_auto_mode(),
        llm_classifier: p.has_llm_side_query(),
        edit_grant: p.session_edit_grant(),
        peer_influenced: p.is_peer_influenced(),
        trusted: crate::agent::folder_trust::project_scope_allowed(actor.tool_context.cwd.as_path()),
        yolo_lock: fuigo_workspace::permission::resolution::yolo_disabled_by_policy().map(str::to_owned),
        agent_type: actor.active_agent_type.lock().clone(),
    }
}

#[track_caller]
fn assert_authority(actor: &SessionActor, before: &Authority) {
    assert_eq!(&authority(actor), before, "browser mode moved an approval or the agent");
}

async fn wire_rig(head: &str) -> (MockInferenceServer, Arc<SessionActor>) {
    let server = MockInferenceServer::start().await.expect("mock inference server");
    let (actor, _h, _c, _p) =
        actor_with_sampler(&server, Arc::new(RecordingTerminal { calls: Arc::new(AtomicUsize::new(0)) })).await;
    actor.chat_state_handle.replace_conversation(vec![ConversationItem::system(head)]);
    (server, actor)
}

async fn turn(server: &MockInferenceServer, actor: &Arc<SessionActor>, text: &str) {
    server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("ok", "test")));
    let result = run_parent_turn(actor, task_request(text, Vec::new())).await;
    assert!(result.is_ok(), "{result:?}");
}

/// Test 1 (wire): browse → turn → exit by `default`, `ask` and `plan`. The stored head never changes; while browsing the
/// request head is the stored head plus the overlay; after each exit it is the stored head again.
#[tokio::test(flavor = "current_thread")]
async fn round_trip_three_exits_restores_the_head_on_the_wire() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for exit in ["default", "ask", "plan"] {
                let (server, actor) = wire_rig(HEAD).await;
                let before = authority(&actor);
                turn(&server, &actor, "before").await;
                assert_eq!(last_request_head(&server, HEAD), HEAD, "{exit}: never-browser head");
                actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
                assert_eq!(stored_head(&actor).await, HEAD, "{exit}: browser mode stores nothing");
                turn(&server, &actor, "browse").await;
                assert_eq!(last_request_head(&server, HEAD), browsing_head(HEAD), "{exit}: overlay while browsing");
                assert_authority(&actor, &before);
                actor.handle_session_mode(acp::SessionModeId::new(exit)).await;
                assert!(!actor.browser_mode_on(), "{exit} clears the bit");
                turn(&server, &actor, "after").await;
                assert_eq!(last_request_head(&server, HEAD), HEAD, "{exit}: head restored byte-for-byte");
                assert_eq!(stored_head(&actor).await, HEAD, "{exit}: stored head unchanged");
                assert_authority(&actor, &before);
            }
        })
        .await;
}

/// Test 2 (wire): a stored memory-context tail stays where it is; the overlay goes after it while browsing, none after.
#[tokio::test(flavor = "current_thread")]
async fn memory_tail_stays_and_the_overlay_follows_it() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let block = format!(
                "{}remember the build box{}",
                fuigo_chat_state::memory_context_open_tag("u36nonce"),
                fuigo_chat_state::memory_context_close_tag("u36nonce")
            );
            let head = format!("{HEAD}\n\n{block}");
            let (server, actor) = wire_rig(&head).await;
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            turn(&server, &actor, "browse").await;
            let wire = last_request_head(&server, HEAD);
            assert!(wire.starts_with(&head), "stored head (with its memory block) leads the request head");
            assert_eq!(wire, browsing_head(&stored_head(&actor).await));
            actor.handle_session_mode(acp::SessionModeId::new("default")).await;
            turn(&server, &actor, "after").await;
            let wire = last_request_head(&server, HEAD);
            assert!(!wire.contains(OVERLAY_MARK), "no overlay after leaving: {wire}");
            assert_eq!(wire, stored_head(&actor).await);
        })
        .await;
}

/// Test 8 (wire): a client system-prompt override while browsing writes the stored head and keeps the bit and overlay;
/// `active_agent_type` stays the session's agent.
#[tokio::test(flavor = "current_thread")]
async fn head_rewrite_while_browsing_keeps_browser_mode() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (server, actor) = wire_rig(HEAD).await;
            let agent_type = actor.active_agent_type.lock().clone();
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            let replaced = "U36-SYS-HEAD replaced by the client.";
            actor.handle_replace_system_prompt(replaced.to_string()).await;
            assert!(actor.browser_mode_on());
            assert_eq!(stored_head(&actor).await, replaced, "the stored head is what the rewrite wrote");
            turn(&server, &actor, "browse").await;
            assert_eq!(last_request_head(&server, "U36-SYS-HEAD"), browsing_head(replaced));
            assert_eq!(*actor.active_agent_type.lock(), agent_type);
        })
        .await;
}

/// Parent-cache side calls carry the overlay while browsing (same prefix as the main turn), and nothing when it is off.
#[tokio::test(flavor = "current_thread")]
async fn side_call_requests_follow_the_mode() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_server, actor) = wire_rig(HEAD).await;
            let mut items = vec![ConversationItem::system(HEAD), ConversationItem::user("q")];
            actor.apply_effective_head(&mut items);
            let ConversationItem::System(sys) = &items[0] else { panic!("head") };
            assert_eq!(sys.content.as_ref(), HEAD);
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            actor.apply_effective_head(&mut items);
            let ConversationItem::System(sys) = &items[0] else { panic!("head") };
            assert_eq!(sys.content.as_ref(), browsing_head(HEAD));
        })
        .await;
}

// ── mode ids (bare actor) ──────────────────────────────────────────────────────────────────────────────────────────

async fn actor_with_events() -> (
    Arc<SessionActor>,
    tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
    tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) {
    let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    drain_persistence(persistence_rx);
    let (actor, events) = create_test_actor_ex(1_000, 200_000, 85, gateway_tx, persistence_tx).await;
    actor.chat_state_handle.replace_conversation(vec![ConversationItem::system(HEAD)]);
    (Arc::new(actor), events, gateway_rx)
}

fn mode_updates(events: &mut tokio::sync::mpsc::UnboundedReceiver<SessionEvent>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(event) = events.try_recv() {
        let text = format!("{event:?}");
        if text.contains("CurrentModeUpdate") {
            for id in ["default", "plan", "ask", "browser_use"] {
                if text.contains(&format!("SessionModeId(\"{id}\")")) {
                    out.push(id.to_string());
                }
            }
        }
    }
    out
}

/// Test 1 (ids and authority): each exit reports its own id; the stored head, permission mode and agent never move.
#[tokio::test(flavor = "current_thread")]
async fn each_exit_reports_its_own_mode() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for exit in ["default", "ask", "plan"] {
                let (actor, mut events, _gw) = actor_with_events().await;
                let before = authority(&actor);
                let _ = mode_updates(&mut events);
                actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
                actor.handle_session_mode(acp::SessionModeId::new(exit)).await;
                assert_eq!(mode_updates(&mut events), ["browser_use", exit], "{exit}");
                assert_eq!(stored_head(&actor).await, HEAD, "{exit}");
                assert!(!actor.browser_mode_on(), "{exit}");
                assert_authority(&actor, &before);
            }
        })
        .await;
}

/// Test 3: plan coexistence. Plan entered by the prompt keeps the bit and its exit returns to `browser_use`; picking
/// Plan clears it (exit → `default`); `_meta.mode` re-declares are silent; plan-by-tool then `set_mode browser_use`
/// emits only `browser_use`.
#[tokio::test(flavor = "current_thread")]
async fn plan_coexistence() {
    tokio::task::LocalSet::new()
        .run_until(async {
            // `_meta.mode: plan` then `default` while browsing.
            let (actor, mut events, _gw) = actor_with_events().await;
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            actor.reconcile_plan_mode_with_prompt(PromptMode::Plan);
            actor.reconcile_plan_mode_with_prompt(PromptMode::Agent);
            assert_eq!(mode_updates(&mut events), ["browser_use", "plan", "browser_use"]);
            assert!(actor.browser_mode_on());
            // A `_meta.mode` re-declare (browser maps to Agent) keeps the bit and emits nothing.
            actor.reconcile_plan_mode_with_prompt(PromptMode::Agent);
            assert!(mode_updates(&mut events).is_empty());
            assert!(actor.browser_mode_on());

            // Picking Plan leaves browser mode: the plan exit lands on `default`.
            actor.handle_session_mode(acp::SessionModeId::new("plan")).await;
            assert!(!actor.browser_mode_on());
            actor.reconcile_plan_mode_with_prompt(PromptMode::Agent);
            assert_eq!(mode_updates(&mut events), ["plan", "default"]);

            // Plan by tool (prompt-entered here), then `set_mode browser_use`: one update, `browser_use`.
            activate_plan_mode(&actor);
            let _ = mode_updates(&mut events);
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            assert_eq!(mode_updates(&mut events), ["browser_use"]);
            assert_eq!(actor.plan_mode.lock().state(), crate::session::plan_mode::PlanModeState::Inactive);
        })
        .await;
}

/// Test 3 (approved exit): `leave_plan_mode_to_default` reports `browser_use` while the bit is on.
#[tokio::test(flavor = "current_thread")]
async fn approved_plan_exit_returns_to_browser_mode() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, mut events, _gw) = actor_with_events().await;
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            activate_plan_mode(&actor);
            let _ = mode_updates(&mut events);
            actor.leave_plan_mode_to_default();
            assert_eq!(mode_updates(&mut events), ["browser_use"]);
        })
        .await;
}

/// Test 9: the unset path. With the bit off the request head is the same `Arc`, `plan_mode.json` bytes equal the
/// v1.0.35 shape, and re-selecting `default` / `ask` echoes once each.
#[tokio::test(flavor = "current_thread")]
async fn unset_path_is_byte_identical() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, mut events, _gw) = actor_with_events().await;
            let mut items = vec![ConversationItem::system(HEAD), ConversationItem::user("q")];
            let ConversationItem::System(sys) = &items[0] else { panic!("head") };
            let before = Arc::clone(&sys.content);
            actor.apply_effective_head(&mut items);
            let ConversationItem::System(sys) = &items[0] else { panic!("head") };
            assert!(Arc::ptr_eq(&before, &sys.content), "the unset path writes nothing");

            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            let snapshot = serde_json::to_string(&actor.plan_mode.lock().snapshot()).unwrap();
            assert_eq!(
                snapshot,
                r#"{"state":"Inactive","was_previously_active":false,"reminder_count":0,"pending_exit_reminder":false,"awaiting_plan_approval":false}"#,
                "plan_mode.json never carries the browser bit"
            );
            let _ = mode_updates(&mut events);
            for id in ["default", "default", "ask", "ask"] {
                actor.handle_session_mode(acp::SessionModeId::new(id)).await;
                assert_eq!(mode_updates(&mut events), [id], "re-select echoes once");
            }
        })
        .await;
}

/// A tracker restored from disk (load, resume, fork) starts with browser mode off.
#[test]
fn snapshot_restore_starts_normal() {
    let dir = tempfile::tempdir().unwrap();
    let mut tracker = crate::session::plan_mode::PlanModeTracker::new(dir.path().to_path_buf());
    tracker.set_browser_use(true);
    let restored =
        crate::session::plan_mode::PlanModeTracker::from_snapshot(dir.path().to_path_buf(), tracker.snapshot());
    assert!(!restored.browser_use());
}

// ── legacy repair (D3) ─────────────────────────────────────────────────────────────────────────────────────────────

/// `B` pinned by render: the 1.0.35 head is a Full-mode render of the built-in `browser_use()` definition, exactly
/// as `handle_session_mode` rendered it.
#[tokio::test(flavor = "current_thread")]
async fn browser_body_is_the_1_0_35_render() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = actor_with_events().await;
            let (ctx, bridge) = {
                let agent = actor.agent.borrow();
                (
                    agent.prompt_context_for_definition(&fuigo_agent::AgentDefinition::browser_use()),
                    Arc::clone(agent.tool_bridge()),
                )
            };
            assert_eq!(ctx.render(&bridge).await.unwrap_or_default(), browser_body());
        })
        .await;
}

fn legacy_conversation(head: &str) -> Vec<ConversationItem> {
    vec![ConversationItem::system(head), ConversationItem::user("hi"), ConversationItem::user("again")]
}

fn head_of(conversation: &[ConversationItem]) -> &str {
    match conversation.first() {
        Some(ConversationItem::System(sys)) => sys.content.as_ref(),
        other => panic!("no head: {other:?}"),
    }
}

/// This installation's memory-context nonce: the only one the legacy-head check recognises.
fn memory_nonce() -> &'static str {
    crate::session::helpers::memory_context::memory_context_nonce()
}

fn legacy_heads() -> Vec<String> {
    let b = browser_body();
    let block = format!(
        "{}remembered{}",
        fuigo_chat_state::memory_context_open_tag(memory_nonce()),
        fuigo_chat_state::memory_context_close_tag(memory_nonce())
    );
    vec![b.to_owned(), format!("{b}\n\n"), format!("{b}\n\n{block}")]
}

fn negative_heads() -> Vec<String> {
    let b = browser_body();
    let block = format!(
        "{}remembered{}",
        fuigo_chat_state::memory_context_open_tag(memory_nonce()),
        fuigo_chat_state::memory_context_close_tag(memory_nonce())
    );
    let unclosed = fuigo_chat_state::memory_context_open_tag(memory_nonce());
    vec![
        format!("{b} and more"),
        format!("{b}\n\n{block}\ntext"),
        format!("text\n\n{b}"),
        format!("{b}\n\n{unclosed}remembered"),
        HEAD.to_owned(),
    ]
}

async fn run_load_repair(
    actor: &SessionActor,
    conversation: &mut Vec<ConversationItem>,
    system_prompt: &str,
) {
    // A separate agent of the same build: holding the actor's `Ref<Agent>` across the render await is not allowed.
    let agent = test_agent_default().await;
    super::super::spawn::repair_legacy_browser_head(
        conversation,
        &actor.session_info,
        &agent,
        system_prompt,
        actor.tool_context.cwd.as_path(),
    )
    .await;
}

/// Test 7: every 1.0.35 browser head is replaced by the canonical head (the restored override when there is one) at
/// load; a second load makes no further change; negatives stay byte-identical.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn legacy_heads_are_repaired_at_load() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = actor_with_events().await;
            for head in legacy_heads() {
                assert!(is_legacy_browser_head(&head));
                let mut conversation = legacy_conversation(&head);
                run_load_repair(&actor, &mut conversation, HEAD).await;
                assert_eq!(head_of(&conversation), HEAD, "{head:?}");
                assert_eq!(conversation.len(), 3, "only the head changes");
                let again = format!("{conversation:?}");
                run_load_repair(&actor, &mut conversation, HEAD).await;
                assert_eq!(format!("{conversation:?}"), again, "a second load changes nothing more");
            }
            for head in negative_heads() {
                let mut conversation = legacy_conversation(&head);
                run_load_repair(&actor, &mut conversation, HEAD).await;
                assert_eq!(head_of(&conversation), head, "negative stays byte-identical");
            }
            // Override variant: the restored client override is the canonical head.
            crate::session::acp_session::save_system_prompt_override(&actor.session_info, "U36 client override");
            let mut conversation = legacy_conversation(browser_body());
            run_load_repair(&actor, &mut conversation, HEAD).await;
            assert_eq!(head_of(&conversation), "U36 client override");
        })
        .await;
}

/// Guard: a `browser-use` profile session (its own head is `B`) is never repaired.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_browser_use_profile_head_is_left_alone() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = actor_with_events().await;
            for head in legacy_heads() {
                let mut conversation = legacy_conversation(&head);
                run_load_repair(&actor, &mut conversation, browser_body()).await;
                assert_eq!(head_of(&conversation), head);
            }
        })
        .await;
}

fn repo_with_agent(stem: &str, body: &str) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    git2::Repository::init(tmp.path()).unwrap();
    let agents = tmp.path().join(".fuigo").join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    let path = agents.join(format!("{stem}.md"));
    std::fs::write(&path, format!("---\nname: {stem}\ndescription: u36 fixture\npromptMode: full\n---\n{body}\n")).unwrap();
    fuigo_agent::AgentDefinition::from_file(&path).expect("fixture must parse");
    tmp
}

/// Guard: a trusted cwd `default.md` / `ask.md` whose Full-mode body renders to `B` blocks the repair (that is how a
/// never-browser session holds a `B` head); the same file in an untrusted cwd does not.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn a_trusted_mode_file_rendering_to_the_body_blocks_the_repair() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::create_dir_all(home.path().join("agents")).unwrap();
    let _release = fuigo_test_support::EnvGuard::set(fuigo_version::TEST_VERSION_ENV, "0.0.0-sim");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    tokio::task::LocalSet::new()
        .run_until(async {
            for stem in ["default", "ask"] {
                for trusted in [true, false] {
                    let repo = repo_with_agent(stem, browser_body());
                    crate::agent::folder_trust::record_for_test(repo.path(), trusted);
                    let (actor, _events, _gw) = actor_with_events().await;
                    let mut actor = Arc::try_unwrap(actor).ok().expect("sole owner");
                    actor.tool_context.cwd = fuigo_paths::AbsPathBuf::new(repo.path().to_path_buf()).unwrap();
                    let mut conversation = legacy_conversation(browser_body());
                    run_load_repair(&actor, &mut conversation, HEAD).await;
                    let want = if trusted { browser_body() } else { HEAD };
                    assert_eq!(head_of(&conversation), want, "{stem}.md trusted={trusted}");
                }
            }
        })
        .await;
}

/// Test 6: a cross-compaction rewind installing a 1.0.35 browser checkpoint head gets the live head; a normal
/// checkpoint head is kept.
#[tokio::test(flavor = "current_thread")]
async fn cross_compaction_rewind_repairs_a_legacy_checkpoint_head() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _events, _gw) = actor_with_events().await;
            for head in legacy_heads() {
                let mut conversation = legacy_conversation(&head);
                actor.repair_legacy_browser_checkpoint_head(&mut conversation, HEAD).await;
                assert_eq!(head_of(&conversation), HEAD, "{head:?}");
            }
            for head in negative_heads() {
                let mut conversation = legacy_conversation(&head);
                actor.repair_legacy_browser_checkpoint_head(&mut conversation, "live").await;
                assert_eq!(head_of(&conversation), head);
            }
        })
        .await;
}

/// Finding (rewind collision): a real cross-compaction rewind (`handle_rewind`, replay from the checkpoint) in a session
/// whose canonical head is the browsing body (client override `B`). The checkpoint holds `B` + an older memory block, the
/// live head `B` + a newer one. The checkpoint head is the session's own, so it is installed as is; the live head is
/// only ever the replacement. Control: the same checkpoint in a session whose canonical head is `HEAD` gets the live head.
#[tokio::test(flavor = "current_thread")]
async fn cross_compaction_rewind_keeps_a_browser_canonical_checkpoint_head() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let b = browser_body();
            let memory = |nonce: &str, body: &str| {
                format!(
                    "{}{body}{}",
                    fuigo_chat_state::memory_context_open_tag(nonce),
                    fuigo_chat_state::memory_context_close_tag(nonce)
                )
            };
            let checkpoint_head = format!("{b}\n\n{}", memory(memory_nonce(), "memory_old"));
            assert!(is_legacy_browser_head(&checkpoint_head), "the checkpoint head has the 1.0.35 shape");
            for (canonical, live_head, want) in [
                (b.to_owned(), format!("{b}\n\n{}", memory(memory_nonce(), "memory_new")), checkpoint_head.clone()),
                (HEAD.to_owned(), format!("{HEAD}\n\n{}", memory(memory_nonce(), "memory_new")), String::new()),
            ] {
                let want = if want.is_empty() { live_head.clone() } else { want };
                let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
                let (persistence_tx, _recorded) = crate::session::acp_session::support::answering_persistence();
                let mut actor = crate::session::acp_session::support::create_test_actor(
                    0,
                    200_000,
                    80,
                    gateway_tx,
                    persistence_tx,
                )
                .await;
                let unique = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                actor.session_info.id = acp::SessionId::new(format!("u36-rewind-{unique}"));
                *actor.system_prompt_override.borrow_mut() = Some(canonical.clone());
                let session_dir = crate::session::persistence::session_dir(&actor.session_info);
                crate::session::acp_session::rewind_cross_compaction_tests::write_compacted_session_fixture_with_head(
                    &session_dir,
                    "u36ckpt",
                    &checkpoint_head,
                );
                let mut snap = actor.chat_state_handle.snapshot().await.expect("snapshot available");
                snap.conversation = vec![
                    ConversationItem::system(live_head.as_str()),
                    ConversationItem::user("UI1"),
                    ConversationItem::user("SUMMARY"),
                    ConversationItem::user("P5"),
                    ConversationItem::assistant("R5"),
                    ConversationItem::user("P6"),
                ];
                snap.prompt_index = 7;
                snap.prompt_texts = (0..7).map(|i| format!("P{i}")).collect();
                snap.last_compaction_prompt_index = Some(5);
                actor.chat_state_handle.restore_snapshot(snap);

                let resp = actor
                    .handle_rewind(crate::session::RewindRequest {
                        target_prompt_index: 6,
                        force: true,
                        mode: crate::session::RewindMode::ConversationOnly,
                    })
                    .await
                    .expect("handle_rewind ok");
                let head = stored_head(&actor).await;
                let _ = std::fs::remove_dir_all(&session_dir);
                assert!(resp.success, "{resp:?}");
                assert_eq!(head, want, "canonical head {:?}", &canonical[..canonical.len().min(40)]);
            }
        })
        .await;
}

/// Finding (`/btw` retry): a side question whose first attempt fails transiently while browsing, with browser mode left
/// (`set_mode default`) during the backoff. The first attempt carried the overlay; the retry reads the bit again and
/// carries the stored head alone.
#[tokio::test(flavor = "current_thread")]
async fn a_btw_retry_after_leaving_browser_mode_carries_no_overlay() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (server, actor) = wire_rig(HEAD).await;
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            let before = server.request_bodies().len();
            server.enqueue_response(
                "/v1/responses",
                ScriptedResponse::json(502, serde_json::json!({ "error": "bad gateway" })),
            );
            server.enqueue_response("/v1/responses", ScriptedResponse::sse(responses_api_script_exact("side answer", "test")));
            let leave = async {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                while server.request_bodies().len() <= before && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                // The first attempt is out (and failed); the backoff is at least 500 ms.
                actor.handle_session_mode(acp::SessionModeId::new("default")).await;
            };
            let (answer, ()) = tokio::join!(actor.handle_side_question("what now?", Vec::new()), leave);
            assert_eq!(answer.expect("the retry answers"), "side answer");
            let heads: Vec<String> = server.request_bodies()[before..]
                .iter()
                .map(|body| {
                    let mut found = Vec::new();
                    strings_containing(body, HEAD, &mut found);
                    assert_eq!(found.len(), 1, "one wire string carries the head: {found:?}");
                    found.remove(0)
                })
                .collect();
            assert_eq!(heads.len(), 2, "one failed attempt, one retry");
            assert_eq!(heads[0], browsing_head(HEAD), "the first attempt was sent while browsing");
            assert_eq!(heads[1], HEAD, "the retry carries the session's own head, no overlay");
        })
        .await;
}

/// `_meta.rules` (folded into the head at creation as a `<human_rules>` block) survives browse → default byte for byte,
/// on the wire and in the stored head.
#[tokio::test(flavor = "current_thread")]
async fn human_rules_survive_browse_and_leave() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut head = HEAD.to_owned();
            crate::session::human_rules::append_human_rules(&mut head, "U36-RULE: always cite the file.");
            assert!(head.contains("<human_rules>"));
            let (server, actor) = wire_rig(&head).await;
            let before = authority(&actor);
            turn(&server, &actor, "before").await;
            assert_eq!(last_request_head(&server, HEAD), head);
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            turn(&server, &actor, "browse").await;
            assert_eq!(last_request_head(&server, HEAD), browsing_head(&head), "rules stay ahead of the overlay");
            actor.handle_session_mode(acp::SessionModeId::new("default")).await;
            turn(&server, &actor, "after").await;
            assert_eq!(last_request_head(&server, HEAD), head, "rules and head restored byte for byte");
            assert_eq!(stored_head(&actor).await, head);
            assert_authority(&actor, &before);
        })
        .await;
}
