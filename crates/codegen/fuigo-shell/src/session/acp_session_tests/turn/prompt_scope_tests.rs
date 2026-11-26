//! Prompt scope (1.0.48, design 1022-grokwarm section A) on the real turn path: a queued input is promoted by
//! `maybe_start_running_task`, runs as a spawned turn task against a scripted model, and is settled by
//! `handle_completion`, exactly as the actor's run loop does. Frames are captured at the gateway in arrival order.

use super::disk_full_tests::{
    actor_with_mock_sampler_configured, block_on_session, current_thread_local,
};
use super::support::*;
use super::*;
use crate::session::prompt_scope::{self as ps, PromptScope};
use fuigo_test_support::sse::responses_api_script_exact;
use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
use std::sync::Arc;
use std::time::Duration;

/// One captured gateway frame: `("acp", SessionNotification)` or `("fuigo", fuigo/session_notification params)`.
type Frames = Arc<std::sync::Mutex<Vec<(&'static str, serde_json::Value)>>>;

fn capture_frames(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> Frames {
    let frames: Frames = Arc::default();
    let sink = frames.clone();
    tokio::task::spawn_local(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                fuigo_acp_lib::AcpClientMessage::SessionNotification(args) => {
                    if let Ok(v) = serde_json::to_value(&args.request) {
                        sink.lock().unwrap().push(("acp", v));
                    }
                    let _ = args.response_tx.send(Ok(()));
                }
                fuigo_acp_lib::AcpClientMessage::ExtNotification(args)
                    if args.request.method.as_ref() == "fuigo/session_notification" =>
                {
                    let params: serde_json::Value =
                        serde_json::from_str(args.request.params.get()).unwrap_or_default();
                    sink.lock().unwrap().push(("fuigo", params));
                }
                _ => {}
            }
        }
    });
    frames
}

fn text_input(
    prompt_id: &str,
    origin: crate::session::PromptOrigin,
) -> (InputItem, tokio::sync::oneshot::Receiver<PromptTurnResult>) {
    let (respond_to, rx) = tokio::sync::oneshot::channel();
    let item = InputItem {
        prompt_id: prompt_id.to_string(),
        prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new(
            "hello".to_string(),
        ))],
        prompt_mode: PromptMode::Agent,
        trace_gcs_config: None,
        artifact_tracker: None,
        client_identifier: None,
        screen_mode: None,
        verbatim: true,
        json_schema: None,
        input_origin: InputOrigin::new(origin),
        task_wake_fallback: None,
        tool_overrides_update: None,
        respond_to,
        persist_ack: None,
        parsed_prompt_tx: None,
        initial_child_prompt_ready: None,
        queue_meta: None,
        queue_mutation_policy: QueueMutationPolicy::hidden(),
        send_now: false,
        traceparent: None,
    };
    (item, rx)
}

/// Promote the queue head through the production spawn path and settle it like the run loop does.
async fn run_queued_turn(actor: &Arc<SessionActor>) -> String {
    let (completion_tx, mut completion_rx) = tokio::sync::mpsc::unbounded_channel();
    actor.clone().maybe_start_running_task(completion_tx).await;
    let identity = completion_identity(actor);
    let msg = tokio::time::timeout(Duration::from_secs(60), completion_rx.recv())
        .await
        .expect("turn finishes")
        .expect("completion sent");
    let prompt_id = msg.prompt_id.clone();
    actor
        .handle_completion(
            msg.prompt_id,
            msg.epoch,
            &identity,
            msg.result,
            msg.elapsed_ms,
        )
        .await;
    drain_gateway_turns().await;
    prompt_id
}

async fn run_client_prompt(actor: &Arc<SessionActor>, prompt_id: &str) {
    let (item, _rx) = text_input(prompt_id, crate::session::PromptOrigin::User);
    actor.state.lock().await.pending_inputs.push_back(item);
    assert_eq!(run_queued_turn(actor).await, prompt_id);
}

fn update_kind<'a>(frame: &'a (&'static str, serde_json::Value)) -> Option<&'a str> {
    frame.1["update"]["sessionUpdate"].as_str()
}

fn meta_str<'a>(frame: &'a (&'static str, serde_json::Value), key: &str) -> Option<&'a str> {
    frame.1["_meta"][key].as_str()
}

async fn scripted_actor(
    session_id: &str,
    turns: usize,
) -> (Arc<SessionActor>, Frames, MockInferenceServer) {
    let server = MockInferenceServer::start().await.expect("mock server");
    for _ in 0..turns {
        server.enqueue_response(
            "/v1/responses",
            ScriptedResponse::sse(responses_api_script_exact("done", "test")),
        );
    }
    let (persistence_tx, persistence_rx) = tokio::sync::mpsc::unbounded_channel();
    super::disk_full_tests::spawn_persistence_stub(persistence_rx, || Ok(()));
    let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
    let frames = capture_frames(gateway_rx);
    // The run loop owns the event pipeline in production; here a pump feeds every queued event through the same
    // `handle_session_event` the loop calls, so buffered updates reach the gateway in the order they were produced.
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<SessionEvent>();
    let actor = actor_with_mock_sampler_configured(
        &server,
        session_id,
        persistence_tx,
        gateway_tx,
        None,
        None,
        move |a| a.event_tx = event_tx,
    )
    .await;
    let pump = actor.clone();
    tokio::task::spawn_local(async move {
        let mut replay_buffer =
            crate::agent::update_chunk_merge::ReplayBuffer::new(pump.buffering_settings.clone());
        while let Some(event) = event_rx.recv().await {
            pump.handle_session_event(event, &mut replay_buffer).await;
        }
    });
    (actor, frames, server)
}

/// WF-3 echo order (+ A8 at the turn_completed of a quiet turn). For three prompts: `turn_started{P}` reaches the client
/// before any session/update of P, names P as its own root, and P's `turn_completed` carries P's pair and `background: 0`.
#[test]
fn wf3_turn_started_precedes_each_prompts_updates_and_completion_names_it() {
    block_on_session(|| {
        current_thread_local(async {
            let (actor, frames, _server) = scripted_actor("pscope-wf3", 3).await;
            let prompts = ["wf3-p1", "wf3-p2", "wf3-p3"];
            for p in prompts {
                run_client_prompt(&actor, p).await;
            }
            let frames = frames.lock().unwrap().clone();
            for p in prompts {
                let started = frames
                    .iter()
                    .position(|f| {
                        f.0 == "fuigo"
                            && update_kind(f) == Some("turn_started")
                            && f.1["update"]["prompt_id"] == p
                    })
                    .unwrap_or_else(|| panic!("no turn_started for {p}"));
                assert_eq!(
                    frames[started].1["update"]["origin_prompt_id"], p,
                    "a client prompt is its own root"
                );
                let first_update = frames
                    .iter()
                    .position(|f| f.0 == "acp" && meta_str(f, ps::META_PROMPT_ID) == Some(p))
                    .unwrap_or_else(|| panic!("no session/update for {p}"));
                assert!(
                    started < first_update,
                    "turn_started({p}) at {started} must precede its first update at {first_update}"
                );
                for f in frames
                    .iter()
                    .filter(|f| f.0 == "acp" && meta_str(f, ps::META_PROMPT_ID) == Some(p))
                {
                    assert_eq!(meta_str(f, ps::META_ORIGIN_PROMPT_ID), Some(p), "{:?}", f.1);
                }
                let completed = frames
                    .iter()
                    .find(|f| {
                        f.0 == "fuigo"
                            && update_kind(f) == Some("turn_completed")
                            && f.1["update"]["prompt_id"] == p
                    })
                    .unwrap_or_else(|| panic!("no turn_completed for {p}"));
                assert_eq!(meta_str(completed, ps::META_PROMPT_ID), Some(p));
                assert_eq!(meta_str(completed, ps::META_ORIGIN_PROMPT_ID), Some(p));
                assert_eq!(completed.1["_meta"][ps::META_BACKGROUND], 0);
            }
        });
    });
}

/// WF-1 drain origin. P1's background task finished while P2 was the latest turn: the drain turn that reports it keeps
/// its own minted id, names P1 (not P2) as its root on `turn_started`, and every session/update it sends carries
/// `originPromptId = P1`.
#[test]
fn wf1_drain_turn_for_p1_task_names_p1_while_p2_is_latest() {
    block_on_session(|| {
        current_thread_local(async {
            let (actor, frames, _server) = scripted_actor("pscope-wf1", 2).await;
            let registry = actor.tool_context.prompt_scope.clone();
            // P1 ran and backgrounded task t1 (bound at origin); then P2 ran to completion.
            registry.begin_turn(&PromptScope::client("wf1-p1"));
            registry.bind(&ps::bash_work_id("wf1-t1"), PromptScope::client("wf1-p1"));
            run_client_prompt(&actor, "wf1-p2").await;
            registry.finish(&ps::bash_work_id("wf1-t1"));
            {
                let mut state = actor.state.lock().await;
                state.pending_notifications.push(PendingNotification {
                    prompt_id: "task-completed-wf1-t1".to_string(),
                    prompt_blocks: vec![acp::ContentBlock::Text(acp::TextContent::new(
                        "task wf1-t1 finished".to_string(),
                    ))],
                    priority: NotificationPriority::Next,
                    source: crate::session::commands::NotificationSource::BashTaskCompleted {
                        task_id: "wf1-t1".to_string(),
                    },
                });
            }
            let (completion_tx, mut completion_rx) = tokio::sync::mpsc::unbounded_channel();
            let identity_actor = actor.clone();
            actor.clone().maybe_drain_notifications(completion_tx).await;
            let identity = completion_identity(&identity_actor);
            let msg = tokio::time::timeout(Duration::from_secs(60), completion_rx.recv())
                .await
                .expect("drain turn finishes")
                .expect("completion sent");
            let drain_id = msg.prompt_id.clone();
            assert!(drain_id.starts_with("notifications-"), "{drain_id}");
            actor
                .handle_completion(
                    msg.prompt_id,
                    msg.epoch,
                    &identity,
                    msg.result,
                    msg.elapsed_ms,
                )
                .await;
            drain_gateway_turns().await;

            let frames = frames.lock().unwrap().clone();
            let started = frames
                .iter()
                .find(|f| {
                    f.0 == "fuigo"
                        && update_kind(f) == Some("turn_started")
                        && f.1["update"]["prompt_id"] == drain_id.as_str()
                })
                .expect("drain turn_started");
            assert_eq!(started.1["update"]["origin_prompt_id"], "wf1-p1");
            let drain_updates: Vec<_> = frames
                .iter()
                .filter(|f| {
                    f.0 == "acp" && meta_str(f, ps::META_PROMPT_ID) == Some(drain_id.as_str())
                })
                .collect();
            assert!(!drain_updates.is_empty(), "the drain turn sent updates");
            for f in drain_updates {
                assert_eq!(
                    meta_str(f, ps::META_ORIGIN_PROMPT_ID),
                    Some("wf1-p1"),
                    "{:?}",
                    f.1
                );
            }
            // P2's own frames name P2.
            assert!(frames.iter().any(|f| f.0 == "acp"
                && meta_str(f, ps::META_PROMPT_ID) == Some("wf1-p2")
                && meta_str(f, ps::META_ORIGIN_PROMPT_ID) == Some("wf1-p2")));
        });
    });
}

/// WF-7 background count. Live tasks, live subagents (pending, active, queued) and scheduled drains all count; an
/// unreadable source omits the field (`None`), so a prompt-scoped client never parks on a guess.
#[test]
fn wf7_background_counts_live_work_and_omits_when_unknown() {
    use fuigo_tools::implementations::fuigo_build::task::types::SubagentRegistryCounts;
    let quiet = SubagentRegistryCounts::default();
    assert_eq!(
        ps::live_background_count(Some(1), Some(&quiet), Some(0)),
        Some(1)
    );
    assert_eq!(
        ps::live_background_count(Some(0), Some(&quiet), Some(0)),
        Some(0)
    );
    let busy = SubagentRegistryCounts {
        pending: 1,
        active: 1,
        completed: 5,
        queued: 1,
    };
    assert_eq!(
        ps::live_background_count(Some(0), Some(&busy), Some(0)),
        Some(3)
    );
    assert_eq!(
        ps::live_background_count(Some(0), Some(&quiet), Some(2)),
        Some(2)
    );
    assert_eq!(ps::live_background_count(None, Some(&quiet), Some(0)), None);
    assert_eq!(ps::live_background_count(Some(0), None, Some(0)), None);
    assert_eq!(ps::live_background_count(Some(0), Some(&quiet), None), None);
}

/// WF-7r background count on the real turn path: a drain already queued behind P when P completes makes P's
/// `turn_completed` report `background: 1` (the process is not quiet: the drain turn is about to run on it).
#[test]
fn wf7r_turn_completed_counts_a_drain_queued_behind_the_prompt() {
    block_on_session(|| {
        current_thread_local(async {
            let (actor, frames, _server) = scripted_actor("pscope-wf7r", 1).await;
            let (item, _rx) = text_input("wf7r-p1", crate::session::PromptOrigin::User);
            let (drain, _drain_rx) = text_input(
                "notifications-wf7r",
                crate::session::PromptOrigin::NotificationDrain,
            );
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(item);
                state.pending_inputs.push_back(drain);
            }
            assert_eq!(run_queued_turn(&actor).await, "wf7r-p1");
            let frames = frames.lock().unwrap().clone();
            let completed = frames
                .iter()
                .find(|f| {
                    f.0 == "fuigo"
                        && update_kind(f) == Some("turn_completed")
                        && f.1["update"]["prompt_id"] == "wf7r-p1"
                })
                .expect("turn_completed for wf7r-p1");
            assert_eq!(
                completed.1["_meta"][ps::META_BACKGROUND],
                1,
                "{:?}",
                completed.1
            );
        });
    });
}

/// Send sites WF-4 counts in one source file, from its syntax tree (syn, full grammar), not its line text: every method
/// call whose method is in `SEND_METHODS` (turbofish, whitespace and line splits included), every path expression whose
/// last segment is one (UFCS `acp::Client::session_notification(&gateway, frame)`, `<G as acp::Client>::m`, a subtrait or
/// alias path, the method used as a value), and every such identifier in a macro's tokens (syn does not parse macro
/// bodies) unless it follows `fn`. Definitions are not expressions and comments and strings are not tokens, so neither
/// counts. A bare name that the file binds as a local (`let`, parameter or closure pattern) is that local, not a send,
/// unless it is called, so a variable named like a send cannot pad a file's count. A source that does not parse fails.
fn send_site_list(text: &str) -> Vec<String> {
    use quote::ToTokens;
    use syn::visit::Visit;
    struct Locals(std::collections::HashSet<String>);
    impl<'ast> Visit<'ast> for Locals {
        fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
            self.0.insert(pat.ident.unraw().to_string());
            syn::visit::visit_pat_ident(self, pat);
        }
    }
    struct Sends(Vec<String>, std::collections::HashSet<String>);
    fn is_send(name: &str) -> bool {
        ps::SEND_METHODS.contains(&name)
    }
    fn is_mcp_call(name: &str) -> bool {
        ps::MCP_CALL_PATHS.contains(&name)
    }
    fn tokens(stream: proc_macro2::TokenStream, site: &str, n: &mut Vec<String>) {
        let mut after_fn = false;
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Group(g) => {
                    tokens(g.stream(), site, n);
                    after_fn = false;
                }
                proc_macro2::TokenTree::Ident(id) => {
                    let name = id.to_string();
                    let bare = name.trim_start_matches("r#");
                    if !after_fn && (is_send(bare) || is_mcp_call(bare)) {
                        n.push(site.to_string());
                    }
                    after_fn = name == "fn";
                }
                _ => after_fn = false,
            }
        }
    }
    impl<'ast> Visit<'ast> for Sends {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if is_send(&call.method.unraw().to_string()) {
                self.0.push(call.to_token_stream().to_string());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(callee) = call.func.as_ref()
                && callee
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| is_send(&s.ident.unraw().to_string()))
            {
                // A called name is a send even when a local shares it.
                self.0.push(call.to_token_stream().to_string());
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                return;
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            let local = path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == 1
                && self
                    .1
                    .contains(&path.path.segments[0].ident.unraw().to_string());
            if !local
                && (path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| is_send(&s.ident.unraw().to_string()))
                    || path
                        .path
                        .segments
                        .iter()
                        .any(|s| is_mcp_call(&s.ident.unraw().to_string())))
            {
                self.0.push(path.to_token_stream().to_string());
            }
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            tokens(
                mac.tokens.clone(),
                &mac.to_token_stream().to_string(),
                &mut self.0,
            );
            syn::visit::visit_macro(self, mac);
        }
    }
    use syn::ext::IdentExt;
    let file =
        syn::parse_file(text).unwrap_or_else(|e| panic!("WF-4 cannot parse a scanned source: {e}"));
    let mut locals = Locals(Default::default());
    locals.visit_file(&file);
    let mut sends = Sends(Vec::new(), locals.0);
    sends.visit_file(&file);
    sends.0
}

/// Send sites WF-4 counts in one source file (see [`send_site_list`]).
fn send_sites_in(text: &str) -> usize {
    send_site_list(text).len()
}

/// WF-4 capability bound to coverage. Every agent-to-client send site in the non-test sources is enumerated by scanning
/// the tree; the per-file counts must equal the registered `SEND_SITES` table (a new route that is not registered fails
/// here), and `initialize` advertises `fuigo/promptScope` exactly when every registered file is scoped.
#[test]
fn wf4_capability_is_advertised_only_with_full_coverage() {
    fn is_test_file(rel: &str) -> bool {
        let base = rel.rsplit('/').next().unwrap_or(rel);
        base.ends_with("_tests.rs")
            || base.ends_with("_test.rs")
            || base == "tests.rs"
            || rel.contains("/tests/")
            || rel.contains("test_support")
    }
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let codegen = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/codegen");
    let mut found = std::collections::BTreeMap::<String, usize>::new();
    for root in ps::SEND_SITE_CRATES {
        let mut files = Vec::new();
        walk(&codegen.join(root), &mut files);
        for file in files {
            let rel = file
                .strip_prefix(codegen)
                .expect("under codegen")
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&file).expect("read source");
            let n = send_sites_in(&text);
            if n > 0 {
                found.insert(rel, n);
            }
        }
    }
    let registered: std::collections::BTreeMap<String, usize> = ps::SEND_SITES
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        found, registered,
        "unregistered or changed agent-to-client send sites"
    );
    // Per-site token pins (r1) are retired: the gateway now stamps every frame, so a send swapped at an equal count still
    // carries a pair; what a new or moved send needs is a class, which an unregistered count forces.
    let meta = crate::agent::mvp_agent::agent_capabilities_meta();
    assert_eq!(
        meta.contains_key(ps::CAPABILITY_KEY),
        ps::uncovered_routes().is_empty(),
        "uncovered: {:?}",
        ps::uncovered_routes()
    );
}

/// WF-4b the scan sees every agent-to-client call of the ACP client trait, not only the request methods: these are the
/// `acp::Client` methods of agent-client-protocol 0.10 (its src/client.rs), the notifications included. A method missing
/// from `SEND_METHODS` makes all of its send sites invisible to WF-4, so the capability could be advertised while
/// they still go out without the pair.
#[test]
fn wf4b_send_site_patterns_cover_every_acp_client_method() {
    const ACP_CLIENT_METHODS: &[&str] = &[
        "request_permission",
        "session_notification",
        "write_text_file",
        "read_text_file",
        "create_terminal",
        "terminal_output",
        "release_terminal",
        "wait_for_terminal_exit",
        "kill_terminal",
        "ext_method",
        "ext_notification",
    ];
    let missing: Vec<&str> = ACP_CLIENT_METHODS
        .iter()
        .copied()
        .filter(|m| !ps::SEND_METHODS.contains(m))
        .collect();
    assert_eq!(
        missing,
        Vec::<&str>::new(),
        "acp::Client methods not scanned by WF-4"
    );
}

/// WF-4c an unscoped notification send is a counted send site. The sends are the bash-output `session/update`
/// (tools/notification_bridge.rs), a park-hold `ext_notification` split over lines (agent/park_hold.rs) and a hub
/// `send_notification` (fuigo-workspace handle.rs) and an fs/* request through the gateway's generic sender
/// (fuigo-workspace file_system/acp_fs.rs), none of which carries the pair; WF-4 can only hold the capability off for
/// them if the scan counts them. (The same four lines as before, now inside one fn so the source parses.)
#[test]
fn wf4c_scan_counts_unscoped_notification_sends() {
    const UNSCOPED_SENDS: &str = r#"
        async fn unscoped() {
                let _ = config.gateway.session_notification(notification).await;
                sink
                    .ext_notification(acp::ExtNotification::new(notification.method, params));
                        if let Err(e) = server_for_events.send_notification(frame).await {}
        match self.gateway.send_request(read_req).await {}
        }
    "#;
    assert_eq!(
        send_sites_in(UNSCOPED_SENDS),
        4,
        "unscoped notification sends not counted"
    );
}

/// WF-4d the gateway's own senders are scanned too: `AcpGatewaySender` can send any ACP request or notification to the
/// client by itself (fs/*, terminal/*, `_fuigo/*`), so every non-private fn of its inherent impls (`pub`, `pub(crate)`,
/// ...; any receiver form, `self: &Self` included, or none) other than its builders `new`/`with_tracing`, and every method
/// of its `acp::Client` impl, must be in `SEND_METHODS`. A generic sender added under
/// another name (as `send` was), or a client method the ACP crate adds, fails here until it is scanned. Read from the
/// syntax tree of gateway.rs, so a split signature or a restricted visibility cannot hide a sender.
#[test]
fn wf4d_every_gateway_sender_method_is_scanned() {
    let gateway = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/codegen")
        .join("fuigo-acp-lib/src/gateway.rs");
    let text = std::fs::read_to_string(gateway).expect("read gateway.rs");
    let file = syn::parse_file(&text).expect("parse gateway.rs");
    // Constructors/builders that take or return the sender itself, never the raw channel.
    const GATEWAY_BUILDERS: &[&str] = &["new", "with_tracing"];
    let mut senders = Vec::new();
    for item in &file.items {
        let syn::Item::Impl(imp) = item else { continue };
        let syn::Type::Path(ty) = imp.self_ty.as_ref() else {
            continue;
        };
        if ty
            .path
            .segments
            .last()
            .is_none_or(|s| s.ident != "AcpGatewaySender")
        {
            continue;
        }
        let client_impl = imp
            .trait_
            .as_ref()
            .is_some_and(|(_, path, _)| path.segments.last().is_some_and(|s| s.ident == "Client"));
        if imp.trait_.is_some() && !client_impl {
            continue;
        }
        for member in &imp.items {
            let syn::ImplItem::Fn(f) = member else {
                continue;
            };
            // Any receiver form (`&self`, `self: &Self`, `self`) or none: a non-private fn can hand out the channel.
            let exposed = client_impl || !matches!(f.vis, syn::Visibility::Inherited);
            if exposed && !GATEWAY_BUILDERS.contains(&f.sig.ident.to_string().as_str()) {
                senders.push(f.sig.ident.to_string());
            }
        }
    }
    assert!(
        senders.iter().any(|m| m == "session_notification"),
        "gateway.rs parse found no acp::Client impl: {senders:?}"
    );
    let unscanned: Vec<&String> = senders
        .iter()
        .filter(|m| !ps::SEND_METHODS.contains(&m.as_str()))
        .collect();
    assert_eq!(
        unscanned,
        Vec::<&String>::new(),
        "AcpGatewaySender senders not scanned by WF-4 (all: {senders:?})"
    );
}

/// WF-4e (ASTRA 2669 H1) the scan finds an ACP send in every form Rust can spell it, not only `.method(` on one line: the
/// UFCS trait call `acp::Client::session_notification(&config.gateway, n)`, a qualified `<G as acp::Client>::` call, a
/// turbofish, the method name and its arguments on different lines, the method taken as a value, a send inside a
/// one-line `fn`, and one inside a macro body. Each is an unscoped send that a line match would let through, so a file
/// could be marked Scoped and the capability advertised while it still sends without the pair. A comment, a string, a
/// trait method definition and a local variable (ASTRA r3 precheck: a counted local let a Scoped file swap it for a real
/// send) that only share a send name are not sends.
#[test]
fn wf4e_scan_counts_every_call_form_of_a_send() {
    const EVERY_FORM: &str = r#"
        async fn unscoped(config: &Config, gateway: &G, n: acp::SessionNotification) {
            let _ = acp::Client::session_notification(&config.gateway, n.clone()).await;
            let _ = <G as acp::Client>::ext_notification(gateway, ext()).await;
            let _ = gateway.send_request::<acp::ReadTextFileRequest>(read()).await;
            let _ = gateway
                .session_notification
                (n.clone()).await;
            let send = acp::Client::session_notification;
            fn inner(g: &G, n: N) { let _ = g.session_notification(n); }
            notify!(gateway.session_notification(n));
            let ext_notification = ext();
            gateway.forward_fire_and_forget(ext_notification);
            // gateway.session_notification(n) in a comment
            let s = "gateway.session_notification(n) in a string";
        }
        trait Sends { fn session_notification(&self, n: N); }
    "#;
    assert_eq!(
        send_sites_in(EVERY_FORM),
        8,
        "ACP sends the WF-4 scan does not see"
    );
}
