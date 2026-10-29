//! 1.0.36 item a (design §3.3, tests 3-7): the launch-ask clamp, answers that remember nothing, the edit floor.

use super::*;
use crate::permission::rules::parse_permission_rule;
use crate::permission::types::{PermissionConfig, PromptPolicy, RuleAction};
use std::cell::RefCell;
use std::rc::Rc;

/// Answers every prompt with the first option of `pick`'s kind (else allow-once) and records the option ids offered.
#[derive(Clone)]
struct LaunchClient {
    pick: acp::PermissionOptionKind,
    offered: Rc<RefCell<Vec<Vec<String>>>>,
}

impl LaunchClient {
    fn new(pick: acp::PermissionOptionKind) -> Self {
        Self { pick, offered: Rc::default() }
    }

    fn prompts(&self) -> usize {
        self.offered.borrow().len()
    }
}

#[async_trait::async_trait(?Send)]
impl acp::Client for LaunchClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        self.offered
            .borrow_mut()
            .push(args.options.iter().map(|o| o.option_id.0.to_string()).collect());
        let option = args
            .options
            .iter()
            .find(|o| o.kind == self.pick)
            .or_else(|| args.options.iter().find(|o| o.kind == acp::PermissionOptionKind::AllowOnce))
            .expect("an allow option");
        Ok(acp::RequestPermissionResponse::new(acp::RequestPermissionOutcome::Selected(
            acp::SelectedPermissionOutcome::new(option.option_id.clone()),
        )))
    }

    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
}

fn rules(texts: &[(&str, RuleAction)]) -> Vec<crate::permission::types::PermissionRule> {
    texts.iter().map(|(t, a)| parse_permission_rule(t, *a).unwrap()).collect()
}

/// A config as the resolver builds it: owner rules plus the launch rules, the launch rules also in `launch_rules`.
fn config(owner: &[(&str, RuleAction)], launch: &[(&str, RuleAction)], prompt: PromptPolicy) -> PermissionConfig {
    let launch = rules(launch);
    let mut all = rules(owner);
    all.extend(launch.iter().cloned());
    PermissionConfig { prompt_policy: prompt, launch_rules: launch, ..PermissionConfig::new(all) }
}

fn cwd() -> (tempfile::TempDir, AbsPathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = AbsPathBuf::new(dunce::canonicalize(tmp.path()).unwrap()).unwrap();
    (tmp, cwd)
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Default,
    Yolo,
    AlwaysAllow,
    DontAsk,
    Auto,
}

const MODES: [Mode; 5] = [Mode::Default, Mode::Yolo, Mode::AlwaysAllow, Mode::DontAsk, Mode::Auto];

/// Run one request under `mode` and return (decision, prompts, event).
async fn run(
    cwd: &AbsPathBuf,
    mode: Mode,
    owner: &[(&str, RuleAction)],
    launch: &[(&str, RuleAction)],
    access: AccessKind,
    pick: acp::PermissionOptionKind,
) -> (Decision, usize, Option<PermissionEvent>) {
    let prompt = match mode {
        Mode::AlwaysAllow => PromptPolicy::Allow,
        Mode::DontAsk => PromptPolicy::Deny,
        _ => PromptPolicy::Ask,
    };
    let client = LaunchClient::new(pick);
    let (mgr, _events) = manager_with_recording_client_remember(
        cwd,
        Some(config(owner, launch, prompt)),
        client.clone(),
        ClientType::FuigoTUI,
        true,
    );
    match mode {
        Mode::Yolo => mgr.set_yolo_mode(true),
        Mode::Auto => mgr.set_auto_mode(true),
        _ => {}
    }
    let resolution = mgr.request(PermissionRequest::new(access, tool_call())).await;
    (resolution.decision, client.prompts(), resolution.event)
}

/// (name, owner rules, launch rules, access).
type Case = (&'static str, Vec<(&'static str, RuleAction)>, Vec<(String, RuleAction)>, AccessKind);

const ALLOW_ONCE: acp::PermissionOptionKind = acp::PermissionOptionKind::AllowOnce;

#[tokio::test(flavor = "current_thread")]
async fn launch_ask_reaches_the_client_in_every_mode() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            let secret = cwd.as_path().join("secret");
            std::fs::create_dir_all(&secret).unwrap();
            std::fs::write(secret.join("id"), "x").unwrap();
            let read_rule = format!("Read({}/**)", secret.display());
            let cat = format!("cat {}/id", secret.display());
            let cases: Vec<Case> = vec![
                ("bash", vec![("Bash", RuleAction::Allow)], vec![("Bash".into(), RuleAction::Ask)], AccessKind::Bash("ls".into())),
                ("read", vec![("Read", RuleAction::Allow)], vec![("Read".into(), RuleAction::Ask)], AccessKind::Read(Some(cwd.as_path().join("a").to_string_lossy().into_owned()))),
                ("edit", vec![("Edit", RuleAction::Allow)], vec![("Edit".into(), RuleAction::Ask)], AccessKind::Edit(cwd.as_path().join("a").to_string_lossy().into_owned())),
                ("webfetch", vec![("WebFetch", RuleAction::Allow)], vec![("WebFetch".into(), RuleAction::Ask)], AccessKind::WebFetch("https://example.com/".into())),
                ("mcp", vec![("mcp__srv", RuleAction::Allow)], vec![("mcp__srv".into(), RuleAction::Ask)], AccessKind::MCPTool { name: "srv__t".into(), input: serde_json::json!({}) }),
                // G r3 #1: a Read path ask catches a shell read of that file.
                ("shell-file", vec![("Bash", RuleAction::Allow)], vec![(read_rule.clone(), RuleAction::Ask)], AccessKind::Bash(cat.clone())),
            ];
            for (name, owner, launch, access) in &cases {
                let launch: Vec<(&str, RuleAction)> = launch.iter().map(|(t, a)| (t.as_str(), *a)).collect();
                for mode in MODES {
                    let (decision, prompts, event) = run(&cwd, mode, owner, &launch, access.clone(), ALLOW_ONCE).await;
                    assert_eq!(prompts, 1, "{name} {mode:?}: one prompt");
                    assert!(matches!(decision, Decision::Allow), "{name} {mode:?}: the client allowed: {decision:?}");
                    assert!(event.is_some_and(|e| e.user_prompted), "{name} {mode:?}: prompted event");
                }
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn launch_deny_stays_a_refusal_and_user_config_asks_keep_todays_result() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            for mode in MODES {
                let (decision, prompts, _) =
                    run(&cwd, mode, &[], &[("Bash(rm *)", RuleAction::Deny)], AccessKind::Bash("rm -rf x".into()), ALLOW_ONCE).await;
                assert_eq!(prompts, 0, "{mode:?}");
                assert!(matches!(decision, Decision::PolicyDeny(_)), "{mode:?}: {decision:?}");
            }
            // The same ask from user config (no launch rules): yolo still auto-approves a Read, as today.
            let (decision, prompts, _) = run(
                &cwd,
                Mode::Yolo,
                &[("Read", RuleAction::Ask)],
                &[],
                AccessKind::Read(Some(cwd.as_path().join("a").to_string_lossy().into_owned())),
                ALLOW_ONCE,
            )
            .await;
            assert_eq!((prompts, matches!(decision, Decision::Allow)), (0, true));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn launch_ask_invariant_for_a_recovered_script() {
    // Design test 5 (A#1): a launch `Bash(rm *)` ask binds inside a script a covering owner allow would run.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            for mode in [Mode::Default, Mode::Auto] {
                let (_, prompts, _) = run(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[("Bash(rm *)", RuleAction::Ask)],
                    AccessKind::Bash(r#"LOG=/x; ls "$LOG"; rm "$LOG""#.into()),
                    ALLOW_ONCE,
                )
                .await;
                assert_eq!(prompts, 1, "{mode:?}");
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn answering_a_launch_ask_remembers_nothing() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            let client = LaunchClient::new(acp::PermissionOptionKind::AllowAlways);
            let (mgr, _events) = manager_with_recording_client_remember(
                &cwd,
                Some(config(&[], &[("Bash", RuleAction::Ask), ("WebFetch", RuleAction::Ask)], PromptPolicy::Ask)),
                client.clone(),
                ClientType::FuigoTUI,
                true,
            );
            for access in [AccessKind::Bash("npm test".into()), AccessKind::WebFetch("https://example.com/".into())] {
                for _ in 0..2 {
                    let resolution = mgr.request(PermissionRequest::new(access.clone(), tool_call())).await;
                    assert!(matches!(resolution.decision, Decision::Allow));
                    let event = resolution.event.unwrap();
                    assert_eq!(event.prompt_outcome.as_deref(), Some("allow_once"), "{access:?}");
                }
            }
            // Every request prompted again (nothing was stored), and no prompt offered an always row.
            assert_eq!(client.prompts(), 4);
            for options in client.offered.borrow().iter() {
                for id in options {
                    assert!(
                        !id.contains("always") && id != ALLOW_EDITS_SESSION_OPTION_ID_FOR_TEST,
                        "offered {id} for a launch ask"
                    );
                }
            }
        })
        .await;
}

const ALLOW_EDITS_SESSION_OPTION_ID_FOR_TEST: &str = crate::permission::prompter::ALLOW_EDITS_SESSION_OPTION_ID;

#[tokio::test(flavor = "current_thread")]
async fn a_pinned_policy_file_is_never_editable() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            let text = "[permission]\nask = [\"Bash(rm *)\"]\n";
            let file = cwd.as_path().join("policy-floor.toml");
            std::fs::write(&file, text).unwrap();
            let path = file.to_string_lossy().into_owned();
            crate::permission::launch_policy::verify_and_pin(
                &path,
                Some(&crate::permission::launch_policy::sha256_hex(text.as_bytes())),
            )
            .unwrap();
            for mode in [Mode::Default, Mode::Yolo, Mode::AlwaysAllow] {
                let (decision, prompts, _) =
                    run(&cwd, mode, &[("Edit", RuleAction::Allow)], &[], AccessKind::Edit(path.clone()), ALLOW_ONCE).await;
                assert_eq!(prompts, 0, "{mode:?}");
                assert!(matches!(decision, Decision::PolicyDeny(_)), "{mode:?}: {decision:?}");
                let (decision, _, _) = run(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[],
                    AccessKind::Bash(format!("echo x > {path}")),
                    ALLOW_ONCE,
                )
                .await;
                assert!(matches!(decision, Decision::PolicyDeny(_)), "redirect {mode:?}: {decision:?}");
            }
            #[cfg(unix)]
            {
                let hard = cwd.as_path().join("hard-link.toml");
                std::fs::hard_link(&file, &hard).unwrap();
                let (decision, _, _) = run(
                    &cwd,
                    Mode::Yolo,
                    &[],
                    &[],
                    AccessKind::Edit(hard.to_string_lossy().into_owned()),
                    ALLOW_ONCE,
                )
                .await;
                assert!(matches!(decision, Decision::PolicyDeny(_)), "hard link: {decision:?}");
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_launch_policy_holds_nothing() {
    // The unset path: no launch rules, so the request body answers directly (yolo auto-approves, nothing prompts).
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            let read = AccessKind::Read(Some(cwd.as_path().join("a").to_string_lossy().into_owned()));
            let (decision, prompts, event) = run(&cwd, Mode::Yolo, &[("Read", RuleAction::Ask)], &[], read, ALLOW_ONCE).await;
            assert!(matches!(decision, Decision::Allow));
            assert_eq!(prompts, 0);
            assert_eq!(event.and_then(|e| e.decision_reason).as_deref(), Some(reasons::YOLO));
        })
        .await;
}

// ═════════════════════════════════════════════════════════════════════════════
// r1 code review (Astra 5 and 7, Fable M1-M4): every former approval source, normalisation, no over-prompting
// ═════════════════════════════════════════════════════════════════════════════

/// Answers every prompt with the option whose id is `answer` (offered or not, as a hostile or buggy client might) and
/// counts prompts.
#[derive(Clone)]
struct ForcedAnswerClient {
    answer: &'static str,
    offered: Rc<RefCell<Vec<Vec<String>>>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for ForcedAnswerClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        self.offered
            .borrow_mut()
            .push(args.options.iter().map(|o| o.option_id.0.to_string()).collect());
        Ok(acp::RequestPermissionResponse::new(acp::RequestPermissionOutcome::Selected(
            acp::SelectedPermissionOutcome::new(acp::PermissionOptionId::new(self.answer)),
        )))
    }

    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
}

/// One request built by the caller (multi-target constructors), under `mode`; returns (decision, prompts, event).
async fn run_request(
    cwd: &AbsPathBuf,
    mode: Mode,
    owner: &[(&str, RuleAction)],
    launch: &[(&str, RuleAction)],
    request: PermissionRequest,
) -> (Decision, usize, Option<PermissionEvent>) {
    let prompt = match mode {
        Mode::AlwaysAllow => PromptPolicy::Allow,
        Mode::DontAsk => PromptPolicy::Deny,
        _ => PromptPolicy::Ask,
    };
    let client = LaunchClient::new(ALLOW_ONCE);
    let (mgr, _events) = manager_with_recording_client_remember(
        cwd,
        Some(config(owner, launch, prompt)),
        client.clone(),
        ClientType::FuigoTUI,
        true,
    );
    match mode {
        Mode::Yolo => mgr.set_yolo_mode(true),
        Mode::Auto => mgr.set_auto_mode(true),
        _ => {}
    }
    let resolution = mgr.request(request).await;
    (resolution.decision, client.prompts(), resolution.event)
}

fn patch_request(cwd: &AbsPathBuf, patch_text: String) -> PermissionRequest {
    let input = fuigo_tools::types::ToolInput::ApplyPatch(
        fuigo_tools::implementations::codex::apply_patch::ApplyPatchInput { patch: patch_text },
    );
    PermissionRequest {
        path_context: Some(crate::permission::types::RequestPathContext {
            real_cwd: cwd.as_path().to_path_buf(),
            display_cwd: None,
        }),
        edit_targets: crate::permission::types::edit_targets_for(&input),
        ..PermissionRequest::new(AccessKind::from(&input), tool_call())
    }
}

fn multi_read_request(cwd: &AbsPathBuf, first: &str, files: &[&str]) -> PermissionRequest {
    let input = fuigo_tools::types::ToolInput::ReadFile(
        serde_json::from_value(serde_json::json!({
            "target_file": first,
            "files": files.iter().map(|p| serde_json::json!({ "path": p })).collect::<Vec<_>>(),
        }))
        .unwrap(),
    );
    PermissionRequest {
        path_context: Some(crate::permission::types::RequestPathContext {
            real_cwd: cwd.as_path().to_path_buf(),
            display_cwd: None,
        }),
        read_targets: crate::permission::types::read_targets_for(&input),
        ..PermissionRequest::new(AccessKind::from(&input), tool_call())
    }
}

/// Fable M1: the `apply_patch` and multi-file Read constructors carry the launch ask in every mode, also when the
/// asked file is not the first one.
#[tokio::test(flavor = "current_thread")]
async fn launch_ask_reaches_the_client_for_apply_patch_and_multi_file_read() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            let secret = cwd.as_path().join("secret");
            std::fs::create_dir_all(&secret).unwrap();
            std::fs::write(secret.join("key"), "x").unwrap();
            std::fs::write(cwd.as_path().join("ok.txt"), "x").unwrap();
            let edit_ask = format!("Edit({}/**)", secret.display());
            let read_ask = format!("Read({}/**)", secret.display());
            let patch_text = "*** Begin Patch\n*** Add File: plain.txt\n+a\n*** Add File: secret/new.txt\n+b\n*** End Patch\n";
            for mode in MODES {
                let (decision, prompts, event) = run_request(
                    &cwd,
                    mode,
                    &[("Edit", RuleAction::Allow)],
                    &[(&edit_ask, RuleAction::Ask)],
                    patch_request(&cwd, patch_text.to_owned()),
                )
                .await;
                assert_eq!(prompts, 1, "apply_patch {mode:?}");
                assert!(matches!(decision, Decision::Allow), "apply_patch {mode:?}: {decision:?}");
                assert!(event.is_some_and(|e| e.user_prompted), "apply_patch {mode:?}");
                let (decision, prompts, event) = run_request(
                    &cwd,
                    mode,
                    &[("Read", RuleAction::Allow)],
                    &[(&read_ask, RuleAction::Ask)],
                    multi_read_request(&cwd, "ok.txt", &["secret/key"]),
                )
                .await;
                assert_eq!(prompts, 1, "multi-file read {mode:?}");
                assert!(matches!(decision, Decision::Allow), "multi-file read {mode:?}: {decision:?}");
                assert!(event.is_some_and(|e| e.user_prompted), "multi-file read {mode:?}");
            }
        })
        .await;
}

/// Fable M2 / Astra 7: a remembered grant, and another session's `allow_always` in the same folder, do not answer a
/// launch ask; the same grant still answers the same call without a launch policy (control).
#[tokio::test(flavor = "current_thread")]
async fn launch_ask_beats_a_remembered_grant_and_another_sessions_allow_always() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            let npm = || AccessKind::Bash("npm test".into());
            // Session one answers an owner ask with "always": a remembered grant for this folder.
            let always = LaunchClient::new(acp::PermissionOptionKind::AllowAlways);
            let (first, _e1) = manager_with_recording_client_remember(
                &cwd,
                Some(config(&[("Bash", RuleAction::Ask)], &[], PromptPolicy::Ask)),
                always.clone(),
                ClientType::FuigoTUI,
                true,
            );
            let granted = first.request(PermissionRequest::new(npm(), tool_call())).await;
            assert!(matches!(granted.decision, Decision::Allow));
            let remembered = first.request(PermissionRequest::new(npm(), tool_call())).await;
            assert!(matches!(remembered.decision, Decision::Allow));
            assert_eq!(always.prompts(), 1, "the grant answers session one's second call");
            // Session two, no launch policy: the grant answers it too (the control).
            let control_client = LaunchClient::new(ALLOW_ONCE);
            let (control, _e2) = manager_with_recording_client_remember(
                &cwd,
                Some(config(&[("Bash", RuleAction::Ask)], &[], PromptPolicy::Ask)),
                control_client.clone(),
                ClientType::FuigoTUI,
                true,
            );
            let resolution = control.request(PermissionRequest::new(npm(), tool_call())).await;
            assert!(matches!(resolution.decision, Decision::Allow));
            assert_eq!(control_client.prompts(), 0, "another session's grant applies without a launch policy");
            // Session three, launch ask: the client is asked in every mode, and the answer is a once-answer.
            for mode in MODES {
                let (decision, prompts, event) = run(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Ask)],
                    &[("Bash(npm *)", RuleAction::Ask)],
                    npm(),
                    ALLOW_ONCE,
                )
                .await;
                assert_eq!(prompts, 1, "{mode:?}");
                assert!(matches!(decision, Decision::Allow), "{mode:?}: {decision:?}");
                let event = event.expect("event");
                assert!(event.user_prompted, "{mode:?}");
                assert_eq!(event.prompt_outcome.as_deref(), Some("allow_once"), "{mode:?}");
            }
        })
        .await;
}

/// Fable M2: a PreToolUse hook `allow` adds nothing to the request (`tool_calls.rs` passes it through to the normal
/// flow), and a hook `ask` merges with the launch ask into one prompt.
#[tokio::test(flavor = "current_thread")]
async fn launch_ask_beats_a_hook_allow_and_merges_with_a_hook_ask() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            for mode in MODES {
                let after_hook_allow = PermissionRequest::new(AccessKind::Bash("npm test".into()), tool_call());
                let (decision, prompts, _) = run_request(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[("Bash(npm *)", RuleAction::Ask)],
                    after_hook_allow,
                )
                .await;
                assert_eq!((prompts, matches!(decision, Decision::Allow)), (1, true), "hook allow {mode:?}");
                let hook_ask = PermissionRequest {
                    hook_ask: Some(crate::permission::types::HookAsk { hook_name: "h".into(), reason: None }),
                    ..PermissionRequest::new(AccessKind::Bash("npm test".into()), tool_call())
                };
                let (decision, prompts, _) = run_request(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[("Bash(npm *)", RuleAction::Ask)],
                    hook_ask,
                )
                .await;
                assert_eq!((prompts, matches!(decision, Decision::Allow)), (1, true), "hook ask {mode:?}");
            }
        })
        .await;
}

fn event_with(reason: &str, user_prompted: bool) -> PermissionEvent {
    serde_json::from_value(serde_json::json!({
        "tool_id": "t", "tool_name": "Bash", "access_kind": "bash", "yolo_mode": false, "auto_approved": !user_prompted,
        "user_prompted": user_prompted, "decision": "allow", "timestamp": "2026-10-29T00:00:00Z", "decision_reason": reason,
    }))
    .unwrap()
}

/// Fable M2 / Astra 7: the clamp replaces an Allow from every source the client did not answer: sandbox auto-allow, a
/// persisted or session grant, the static allowlist, yolo, auto mode, policy allow, ... (every reason Fuigo emits),
/// and the dontAsk refusal; a client answer and a real refusal stand.
#[test]
fn the_clamp_replaces_every_allow_the_client_did_not_give() {
    for reason in reasons::ALL {
        let unprompted = PermissionResolution { decision: Decision::Allow, event: Some(event_with(reason, false)) };
        assert!(launch_clamp_applies(&unprompted), "{reason}");
        let answered = PermissionResolution { decision: Decision::Allow, event: Some(event_with(reason, true)) };
        assert!(!launch_clamp_applies(&answered), "{reason}");
    }
    assert!(launch_clamp_applies(&PermissionResolution { decision: Decision::Allow, event: None }));
    let dont_ask = PermissionResolution {
        decision: Decision::PolicyDeny("x".into()),
        event: Some(event_with(reasons::PROMPT_DENY, false)),
    };
    assert!(launch_clamp_applies(&dont_ask));
    let deny = PermissionResolution {
        decision: Decision::PolicyDeny("x".into()),
        event: Some(event_with(reasons::POLICY_DENY, false)),
    };
    assert!(!launch_clamp_applies(&deny));
}

/// Astra 7: every "always" answer becomes a once-answer under a launch ask (nothing is remembered).
#[test]
fn every_always_answer_is_normalised_to_once() {
    use crate::permission::prompter::PromptOutcome as O;
    let allows = [
        O::AllowOnce,
        O::AllowAlways,
        O::AllowEditsForSession,
        O::AllowAlwaysBashCommand("npm test".into()),
        O::AllowAlwaysBashGlob("npm *".into()),
        O::AllowAlwaysDomain("example.com".into()),
        O::AllowAlwaysMcpTool("srv__t".into()),
        O::AllowAlwaysMcpServer("srv".into()),
    ];
    for outcome in allows {
        let shown = format!("{outcome:?}");
        assert!(matches!(once_only(outcome), O::AllowOnce), "{shown}");
    }
    let rejects = [
        O::RejectOnce,
        O::RejectAlwaysBashCommand("rm".into()),
        O::RejectAlwaysMcpTool("srv__t".into()),
        O::RejectAlwaysDomain("example.com".into()),
    ];
    for outcome in rejects {
        let shown = format!("{outcome:?}");
        assert!(matches!(once_only(outcome), O::RejectOnce), "{shown}");
    }
    assert!(matches!(once_only(O::Cancelled), O::Cancelled));
}

/// Astra 7: a client that answers a launch ask with an always option it was not offered gets no grant: the call is not
/// allowed by it, an event is emitted, and the next call prompts again.
#[tokio::test(flavor = "current_thread")]
async fn an_unoffered_always_answer_remembers_nothing() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            for answer in ["allow-always", "allow-always-command", ALLOW_EDITS_SESSION_OPTION_ID_FOR_TEST, "enable-always-approve"] {
                let client = ForcedAnswerClient { answer, offered: Rc::default() };
                let (mgr, _events) = manager_with_recording_client_remember(
                    &cwd,
                    Some(config(&[("Bash", RuleAction::Allow)], &[("Bash", RuleAction::Ask)], PromptPolicy::Ask)),
                    client.clone(),
                    ClientType::FuigoTUI,
                    true,
                );
                for _ in 0..2 {
                    let resolution =
                        mgr.request(PermissionRequest::new(AccessKind::Bash("npm test".into()), tool_call())).await;
                    let event = resolution.event.as_ref().expect("an event");
                    if matches!(resolution.decision, Decision::Allow) {
                        assert_eq!(event.prompt_outcome.as_deref(), Some("allow_once"), "{answer}");
                    }
                }
                assert_eq!(client.offered.borrow().len(), 2, "{answer}: every call prompted");
            }
        })
        .await;
}

/// Fable M4: a launch pattern ask binds only the commands it matches. An owner-allowed command it does not match, and
/// a recovered script without one, get exactly the answer they get with no launch policy.
#[tokio::test(flavor = "current_thread")]
async fn an_unmatched_command_keeps_its_answer_under_a_launch_pattern_ask() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            for mode in [Mode::Default, Mode::Yolo, Mode::AlwaysAllow] {
                let (decision, prompts, _) = run(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[("Bash(rm *)", RuleAction::Ask)],
                    AccessKind::Bash("ls".into()),
                    ALLOW_ONCE,
                )
                .await;
                assert_eq!((prompts, matches!(decision, Decision::Allow)), (0, true), "ls {mode:?}");
            }
            let script = r#"LOG=/x; ls "$LOG""#;
            for mode in [Mode::Default, Mode::Auto] {
                let unset = run(&cwd, mode, &[("Bash", RuleAction::Allow)], &[], AccessKind::Bash(script.into()), ALLOW_ONCE).await;
                let governed = run(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[("Bash(rm *)", RuleAction::Ask)],
                    AccessKind::Bash(script.into()),
                    ALLOW_ONCE,
                )
                .await;
                assert_eq!(governed.1, unset.1, "{mode:?}: prompts");
                assert_eq!(format!("{:?}", governed.0), format!("{:?}", unset.0), "{mode:?}: decision");
            }
        })
        .await;
}

/// Astra 5: the pinned policy file's hard refusal is not hidden by an earlier protected target in the same call.
#[tokio::test(flavor = "current_thread")]
async fn a_pinned_policy_file_outranks_an_earlier_protected_target() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (_tmp, cwd) = cwd();
            std::fs::create_dir_all(cwd.as_path().join(".git/hooks")).unwrap();
            let text = "[permission]\nask = [\"Bash(curl *)\"]\n";
            let file = cwd.as_path().join("policy-rank.toml");
            std::fs::write(&file, text).unwrap();
            let path = file.to_string_lossy().into_owned();
            crate::permission::launch_policy::verify_and_pin(
                &path,
                Some(&crate::permission::launch_policy::sha256_hex(text.as_bytes())),
            )
            .unwrap();
            // The earlier target alone prompts (the control); with the policy file after it, the call is refused.
            let hook_only = "*** Begin Patch\n*** Add File: .git/hooks/pre-commit\n+x\n*** End Patch\n";
            let (_, prompts, _) =
                run_request(&cwd, Mode::Default, &[("Edit", RuleAction::Allow)], &[], patch_request(&cwd, hook_only.into()))
                    .await;
            assert_eq!(prompts, 1, "the git hook alone prompts");
            let both = "*** Begin Patch\n*** Add File: .git/hooks/pre-commit\n+x\n*** Add File: policy-rank.toml\n+x\n*** End Patch\n";
            for mode in [Mode::Default, Mode::Yolo, Mode::AlwaysAllow] {
                let (decision, prompts, _) =
                    run_request(&cwd, mode, &[("Edit", RuleAction::Allow)], &[], patch_request(&cwd, both.into())).await;
                assert_eq!(prompts, 0, "patch {mode:?}");
                assert!(matches!(decision, Decision::PolicyDeny(_)), "patch {mode:?}: {decision:?}");
                let (decision, prompts, _) = run(
                    &cwd,
                    mode,
                    &[("Bash", RuleAction::Allow)],
                    &[],
                    AccessKind::Bash(format!("echo x > .git/hooks/pre-commit; echo y > {path}")),
                    ALLOW_ONCE,
                )
                .await;
                assert_eq!(prompts, 0, "redirects {mode:?}");
                assert!(matches!(decision, Decision::PolicyDeny(_)), "redirects {mode:?}: {decision:?}");
            }
        })
        .await;
}
