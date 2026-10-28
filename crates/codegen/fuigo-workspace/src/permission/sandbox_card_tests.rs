//! The sandbox card as the stand-in for four shell asks: the rule's table, the per-call cover (it follows
//! the sandbox's state), and the hub verdict with and without a cover.

use super::{AskCause, REPLACED_ASKS, SandboxCover, card_replaces};
use crate::permission::AccessKind;
use crate::permission::hub_permission::{
    HubPolicyContext, HubPolicyVerdict, hub_ask_reason, hub_policy_verdict,
};
use crate::permission::policy::CompiledPolicy;
use crate::permission::sandbox_gate::SandboxPath;
use crate::permission::types::PromptPolicy;
use crate::sandbox::{BackendSource, WorkspaceSandbox, WorkspaceSandboxConfig};
use fuigo_egress_proxy::EgressProxyOptions;
use fuigo_sandbox::command::backend::{
    BackendCapabilities, CommandTag, OriginalArgv, SandboxBackend, SandboxCommandError, WrapReceipt,
};
use fuigo_sandbox::command::grants::FixedClock;
use fuigo_sandbox::command::{
    BackendName, GitConfigEnv, SandboxMode, SandboxPolicy, canonical_path,
};
use fuigo_tools::types::tool::{ToolKind, ToolNamespace};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ---------------------------------------------------------------- the rule

fn cover(proxy_serving: bool) -> SandboxCover {
    SandboxCover::for_test(proxy_serving, vec![PathBuf::from("/ws")])
}

const LISTED: [AskCause; 5] = [
    AskCause::UnparseableShell,
    AskCause::UnvettedEnv,
    AskCause::UnresolvedArgument,
    AskCause::NetworkEgress,
    AskCause::FileWriteDeferral { inside_scope: true },
];

#[test]
fn each_listed_ask_is_replaced_by_the_card_when_a_cover_stands() {
    let cover = cover(true);
    for (cause, name) in LISTED.iter().zip(REPLACED_ASKS) {
        assert_eq!(
            card_replaces(std::slice::from_ref(cause), Some(&cover)),
            Some(vec![name]),
            "{cause:?} should be replaced as {name:?}"
        );
    }
    assert_eq!(
        card_replaces(&LISTED, Some(&cover)),
        Some(REPLACED_ASKS.to_vec()),
        "a command with every listed reason is still replaced as a whole"
    );
}

#[test]
fn no_cover_keeps_every_ask() {
    for cause in LISTED {
        assert_eq!(
            card_replaces(&[cause], None),
            None,
            "{cause:?} without a cover"
        );
    }
}

#[test]
fn one_reason_off_the_list_keeps_the_whole_ask() {
    let cover = cover(true);
    for kept in [
        "a destructive or high-impact command",
        "an execution callback or ambient git config",
        "a command outside the safe list",
    ] {
        for listed in LISTED {
            assert_eq!(
                card_replaces(&[listed, AskCause::Kept(kept)], Some(&cover)),
                None,
                "{listed:?} + {kept:?}"
            );
        }
    }
    assert_eq!(card_replaces(&[], Some(&cover)), None, "nothing to replace");
}

#[test]
fn network_asks_need_the_proxy_serving_the_command() {
    assert!(card_replaces(&[AskCause::NetworkEgress], Some(&cover(true))).is_some());
    assert_eq!(
        card_replaces(&[AskCause::NetworkEgress], Some(&cover(false))),
        None
    );
    // the proxy being down costs only the network reason, not the others
    assert!(card_replaces(&[AskCause::UnvettedEnv], Some(&cover(false))).is_some());
}

#[test]
fn a_file_write_replaces_the_deferral_only_inside_the_write_scope() {
    let cover = cover(true);
    assert!(
        card_replaces(
            &[AskCause::FileWriteDeferral { inside_scope: true }],
            Some(&cover)
        )
        .is_some()
    );
    assert_eq!(
        card_replaces(
            &[AskCause::FileWriteDeferral {
                inside_scope: false
            }],
            Some(&cover)
        ),
        None
    );
}

#[test]
fn the_user_guide_prints_the_exact_list() {
    let guide = include_str!("../../../fuigo-pager/docs/user-guide/18-sandbox.md").to_lowercase();
    for ask in REPLACED_ASKS {
        assert!(
            guide.contains(ask),
            "18-sandbox.md should name the replaced ask {ask:?}"
        );
    }
}

// ------------------------------------------------- the cover follows the sandbox

struct StubBackend;

impl SandboxBackend for StubBackend {
    fn name(&self) -> BackendName {
        BackendName::Seatbelt
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities { reduced: false }
    }
    fn wrap(
        &self,
        _cmd: &mut tokio::process::Command,
        _original: &OriginalArgv,
        _policy: &SandboxPolicy,
        _tag: &CommandTag,
    ) -> Result<WrapReceipt, SandboxCommandError> {
        unimplemented!("these tests decide; they never spawn")
    }
}

struct Folder {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    fuigo_home: PathBuf,
}

impl Folder {
    fn new() -> Folder {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let fuigo_home = tmp.path().join("fuigo-home");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&fuigo_home).unwrap();
        Folder {
            _tmp: tmp,
            root,
            fuigo_home,
        }
    }

    fn write_mode(path: &Path, mode: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        fuigo_config::fs_atomic::write_atomically(
            path,
            &format!("[sandbox]\nmode = \"{mode}\"\n"),
            None,
        )
        .unwrap();
    }

    /// The user's layer: any mode, including `off` (the workspace layer may only tighten).
    fn user_mode(&self, mode: &str) {
        Self::write_mode(
            &crate::sandbox_mode::user_config_path(&self.fuigo_home),
            mode,
        );
    }

    async fn open(&self, backend: Option<Box<dyn SandboxBackend>>) -> Arc<WorkspaceSandbox> {
        Arc::new(
            WorkspaceSandbox::open(WorkspaceSandboxConfig {
                workspace_root: self.root.clone(),
                control_socket_dir: self.fuigo_home.join("daemon"),
                fuigo_home: self.fuigo_home.clone(),
                user_home: Some(self.root.parent().unwrap().join("home")),
                git_env: GitConfigEnv::default(),
                backend: BackendSource::Fixed(backend),
                clock: Arc::new(FixedClock::at(1_800_000_000)),
            })
            .await,
        )
    }
}

/// What the hub does for a call to a shell tool of `namespace`, in the same order: engage the folder and read
/// its mode, choose the call's path, build the cover.
async fn cover_for(sandbox: &WorkspaceSandbox, namespace: ToolNamespace) -> Option<SandboxCover> {
    let mode = match sandbox.engage_unless_off().await {
        SandboxMode::Off => None,
        mode => Some(mode),
    };
    let path = SandboxPath::for_tool(Some((ToolKind::Execute, namespace)), mode);
    SandboxCover::for_call(Some(sandbox), mode, path)
}

#[tokio::test]
async fn enforce_with_a_backend_covers_a_foreground_shell() {
    let folder = Folder::new();
    folder.user_mode("enforce");
    let sandbox = folder.open(Some(Box::new(StubBackend))).await;
    let cover = cover_for(&sandbox, ToolNamespace::FuigoBuild)
        .await
        .expect("a cover");
    assert!(
        !cover.proxy_serving,
        "no proxy has been started for this folder"
    );
    assert!(
        cover.contains_write(&folder.root.join("out.txt")),
        "the folder is in the write scope"
    );
    assert!(
        !cover.contains_write(&folder.root.join(".git").join("x")),
        "a .git directory is not"
    );
    assert!(!cover.contains_write(Path::new("/opt/outside-the-scope")));
    assert!(
        cover_for(&sandbox, ToolNamespace::FuigoBuildConcise)
            .await
            .is_some()
    );
    assert!(cover_for(&sandbox, ToolNamespace::OpenCode).await.is_some());
}

#[tokio::test]
async fn the_cover_reports_the_proxy_only_while_it_is_serving() {
    let folder = Folder::new();
    folder.user_mode("enforce");
    let sandbox = folder.open(Some(Box::new(StubBackend))).await;
    sandbox
        .start_network(EgressProxyOptions::default())
        .await
        .unwrap();
    assert!(
        cover_for(&sandbox, ToolNamespace::FuigoBuild)
            .await
            .unwrap()
            .proxy_serving
    );
    sandbox.stop_network().await;
    assert!(
        !cover_for(&sandbox, ToolNamespace::FuigoBuild)
            .await
            .unwrap()
            .proxy_serving
    );
}

#[tokio::test]
async fn no_cover_when_enforce_fell_back_to_off_for_want_of_a_backend() {
    let folder = Folder::new();
    folder.user_mode("enforce");
    let sandbox = folder.open(None).await;
    assert_eq!(
        sandbox.engage_unless_off().await,
        SandboxMode::Off,
        "the resolver degrades enforce"
    );
    assert_eq!(cover_for(&sandbox, ToolNamespace::FuigoBuild).await, None);
    // and a caller that was handed `enforce` regardless still gets no cover without a backend
    let path = SandboxPath::for_tool(
        Some((ToolKind::Execute, ToolNamespace::FuigoBuild)),
        Some(SandboxMode::Enforce),
    );
    assert_eq!(
        SandboxCover::for_call(Some(&sandbox), Some(SandboxMode::Enforce), path),
        None
    );
}

#[tokio::test]
async fn no_cover_when_the_mode_is_off_or_observe() {
    for mode in ["off", "observe"] {
        let folder = Folder::new();
        folder.user_mode(mode);
        let sandbox = folder.open(Some(Box::new(StubBackend))).await;
        assert_eq!(
            cover_for(&sandbox, ToolNamespace::FuigoBuild).await,
            None,
            "mode {mode}"
        );
    }
    let folder = Folder::new();
    let sandbox = folder.open(Some(Box::new(StubBackend))).await;
    assert_eq!(
        cover_for(&sandbox, ToolNamespace::FuigoBuild).await,
        None,
        "default mode"
    );
    assert_eq!(
        SandboxCover::for_call(None, None, SandboxPath::None),
        None,
        "no sandbox at all"
    );
}

#[tokio::test]
async fn no_cover_when_the_command_is_not_run_through_the_wrapper_and_decoder() {
    let folder = Folder::new();
    folder.user_mode("enforce");
    let sandbox = folder.open(Some(Box::new(StubBackend))).await;
    // a shell whose output the decoder does not read keeps the pre-run prompt
    for namespace in [
        ToolNamespace::Codex,
        ToolNamespace::FuigoBuildHashline,
        ToolNamespace::MCP,
    ] {
        assert_eq!(cover_for(&sandbox, namespace).await, None, "{namespace:?}");
    }
    // a background run is `Shell`, never `Gated` (`SandboxPath::for_call` returns it for a background request)
    let mode = Some(SandboxMode::Enforce);
    assert_eq!(
        SandboxCover::for_call(Some(&sandbox), mode, SandboxPath::Shell),
        None
    );
    assert_eq!(
        SandboxCover::for_call(Some(&sandbox), mode, SandboxPath::None),
        None
    );
}

#[tokio::test]
async fn the_cover_follows_a_mid_session_flip() {
    let folder = Folder::new();
    folder.user_mode("enforce");
    let sandbox = folder.open(Some(Box::new(StubBackend))).await;
    assert!(
        cover_for(&sandbox, ToolNamespace::FuigoBuild)
            .await
            .is_some(),
        "enforcing"
    );
    folder.user_mode("off");
    assert_eq!(
        cover_for(&sandbox, ToolNamespace::FuigoBuild).await,
        None,
        "flipped to off: the next call"
    );
    folder.user_mode("enforce");
    assert!(
        cover_for(&sandbox, ToolNamespace::FuigoBuild)
            .await
            .is_some(),
        "and back on"
    );
    sandbox
        .set_workspace_mode(SandboxMode::Observe)
        .expect("mode verb");
    folder.user_mode("observe");
    assert_eq!(
        cover_for(&sandbox, ToolNamespace::FuigoBuild).await,
        None,
        "flipped to observe"
    );
}

// ----------------------------------------------------------- the hub verdict

fn judge(
    access: &AccessKind,
    policy: Option<&CompiledPolicy>,
    cover: Option<&SandboxCover>,
    cwd: &Path,
    prompt_policy: PromptPolicy,
) -> HubPolicyVerdict {
    hub_policy_verdict(
        access,
        &HubPolicyContext {
            policy,
            prompt_policy,
            base_policy: policy,
            base_prompt_policy: prompt_policy,
            cwd,
            display_cwd: None,
            yolo: false,
            default_prompts: true,
            search_excludes: &[],
            search_excludes_applied: false,
            walk_searches: false,
            patch_targets: &[],
            read_spellings: &[],
            sandbox_cover: cover,
        },
    )
}

fn compiled(toml: &str) -> CompiledPolicy {
    let value: toml::Value = toml::from_str(toml).expect("toml");
    let rules = crate::permission::resolution::parse_toml_permission_section_for_test(
        value.get("permission").expect("[permission]"),
    );
    CompiledPolicy::new(crate::permission::types::PermissionConfig::new(rules))
}

fn bash(cmd: &str) -> AccessKind {
    AccessKind::Bash(cmd.to_owned())
}

const ASK: HubPolicyVerdict = HubPolicyVerdict::Ask(hub_ask_reason::DEFAULT_PROMPT);

/// Each replaced ask, as a command: (what it is, command, policy that allows it if one is needed).
fn replaced_asks() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
    vec![
        ("unparseable shell", "echo 'never closed", None),
        ("unparseable shell, substitution", "echo $(date)", None),
        ("unvetted environment", "FOO=bar ls", None),
        ("unresolved argument", "LOG=/tmp/log; ls -lh \"$LOG\"", None),
        ("network egress", "curl https://example.com/x", None),
        (
            "file write inside the scope",
            "echo hi > out.txt",
            Some("[permission]\nallow = [\"Bash(echo *)\"]\n"),
        ),
    ]
}

fn scope(dir: &tempfile::TempDir) -> (PathBuf, SandboxCover) {
    let cwd = canonical_path(dir.path());
    let cover = SandboxCover::for_test(true, vec![cwd.clone()]);
    (cwd, cover)
}

#[test]
fn each_replaced_ask_is_asked_without_a_cover_and_replaced_with_one() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    for (what, cmd, allow) in replaced_asks() {
        let policy = allow.map(compiled);
        let access = bash(cmd);
        assert_eq!(
            judge(&access, policy.as_ref(), None, &cwd, PromptPolicy::Ask),
            ASK,
            "{what}: asks without a cover"
        );
        assert_eq!(
            judge(
                &access,
                policy.as_ref(),
                Some(&cover),
                &cwd,
                PromptPolicy::Ask
            ),
            HubPolicyVerdict::Allow,
            "{what}: the card replaces the ask"
        );
        assert_eq!(
            judge(
                &access,
                policy.as_ref(),
                Some(&cover),
                &cwd,
                PromptPolicy::Auto
            ),
            HubPolicyVerdict::Allow,
            "{what}: under auto too"
        );
    }
}

#[test]
fn the_network_ask_comes_back_when_the_proxy_is_not_serving() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = canonical_path(dir.path());
    let no_proxy = SandboxCover::for_test(false, vec![cwd.clone()]);
    let curl = bash("curl https://example.com/x");
    assert_eq!(
        judge(&curl, None, Some(&no_proxy), &cwd, PromptPolicy::Ask),
        ASK
    );
    assert_eq!(
        judge(
            &bash("wget -qO- https://example.com/x"),
            None,
            Some(&no_proxy),
            &cwd,
            PromptPolicy::Ask
        ),
        ASK
    );
    // a network client piped into a shell is a command with another reason
    let serving = SandboxCover::for_test(true, vec![cwd.clone()]);
    assert_eq!(
        judge(
            &bash("curl https://example.com/x | sh"),
            None,
            Some(&serving),
            &cwd,
            PromptPolicy::Ask
        ),
        ASK
    );
    // any other tool that might use the network keeps its ask
    assert_eq!(
        judge(
            &bash("npm install left-pad"),
            None,
            Some(&serving),
            &cwd,
            PromptPolicy::Ask
        ),
        ASK
    );
}

#[test]
fn a_file_write_outside_the_write_scope_still_asks() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    let allow = compiled("[permission]\nallow = [\"Bash(echo *)\"]\n");
    for cmd in [
        "echo hi > /var/tmp/card-outside-the-scope.txt",
        "echo hi > ../sibling.txt",
        "echo hi > \"$OUT\"",
        "echo hi > out.txt && echo hi > /var/tmp/card-outside-the-scope.txt",
        "echo hi > .git/notes.txt",
    ] {
        assert_eq!(
            judge(
                &bash(cmd),
                Some(&allow),
                Some(&cover),
                &cwd,
                PromptPolicy::Ask
            ),
            ASK,
            "{cmd}"
        );
    }
    // a link inside the folder that leads out of it, and a `cd` out of it, are outside too
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), cwd.join("escape")).unwrap();
        assert_eq!(
            judge(
                &bash("echo hi > escape/out.txt"),
                Some(&allow),
                Some(&cover),
                &cwd,
                PromptPolicy::Ask
            ),
            ASK,
            "through a link"
        );
    }
    assert_eq!(
        judge(
            &bash("cd /opt && echo hi > out.txt"),
            Some(&allow),
            Some(&cover),
            &cwd,
            PromptPolicy::Ask
        ),
        ASK,
        "after a cd out of the folder"
    );
    // a `cd` nothing can pin is a protected-target ask: still an ask
    let unpinned = judge(
        &bash("cd \"$X\" && echo hi > out.txt"),
        Some(&allow),
        Some(&cover),
        &cwd,
        PromptPolicy::Ask,
    );
    assert!(
        matches!(unpinned, HubPolicyVerdict::Ask(_)),
        "after a cd nothing can pin: {unpinned:?}"
    );
    // a write with no allow rule behind it is not the deferral: it keeps its ask even inside the scope
    assert_eq!(
        judge(
            &bash("echo hi > out.txt"),
            None,
            Some(&cover),
            &cwd,
            PromptPolicy::Ask
        ),
        ASK
    );
}

#[test]
fn every_ask_comes_back_when_the_sandbox_state_gives_no_cover() {
    // enforce fell back to off, mode off, command not wrapped and a flip to off all end in `None`
    // (`the_cover_*` / `no_cover_*` above); here the verdicts for that `None`
    let dir = tempfile::tempdir().unwrap();
    let cwd = canonical_path(dir.path());
    for (what, cmd, allow) in replaced_asks() {
        let policy = allow.map(compiled);
        assert_eq!(
            judge(&bash(cmd), policy.as_ref(), None, &cwd, PromptPolicy::Ask),
            ASK,
            "{what}"
        );
    }
}

#[test]
fn dont_ask_still_refuses_what_the_card_would_replace() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    let verdict = judge(
        &bash("FOO=bar ls"),
        None,
        Some(&cover),
        &cwd,
        PromptPolicy::Deny,
    );
    assert!(matches!(verdict, HubPolicyVerdict::Deny(_)), "{verdict:?}");
}

#[test]
fn host_effect_asks_are_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    for cmd in [
        "rm -rf build",
        "git push origin main",
        "FOO=bar rm -rf build",
        "echo $(date); rm -rf build",
        "GIT_EXEC_PATH=/tmp/x ls",
        "LD_PRELOAD=/tmp/x.so ls",
        "bash -c \"$SCRIPT\"",
        "eval \"$SCRIPT\"",
        "rg --pre /tmp/x foo",
        "make build",
    ] {
        let access = bash(cmd);
        assert_eq!(
            judge(&access, None, Some(&cover), &cwd, PromptPolicy::Ask),
            judge(&access, None, None, &cwd, PromptPolicy::Ask),
            "{cmd}: the card changes nothing"
        );
        assert_eq!(
            judge(&access, None, Some(&cover), &cwd, PromptPolicy::Ask),
            ASK,
            "{cmd}"
        );
    }
}

#[test]
fn the_protected_target_floor_still_asks_while_enforcing() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    for cmd in [
        "echo '#!/bin/sh' > .git/hooks/pre-commit",
        "echo 'alias x=y' >> ~/.bashrc",
        "echo '{}' > .fuigo/mcp.json",
        "echo x > /etc/profile",
    ] {
        let access = bash(cmd);
        for policy_text in [None, Some("[permission]\nallow = [\"Bash(echo *)\"]\n")] {
            let policy = policy_text.map(compiled);
            assert_eq!(
                judge(
                    &access,
                    policy.as_ref(),
                    Some(&cover),
                    &cwd,
                    PromptPolicy::Ask
                ),
                HubPolicyVerdict::Ask(hub_ask_reason::PROTECTED_PATH),
                "{cmd} (policy: {policy_text:?})"
            );
        }
    }
}

#[test]
fn user_deny_and_ask_rules_still_bind_while_enforcing() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    let deny = compiled("[permission]\ndeny = [\"Bash(curl *)\"]\n");
    let ask = compiled("[permission]\nask = [\"Bash(curl *)\"]\n");
    let curl = bash("curl https://example.com/x");
    let denied = judge(&curl, Some(&deny), Some(&cover), &cwd, PromptPolicy::Ask);
    assert!(matches!(denied, HubPolicyVerdict::Deny(_)), "{denied:?}");
    let asked = judge(&curl, Some(&ask), Some(&cover), &cwd, PromptPolicy::Ask);
    assert!(matches!(asked, HubPolicyVerdict::Ask(_)), "{asked:?}");
    assert_ne!(asked, HubPolicyVerdict::Allow);
    // an ask rule on a command the card would otherwise cover
    let ask_env = compiled("[permission]\nask = [\"Bash(ls *)\"]\n");
    let still = judge(
        &bash("FOO=bar ls -l"),
        Some(&ask_env),
        Some(&cover),
        &cwd,
        PromptPolicy::Ask,
    );
    assert!(matches!(still, HubPolicyVerdict::Ask(_)), "{still:?}");
    // a rule set that cannot be checked against an unparseable script keeps its shell-gate ask
    let rules = compiled("[permission]\ndeny = [\"Bash(rm *)\"]\n");
    let gate = judge(
        &bash("echo 'never closed"),
        Some(&rules),
        Some(&cover),
        &cwd,
        PromptPolicy::Ask,
    );
    assert!(matches!(gate, HubPolicyVerdict::Ask(_)), "{gate:?}");
}

#[test]
fn non_shell_tools_are_unaffected_by_a_cover() {
    let dir = tempfile::tempdir().unwrap();
    let (cwd, cover) = scope(&dir);
    let notes = cwd.join("notes.txt").to_string_lossy().into_owned();
    for access in [
        AccessKind::Edit(notes),
        AccessKind::MCPTool {
            name: "srv__deploy".into(),
            input: serde_json::json!({}),
        },
        AccessKind::WebFetch("https://example.com/".into()),
        AccessKind::Tool("scheduler_create".into()),
        AccessKind::Read(Some("README.md".into())),
        AccessKind::WebSearch("rust".into()),
    ] {
        assert_eq!(
            judge(&access, None, Some(&cover), &cwd, PromptPolicy::Ask),
            judge(&access, None, None, &cwd, PromptPolicy::Ask),
            "{access:?}"
        );
    }
}

/// The sandbox off is the default: with no cover every verdict is what the hub path always said.
#[test]
fn default_config_decisions_are_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = canonical_path(dir.path());
    let allow_echo = compiled("[permission]\nallow = [\"Bash(echo *)\"]\n");
    let protected = HubPolicyVerdict::Ask(hub_ask_reason::PROTECTED_PATH);
    // (command, policy, default_prompts on, expected)
    let table: Vec<(&str, Option<&CompiledPolicy>, HubPolicyVerdict)> = vec![
        ("ls", None, HubPolicyVerdict::Allow),
        ("git status", None, HubPolicyVerdict::Allow),
        ("echo 'never closed", None, ASK),
        ("echo $(date)", None, ASK),
        ("FOO=bar ls", None, ASK),
        ("LOG=/tmp/log; ls -lh \"$LOG\"", None, ASK),
        ("curl https://example.com/x", None, ASK),
        ("rm -rf build", None, ASK),
        ("make build", None, ASK),
        ("echo hi > out.txt", Some(&allow_echo), ASK),
        ("echo hi", Some(&allow_echo), HubPolicyVerdict::Allow),
        ("echo x > .git/hooks/pre-commit", None, protected),
    ];
    for (cmd, policy, expected) in table {
        assert_eq!(
            judge(&bash(cmd), policy, None, &cwd, PromptPolicy::Ask),
            expected,
            "{cmd}"
        );
    }
    // with the live prompt off (the default) every one of them is left to the agent's own user
    for cmd in ["FOO=bar ls", "curl https://example.com/x", "rm -rf build"] {
        let ctx = HubPolicyContext {
            policy: None,
            prompt_policy: PromptPolicy::Ask,
            base_policy: None,
            base_prompt_policy: PromptPolicy::Ask,
            cwd: &cwd,
            display_cwd: None,
            yolo: false,
            default_prompts: false,
            search_excludes: &[],
            search_excludes_applied: false,
            walk_searches: false,
            patch_targets: &[],
            read_spellings: &[],
            sandbox_cover: None,
        };
        assert_eq!(
            hub_policy_verdict(&bash(cmd), &ctx),
            HubPolicyVerdict::Allow,
            "{cmd}"
        );
    }
}

/// The peer guard denies before the verdict is asked, whatever the sandbox covers.
#[tokio::test]
async fn the_peer_guard_still_denies_with_a_cover() {
    use crate::hub::{HubCallFacts, enforce_hub_policy};
    let handle = crate::handle::WorkspaceHandle::for_test();
    handle.create_session("s").expect("session");
    let session = handle.session("s").unwrap();
    session.peer_influence().set(true);
    let accesses = [bash("echo 'x' > CLAUDE.md")];
    let facts = HubCallFacts {
        sandbox_cover: Some(SandboxCover::for_test(
            true,
            vec![session.cwd().to_path_buf()],
        )),
        ..HubCallFacts::default()
    };
    let err = enforce_hub_policy(
        &handle, &session, "s", "call-1", "bash", &accesses, &accesses, facts,
    )
    .await
    .expect_err("peer guard denial");
    assert!(err.to_string().contains("/peers clear-influence"), "{err}");
}
