//! P174: a tool that reads several files in one call is judged per file. A codex or Fuigo `read_file` with a
//! `files: [...]` list classified as one `Read` naming only `file_path` (or none at all when `file_path` was empty), so
//! path-scoped Read rules never saw the other files. The request now carries every file the call reads
//! ([`read_targets_for`]) and the manager judges each one as a `Read`, the strictest result winning: a denied file
//! refuses the call, an ask prompts and the prompt lists every file. Tools that are not reads but open local files
//! (`image_edit`, `image_to_video`, `reference_to_video`) have those files judged the same way (deny and ask only).

use super::*;
use crate::permission::types::{
    PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter, read_targets_for,
};
use fuigo_tools::types::ToolInput;

/// Records every hub prompt payload and answers each with `reply`.
struct RecordingHub {
    reply: serde_json::Value,
    seen: std::sync::Mutex<Vec<serde_json::Value>>,
}

#[async_trait::async_trait]
impl crate::permission::PermissionHookTransport for RecordingHub {
    async fn request_permission(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.seen.lock().unwrap().push(payload);
        Ok(self.reply.clone())
    }
}

fn hub(outcome: &str) -> Arc<RecordingHub> {
    Arc::new(RecordingHub {
        reply: serde_json::json!({ "outcome": outcome }),
        seen: std::sync::Mutex::new(Vec::new()),
    })
}

/// ACP client that records every prompt and answers reject-once.
#[derive(Default)]
struct RecordingClient {
    prompts: std::rc::Rc<std::cell::RefCell<Vec<acp::RequestPermissionRequest>>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for RecordingClient {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        let option_id = args
            .options
            .iter()
            .find(|o| o.kind == acp::PermissionOptionKind::RejectOnce)
            .map(|o| o.option_id.clone())
            .expect("prompt must offer reject-once");
        self.prompts.borrow_mut().push(args);
        Ok(acp::RequestPermissionResponse::new(
            acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(option_id)),
        ))
    }

    async fn session_notification(&self, _: acp::SessionNotification) -> acp::Result<()> {
        Ok(())
    }
}

fn read_rule(action: RuleAction, pattern: &str) -> PermissionRule {
    PermissionRule {
        action,
        tool: ToolFilter::Read,
        pattern: Some(pattern.to_owned()),
        pattern_mode: PatternMode::Glob,
    }
}

/// A manager with `rules` (none: default config) whose prompts go to `hub`.
fn manager(
    cwd: &AbsPathBuf,
    rules: Vec<PermissionRule>,
    hub: Arc<RecordingHub>,
    initial_yolo: bool,
) -> PermissionHandle {
    let (tx, _rx) = mpsc::unbounded_channel();
    let config = (!rules.is_empty()).then(|| PermissionConfig::new(rules));
    spawn_permission_manager_with_pin(
        acp::SessionId::new(Arc::from("p174-session")),
        GatewaySender::new(tx),
        cwd.clone(),
        ClientType::Generic,
        config,
        vec![],
        vec![],
        initial_yolo,
        None,
        true,
        None,
        Some(hub),
    )
    .0
}

/// A manager whose prompts go to a live ACP client (the TUI path).
fn acp_manager(cwd: &AbsPathBuf, rules: Vec<PermissionRule>, client: RecordingClient) -> PermissionHandle {
    let (gateway, receiver) = fuigo_acp_lib::acp_gateway::<acp::AgentSide, _>(client);
    tokio::task::spawn_local(receiver.run());
    spawn_permission_manager_with_pin(
        acp::SessionId::new(Arc::from("p174-acp")),
        gateway,
        cwd.clone(),
        ClientType::FuigoPager,
        Some(PermissionConfig::new(rules)),
        vec![],
        vec![],
        false,
        None,
        true,
        None,
        None,
    )
    .0
}

fn codex_read(file_path: &str, files: &[&str]) -> ToolInput {
    ToolInput::CodexReadFile(
        serde_json::from_value(serde_json::json!({
            "file_path": file_path,
            "files": files.iter().map(|p| serde_json::json!({ "path": p })).collect::<Vec<_>>(),
        }))
        .unwrap(),
    )
}

fn fuigo_read(target_file: &str, files: &[&str]) -> ToolInput {
    ToolInput::ReadFile(
        serde_json::from_value(serde_json::json!({
            "target_file": target_file,
            "files": files.iter().map(|p| serde_json::json!({ "path": p })).collect::<Vec<_>>(),
        }))
        .unwrap(),
    )
}

fn image_edit(images: &[&str]) -> ToolInput {
    ToolInput::ImageEdit(fuigo_tools::implementations::fuigo_build::image_edit::ImageEditInput {
        prompt: "make it blue".to_owned(),
        image: images.iter().map(|s| (*s).to_owned()).collect(),
        aspect_ratio: String::new(),
    })
}

/// Request permission for `input` exactly as the ACP session does.
async fn decide(mgr: &PermissionHandle, cwd: &std::path::Path, input: &ToolInput) -> Decision {
    decide_in(mgr, cwd, None, input).await
}

/// [`decide`] for a session whose model-facing cwd is `display_cwd` (a forked session).
async fn decide_in(
    mgr: &PermissionHandle,
    cwd: &std::path::Path,
    display_cwd: Option<&std::path::Path>,
    input: &ToolInput,
) -> Decision {
    mgr.request(PermissionRequest {
        path_context: Some(crate::permission::types::RequestPathContext {
            real_cwd: cwd.to_path_buf(),
            display_cwd: display_cwd.map(std::path::Path::to_path_buf),
        }),
        read_targets: read_targets_for(input),
        ..PermissionRequest::new(
            AccessKind::from(input),
            acp::ToolCallUpdate::new(
                acp::ToolCallId::new(Arc::from("tc-read")),
                acp::ToolCallUpdateFields::new().title(Some("Read".to_owned())),
            ),
        )
    })
    .await
    .decision
}

fn run<F: std::future::Future<Output = ()>>(f: impl FnOnce(tempfile::TempDir, AbsPathBuf) -> F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = AbsPathBuf::new(tmp.path().to_path_buf()).unwrap();
        f(tmp, cwd).await;
    });
}

fn abs(tmp: &tempfile::TempDir, rel: &str) -> String {
    tmp.path().join(rel).to_string_lossy().into_owned()
}

#[test]
fn read_targets_name_every_file_a_read_opens() {
    use crate::permission::types::{ReadResolution, ReadTargets};
    let targets = |paths: &[&str], resolution| {
        Some(ReadTargets {
            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            resolution,
        })
    };
    assert_eq!(
        read_targets_for(&codex_read("", &["ok.txt", "secrets/key"])),
        targets(&["ok.txt", "secrets/key"], ReadResolution::Literal)
    );
    assert_eq!(
        read_targets_for(&codex_read("/w/a", &["/w/b", " ", "/w/a"])),
        targets(&["/w/a", "/w/b"], ReadResolution::Literal)
    );
    assert_eq!(
        read_targets_for(&fuigo_read("t.rs", &["secrets/key"])),
        targets(&["t.rs", "secrets/key"], ReadResolution::ModelPath)
    );
    // A single-path read is judged through the reader's resolution too (Astra r1).
    assert_eq!(
        read_targets_for(&codex_read("/w/a", &[" "])),
        targets(&["/w/a"], ReadResolution::Literal)
    );
    assert_eq!(
        read_targets_for(&fuigo_read("a.rs", &[])),
        targets(&["a.rs"], ReadResolution::ModelPath)
    );
    assert_eq!(read_targets_for(&codex_read("", &[])), None);
    // Image tools: local files only, made absolute against the process cwd as the tool opens them.
    let cwd = std::env::current_dir().unwrap();
    let b = cwd.join("b.png").to_string_lossy().into_owned();
    assert_eq!(
        read_targets_for(&image_edit(&["[Image #1]", "data:image/png;base64,AA", "/w/a.png", "b.png"])),
        targets(&["/w/a.png", &b], ReadResolution::Literal)
    );
    assert_eq!(read_targets_for(&image_edit(&["data:image/png;base64,AA"])), None);
}

/// The packet's red test: `deny = ["Read(secrets/**)"]` refuses a codex `read_file` of `["ok.txt", "secrets/key"]`.
#[test]
fn codex_files_list_with_a_denied_path_is_refused() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &codex_read("", &["ok.txt", "secrets/key"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        let d = decide(&mgr, tmp.path(), &codex_read("", &[&abs(&tmp, "ok.txt"), &abs(&tmp, "secrets/key")])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        assert!(hub.seen.lock().unwrap().is_empty(), "a deny refuses without a prompt");
    });
}

/// With `file_path` set, the `files` entries were not judged: a denied file in `files` refuses the call wherever it is.
#[test]
fn codex_file_path_plus_files_judges_every_path() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let (ok, key) = (abs(&tmp, "ok.txt"), abs(&tmp, "secrets/key"));
        let d = decide(&mgr, tmp.path(), &codex_read(&ok, &[&key])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        let d = decide(&mgr, tmp.path(), &codex_read(&key, &[&ok])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

#[test]
fn fuigo_read_file_files_list_with_a_denied_path_is_refused() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &fuigo_read("", &["ok.txt", "secrets/key"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        let d = decide(&mgr, tmp.path(), &fuigo_read("ok.txt", &["secrets/key"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

/// A deny binds before always-approve, as for a single-file read.
#[test]
fn deny_on_any_path_binds_in_yolo() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), true);
        let d = decide(&mgr, tmp.path(), &codex_read("", &["ok.txt", "secrets/key"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

/// An ask rule on one file prompts for the whole call, and the prompt names every file (title and locations).
#[test]
fn ask_rule_on_one_path_prompts_listing_every_path() {
    run(|tmp, cwd| async move {
        let client = RecordingClient::default();
        let prompts = client.prompts.clone();
        let mgr = acp_manager(&cwd, vec![read_rule(RuleAction::Ask, "secrets/**")], client);
        let d = decide(&mgr, tmp.path(), &codex_read("", &["ok.txt", "secrets/key"])).await;
        assert!(matches!(d, Decision::Reject(_)), "the user rejected the prompt, got {d:?}");
        // Own the prompts: no RefCell borrow may be held across an await.
        let prompts = std::mem::take(&mut *prompts.borrow_mut());
        assert_eq!(prompts.len(), 1, "the ask rule on secrets/key must prompt");
        let fields = &prompts[0].tool_call.fields;
        assert_eq!(fields.title.as_deref(), Some("Read: ok.txt, secrets/key"));
        let locations: Vec<_> = fields
            .locations
            .iter()
            .flatten()
            .map(|l| l.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(locations, vec!["ok.txt", "secrets/key"]);

        // Through the hub as well: the call prompts.
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Ask, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &fuigo_read("ok.txt", &["secrets/key"])).await;
        assert_eq!(d, Decision::Allow, "the hub approved");
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the ask rule must prompt");
    });
}

/// Ordinary use is unchanged: a multi-file read of files no rule restricts runs without a prompt.
#[test]
fn ordinary_multi_file_read_does_not_prompt() {
    run(|tmp, cwd| async move {
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &codex_read("", &[&abs(&tmp, "a.txt"), &abs(&tmp, "b.txt")])).await;
        assert_eq!(d, Decision::Allow);
        let d = decide(&mgr, tmp.path(), &fuigo_read("", &["a.txt", "src/b.rs"])).await;
        assert_eq!(d, Decision::Allow);
        assert!(hub.seen.lock().unwrap().is_empty());
    });
}

/// The judge sees the file the reader opens: through `..` and through a symlink into the denied directory.
#[test]
#[cfg(unix)]
fn deny_sees_through_dot_dot_and_symlinks() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("secrets/key"), "k").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secrets"), tmp.path().join("alias")).unwrap();
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &codex_read("", &[&abs(&tmp, "ok"), &abs(&tmp, "src/../secrets/key")])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        let d = decide(&mgr, tmp.path(), &fuigo_read("", &["ok", "alias/key"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

/// In a forked session the Fuigo reader maps a display-cwd path onto the real cwd; the judge does too.
#[test]
fn deny_follows_the_display_cwd_mapping_of_the_reader() {
    run(|tmp, cwd| async move {
        let display = std::path::Path::new("/display-root");
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide_in(&mgr, tmp.path(), Some(display), &fuigo_read("", &["ok", "/display-root/secrets/key"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

/// `image_edit` opens local image files: a Read deny on one refuses the call (it still prompts otherwise).
#[test]
fn image_tool_reading_a_denied_file_is_refused() {
    run(|tmp, cwd| async move {
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &image_edit(&[&abs(&tmp, "a.png"), &abs(&tmp, "secrets/b.png")])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        assert!(hub.seen.lock().unwrap().is_empty());
        let d = decide(&mgr, tmp.path(), &image_edit(&[&abs(&tmp, "a.png")])).await;
        assert_eq!(d, Decision::Allow, "the hub approved");
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "an image tool still prompts");
    });
}

/// Reading a file never allows a side effect: a Read allow rule covering an image tool's files leaves its prompt.
#[test]
fn read_allow_on_an_image_tools_files_does_not_skip_its_prompt() {
    run(|tmp, cwd| async move {
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Allow, "**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &image_edit(&[&abs(&tmp, "a.png")])).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        assert_eq!(hub.seen.lock().unwrap().len(), 1, "the image tool must still prompt");
    });
}

/// Astra r1: a single-path Fuigo read is judged as the reader resolves it (here: surrounding quotes stripped).
#[test]
fn single_fuigo_read_is_judged_as_the_reader_resolves_it() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::write(tmp.path().join("secrets/key"), "k").unwrap();
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &fuigo_read("\"secrets/key\"", &[])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

/// Astra r1: the Fuigo reader falls back to a Unicode-confusable sibling of a name that does not exist (here a
/// no-break space); the judge follows the same fallback, and the symlink behind it.
#[test]
#[cfg(unix)]
fn deny_follows_the_readers_unicode_fallback() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::create_dir_all(tmp.path().join("public")).unwrap();
        std::fs::write(tmp.path().join("secrets/key"), "k").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secrets/key"), tmp.path().join("public/k\u{a0}ey")).unwrap();
        let resolved = fuigo_tools::implementations::fuigo_build::read_file::resolve_read_target(
            tmp.path(),
            None,
            "public/k ey",
        )
        .await;
        assert_eq!(resolved.file_name().unwrap(), "k\u{a0}ey", "the reader falls back to the no-break-space sibling");
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &fuigo_read("", &["ok.txt", "public/k ey"])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
    });
}

/// Astra r1: a Unix name containing `\` is a literal filename; the judge follows that symlink as the reader does
/// (the policy alone would read `\` as a separator and look at another path).
#[test]
#[cfg(unix)]
fn deny_follows_a_backslash_named_symlink_like_the_reader() {
    run(|tmp, cwd| async move {
        std::fs::create_dir_all(tmp.path().join("secrets")).unwrap();
        std::fs::create_dir_all(tmp.path().join("public")).unwrap();
        std::fs::write(tmp.path().join("secrets/key"), "k").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secrets/key"), tmp.path().join("public\\link")).unwrap();
        let hub = hub("approve");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "secrets/**")], hub.clone(), false);
        let link = abs(&tmp, "public\\link");
        let d = decide(&mgr, tmp.path(), &codex_read("", &[&abs(&tmp, "ok.txt"), &link])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "got {d:?}");
        let d = decide(&mgr, tmp.path(), &codex_read(&link, &[])).await;
        assert!(matches!(d, Decision::PolicyDeny(_)), "single-path form, got {d:?}");
    });
}

/// Astra r1 MEDIUM: the codex reader opens absolute paths literally, so its paths are not rewritten the Fuigo way (a
/// trailing quote is part of the name): a deny on another file does not refuse the call.
#[test]
fn codex_paths_are_judged_literally() {
    run(|tmp, cwd| async move {
        let hub = hub("reject");
        let mgr = manager(&cwd, vec![read_rule(RuleAction::Deny, "public/note")], hub.clone(), false);
        let d = decide(&mgr, tmp.path(), &codex_read("", &[&abs(&tmp, "a.txt"), &abs(&tmp, "public/note'")])).await;
        assert_eq!(d, Decision::Allow);
        assert!(hub.seen.lock().unwrap().is_empty());
    });
}

/// Astra r2: a `files` list of one file (and an image tool's one file) still names that file in the prompt; only a
/// single-path read, whose title already names it, is left as is.
#[test]
fn ask_on_a_one_file_list_names_the_file() {
    run(|tmp, cwd| async move {
        let client = RecordingClient::default();
        let prompts = client.prompts.clone();
        let mgr = acp_manager(&cwd, vec![read_rule(RuleAction::Ask, "secrets/**")], client);
        let d = decide(&mgr, tmp.path(), &fuigo_read("", &["secrets/key"])).await;
        assert!(matches!(d, Decision::Reject(_)), "got {d:?}");
        // Own the prompts: no RefCell borrow may be held across an await.
        let prompts = std::mem::take(&mut *prompts.borrow_mut());
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].tool_call.fields.title.as_deref(), Some("Read: secrets/key"));
    });
}

/// Astra r2/r3: a target the manager could not resolve in time is refused, never an approvable prompt (the reader
/// could open a file nobody judged).
#[test]
fn unresolved_read_target_is_refused() {
    use crate::permission::gate_preflight::GatePreflight;
    let policy = crate::permission::policy::CompiledPolicy::new(PermissionConfig::new(vec![read_rule(
        RuleAction::Deny,
        "secrets/**",
    )]));
    let cwd = std::path::Path::new("/w");
    let access = AccessKind::Read(None);
    let judge = |targets: &[(Vec<String>, bool)]| {
        GatePreflight::evaluate_read_targets(Some(&policy), &access, targets, cwd, false).policy_decision()
    };
    assert_eq!(judge(&[(vec!["/w/a".to_owned()], true)]), None);
    assert!(matches!(judge(&[(vec!["/w/a".to_owned()], false)]), Some(Decision::Reject(_))));
    assert!(matches!(
        judge(&[(vec!["/w/a".to_owned()], false), (vec!["/w/secrets/k".to_owned()], false)]),
        Some(Decision::Reject(_) | Decision::PolicyDeny(_))
    ));
}
