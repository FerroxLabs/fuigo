use super::{
    build_minimal_agent_for_tests, make_test_handle, t04_build_agent_from_spawn_inputs,
    t04_call_tool, t04_next_request, t04_start_auxiliary_receiver,
};
use agent_client_protocol as acp;
use fuigo_acp_lib::AcpAgentGatewaySender as GatewaySender;
#[tokio::test]
async fn subagent_spawn_context_inherits_parent_permission_handle() {
    use fuigo_workspace::permission::types::{
        PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter,
    };
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let agent = build_minimal_agent_for_tests();
            let sid = acp::SessionId::new("parent-permission");
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let gateway = GatewaySender::new(tx);
            let cwd = fuigo_paths::AbsPathBuf::new(std::path::PathBuf::from("/tmp"))
                .expect("absolute cwd");
            let (permission_handle, _events_rx) = fuigo_workspace::permission::spawn_permission_manager(
                sid.clone(),
                gateway,
                cwd,
                fuigo_workspace::permission::types::ClientType::Generic,
                Some(
                    PermissionConfig::new(
                        vec![PermissionRule {
                        action: RuleAction::Deny,
                        tool: ToolFilter::Read,
                        pattern: Some("**/.env".to_owned()),
                        pattern_mode: PatternMode::Glob,
                    }],
                    ),
                ),
                Vec::new(),
                Vec::new(),
                false,
                None,
            );
            let mut handle = make_test_handle("test-model", false, None);
            handle.permission_handle = permission_handle;
            agent.insert_resident(&sid, handle);
            let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
            let inherited = ctx
                .permission_handle
                .expect("subagent context must inherit parent permission handle");
            for access in [
                fuigo_workspace::permission::AccessKind::Read(Some(".env".into())),
                fuigo_workspace::permission::AccessKind::Bash("cat .env".into()),
            ] {
                let decision = inherited
                    .request(fuigo_workspace::permission::PermissionRequest {
                        session_id: Some("child-session".to_owned()),
                        subagent_type: Some("general-purpose".to_owned()),
                        subagent_description: Some(
                            "permission inheritance regression".to_owned(),
                        ),
                        ..fuigo_workspace::permission::PermissionRequest::new(
                            access.clone(),
                            acp::ToolCallUpdate::new(
                                acp::ToolCallId::new("tc"),
                                Default::default(),
                            ),
                        )
                    })
                    .await
                    .decision;
                assert!(
                    matches!(
                        decision,
                        fuigo_workspace::permission::Decision::PolicyDeny(_)
                    ),
                    "subagent-inherited handle must enforce parent deny for {access:?}, got {decision:?}"
                );
            }
        })
        .await;
}
#[tokio::test]
async fn subagent_spawn_context_shares_active_message_parent_prompt_index() {
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("parent-telemetry");
    let handle = make_test_handle("test-model", false, None);
    let live_prompt_index = handle
        .tool_context
        .active_message_parent_prompt_index
        .clone();
    agent.insert_resident(&sid, handle);
    let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    live_prompt_index.store(6, std::sync::atomic::Ordering::Release);
    assert_eq!(
        ctx.active_message_parent_prompt_index
            .load(std::sync::atomic::Ordering::Acquire),
        6,
    );
}
#[tokio::test]
async fn subagent_spawn_context_shares_parent_goal_loop_gate() {
    use std::sync::atomic::Ordering::Relaxed;
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("parent-goal");
    let handle = make_test_handle("test-model", false, None);
    let parent_gate = handle.tool_context.goal_loop_active_gate.clone();
    agent.insert_resident(&sid, handle);
    let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    assert!(!ctx.goal_loop_active.load(Relaxed));
    parent_gate.store(true, Relaxed);
    assert!(
        ctx.goal_loop_active.load(Relaxed),
        "subagent context must observe the parent's goal-loop gate (same Arc)"
    );
}
#[tokio::test]
async fn subagent_spawn_context_disables_ask_user_question_from_enabled_parent() {
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("parent-ask-enabled");
    let mut handle = make_test_handle("test-model", false, None);
    handle.ask_user_question_enabled = true;
    agent.insert_resident(&sid, handle);
    let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    assert!(
        !ctx.ask_user_question_enabled,
        "subagent must not inherit the enabled parent ask_user_question gate"
    );
}
/// Subagents and workflow children resolve `[toolset.bash]` exactly like the parent (incl. remote fallbacks): a dropped default would cap the child's
/// foreground commands at the compiled 5-minute ceiling instead of the parent's configured timeout and auto-background settings.
#[tokio::test]
async fn subagent_spawn_context_carries_parent_bash_tool_params() {
    let agent = build_minimal_agent_for_tests();
    {
        let mut cfg = agent.cfg.borrow_mut();
        cfg.toolset.bash.max_timeout_secs = Some(36_000.0);
        cfg.toolset.bash.output_byte_limit = Some(65_536);
        cfg.remote_settings = Some(crate::util::config::RemoteSettings {
            auto_background_on_timeout: Some(false),
            ..Default::default()
        });
    }
    let sid = acp::SessionId::new("parent-bash-params");
    agent.insert_resident(&sid, make_test_handle("test-model", false, None));
    let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    let expected_bash = serde_json::json!({
        "max_timeout_secs": 36_000.0,
        "output_byte_limit": 65_536,
        "auto_background_on_timeout": false,
        "allow_background_operator": true,
    });
    assert_eq!(
        ctx.tool_params_json.bash,
        expected_bash.as_object().cloned(),
        "child bash params must equal the parent's resolved [toolset.bash] (incl. remote fallbacks)"
    );
    let parent_bash = {
        let cfg = agent.cfg.borrow();
        cfg.toolset
            .bash
            .to_bash_params_json_with_remote(cfg.remote_settings.as_ref())
    };
    assert_eq!(
        ctx.tool_params_json.bash.as_ref(),
        Some(&parent_bash),
        "child and top-level session must resolve bash params through the same path"
    );
    let spawn_src = include_str!("../../subagent/handle_request.rs");
    assert!(
        spawn_src.contains("std::mem::take(&mut ctx.tool_params_json)"),
        "run_shell_child must forward ctx.tool_params_json into spawn_session_on_thread"
    );
}
#[tokio::test]
async fn subagent_spawn_context_copies_parent_non_interactive() {
    let agent = build_minimal_agent_for_tests();
    let sid_headless = acp::SessionId::new("parent-headless");
    let mut handle_headless = make_test_handle("test-model", false, None);
    handle_headless.non_interactive = true;
    agent.insert_resident(&sid_headless, handle_headless);
    let ctx_headless = agent.build_subagent_spawn_context(sid_headless.0.as_ref());
    assert!(
        ctx_headless.parent_non_interactive,
        "subagent must copy the parent's non_interactive flag (headless -p parent)"
    );
    let sid_tui = acp::SessionId::new("parent-tui");
    agent.insert_resident(&sid_tui, make_test_handle("test-model", false, None));
    let ctx_tui = agent.build_subagent_spawn_context(sid_tui.0.as_ref());
    assert!(
        !ctx_tui.parent_non_interactive,
        "an interactive parent must not mark its subagents non-interactive"
    );
}
#[tokio::test]
async fn subagent_spawn_context_inherits_parent_configured_cutoff() {
    let agent = build_minimal_agent_for_tests();
    let cutoff = fuigo_sampling_types::ToolOverrides {
        x_search: Some(fuigo_sampling_types::XSearchOptions {
            date_bound: Some(
                fuigo_sampling_types::SearchDateBound::new(None, Some("2020-01-01".to_string()))
                    .unwrap(),
            ),
        }),
        web_search: None,
    };
    let sid = acp::SessionId::new("parent-cutoff");
    let handle = make_test_handle("test-model", false, None);
    handle
        .resolved_tool_overrides
        .store(Some(std::sync::Arc::new(cutoff.clone())));
    agent.insert_resident(&sid, handle);
    let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    assert_eq!(
        ctx.inherited_tool_overrides,
        Some(cutoff),
        "subagent context must inherit the parent's configured cutoff for its first-turn update"
    );
    let sid_none = acp::SessionId::new("parent-unbounded");
    agent.insert_resident(&sid_none, make_test_handle("test-model", false, None));
    let ctx_none = agent.build_subagent_spawn_context(sid_none.0.as_ref());
    assert!(
        ctx_none.inherited_tool_overrides.is_none(),
        "an unbounded parent must not hand a subagent a cutoff"
    );
}
#[tokio::test]
async fn subagent_spawn_context_inherits_parent_process_scope() {
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("parent-process-scope");
    let mut handle = make_test_handle("test-model", false, None);
    let parent_scope = fuigo_tty_utils::ProcessScope::new();
    handle.tool_context.process_scope = Some(parent_scope.clone());
    agent.insert_resident(&sid, handle);
    let owner = std::sync::Arc::new(fuigo_tty_utils::ProcessGroup::new().expect("process group"));
    parent_scope.register(&owner);
    let ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    let inherited = ctx
        .process_scope
        .expect("subagent context must inherit the parent's process scope");
    assert_eq!(
        inherited.live_count(),
        1,
        "the child sees the owner enrolled through the parent scope"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
#[serial_test::serial(FUIGO_HOME)]
async fn t04_subagent_construction_preserves_live_credential_ownership() {
    tokio::task::LocalSet::new().run_until(async {
    use fuigo_test_support::EnvGuard;
    use fuigo_tools::types::tool::ToolKind;

    let Some(process_home) = fuigo_test_support::env::fresh_process_home(
        "agent::mvp_agent::tests::subagent_spawn_context_tests::t04_subagent_construction_preserves_live_credential_ownership",
    ) else {
        return;
    };
    let _auth = EnvGuard::unset("FUIGO_AUTH");
    let _auth_path = EnvGuard::unset("FUIGO_AUTH_PATH");
    let _global = EnvGuard::unset("FUIGO_API_KEY");
    let _legacy = EnvGuard::unset("FUIGO_CODE_API_KEY");
        let (base_url, mut requests, _tls_dir, _tls_roots) = t04_start_auxiliary_receiver().await;
    let api_base = format!("{base_url}/v1");
    std::fs::write(
        process_home.as_path().join("config.toml"),
        format!("[endpoints]\nfuigo_api_base_url = \"{api_base}\"\n"),
    )
    .unwrap();

    let auth_dir = tempfile::tempdir_in(process_home.as_path()).unwrap();
    crate::auth::store_api_key(auth_dir.path(), "child-aux-key-1").unwrap();
    let manager = std::sync::Arc::new(crate::auth::AuthManager::new(
        auth_dir.path(),
        crate::auth::FuigoComConfig::default(),
    ));
    manager.set_process_static_api_key(Some("parent-inference-key".into()));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let gateway = GatewaySender::new(tx);
    let mut cfg = crate::agent::config::Config::default();
    cfg.endpoints.fuigo_api_base_url = api_base;
    let parent = super::MvpAgent::new(gateway, &cfg, manager.clone(), None)
        .expect("parent agent config must be valid");
    parent.sampling_config.borrow_mut().api_key = Some("parent-inference-key".into());
    let parent_sid = acp::SessionId::new("t04-parent-live-ownership");
    parent.insert_resident(
        &parent_sid,
        make_test_handle("parent-inference-model", false, None),
    );

    let ctx = parent
        .try_build_subagent_spawn_context(parent_sid.0.as_ref())
        .expect("production spawn context must be constructed from the live parent");
    let child_provider = ctx
        .api_key_provider
        .clone()
        .expect("spawn context must carry the parent's live credential provider");
    let child_image_config = ctx.image_gen_config.clone();
    let work = tempfile::tempdir().unwrap();
    let child = t04_build_agent_from_spawn_inputs(
        work.path(),
        "t04-child-live-ownership",
        child_provider,
        child_image_config,
        Default::default(),
    )
    .await;

    t04_call_tool(&child, ToolKind::ImageGen).await;
    let initial = t04_next_request(&mut requests).await;
    assert_eq!(initial.path, "/v1/images/generations");
    assert_eq!(
        initial.authorization.as_deref(),
        Some("Bearer child-aux-key-1")
    );
    assert_ne!(
        initial.authorization.as_deref(),
        Some("Bearer parent-inference-key")
    );

    crate::auth::store_api_key(auth_dir.path(), "child-aux-key-2").unwrap();
    t04_call_tool(&child, ToolKind::ImageGen).await;
    assert_eq!(
        t04_next_request(&mut requests)
            .await
            .authorization
            .as_deref(),
        Some("Bearer child-aux-key-2"),
        "the already-constructed child must resolve the rotated parent-owned credential live"
    );

    crate::auth::clear_api_key(auth_dir.path()).unwrap();
    let image_name = child
        .tool_bridge()
        .tool_for_kind(ToolKind::ImageGen)
        .await
        .unwrap();
    assert!(
        child
            .tool_bridge()
            .call(
                &image_name,
                serde_json::json!({"prompt": "revoked child", "aspect_ratio": "1:1"}),
                "t04-child-revoked",
            )
            .await
            .is_err(),
        "revocation must fail in the constructed child's real image client before dispatch"
    );
    assert!(
        requests.try_recv().is_err(),
        "the child must not resurrect its construction-time credential after revocation"
    );
    }).await;
}
fn model_entry_with_rate_limit(
    slug: &str,
    attempts: Option<u32>,
) -> crate::agent::config::ModelEntry {
    let mut info = crate::agent::config::ModelInfo::fallback(slug);
    info.subagent_rate_limit_max_attempts = attempts;
    crate::agent::config::ModelEntry {
        info,
        api_key: None,
        env_key: None,
        auth_provider: None,
        api_base_url: None,
    }
}
#[tokio::test]
async fn subagent_spawn_context_resolves_rate_limit_attempts_against_child_model() {
    let agent = build_minimal_agent_for_tests();
    let sid = acp::SessionId::new("parent-rate-limit");
    agent.insert_resident(&sid, make_test_handle("parent-model", false, None));
    let mut ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
    let mut models = indexmap::IndexMap::new();
    models.insert(
        "parent-model".to_string(),
        model_entry_with_rate_limit("parent-model", Some(4)),
    );
    models.insert(
        "child-model".to_string(),
        model_entry_with_rate_limit("child-model", Some(0)),
    );
    ctx.available_models = models;
    assert_eq!(
        ctx.resolve_subagent_rate_limit_max_attempts("child-model"),
        0,
        "a subagent on a different model must honor that model's disable (0), not the parent's"
    );
    assert_eq!(
        ctx.resolve_subagent_rate_limit_max_attempts("parent-model"),
        4,
        "the per-model lookup keys on the passed model id"
    );
}
#[test]
#[serial_test::serial]
fn subagent_spawn_context_resolves_compaction_mode_like_parent() {
    use crate::agent::config::Config;
    use fuigo_chat_state::{CompactionDetail, CompactionMode};
    use fuigo_test_support::EnvGuard;
    let _mode = EnvGuard::unset("FUIGO_COMPACTION_MODE");
    let _detail = EnvGuard::unset("FUIGO_COMPACTION_DETAIL");
    let mut ctx = crate::test_support::lsp_runtime::ctx_with_toggle(Default::default());
    assert_eq!(
        ctx.resolve_compaction_mode(),
        CompactionMode::default(),
        "empty spawn context must inherit the compiled Segments default, not Summary"
    );
    let mut summary_cfg = Config::default();
    summary_cfg.features.compaction_mode = Some("summary".into());
    ctx.agent_config = Some(summary_cfg);
    assert_eq!(
        ctx.resolve_compaction_mode(),
        CompactionMode::Summary,
        "parent [features].compaction_mode must win over remote/default"
    );
    ctx.agent_config = None;
    ctx.remote_settings = Some(crate::util::config::RemoteSettings {
        compaction_mode: Some("segments".into()),
        compaction_detail: Some("minimal".into()),
        ..Default::default()
    });
    assert_eq!(
        ctx.resolve_compaction_mode(),
        CompactionMode::Segments(CompactionDetail::Minimal),
        "remote mode+detail must attach via with_segment_detail"
    );
    let mut segments_cfg = Config::default();
    segments_cfg.features.compaction_mode = Some("segments".into());
    segments_cfg.features.compaction_detail = Some("balanced".into());
    ctx.agent_config = Some(segments_cfg);
    assert_eq!(
        ctx.resolve_compaction_mode(),
        CompactionMode::Segments(CompactionDetail::Balanced),
        "parent config detail must win over remote detail"
    );
    let _env_mode = EnvGuard::set("FUIGO_COMPACTION_MODE", "transcript");
    assert_eq!(
        ctx.resolve_compaction_mode(),
        CompactionMode::Transcript,
        "FUIGO_COMPACTION_MODE must win over parent config and remote"
    );
}
#[test]
fn run_shell_child_passes_parent_compaction_pins_into_spawn() {
    use crate::agent::subagent::SubagentSpawnContext;
    use crate::session::CompactionPins;
    use fuigo_agent::prompt::user_message::UserMessageTemplate;
    use fuigo_chat_state::CompactionMode;
    let default_child = UserMessageTemplate::Default;
    let mut ctx = crate::test_support::lsp_runtime::ctx_with_toggle(Default::default());
    ctx.parent_compaction = CompactionPins {
        mode: CompactionMode::default(),
        two_pass: true,
    };
    assert_eq!(
        ctx.compaction_pins_for_child(&default_child),
        CompactionPins {
            mode: CompactionMode::default(),
            two_pass: true,
        },
    );
    ctx.parent_compaction = CompactionPins {
        mode: CompactionMode::Summary,
        two_pass: false,
    };
    assert_eq!(
        ctx.compaction_pins_for_child(&default_child),
        CompactionPins {
            mode: CompactionMode::Summary,
            two_pass: false,
        },
    );
    ctx.parent_compaction = CompactionPins {
        mode: CompactionMode::default(),
        two_pass: true,
    };
    assert_eq!(
        SubagentSpawnContext::snapshot_parent_compaction_pins(
            CompactionMode::default(),
            true,
            Some("fuigo-build"),
            Some("fuigo-build"),
            std::path::Path::new("/tmp"),
        ),
        CompactionPins {
            mode: CompactionMode::default(),
            two_pass: true,
        },
    );
    let spawn_src = include_str!("../../subagent/handle_request.rs");
    assert!(
        spawn_src.contains("ctx.compaction_pins_for_child(&definition.user_message_template)"),
        "run_shell_child must pass compaction_pins_for_child into spawn"
    );
    assert!(
        spawn_src.contains("pins.two_pass"),
        "run_shell_child must pass pins.two_pass into spawn_session_on_thread"
    );
    assert!(
        !spawn_src.contains("CompactionMode::Summary"),
        "run_shell_child must not hard-pin Summary at the spawn site"
    );
    assert!(
        !spawn_src.contains("two_pass_enabled = false")
            && !spawn_src.contains("false, // two_pass"),
        "run_shell_child must not hard-pin two-pass off at the spawn site"
    );
}
