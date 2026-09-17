#![cfg_attr(rustfmt, rustfmt::skip)]
    //! Hook notifications: success leaves no trace, a failed run gets one bulleted `HookOutcome` line, a deny gets none here (the shell's annotation carries it).
    use super::*;
    use fuigo_shell::extensions::notification::{HookRunEntryDto, HookRunStatusDto};

    fn run(name: &str, status: HookRunStatusDto) -> HookRunEntryDto {
        HookRunEntryDto { name: name.into(), status, output: None }
    }

    /// Every failed-hook line; a plain `HookAnnotation` here would mean the line lost its tool-row bullet.
    fn annotation_lines(sb: &ScrollbackState) -> Vec<String> {
        (0..sb.len())
            .filter_map(|i| match sb.get(i).map(|e| &e.block) {
                Some(RenderBlock::SessionEvent(b)) => match &b.event {
                    SessionEvent::HookOutcome { message } => Some(message.clone()),
                    SessionEvent::HookAnnotation { message } => panic!("failed-hook line pushed without the tool bullet: {message}"),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    #[test]
    fn successful_batch_leaves_no_scrollback_trace() {
        let mut app = make_app_with_agent("sess-hooks");
        let len_before = app.agents[&AgentId(0)].scrollback.len();
        for event in ["pre_tool_use", "post_tool_use", "user_prompt_submit", "stop", "session_start"] {
            let affected = handle_ext_notification(
                &fuigo_hook_execution_notif_with_runs(
                    "sess-hooks",
                    event,
                    Some("p1"),
                    false,
                    vec![
                        run("global/lint", HookRunStatusDto::Success { elapsed_ms: 12 }),
                        run("global/off", HookRunStatusDto::Skipped),
                    ],
                ),
                &mut app,
            );
            assert!(!affected, "{event}: nothing changed on screen, so no redraw");
        }
        assert_eq!(
            app.agents[&AgentId(0)].scrollback.len(),
            len_before,
            "successful and skipped runs must not push any block"
        );
    }

    /// A live stop batch mid-turn used to be stashed for the turn marker; it now leaves nothing behind at all.
    #[test]
    fn successful_stop_batch_mid_turn_leaves_nothing_behind() {
        let mut app = make_app_with_agent("sess-stop");
        {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            agent.session.start_turn(&mut agent.scrollback);
            agent.session.current_prompt_id = Some("pid-1".into());
        }
        let len_before = app.agents[&AgentId(0)].scrollback.len();
        let affected = handle_ext_notification(
            &fuigo_hook_execution_notif("sess-stop", "stop", false),
            &mut app,
        );
        assert!(!affected);
        let agent = app.agents.get(&AgentId(0)).unwrap();
        assert_eq!(agent.scrollback.len(), len_before);
    }

    #[test]
    fn failed_run_gets_one_line_and_a_tier_source_names_only_the_event() {
        let mut app = make_app_with_agent("sess-hooks");
        let affected = handle_ext_notification(
            &fuigo_hook_execution_notif_with_runs(
                "sess-hooks",
                "pre_tool_use",
                Some("p1"),
                false,
                vec![
                    run("global/lint", HookRunStatusDto::Success { elapsed_ms: 3 }),
                    run(
                        "requirements/system:pre_tool_use[0].hooks[0]",
                        HookRunStatusDto::Failed {
                            error: "timed out after 1000ms\nsecond line".into(),
                            elapsed_ms: 1000,
                            blocked: false,
                        },
                    ),
                ],
            ),
            &mut app,
        );
        assert!(affected);
        assert_eq!(
            annotation_lines(&app.agents[&AgentId(0)].scrollback),
            vec!["pre_tool_use hook failed, ignored: timed out after 1000ms".to_string()],
            "one line per failed run, first error line only; the config spec path never reaches the user"
        );
    }

    #[test]
    fn named_hook_failure_carries_the_name_and_the_runner_error() {
        let mut app = make_app_with_agent("sess-hooks");
        let _ = handle_ext_notification(
            &fuigo_hook_execution_notif_with_runs(
                "sess-hooks",
                "post_tool_use",
                Some("p1"),
                false,
                vec![run(
                    "global/qa:post_tool_use[1].hooks[0]",
                    HookRunStatusDto::Failed {
                        error: "exit code 1: lint: 3 errors".into(),
                        elapsed_ms: 40,
                        blocked: false,
                    },
                )],
            ),
            &mut app,
        );
        assert_eq!(
            annotation_lines(&app.agents[&AgentId(0)].scrollback),
            vec!["post_tool_use hook (global/qa) failed, ignored: exit code 1: lint: 3 errors".to_string()],
        );
    }

    #[test]
    fn blocked_run_is_not_reported_twice() {
        // The shell annotates every deny with its reason; the batch outcome must not add a second line
        let mut app = make_app_with_agent("sess-hooks");
        let len_before = app.agents[&AgentId(0)].scrollback.len();
        let affected = handle_ext_notification(
            &fuigo_hook_execution_notif_with_runs(
                "sess-hooks",
                "pre_tool_use",
                Some("p1"),
                false,
                vec![run(
                    "global/policy",
                    HookRunStatusDto::Failed {
                        error: "rm is not allowed".into(),
                        elapsed_ms: 5,
                        blocked: true,
                    },
                )],
            ),
            &mut app,
        );
        assert!(!affected);
        assert_eq!(app.agents[&AgentId(0)].scrollback.len(), len_before);
    }

    #[test]
    fn hook_notifications_are_inert_when_plugins_are_disabled() {
        let mut app = make_app_with_agent("sess-hooks");
        app.appearance.disable_plugins = true;
        let len_before = app.agents[&AgentId(0)].scrollback.len();
        let _ = handle_ext_notification(
            &fuigo_hook_execution_notif_with_runs(
                "sess-hooks",
                "pre_tool_use",
                Some("p1"),
                false,
                vec![run("global/lint", HookRunStatusDto::Failed { error: "boom".into(), elapsed_ms: 1, blocked: false })],
            ),
            &mut app,
        );
        let agent = &app.agents[&AgentId(0)];
        assert_eq!(agent.scrollback.len(), len_before);
    }

    /// One batch carrying a deny AND a plain failure: the two are still treated differently.
    /// The base suite pinned this mix in `blocked_wire_flag_maps_to_blocked_status`; after the
    /// silent-success feature the reporting moved, but the split stays a per-run decision, not a
    /// per-batch one. A batch-level "any deny silences the batch" rule passes both single-run
    /// tests above and loses the failure line here.
    #[test]
    fn a_deny_beside_a_failure_silences_only_the_deny() {
        let mut app = make_app_with_agent("sess-hooks");
        let affected = handle_ext_notification(
            &fuigo_hook_execution_notif_with_runs(
                "sess-hooks",
                "stop",
                Some("pid-1"),
                false,
                vec![
                    run(
                        "global/gate",
                        HookRunStatusDto::Failed {
                            error: "blocked stop: run the tests".into(),
                            elapsed_ms: 7,
                            blocked: true,
                        },
                    ),
                    run(
                        "global/broken",
                        HookRunStatusDto::Failed {
                            error: "exit code 1".into(),
                            elapsed_ms: 3,
                            blocked: false,
                        },
                    ),
                ],
            ),
            &mut app,
        );
        assert!(affected, "the failure line is new output, so the frame is dirty");
        assert_eq!(
            annotation_lines(&app.agents[&AgentId(0)].scrollback),
            vec!["stop hook (global/broken) failed, ignored: exit code 1".to_string()],
            "the failure gets its line; the deny beside it is still the shell's to report"
        );
    }
