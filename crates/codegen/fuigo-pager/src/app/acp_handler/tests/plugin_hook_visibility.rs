#![cfg_attr(rustfmt, rustfmt::skip)]
    //! P07b: a fired plugin hook is visible in the pager, through the production `HookExecution` handler.
    //!
    //! `e89bbd1` deleted the hook render machinery after F045 (`87d2e35`) had removed its only producer, so a plugin hook that
    //! ran left no trace. P07b keeps F045 for every source (success silent, one line per failure, a deny left to the shell's
    //! annotation) and shows PLUGIN-origin runs as a badge: on their own tool call's row (found by the batch's `tool_call_id`),
    //! or on a lifecycle row for non-tool events, in whichever view (root or subagent child) the hook ran in.
    use super::*;
    use crate::scrollback::blocks::tool::ToolCallBlock;
    use fuigo_shell::extensions::notification::{HookRunEntryDto, HookRunStatusDto};

    const SID: &str = "sess-plugin-hooks";

    fn run(name: &str, status: HookRunStatusDto) -> HookRunEntryDto {
        HookRunEntryDto { name: name.into(), status, output: None }
    }
    fn ok() -> HookRunStatusDto {
        HookRunStatusDto::Success { elapsed_ms: 3 }
    }
    fn plugin(tag: &str) -> String {
        format!("plugin/{tag}/hooks:pre_tool_use[0].hooks[0]")
    }

    fn deliver(app: &mut AppView, sid: &str, event: &str, call: Option<&str>, runs: Vec<HookRunEntryDto>) {
        let _ = handle_ext_notification(&fuigo_hook_execution_notif_for_call(sid, event, call, runs), app);
    }

    /// Everything entry `index` renders (collapsed, or expanded with `expanded`), hooks included, as plain text.
    fn rendered_text(sb: &ScrollbackState, index: usize, expanded: bool) -> String {
        let entry = sb.get(index).expect("entry");
        let mut ctx = entry.context_with_budget(160, 60, &Default::default(), None);
        if expanded {
            ctx.mode = crate::scrollback::types::DisplayMode::Expanded;
        }
        entry
            .output_with_hooks(&ctx)
            .lines
            .iter()
            .map(|l| l.content.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn index_of(sb: &ScrollbackState, id: crate::scrollback::entry::EntryId) -> usize {
        (0..sb.len()).find(|&i| sb.get(i).map(|e| e.id) == Some(id)).expect("row")
    }

    /// The row the tracker created for tool call `tc` (seeded through the real tracker).
    fn row_of(agent: &AgentView, tc: &str) -> usize {
        let id = agent.session.tracker.pending_tool_entry_id(tc).expect("tool row");
        index_of(&agent.scrollback, id)
    }

    fn count_lifecycle_blocks(sb: &ScrollbackState) -> usize {
        (0..sb.len()).filter(|&i| matches!(
            sb.get(i).map(|e| &e.block), Some(RenderBlock::ToolCall(ToolCallBlock::Lifecycle(_)))
        )).count()
    }

    fn complete_tool(agent: &mut AgentView, tc: &str) {
        agent.session.tracker.handle_update(
            acp::SessionUpdate::ToolCallUpdate(acp::ToolCallUpdate::new(
                acp::ToolCallId::new(std::sync::Arc::from(tc.to_owned())),
                acp::ToolCallUpdateFields::new().status(Some(acp::ToolCallStatus::Completed)),
            )),
            &NotificationMeta::default(),
            &mut agent.scrollback,
        );
        assert!(agent.session.tracker.pending_tool_entry_id(tc).is_none(), "fixture: {tc} completed");
    }

    fn badge_count(sb: &ScrollbackState) -> usize {
        (0..sb.len()).filter(|&i| rendered_text(sb, i, false).contains("[hooks:")).count()
    }

    /// Hostile: two calls of one batch in flight; each call's post-hook batch arrives AFTER both rows exist, the second
    /// call's first. Each badge must land on its own row (position-based attachment put both on the last row).
    #[test]
    fn concurrent_tool_calls_each_get_their_own_hook_badge() {
        let mut app = make_app_with_agent(SID);
        let (row_a, row_b) = {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            seed_pending_tool(agent, "tc-a", "Tool A");
            seed_pending_tool(agent, "tc-b", "Tool B");
            let rows = (row_of(agent, "tc-a"), row_of(agent, "tc-b"));
            // Both calls complete before their post-hooks arrive, so neither is pending any more: only the recorded call->row map finds them
            complete_tool(agent, "tc-a");
            complete_tool(agent, "tc-b");
            rows
        };
        assert_ne!(row_a, row_b);
        deliver(&mut app, SID, "post_tool_use", Some("tc-b"), vec![run(&plugin("bee"), ok())]);
        deliver(&mut app, SID, "post_tool_use", Some("tc-a"), vec![run(&plugin("ay"), ok()), run(&plugin("ay2"), ok())]);
        let sb = &app.agents[&AgentId(0)].scrollback;
        let a = rendered_text(sb, row_a, false);
        let b = rendered_text(sb, row_b, false);
        assert!(a.contains("[hooks: 2]"), "tc-a's two runs on tc-a's row: {a:?}");
        assert!(b.contains("[hooks: 1]"), "tc-b's run on tc-b's row: {b:?}");
        assert!(rendered_text(sb, row_a, true).contains("plugin/ay/"), "expanded row names its own plugin");
        assert!(!rendered_text(sb, row_a, true).contains("plugin/bee/"), "and not the other call's");
        assert!(rendered_text(sb, row_b, true).contains("plugin/bee/"));
    }

    /// Hostile: a `pre_tool_use` batch can arrive before its `ToolCall`; it is held and lands on that call's row when the row
    /// appears, not on whatever row was last.
    #[test]
    fn a_hook_batch_before_its_tool_row_lands_on_that_row() {
        let mut app = make_app_with_agent(SID);
        {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            seed_pending_tool(agent, "tc-old", "Earlier tool");
        }
        deliver(&mut app, SID, "pre_tool_use", Some("tc-new"), vec![run(&plugin("early"), ok())]);
        let row_old = row_of(&app.agents[&AgentId(0)], "tc-old");
        assert!(!rendered_text(&app.agents[&AgentId(0)].scrollback, row_old, false).contains("[hooks:"));
        let row_new = {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            seed_pending_tool(agent, "tc-new", "Later tool");
            row_of(agent, "tc-new")
        };
        let sb = &app.agents[&AgentId(0)].scrollback;
        assert!(rendered_text(sb, row_new, false).contains("[hooks: 1]"));
        assert!(!rendered_text(sb, row_old, false).contains("[hooks:"));
    }

    /// A tool batch without a call id (an older shell) gets no badge rather than a guessed row; an unknown call's batch
    /// never lands on another row.
    #[test]
    fn an_unattributable_tool_batch_badges_nothing() {
        let mut app = make_app_with_agent(SID);
        {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            seed_pending_tool(agent, "tc-a", "Tool A");
        }
        deliver(&mut app, SID, "post_tool_use", None, vec![run(&plugin("anon"), ok())]);
        deliver(&mut app, SID, "post_tool_use", Some("tc-never"), vec![run(&plugin("lost"), ok())]);
        assert_eq!(badge_count(&app.agents[&AgentId(0)].scrollback), 0);
    }

    /// Hostile: a subagent's plugin hook is shown in the CHILD view (the child route used to drop `HookExecution`), not the root.
    #[test]
    fn a_subagent_plugin_hook_shows_in_the_child_view() {
        let mut app = make_app_with_parent_and_child(SID, "child-1");
        let root_len = app.agents[&AgentId(0)].scrollback.len();
        let child_row = {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            let child = agent.subagent_views.get_mut("child-1").unwrap();
            seed_pending_tool(child, "tc-child", "Child tool");
            row_of(child, "tc-child")
        };
        deliver(&mut app, "child-1", "pre_tool_use", Some("tc-child"), vec![run(&plugin("kid"), ok())]);
        deliver(&mut app, "child-1", "session_start", None, vec![run(&plugin("kid"), ok())]);
        let agent = &app.agents[&AgentId(0)];
        let child = &agent.subagent_views["child-1"].scrollback;
        assert!(rendered_text(child, child_row, false).contains("[hooks: 1]"), "tool badge in the child view");
        assert_eq!(count_lifecycle_blocks(child), 1, "lifecycle row in the child view");
        assert_eq!(agent.scrollback.len(), root_len, "nothing in the root view");
        assert_eq!(badge_count(&agent.scrollback), 0);
    }

    /// A plugin lifecycle run gets its own row naming the event; it is not counted as a tool operation.
    #[test]
    fn a_plugin_lifecycle_run_gets_a_row_outside_tool_stats() {
        let mut app = make_app_with_agent(SID);
        deliver(&mut app, SID, "session_start", None, vec![run(&plugin("boot"), ok())]);
        let sb = &app.agents[&AgentId(0)].scrollback;
        assert_eq!(count_lifecycle_blocks(sb), 1);
        let text = rendered_text(sb, sb.len() - 1, false);
        assert!(text.contains("session_start") && text.contains("[hooks: 1]"), "{text:?}");
        assert_eq!(crate::tool_usage::ToolUsageStats::from_scrollback(sb).total_operations, 0, "not a tool operation");
    }

    /// F045 stays for every source: non-plugin success and skip leave nothing, a non-plugin failure gets its one line and no badge,
    /// a plugin failure gets the line AND a badge, a plugin deny gets neither (the shell's annotation reports it once).
    #[test]
    fn f045_is_kept_and_only_plugin_runs_are_badged() {
        let mut app = make_app_with_agent(SID);
        let before = app.agents[&AgentId(0)].scrollback.len();
        deliver(&mut app, SID, "session_start", None, vec![
            run("global/notify", ok()),
            run("project/x:session_start[0].hooks[0]", HookRunStatusDto::Skipped),
        ]);
        assert_eq!(app.agents[&AgentId(0)].scrollback.len(), before, "non-plugin success and skip stay silent");

        deliver(&mut app, SID, "user_prompt_submit", None, vec![run(
            "global/check",
            HookRunStatusDto::Failed { error: "exit 1: nope".into(), elapsed_ms: 2, blocked: false },
        )]);
        let sb = &app.agents[&AgentId(0)].scrollback;
        assert_eq!(sb.len(), before + 1, "one line for the non-plugin failure");
        assert!(matches!(last_session_event(sb), Some(SessionEvent::HookOutcome { .. })));
        assert_eq!(count_lifecycle_blocks(sb), 0, "and no badge row");

        deliver(&mut app, SID, "user_prompt_submit", None, vec![run(
            &plugin("gate"),
            HookRunStatusDto::Failed { error: "exit 1: broke".into(), elapsed_ms: 2, blocked: false },
        )]);
        let sb = &app.agents[&AgentId(0)].scrollback;
        assert_eq!(count_lifecycle_blocks(sb), 1, "a plugin failure is badged");
        let outcome_lines = (0..sb.len()).filter(|&i| matches!(
            sb.get(i).map(|e| &e.block),
            Some(RenderBlock::SessionEvent(b)) if matches!(b.event, SessionEvent::HookOutcome { .. })
        )).count();
        assert_eq!(outcome_lines, 2, "and keeps its F045 line");
        let badge = (0..sb.len()).find(|&i| matches!(
            sb.get(i).map(|e| &e.block), Some(RenderBlock::ToolCall(ToolCallBlock::Lifecycle(_)))
        )).unwrap();
        assert!(rendered_text(sb, badge, true).contains("broke"), "the expanded row carries the failure");

        let len = sb.len();
        deliver(&mut app, SID, "user_prompt_submit", None, vec![run(
            &plugin("deny"),
            HookRunStatusDto::Failed { error: "denied".into(), elapsed_ms: 2, blocked: true },
        )]);
        assert_eq!(app.agents[&AgentId(0)].scrollback.len(), len, "a plugin deny adds nothing");
    }

    #[test]
    fn hook_rows_stay_hidden_with_the_plugins_ui_disabled() {
        let mut app = make_app_with_agent(SID);
        app.appearance.disable_plugins = true;
        let row = {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            seed_pending_tool(agent, "tc-a", "Tool A");
            row_of(agent, "tc-a")
        };
        let len = app.agents[&AgentId(0)].scrollback.len();
        deliver(&mut app, SID, "pre_tool_use", Some("tc-a"), vec![run(&plugin("p"), ok())]);
        deliver(&mut app, SID, "session_start", None, vec![run(&plugin("p"), ok())]);
        let sb = &app.agents[&AgentId(0)].scrollback;
        assert_eq!(sb.len(), len);
        assert!(!rendered_text(sb, row, false).contains("[hooks:"));
    }

    /// A backgrounded call shown as a fresh BgTask row (no Execute row to convert) receives the hook batch held for its call.
    #[test]
    fn a_backgrounded_call_row_receives_its_held_hooks() {
        let mut app = make_app_with_agent(SID);
        deliver(&mut app, SID, "pre_tool_use", Some("call-bg"), vec![run(&plugin("bg"), ok())]);
        let notif = SessionNotification {
            session_id: acp::SessionId::new(SID),
            update: FuigoSessionUpdate::TaskBackgrounded {
                tool_call_id: "call-bg".into(),
                task_id: "task-bg".into(),
                command: "sleep 9999".into(),
                cwd: "/tmp".into(),
                output_file: "/tmp/output.log".into(),
                monitor_description: None,
                description: None,
            },
            meta: None,
        };
        let raw = serde_json::value::to_raw_value(&notif).unwrap();
        let notif = acp::ExtNotification::new("fuigo/task_backgrounded", raw.into());
        let _ = handle_ext_notification(&notif, &mut app);
        let sb = &app.agents[&AgentId(0)].scrollback;
        let bg = (0..sb.len())
            .find(|&i| matches!(sb.get(i).map(|e| &e.block), Some(RenderBlock::BgTask(_))))
            .expect("fixture: a BgTask row");
        assert!(
            sb.get(bg).and_then(|e| e.hook_data.as_ref()).is_some_and(|d| d.pre_hooks.len() == 1),
            "the held batch is on the BgTask row"
        );
    }

    /// A subagent's deny explanation (the shell's annotation, which F045 leaves as the deny's one report) shows in the child view.
    #[test]
    fn a_subagent_hook_annotation_shows_in_the_child_view() {
        let mut app = make_app_with_parent_and_child(SID, "child-1");
        let root_len = app.agents[&AgentId(0)].scrollback.len();
        let payload = SessionNotification {
            session_id: acp::SessionId::new("child-1"),
            update: FuigoSessionUpdate::HookAnnotation { message: "denied by policy".into() },
            meta: None,
        };
        let raw = serde_json::value::to_raw_value(&payload).unwrap();
        let _ = handle_ext_notification(&acp::ExtNotification::new("fuigo/session/update", raw.into()), &mut app);
        let agent = &app.agents[&AgentId(0)];
        assert!(matches!(
            last_session_event(&agent.subagent_views["child-1"].scrollback),
            Some(SessionEvent::HookAnnotation { .. })
        ));
        assert_eq!(agent.scrollback.len(), root_len);
    }

    /// A child hook batch stamped with `_meta.eventId` (`None` = an older shell that stamps nothing).
    fn deliver_child_batch(app: &mut AppView, sid: &str, call: Option<&str>, event: &str, event_id: Option<&str>) {
        let mut meta = serde_json::json!({ "isReplay": false });
        if let Some(id) = event_id {
            meta["eventId"] = id.into();
        }
        let payload = SessionNotification {
            session_id: acp::SessionId::new(sid),
            update: FuigoSessionUpdate::HookExecution {
                event_name: event.into(),
                tool_name: None,
                tool_call_id: call.map(str::to_string),
                prompt_id: None,
                runs: vec![run(&plugin("kid"), ok())],
            },
            meta: Some(meta),
        };
        let raw = serde_json::value::to_raw_value(&payload).unwrap();
        let _ = handle_ext_notification(&acp::ExtNotification::new("fuigo/session/update", raw.into()), app);
    }

    fn deliver_child_annotation(app: &mut AppView, sid: &str, event_id: &str) {
        let payload = SessionNotification {
            session_id: acp::SessionId::new(sid),
            update: FuigoSessionUpdate::HookAnnotation { message: "denied by policy".into() },
            meta: Some(serde_json::json!({ "eventId": event_id })),
        };
        let raw = serde_json::value::to_raw_value(&payload).unwrap();
        let _ = handle_ext_notification(&acp::ExtNotification::new("fuigo/session/update", raw.into()), app);
    }

    /// Astra MEDIUM: a child hook event delivered twice (same `eventId`) is applied once, for a tool batch, a lifecycle batch and an
    /// annotation alike. Dedup is by exact id, not a counter highwater: an unseen LOWER id still applies.
    #[test]
    fn a_subagent_hook_event_delivered_twice_is_applied_once() {
        let mut app = make_app_with_parent_and_child(SID, "child-1");
        let root_len = app.agents[&AgentId(0)].scrollback.len();
        let row = {
            let agent = app.agents.get_mut(&AgentId(0)).unwrap();
            let child = agent.subagent_views.get_mut("child-1").unwrap();
            seed_pending_tool(child, "tc-child", "Child tool");
            row_of(child, "tc-child")
        };
        let runs_on_row = |app: &AppView| {
            app.agents[&AgentId(0)].subagent_views["child-1"].scrollback.get(row)
                .and_then(|e| e.hook_data.as_ref()).map_or(0, |d| d.pre_hooks.len() + d.post_hooks.len())
        };
        deliver_child_batch(&mut app, "child-1", Some("tc-child"), "pre_tool_use", Some("child-1-41"));
        deliver_child_batch(&mut app, "child-1", Some("tc-child"), "pre_tool_use", Some("child-1-41"));
        assert_eq!(runs_on_row(&app), 1, "the re-delivered tool batch is dropped");
        assert!(rendered_text(&app.agents[&AgentId(0)].subagent_views["child-1"].scrollback, row, false).contains("[hooks: 1]"));

        deliver_child_batch(&mut app, "child-1", None, "session_start", Some("child-1-42"));
        deliver_child_batch(&mut app, "child-1", None, "session_start", Some("child-1-42"));
        assert_eq!(count_lifecycle_blocks(&app.agents[&AgentId(0)].subagent_views["child-1"].scrollback), 1, "one lifecycle row");

        deliver_child_annotation(&mut app, "child-1", "child-1-43");
        deliver_child_annotation(&mut app, "child-1", "child-1-43");
        let child = &app.agents[&AgentId(0)].subagent_views["child-1"].scrollback;
        let annotations = (0..child.len()).filter(|&i| matches!(
            child.get(i).map(|e| &e.block),
            Some(RenderBlock::SessionEvent(b)) if matches!(b.event, SessionEvent::HookAnnotation { .. })
        )).count();
        assert_eq!(annotations, 1, "one annotation line");

        deliver_child_batch(&mut app, "child-1", Some("tc-child"), "post_tool_use", Some("child-1-44"));
        assert_eq!(runs_on_row(&app), 2, "a new event applies");
        deliver_child_batch(&mut app, "child-1", Some("tc-child"), "post_tool_use", Some("child-1-7"));
        assert_eq!(runs_on_row(&app), 3, "an unseen lower id is not a duplicate");
        // An unstamped batch (older shell) carries nothing to dedup on, so each delivery applies
        deliver_child_batch(&mut app, "child-1", Some("tc-child"), "post_tool_use", None);
        deliver_child_batch(&mut app, "child-1", Some("tc-child"), "post_tool_use", None);
        assert_eq!(runs_on_row(&app), 5);
        assert_eq!(app.agents[&AgentId(0)].scrollback.len(), root_len, "nothing in the root view");
    }

    /// The hydration overlap: a resumed child's first live hook event triggers the disk replay, which already holds that event,
    /// and then the live copy applies. It must not double the row's runs.
    #[test]
    fn a_resumed_childs_replayed_hook_is_not_doubled_by_its_live_copy() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        with_replay_disk_home(|home| {
            let child_sid = "child-hook-hydrate";
            let id = format!("{child_sid}-5");
            write_child_updates_jsonl(
                home,
                child_sid,
                &format!("{}\n{}\n", child_tool_line(child_sid), child_hook_line(child_sid, "tc1", &id)),
            );
            let mut app = make_app_with_agent("sess-parent");
            let mut spawned = test_subagent_spawned("sess-parent", child_sid);
            let FuigoSessionUpdate::SubagentSpawned { resumed_from, .. } = &mut spawned else {
                unreachable!();
            };
            *resumed_from = Some("orig-child".into());
            let _ = handle(make_ext_session_notification_with_method("sess-parent", "fuigo/session/update", spawned), &mut app);
            app.agents.get_mut(&AgentId(0)).unwrap().subagent_sessions.get_mut(child_sid).unwrap().is_background = true;
            assert_eq!(child_hook_run_count(&app.agents[&AgentId(0)], child_sid), 0, "nothing read yet");

            deliver_child_batch(&mut app, child_sid, Some("tc1"), "post_tool_use", Some(&id));
            let agent = &app.agents[&AgentId(0)];
            assert_eq!(child_scrollback_tool_call_count(agent, child_sid), 1, "the replay ran before the live copy");
            assert_eq!(child_hook_run_count(agent, child_sid), 1, "the live copy of a replayed event is dropped");
        });
    }
