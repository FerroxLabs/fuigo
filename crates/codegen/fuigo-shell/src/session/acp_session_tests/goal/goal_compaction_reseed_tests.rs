use super::support::*;
use super::*;
use crate::session::helpers::compaction_context::{CompactionInputs, CompactionStateContext};
use std::sync::Arc as StdArc;
use tempfile::TempDir;
use fuigo_chat_state::compaction_utils::{
    CompactedHistoryInput, build_compacted_history, wrap_user_query,
};
use fuigo_sampling_types::{ConversationItem, SyntheticReason};

const DEVICE_TEST_OBJECTIVE: &str = "ssh to root@example.test and test that a genbw meter profile does NOT produce aggregate meter data on dnp3 or modbus";
const STALE_CODE_REVIEW: &str = "please review the PR for config-json-go";

#[tokio::test(flavor = "current_thread")]
async fn last_user_query_seeds_from_active_goal_not_stale_pre_goal_prompt() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _tmp) = make_goal_actor().await;
            start_device_test_goal(&actor);
            let conversation = stale_pre_goal_conversation();

            let without_goal =
                CompactionStateContext::build(&conversation, CompactionInputs::default()).await;
            assert_eq!(
                without_goal.last_user_query.as_deref(),
                Some(STALE_CODE_REVIEW),
                "without the goal field, compact would revive the pre-goal code review"
            );

            let with_goal = CompactionStateContext::build(
                &conversation,
                CompactionInputs {
                    goal_objective: actor.goal_objective_for_compaction(),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(
                with_goal.last_user_query.as_deref(),
                Some(DEVICE_TEST_OBJECTIVE),
                "active goal must seed last_user_query from GoalTracker.objective"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn compaction_goal_section_is_continuation_not_create_style_rules() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _tmp) = make_goal_actor().await;
            start_device_test_goal(&actor);

            let section = actor
                .compaction_goal_section()
                .await
                .expect("active goal must produce a compaction reminder section");
            assert!(
                section.contains(DEVICE_TEST_OBJECTIVE),
                "reminder must pin the live objective:\n{section}"
            );
            assert!(
                section.contains(GOAL_CONTINUATION_SENTINEL),
                "reminder must be continuation-style, not create-style rules:\n{section}"
            );
            assert!(
                !section.contains("A goal has been set"),
                "create-style goal_rules must not be the post-compact cue:\n{section}"
            );
            assert!(
                section.contains("Do not restart this goal"),
                "reminder must tell the model not to restart:\n{section}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn summarizer_user_context_pins_objective() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, tmp) = make_goal_actor().await;
            start_device_test_goal(&actor);
            let plan = tmp.path().join("plan.md");
            std::fs::write(&plan, "- [x] connect to the device\n- [ ] run the genbw profile check\n")
                .unwrap();
            actor.goal_tracker.lock().snapshot_mut().expect("goal").plan_file = Some(plan);

            let ctx = actor
                .goal_compaction_user_context()
                .expect("active goal must produce summarizer context");
            assert!(ctx.contains(DEVICE_TEST_OBJECTIVE), "{ctx}");
            assert!(ctx.contains("Do not restart this goal"), "{ctx}");
            assert!(
                ctx.contains("Next step: run the genbw profile check") && !ctx.contains("connect to the device"),
                "the summarizer is told the plan's next unchecked step:\n{ctx}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn post_compact_history_keeps_objective_and_goal_summary_continuation() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _tmp) = make_goal_actor().await;
            start_device_test_goal(&actor);
            let conversation = stale_pre_goal_conversation();
            actor
                .chat_state_handle
                .replace_conversation(conversation.clone());
            let _ = actor.chat_state_handle.get_conversation().await;

            let state_context = CompactionStateContext::build(
                &conversation,
                CompactionInputs {
                    goal_objective: actor.goal_objective_for_compaction(),
                    ..Default::default()
                },
            )
            .await
            .for_compaction();
            assert_eq!(
                state_context.last_user_query.as_deref(),
                Some(DEVICE_TEST_OBJECTIVE)
            );

            let goal_section = actor
                .compaction_goal_section()
                .await
                .expect("active goal reminder");
            let system_reminder = format!(
                "<system-reminder>\n## Files Edited This Session\n- src/auth.rs\n\n{goal_section}\n</system-reminder>"
            );

            let compacted = build_compacted_history(CompactedHistoryInput {
                system_message: ConversationItem::system("You are Fuigo."),
                user_message_prefix: "<user_info>OS: linux</user_info>".into(),
                agents_md_reminder: None,
                state_context: &state_context,
                compaction_summary: "<summary>\n1. Primary Request and Intent: code review\n</summary>"
                    .into(),
                system_reminder: Some(system_reminder),
                summary_before_recent: false,
                transcript_hint: None,
                summary_count: 1,
            });

            let query_texts: Vec<String> = compacted
                .iter()
                .filter_map(|item| match item {
                    ConversationItem::User(u) if u.synthetic_reason.is_none() => {
                        Some(item.text_content())
                    }
                    _ => None,
                })
                .collect();
            assert!(
                query_texts.iter().any(|t| t.contains(&wrap_user_query(DEVICE_TEST_OBJECTIVE))),
                "compacted <user_query> must be the goal objective, not the code review:\n{query_texts:?}"
            );
            assert!(
                query_texts.iter().all(|t| !t.contains(STALE_CODE_REVIEW)),
                "stale pre-goal prompt must not occupy last_user_query:\n{query_texts:?}"
            );

            actor
                .chat_state_handle
                .replace_conversation_for_compaction(compacted);
            let _ = actor.chat_state_handle.get_conversation().await;
            actor.reseed_active_goal_after_compaction().await;

            let after = actor.chat_state_handle.get_conversation().await;
            let goal_summaries: Vec<&ConversationItem> = after
                .iter()
                .filter(|item| {
                    matches!(
                        item,
                        ConversationItem::User(u)
                            if u.synthetic_reason == Some(SyntheticReason::GoalSummary)
                    )
                })
                .collect();
            assert_eq!(
                goal_summaries.len(),
                1,
                "exactly one GoalSummary continuation after compact: {after:?}"
            );
            let directive = goal_summaries
                .first()
                .expect("len==1")
                .text_content();
            assert!(
                directive.contains(DEVICE_TEST_OBJECTIVE),
                "GoalSummary must carry the live objective:\n{directive}"
            );
            assert!(
                directive.contains(GOAL_CONTINUATION_SENTINEL),
                "GoalSummary must be the next-step continuation:\n{directive}"
            );
            assert!(
                !directive.contains("A goal has been set"),
                "GoalSummary must not be create-style rules:\n{directive}"
            );

            let last_user = after.iter().rev().find(|item| {
                matches!(item, ConversationItem::User(_))
            });
            let last_user = last_user.expect("post-compact history has a user item");
            assert!(
                matches!(
                    last_user,
                    ConversationItem::User(u)
                        if u.synthetic_reason == Some(SyntheticReason::GoalSummary)
                ),
                "last cue after compact must be GoalSummary, not create-style rules:\n{:?}",
                last_user.text_content()
            );
            assert!(
                last_user.text_content().contains(GOAL_CONTINUATION_SENTINEL),
                "last cue must continue the goal:\n{}",
                last_user.text_content()
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn paused_goal_does_not_override_later_human_query() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _tmp) = make_goal_actor().await;
            start_device_test_goal(&actor);
            assert!(
                actor
                    .goal_tracker
                    .lock()
                    .pause(crate::session::goal_tracker::GoalPauseReason::User)
            );

            assert_eq!(actor.goal_objective_for_compaction(), None);
            assert_eq!(actor.goal_compaction_user_context(), None);

            let conversation = stale_pre_goal_conversation();
            let ctx = CompactionStateContext::build(
                &conversation,
                CompactionInputs {
                    goal_objective: actor.goal_objective_for_compaction(),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(
                ctx.last_user_query.as_deref(),
                Some(STALE_CODE_REVIEW),
                "paused goal must not replace the later human prompt"
            );

            let section = actor
                .compaction_goal_section()
                .await
                .expect("paused goal still belongs in the reminder");
            assert!(
                section.contains(DEVICE_TEST_OBJECTIVE),
                "reminder still pins the live objective:\n{section}"
            );
            assert!(
                !section.contains(GOAL_CONTINUATION_SENTINEL),
                "paused reminder must not be a continue-working cue:\n{section}"
            );

            actor.chat_state_handle.replace_conversation(conversation);
            let _ = actor.chat_state_handle.get_conversation().await;
            actor.reseed_active_goal_after_compaction().await;
            let after = actor.chat_state_handle.get_conversation().await;
            assert!(
                after.iter().all(|item| {
                    !matches!(
                        item,
                        ConversationItem::User(u)
                            if u.synthetic_reason == Some(SyntheticReason::GoalSummary)
                    )
                }),
                "paused compact must not inject GoalSummary: {after:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn compact_reseed_skips_turn_end_drain_and_round_count() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _tmp) = make_goal_actor().await;
            start_device_test_goal(&actor);
            {
                let mut tracker = actor.goal_tracker.lock();
                tracker.snapshot_mut().expect("goal").rounds_since_verify = 4;
            }
            actor.pending_classifier_completions.lock().push_back(
                fuigo_tools::implementations::fuigo_build::update_goal::UpdateGoalInput {
                    completed: None,
                    message: Some("progress".into()),
                    blocked_reason: None,
                },
            );

            actor.reseed_active_goal_after_compaction().await;

            assert_eq!(
                actor
                    .goal_tracker
                    .lock()
                    .snapshot()
                    .expect("goal")
                    .rounds_since_verify,
                4,
                "compact reseed must not count as a worker round"
            );
            assert_eq!(
                actor.pending_classifier_completions.lock().len(),
                1,
                "compact reseed must not TurnEnd-drain pending classifier completions"
            );

            let after = actor.chat_state_handle.get_conversation().await;
            assert!(
                after.iter().any(|item| {
                    matches!(
                        item,
                        ConversationItem::User(u)
                            if u.synthetic_reason == Some(SyntheticReason::GoalSummary)
                    ) && item.text_content().contains(GOAL_CONTINUATION_SENTINEL)
                }),
                "compact still injects a continuation: {after:?}"
            );
        })
        .await;
}

async fn make_goal_actor() -> (StdArc<SessionActor>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let (gateway_tx, _gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.events = crate::session::events::EventTracker::new(tmp.path());
    actor.goal_enabled = true;
    actor.goal_planner_enabled = true;
    set_goal_harness_for_tests(&actor);
    actor.goal_tracker = StdArc::new(parking_lot::Mutex::new(
        crate::session::goal_tracker::GoalTracker::new(tmp.path().to_path_buf()),
    ));
    (StdArc::new(actor), tmp)
}

fn start_device_test_goal(actor: &SessionActor) {
    actor.goal_tracker.lock().create_goal(
        "g-device-test".into(),
        DEVICE_TEST_OBJECTIVE.into(),
        None,
        0,
        "2026-08-06T00:00:00Z".into(),
        None,
    );
}

fn stale_pre_goal_conversation() -> Vec<ConversationItem> {
    vec![
        ConversationItem::system("You are Fuigo."),
        ConversationItem::user(format!(
            "<user_info>OS: linux</user_info>\n\n<user_query>\n{STALE_CODE_REVIEW}\n</user_query>"
        )),
        ConversationItem::assistant("I'll start the branch code review."),
        ConversationItem::system_reminder(format!(
            "A goal has been set: {DEVICE_TEST_OBJECTIVE}\nStart now."
        )),
    ]
}

/// A chat-completions server that answers every request with a one-message summary and captures each request body.
async fn spawn_summary_server() -> (String, StdArc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = StdArc::new(std::sync::Mutex::new(Vec::new()));
    let sink = StdArc::clone(&captured);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let sink = StdArc::clone(&sink);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                let body = loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break String::new(),
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                    if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                        let length: usize = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if raw.len() >= end + 4 + length {
                            break String::from_utf8_lossy(&raw[end + 4..end + 4 + length])
                                .into_owned();
                        }
                    }
                };
                let streaming = body.contains("\"stream\":true");
                sink.lock().unwrap().push(body);
                let summary = "<summary>\\n1. Primary Request and Intent: verify the meter profile on the device.\\n2. Key Technical Concepts: ssh access, genbw meter profiles, dnp3 and modbus aggregate data.\\n3. Files and Code Sections: none edited yet.\\n4. Errors and fixes: none so far.\\n5. Problem Solving: the device is reachable and the profile is loaded; the aggregate check has not run yet.\\n6. Pending Tasks: run the aggregate check on dnp3 and modbus and report the result.\\n7. Current Work: connecting to the device to start the check.\\n</summary>";
                let reply = if streaming {
                    let chunk = format!(
                        "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"test\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":\"{summary}\"}},\"finish_reason\":null}}]}}\n\n\
                         data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"test\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}}}\n\n\
                         data: [DONE]\n\n"
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{chunk}",
                        chunk.len()
                    )
                } else {
                    let json = format!(
                        "{{\"id\":\"c1\",\"object\":\"chat.completion\",\"created\":0,\"model\":\"test\",\"choices\":[{{\"index\":0,\"message\":{{\"role\":\"assistant\",\"content\":\"{summary}\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}}}"
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                        json.len()
                    )
                };
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), captured)
}

/// The compaction run itself, not its parts: an active goal reaches the summarizer request (beside the user's own
/// `/compact` focus), the compacted `<user_query>`, the post-compact system reminder, and the history's last cue.
/// Each stage is wired separately in `run_compact_inner`, so a part tested alone does not prove the run uses it.
#[tokio::test(flavor = "current_thread")]
async fn a_compaction_run_carries_the_active_goal_through_every_stage() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().expect("tempdir");
            let (gateway_tx, _gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let persistence_tx =
                crate::session::persistence::compaction_fixture_persistence(persistence_tx).await;
            let mut actor = create_test_actor(50_000, 256_000, 85, gateway_tx, persistence_tx).await;
            actor.events = crate::session::events::EventTracker::new(tmp.path());
            actor.goal_enabled = true;
            actor.goal_planner_enabled = true;
            set_goal_harness_for_tests(&actor);
            actor.goal_tracker = StdArc::new(parking_lot::Mutex::new(
                crate::session::goal_tracker::GoalTracker::new(tmp.path().to_path_buf()),
            ));
            let actor = StdArc::new(actor);
            start_device_test_goal(&actor);
            let (base_url, requests) = spawn_summary_server().await;
            let mut cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
            cfg.base_url = base_url;
            actor.chat_state_handle.update_sampling_config(cfg);
            actor
                .chat_state_handle
                .replace_conversation(stale_pre_goal_conversation());

            actor
                .run_compact(Some("focus on auth".to_owned()))
                .await
                .expect("the compaction runs against the scripted summarizer");

            let requests = requests.lock().unwrap().clone();
            let summarizer = requests
                .iter()
                .find(|body| body.contains("Continue from the current next step"))
                .unwrap_or_else(|| {
                    panic!("no summarizer request carried the goal pin ({} requests)", requests.len())
                });
            let focus = summarizer.find("focus on auth").expect("the user's /compact focus is sent");
            let pin = summarizer.find("Continue from the current next step").unwrap();
            assert!(focus < pin, "the user's focus leads and the goal pin follows");

            let after = actor.chat_state_handle.get_conversation().await;
            let human_queries: Vec<String> = after
                .iter()
                .filter_map(|item| match item {
                    ConversationItem::User(u) if u.synthetic_reason.is_none() => {
                        Some(item.text_content())
                    }
                    _ => None,
                })
                .collect();
            assert!(
                human_queries
                    .iter()
                    .any(|t| t.contains(&wrap_user_query(DEVICE_TEST_OBJECTIVE))),
                "the compacted <user_query> is the goal objective:\n{human_queries:?}"
            );
            assert!(
                human_queries.iter().all(|t| !t.contains(STALE_CODE_REVIEW)),
                "the stale pre-goal prompt is not revived:\n{human_queries:?}"
            );
            let reminder = after
                .iter()
                .map(ConversationItem::text_content)
                .find(|text| text.contains("## Active Goal"))
                .unwrap_or_else(|| panic!("the post-compact reminder names the goal: {after:?}"));
            assert!(reminder.contains(DEVICE_TEST_OBJECTIVE), "{reminder}");
            assert!(
                reminder.find("## Active Goal").unwrap()
                    < reminder.rfind("</system-reminder>").expect("the goal joined a reminder"),
                "the goal section sits inside the system reminder:\n{reminder}"
            );
            let last_user = after
                .iter()
                .rev()
                .find(|item| matches!(item, ConversationItem::User(_)))
                .expect("a user item");
            assert!(
                matches!(
                    last_user,
                    ConversationItem::User(u) if u.synthetic_reason == Some(SyntheticReason::GoalSummary)
                ) && last_user.text_content().contains(GOAL_CONTINUATION_SENTINEL),
                "the last cue after the compaction continues the goal: {:?}",
                last_user.text_content()
            );
        })
        .await;
}
