//! Mid-turn interjection images: harvesting images from queued rows and the `drain_pending_interjections` image pipeline.
use super::support::*;
use super::*;

/// Send-now of an image-bearing queued prompt keeps its `ContentBlock::Image`s on the promoted row.
#[tokio::test]
async fn queue_send_now_keeps_prompt_block_images_on_promoted_row() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.running_task = Some(running_task_stub("running"));
                state.front_message_committed = true;
                let mut item = user_item("p1", "A");
                item.prompt_blocks
                    .push(acp::ContentBlock::Image(test_image_content()));
                state.pending_inputs.push_back(item);
            }
            *actor
                .current_prompt_id
                .lock()
                .expect("current_prompt_id mutex poisoned") = Some("running".into());

            let cancel = actor
                .handle_interject_queued_prompt("p1", 0, None, None)
                .await
                .cancel_running_turn;
            assert!(cancel, "promotion behind a running turn requests cancel");

            let state = actor.state.lock().await;
            let promoted = state
                .pending_inputs
                .iter()
                .find(|i| i.prompt_id == "p1")
                .expect("promoted row stays queued to run next");
            assert_eq!(
                promoted
                    .prompt_blocks
                    .iter()
                    .filter(|b| matches!(b, acp::ContentBlock::Image(_)))
                    .count(),
                1,
                "image blocks must survive promotion"
            );
            assert!(
                actor.pending_interjections.is_empty(),
                "send-now never buffers into the running turn"
            );
        })
        .await;
}

#[tokio::test]
async fn goal_send_now_routes_text_and_image_as_planner_steering_and_interjection() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.running_task = Some(running_task_stub("running"));
            }
            actor.goal_tracker.lock().create_goal(
                "goal".into(),
                "objective".into(),
                None,
                0,
                "2026-01-01T00:00:00Z".into(),
                None,
            );
            let cancel = tokio_util::sync::CancellationToken::new();
            actor.goal_tracker.lock().start_planner_run(cancel.clone());

            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            let cancelled = actor
                .queue_input(QueueInputRequest {
                    send_now: true,
                    ..queue_input_request(
                        vec![
                            acp::ContentBlock::Text(acp::TextContent::new("steer")),
                            acp::ContentBlock::Image(test_image_content()),
                        ],
                        "steer-image",
                        respond_to,
                    )
                })
                .await;

            assert!(!cancelled);
            assert!(cancel.is_cancelled());
            assert!(matches!(
                response_rx.await.unwrap().unwrap().completion_kind,
                PromptCompletionKind::RemovedFromQueue
            ));
            let run = actor.goal_tracker.lock().take_planner_run().unwrap();
            assert_eq!(run.steering, ["steer"]);
            let interjections = actor.pending_interjections.drain_all();
            assert_eq!(interjections.len(), 1);
            assert_eq!(interjections[0].text, "steer");
            assert_eq!(interjections[0].attachments.len(), 1);
        })
        .await;
}

/// Draining an image-bearing interjection injects structured `ContentPart::Image` parts (base64 data URLs) on the synthetic user message.
/// The message keeps `SyntheticReason::Interjection`.
#[tokio::test]
async fn drain_interjection_with_images_attaches_image_parts() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _gateway_rx) = build_actor().await;
            actor.pending_interjections.push(PendingInterjection {
                text: "look at [Image #1]".to_string(),
                attachments: vec![test_image_content()],
                ..Default::default()
            });

            assert!(actor.drain_pending_interjections().await);

            let conversation = actor.chat_state_handle.get_conversation().await;
            let user_item = match conversation.last() {
                Some(ConversationItem::User(u)) => u,
                other => panic!("conversation tail must be a user item, got: {other:?}"),
            };
            assert_eq!(
                user_item.synthetic_reason,
                Some(SyntheticReason::Interjection)
            );
            let image_urls: Vec<&str> = user_item
                .content
                .iter()
                .filter_map(|p| match p {
                    fuigo_sampling_types::ContentPart::Image { url } => Some(url.as_ref()),
                    _ => None,
                })
                .collect();
            assert_eq!(image_urls.len(), 1, "image part must be attached");
            assert!(
                image_urls[0].starts_with("data:image/"),
                "inline base64 data URL expected, got {}",
                &image_urls[0][..image_urls[0].len().min(32)]
            );
            let text = conversation.last().unwrap().text_content();
            assert!(
                text.contains("[Image #1]") && text.contains("<user_query>"),
                "placeholder text must survive in the wrapped query, got: {text}"
            );
        })
        .await;
}

/// The drain strips `[Image #N: <path>]` down to `[Image #N]` before the text reaches the model, the same gate as the prompt path.
/// Covers raw text from legacy clients and text harvested from a queued row (raw `queue_meta.text`).
#[tokio::test]
async fn drain_interjection_strips_placeholder_paths_from_text() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _gateway_rx) = build_actor().await;
            actor.pending_interjections.push(PendingInterjection {
                text: "look at [Image #1: /tmp/secret/x.png] please".to_string(),
                attachments: vec![test_image_content()],
                ..Default::default()
            });

            assert!(actor.drain_pending_interjections().await);

            let conversation = actor.chat_state_handle.get_conversation().await;
            let text = conversation.last().expect("user item").text_content();
            assert!(
                text.contains("[Image #1]"),
                "bare placeholder must survive, got: {text}"
            );
            assert!(
                !text.contains("/tmp/secret/x.png"),
                "path must be stripped from the model-visible text, got: {text}"
            );
        })
        .await;
}

/// Draining an interjection whose text is a skill slash invocation appends the `<skill_information>` envelope after the wrapped `<user_query>`.
/// Send-now of a queued `/skill` row (and a typed `/skill` interjection) must not reach the model unexpanded.
#[tokio::test]
async fn drain_interjection_expands_skill_slash_reference() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("SKILL.md");
            std::fs::write(&path, "Find sessions matching $ARGUMENTS").unwrap();
            let skill = fuigo_tools::implementations::skills::types::SkillInfo {
                name: "find-session".to_owned(),
                description: "Find past sessions".to_owned(),
                path: path.to_string_lossy().into_owned(),
                ..Default::default()
            };
            actor
                .agent
                .borrow()
                .tool_bridge()
                .clone()
                .seed_skill_discovery(
                    Some(std::path::PathBuf::from("/tmp")),
                    None,
                    vec![skill],
                    None,
                    Some(256_000),
                    None,
                    fuigo_tools::types::compat::CompatConfig::default(),
                )
                .await;

            actor.pending_interjections.push(PendingInterjection {
                text: "/find-session foo".to_string(),
                attachments: vec![],
                ..Default::default()
            });
            assert!(actor.drain_pending_interjections().await);

            let conversation = actor.chat_state_handle.get_conversation().await;
            let text = conversation.last().expect("user item").text_content();
            assert!(
                text.contains("<user_query>\n/find-session foo\n</user_query>"),
                "raw slash text stays the visible query, got: {text}"
            );
            let query_end = text.find("</user_query>").expect("wrapped query");
            let envelope = text
                .find("<skill_information>")
                .unwrap_or_else(|| panic!("skill envelope must be appended, got: {text}"));
            assert!(
                query_end < envelope,
                "envelope must follow the query, got: {text}"
            );
            assert!(
                text.contains("Find sessions matching foo"),
                "SKILL.md body with substituted args must ride along, got: {text}"
            );

            // A steering interjection that only mentions the skill mid-text (no leading slash) stays untouched
            // The same gating applies at turn start, where "don't run /commit yet" is not an invocation
            actor.pending_interjections.push(PendingInterjection {
                text: "don't run /find-session yet".to_string(),
                attachments: vec![],
                ..Default::default()
            });
            assert!(actor.drain_pending_interjections().await);
            let conversation = actor.chat_state_handle.get_conversation().await;
            let text = conversation.last().expect("user item").text_content();
            assert!(
                !text.contains("<skill_information>"),
                "non-leading slash mentions must not grow an envelope, got: {text}"
            );
        })
        .await;
}

/// `format_interjection`'s large-prompt truncation applies to the text only.
/// Image data travels as structured parts and is never truncated or inlined.
#[tokio::test]
async fn drain_interjection_truncation_never_touches_image_data() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _gateway_rx) = build_actor().await;
            let original_image = test_image_content();
            // Way over LARGE_PROMPT_THRESHOLD so the text path truncates.
            let huge_text = "x".repeat(3_000_000);
            actor.pending_interjections.push(PendingInterjection {
                text: huge_text,
                attachments: vec![original_image.clone()],
                ..Default::default()
            });

            assert!(actor.drain_pending_interjections().await);

            let conversation = actor.chat_state_handle.get_conversation().await;
            let user_item = match conversation.last() {
                Some(ConversationItem::User(u)) => u,
                other => panic!("conversation tail must be a user item, got: {other:?}"),
            };
            let text = conversation.last().unwrap().text_content();
            assert!(text.contains("[truncated]"), "oversized text must truncate");
            let image_url = user_item
                .content
                .iter()
                .find_map(|p| match p {
                    fuigo_sampling_types::ContentPart::Image { url } => Some(url.as_ref()),
                    _ => None,
                })
                .expect("image part must survive truncation");
            assert!(
                image_url.ends_with(&original_image.data),
                "image payload must be byte-identical (never truncated)"
            );
        })
        .await;
}

/// A turn abort (send-now or cancel) can drop the drain future at an await before the batch is
/// submitted. The drained entries must go back to the buffer in arrival order so
/// `flush_stranded_interjections` can still convert them into fallback prompts; previously they
/// left the buffer and vanished.
#[tokio::test]
async fn cancelled_drain_restores_entries_for_stranded_flush() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            actor.pending_interjections.push(PendingInterjection {
                text: "first steer".to_string(),
                attachments: vec![],
                ..Default::default()
            });
            actor.pending_interjections.push(PendingInterjection {
                text: "second steer".to_string(),
                attachments: vec![],
                ..Default::default()
            });
            let conversation_len_before = actor.chat_state_handle.get_conversation().await.len();

            {
                let mut drain = std::pin::pin!(actor.drain_pending_interjections());
                // The first poll runs past the buffer drain to the chat-state round trip
                // (`current_model_id`) and pends there, before the batch submit.
                assert!(
                    futures::poll!(drain.as_mut()).is_pending(),
                    "drain must hit an await before submitting the batch"
                );
                // Dropping the pending future here simulates the turn abort.
            }

            let restored: Vec<String> = actor
                .pending_interjections
                .snapshot()
                .into_iter()
                .map(|e| e.text)
                .collect();
            assert_eq!(
                restored,
                vec!["first steer".to_string(), "second steer".to_string()],
                "aborted drain must restore its entries in arrival order"
            );
            assert_eq!(
                actor.chat_state_handle.get_conversation().await.len(),
                conversation_len_before,
                "nothing may reach the model from an aborted drain"
            );
            assert_eq!(
                actor.flush_stranded_interjections().await,
                2,
                "the cancel path can still convert the restored entries into fallback prompts"
            );
        })
        .await;
}

/// An interjection converted to a fallback prompt turn lands at the front of the queue: send-now beats queued-for-later.
/// It carries the text and image blocks and uses the persist-only `interject-fallback-` prompt-id prefix.
#[tokio::test]
async fn interjection_fallback_prompt_queues_front_with_prefix() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            {
                let mut state = actor.state.lock().await;
                state
                    .pending_inputs
                    .push_back(user_item("queued-later", "A"));
            }

            actor
                .queue_interjection_fallback_prompt(
                    "steer now".to_string(),
                    vec![test_image_content()],
                    true,
                    InterjectionAuthority::User,
                )
                .await;

            let state = actor.state.lock().await;
            assert_eq!(state.pending_inputs.len(), 2);
            let front = state.pending_inputs.front().expect("front item");
            assert!(
                front.prompt_id.starts_with("interject-fallback-"),
                "fallback prompt id must carry the persist-only prefix, got {}",
                front.prompt_id
            );
            assert!(
                matches!(
                    front.prompt_blocks.first(),
                    Some(acp::ContentBlock::Text(t)) if t.text == "steer now"
                ),
                "text block first"
            );
            assert!(
                matches!(
                    front.prompt_blocks.get(1),
                    Some(acp::ContentBlock::Image(_))
                ),
                "image blocks ride along"
            );
            assert!(front.queue_meta.is_none(), "not a shared-queue row");
            assert_eq!(
                state.pending_inputs[1].prompt_id, "queued-later",
                "previously queued prompt stays behind the send-now text"
            );
        })
        .await;
}

/// Interjections that miss the completed turn's final drain are flushed into fallback prompt turns, front of the queue in arrival order.
/// Without the flush they strand in `pending_interjections`: the pager said "Interjection sent" but the message never went out.
#[tokio::test]
async fn flush_stranded_interjections_converts_to_front_prompts_in_order() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            {
                let mut state = actor.state.lock().await;
                state
                    .pending_inputs
                    .push_back(user_item("queued-later", "A"));
            }
            actor.pending_interjections.push(PendingInterjection {
                text: "first steer".to_string(),
                attachments: vec![],
                ..Default::default()
            });
            actor.pending_interjections.push(PendingInterjection {
                text: "second steer".to_string(),
                attachments: vec![],
                ..Default::default()
            });

            assert_eq!(actor.flush_stranded_interjections().await, 2);
            assert!(
                actor.pending_interjections.is_empty(),
                "flush must drain the buffer"
            );

            let state = actor.state.lock().await;
            let texts: Vec<String> = state
                .pending_inputs
                .iter()
                .map(|i| match i.prompt_blocks.first() {
                    Some(acp::ContentBlock::Text(t)) => t.text.clone(),
                    other => panic!("expected text block, got {other:?}"),
                })
                .collect();
            assert_eq!(
                texts,
                vec![
                    "first steer".to_string(),
                    "second steer".to_string(),
                    "text for queued-later".to_string()
                ],
                "stranded interjections run next, in arrival order"
            );
        })
        .await;
}

#[tokio::test]
async fn flush_stranded_interjections_noop_when_empty() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            assert_eq!(actor.flush_stranded_interjections().await, 0);
            assert!(actor.state.lock().await.pending_inputs.is_empty());
        })
        .await;
}

/// Front placement never displaces a pinned running front: the fallback item lands right behind it when a promotion raced the check.
#[tokio::test]
async fn fallback_prompt_lands_behind_running_front() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.running_task = Some(running_task_stub("running"));
                state.pending_inputs.push_back(user_item("later", "A"));
            }
            *actor
                .current_prompt_id
                .lock()
                .expect("current_prompt_id mutex poisoned") = Some("running".into());

            actor
                .queue_interjection_fallback_prompt(
                    "urgent".to_string(),
                    vec![],
                    true,
                    InterjectionAuthority::User,
                )
                .await;

            let state = actor.state.lock().await;
            let ids: Vec<&str> = state
                .pending_inputs
                .iter()
                .map(|i| i.prompt_id.as_str())
                .collect();
            assert_eq!(ids[0], "running", "running front stays pinned");
            assert!(
                ids[1].starts_with("interject-fallback-"),
                "fallback lands right behind the running front, got {ids:?}"
            );
            assert_eq!(ids[2], "later");
        })
        .await;
}

/// A fallback prompt turn created while plan mode is active must not escape the plan gate: it carries `PromptMode::Plan`.
#[tokio::test]
async fn fallback_prompt_respects_active_plan_mode() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            {
                let mut tracker = actor.plan_mode.lock();
                tracker.enter_pending();
                tracker.activate();
            }

            actor
                .queue_interjection_fallback_prompt(
                    "plan steer".to_string(),
                    vec![],
                    true,
                    InterjectionAuthority::User,
                )
                .await;

            let state = actor.state.lock().await;
            let front = state.pending_inputs.front().expect("fallback queued");
            assert_eq!(
                front.prompt_mode,
                crate::session::plan_mode::PromptMode::Plan,
                "fallback turn must stay inside plan mode"
            );
        })
        .await;
}

/// A promoted parent-agent message must keep its `ModelAuthoredUntrusted`
/// classification.
///
/// Running it through the human interjection path frames it with
/// `INTERJECTION_NOTE` ("The user sent a message while you were working:") and
/// records it as `ConversationItem::interjection`. That tells the child its
/// parent's words came from its human user and erases a trust boundary the
/// code models deliberately: a parent agent must not be able to speak with
/// user authority.
#[tokio::test]
async fn promoted_parent_message_is_attributed_to_the_agent_not_the_user() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            let (item, _receipt) = parent_agent_message_item("m1", "stop and do X instead");
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.pending_inputs.push_back(item);
                state.running_task = Some(running_task_stub("running"));
            }

            assert!(actor.drain_interjections_at_safe_point().await);

            let conversation = actor.chat_state_handle.get_conversation().await;
            let user_item = match conversation.last() {
                Some(ConversationItem::User(u)) => u,
                other => panic!("conversation tail must be a user item, got: {other:?}"),
            };
            assert_eq!(
                user_item.synthetic_reason,
                Some(SyntheticReason::AgentMessage),
                "a parent-agent message must stay classed as an agent message, \
                 not as the user's own interjection"
            );
            let text = conversation.last().expect("user item").text_content();
            assert!(
                !text.contains(fuigo_interjection_core::INTERJECTION_NOTE),
                "the child must not be told its parent's words came from the user, got: {text}"
            );
            assert!(
                text.contains("stop and do X instead"),
                "the message body must still reach the model, got: {text}"
            );
        })
        .await;
}

/// A promoted parent-agent message's slashes must go through the narrow
/// model-authored resolver, not the human interjection one.
///
/// `interjection_skill_information` runs `parse_skill_references` over the
/// WHOLE text with the full `build_command_availability`, so a parent could
/// smuggle a skill invocation past the leading-command rule that governs every
/// other model-authored input. The model-authored resolver reads only the
/// single leading command against the child-visible catalog, so a leading
/// unknown command means no expansion at all.
#[tokio::test]
async fn promoted_parent_message_resolves_slashes_through_the_model_authored_path() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("SKILL.md");
            std::fs::write(&path, "Find sessions matching $ARGUMENTS").unwrap();
            let skill = fuigo_tools::implementations::skills::types::SkillInfo {
                name: "find-session".to_owned(),
                description: "Find past sessions".to_owned(),
                path: path.to_string_lossy().into_owned(),
                ..Default::default()
            };
            actor
                .agent
                .borrow()
                .tool_bridge()
                .clone()
                .seed_skill_discovery(
                    Some(std::path::PathBuf::from("/tmp")),
                    None,
                    vec![skill],
                    None,
                    Some(256_000),
                    None,
                    fuigo_tools::types::compat::CompatConfig::default(),
                )
                .await;

            let (item, _receipt) =
                parent_agent_message_item("m1", "/not-a-skill then /find-session foo");
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.pending_inputs.push_back(item);
                state.running_task = Some(running_task_stub("running"));
            }

            assert!(actor.drain_interjections_at_safe_point().await);

            let conversation = actor.chat_state_handle.get_conversation().await;
            let text = conversation.last().expect("user item").text_content();
            assert!(
                !text.contains("<skill_information>"),
                "only the leading command may invoke a skill for model-authored input, got: {text}"
            );
            assert!(
                !text.contains("Find sessions matching foo"),
                "the human resolver's whole-text scan must not run on parent text, got: {text}"
            );
        })
        .await;
}

/// Every route that takes a buffered entry back out of the interjection buffer
/// and re-queues it as a prompt turn goes through
/// `queue_interjection_fallback_prompt`. A parent agent's words must come back
/// out as `PromptOrigin::ParentAgentMessage` — `InputAuthority::ModelAuthoredUntrusted` —
/// never as a genuine user prompt with the human slash/workflow resolver, prompt
/// history, and the "the user re-engaged" task-wake gate behind it.
///
/// This is the turn-end strand (`run_loop`) and shutdown route, and the tail of
/// the send-now cancel route (`cancel.rs`): both call
/// `flush_stranded_interjections` directly.
#[tokio::test]
async fn stranded_parent_message_flushes_as_a_parent_prompt_not_a_user_prompt() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            actor.pending_interjections.push(PendingInterjection {
                text: "/compact and then stop".to_string(),
                attachments: vec![],
                authority: InterjectionAuthority::ParentAgent {
                    message_id: "m1".to_string(),
                    sender_session_id: "root-session".to_string(),
                },
            });

            assert_eq!(actor.flush_stranded_interjections().await, 1);

            let state = actor.state.lock().await;
            let row = state.pending_inputs.front().expect("fallback row");
            assert!(
                matches!(
                    row.input_origin.as_prompt_origin(),
                    crate::session::PromptOrigin::ParentAgentMessage {
                        message_id,
                        sender_session_id,
                    } if message_id == "m1" && sender_session_id == "root-session"
                ),
                "a stranded parent message must keep its origin, got {:?}",
                row.input_origin.as_prompt_origin()
            );
            assert!(
                !row.input_origin.policy().authority.is_human_intent(),
                "a parent agent must never speak to its child with user authority"
            );
        })
        .await;
}

/// The cancel route: a turn abort drops the drain future at one of its awaits,
/// `RestoreOnCancel` puts the entries back, and `cancel_turn_for_send_now` /
/// the turn-end arm flush them. The authority has to survive the whole round
/// trip — promotion, restore, flush — not just the promotion.
#[tokio::test]
async fn aborted_drain_of_a_parent_message_keeps_its_authority_through_the_flush() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            let (item, _receipt) = parent_agent_message_item("m1", "stop and do X instead");
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.pending_inputs.push_back(item);
                state.running_task = Some(running_task_stub("running"));
            }

            actor.promote_parent_agent_messages().await;
            {
                let mut drain = std::pin::pin!(actor.drain_pending_interjections());
                assert!(
                    futures::poll!(drain.as_mut()).is_pending(),
                    "drain must hit an await before submitting the batch"
                );
                // Dropping the pending future here simulates the turn abort.
            }

            let restored = actor.pending_interjections.snapshot();
            assert!(
                matches!(
                    restored.first().map(|e| &e.authority),
                    Some(InterjectionAuthority::ParentAgent { message_id, .. }) if message_id == "m1"
                ),
                "the restored entry must still be model-authored, got {:?}",
                restored.first().map(|e| &e.authority)
            );

            assert_eq!(actor.flush_stranded_interjections().await, 1);
            let state = actor.state.lock().await;
            let row = state
                .pending_inputs
                .iter()
                .find(|i| i.prompt_id.starts_with("interject-fallback-"))
                .expect("fallback row");
            assert!(
                matches!(
                    row.input_origin.as_prompt_origin(),
                    crate::session::PromptOrigin::ParentAgentMessage { message_id, .. }
                        if message_id == "m1"
                ),
                "an aborted drain must not launder a parent message into a user prompt, got {:?}",
                row.input_origin.as_prompt_origin()
            );
        })
        .await;
}

/// The other half of the boundary: a human interjection still strands into a
/// real user prompt. Fixing the parent case must not demote the user's own
/// message.
#[tokio::test]
async fn stranded_human_interjection_still_flushes_as_a_user_prompt() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            actor.pending_interjections.push(PendingInterjection {
                text: "actually, stop".to_string(),
                attachments: vec![],
                ..Default::default()
            });

            assert_eq!(actor.flush_stranded_interjections().await, 1);

            let state = actor.state.lock().await;
            let row = state.pending_inputs.front().expect("fallback row");
            assert_eq!(
                row.input_origin.as_prompt_origin(),
                &crate::session::PromptOrigin::User
            );
            assert!(row.input_origin.policy().authority.is_human_intent());
        })
        .await;
}

/// A queue-hidden `interject-fallback-` row carries the parent origin so its
/// own turn is classified correctly — but it is a rescue, not a fresh parent
/// message, so the next safe point must leave it alone. Promoting it would put
/// it straight back into the buffer it was just rescued from.
#[tokio::test]
async fn a_flushed_parent_fallback_row_is_not_promoted_again() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, _rx) = build_actor().await;
            actor.pending_interjections.push(PendingInterjection {
                text: "stop and do X instead".to_string(),
                attachments: vec![],
                authority: InterjectionAuthority::ParentAgent {
                    message_id: "m1".to_string(),
                    sender_session_id: "root-session".to_string(),
                },
            });
            assert_eq!(actor.flush_stranded_interjections().await, 1);
            {
                let mut state = actor.state.lock().await;
                state.pending_inputs.push_back(user_item("running", "A"));
                state.running_task = Some(running_task_stub("running"));
            }

            actor.promote_parent_agent_messages().await;

            assert!(
                actor.pending_interjections.is_empty(),
                "a rescued fallback row must not be pulled back into the buffer"
            );
            let state = actor.state.lock().await;
            assert!(
                state
                    .pending_inputs
                    .iter()
                    .any(|i| i.prompt_id.starts_with("interject-fallback-")),
                "the fallback row must stay queued to run as its own turn"
            );
        })
        .await;
}
