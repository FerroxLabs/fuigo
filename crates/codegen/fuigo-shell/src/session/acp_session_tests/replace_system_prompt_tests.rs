//! Actor-path coverage for `handle_replace_system_prompt`, the resident-reconnect `systemPromptOverride` sync.
//! The head swap itself is unit-tested in `fuigo_chat_state` (`conversation_util` and the actor tests).
//! These tests cover only what is unique to the `SessionActor` path: the end-to-end swap and the `preserve_inherited_system` skip.

use fuigo_sampling_types::conversation::ConversationItem;

use super::support::create_test_actor;
use super::{PersistenceMsg, SessionActor};

fn head_text(conv: &[ConversationItem]) -> Option<String> {
    match conv.first() {
        Some(ConversationItem::System(sys)) => Some(sys.content.to_string()),
        _ => None,
    }
}

async fn actor_with_history(history: Vec<ConversationItem>) -> SessionActor {
    let (gateway_tx, _grx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _prx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.chat_state_handle.replace_conversation(history);
    actor
}

#[tokio::test(flavor = "current_thread")]
async fn handle_replace_system_prompt_replaces_head_and_preserves_turns() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_history(vec![
                ConversationItem::system("composer default"),
                ConversationItem::user("hi"),
                ConversationItem::assistant("yo"),
            ])
            .await;

            actor
                .handle_replace_system_prompt("client override".to_string())
                .await;

            let conv = actor.chat_state_handle.get_conversation().await;
            assert_eq!(head_text(&conv).as_deref(), Some("client override"));
            assert_eq!(conv.len(), 3, "must not wipe user/assistant turns");
            assert!(matches!(conv[1], ConversationItem::User(_)));
            assert!(matches!(conv[2], ConversationItem::Assistant(_)));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn handle_replace_system_prompt_skips_on_preserve_inherited_system() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut actor = actor_with_history(vec![
                ConversationItem::system("parent verbatim"),
                ConversationItem::user("hi"),
            ])
            .await;
            // Verbatim mirror-fork: the inherited cache prefix must survive.
            actor.startup_hints.preserve_inherited_system = true;

            actor
                .handle_replace_system_prompt("client override".to_string())
                .await;

            let conv = actor.chat_state_handle.get_conversation().await;
            assert_eq!(
                head_text(&conv).as_deref(),
                Some("parent verbatim"),
                "preserve_inherited_system must not overwrite the inherited head"
            );
        })
        .await;
}

// ---- #19: a model switch keeps `_meta.rules` (the `<human_rules>` block) and any `systemPromptOverride` ----

const CANARY: &str = "When asked for the canary, reply CANARY-42";

fn switch_cfg() -> fuigo_sampler::SamplerConfig {
    fuigo_sampler::SamplerConfig {
        api_key: Some("test-key".to_string()),
        base_url: "http://127.0.0.1:1".to_string(),
        model: "switch-target".to_string(),
        context_window: 256_000,
        api_backend: crate::sampling::ApiBackend::Responses,
        ..Default::default()
    }
}

async fn switch_model(actor: &std::sync::Arc<SessionActor>, use_concise: bool) {
    actor
        .handle_set_session_model(
            switch_cfg(),
            use_concise,
            false,
            true,
            false,
            85,
            Default::default(),
        )
        .await
        .expect("switch");
}

async fn actor_with_rules(use_rules: bool) -> std::sync::Arc<SessionActor> {
    let (gateway_tx, _grx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _prx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let actor =
        std::sync::Arc::new(create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await);
    let mut prompt = actor.agent.borrow().system_prompt().to_owned();
    if use_rules {
        crate::session::human_rules::append_human_rules(&mut prompt, CANARY);
    }
    actor.chat_state_handle.replace_conversation(vec![
        ConversationItem::system(prompt),
        ConversationItem::user("canary?"),
        ConversationItem::assistant("CANARY-42"),
    ]);
    actor
}

fn assert_rules_kept(conv: &[ConversationItem]) {
    let head = head_text(conv).expect("system head");
    assert!(
        head.contains("<human_rules>"),
        "human_rules block dropped: {head}"
    );
    assert!(head.contains(CANARY), "canary dropped from the system item");
    assert_eq!(conv.len(), 3, "turns must survive");
}

#[tokio::test(flavor = "current_thread")]
async fn set_model_keeps_human_rules_in_system_item() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(true).await;
            switch_model(&actor, false).await;
            assert_rules_kept(&actor.chat_state_handle.get_conversation().await);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn set_model_concise_variant_keeps_human_rules() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(true).await;
            switch_model(&actor, true).await;
            let conv = actor.chat_state_handle.get_conversation().await;
            assert_rules_kept(&conv);
            assert!(
                head_text(&conv)
                    .unwrap()
                    .starts_with(fuigo_agent::prompt::template::COMPACT_SYSTEM_PROMPT),
                "the concise template must still be applied"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn human_rules_survive_a_reload_then_a_switch() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(true).await;
            switch_model(&actor, false).await;
            // The persisted conversation is what a reload restores: a fresh actor seeded with it.
            let persisted = actor.chat_state_handle.get_conversation().await;
            let reloaded = actor_with_rules(false).await;
            reloaded.chat_state_handle.replace_conversation(persisted);
            switch_model(&reloaded, true).await;
            assert_rules_kept(&reloaded.chat_state_handle.get_conversation().await);
            switch_model(&reloaded, false).await;
            assert_rules_kept(&reloaded.chat_state_handle.get_conversation().await);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_rules_means_no_human_rules_block_after_switch() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(false).await;
            switch_model(&actor, false).await;
            let head = head_text(&actor.chat_state_handle.get_conversation().await).unwrap();
            assert!(!head.contains("<human_rules>"));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn set_model_keeps_system_prompt_override() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(false).await;
            actor
                .handle_replace_system_prompt("CLIENT OVERRIDE ONLY".to_string())
                .await;
            switch_model(&actor, false).await;
            let conv = actor.chat_state_handle.get_conversation().await;
            assert_eq!(head_text(&conv).as_deref(), Some("CLIENT OVERRIDE ONLY"));
            switch_model(&actor, true).await;
            let conv = actor.chat_state_handle.get_conversation().await;
            assert_eq!(head_text(&conv).as_deref(), Some("CLIENT OVERRIDE ONLY"));
        })
        .await;
}

/// #19 (cold reload): the override a session was created with survives a restart that does not resend it.
#[tokio::test(flavor = "current_thread")]
async fn set_model_keeps_a_persisted_system_prompt_override_after_a_cold_reload() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let id = format!("override-reload-{}", std::process::id());
            let mut first = create_test_actor_plain().await;
            first.session_info.id = agent_client_protocol::SessionId::new(id.clone());
            first
                .handle_replace_system_prompt("CLIENT OVERRIDE ONLY".to_string())
                .await;
            let info = first.session_info.clone();
            drop(first);

            // A restarted process: a fresh actor over the same session dir, no override resent.
            let mut reloaded = create_test_actor_plain().await;
            reloaded.session_info = info.clone();
            reloaded
                .system_prompt_override
                .replace(crate::session::initial_system_prompt_override(&info));
            let reloaded = std::sync::Arc::new(reloaded);
            reloaded.chat_state_handle.replace_conversation(vec![
                ConversationItem::system("CLIENT OVERRIDE ONLY"),
                ConversationItem::user("hi"),
            ]);
            switch_model(&reloaded, false).await;
            let conv = reloaded.chat_state_handle.get_conversation().await;
            assert_eq!(head_text(&conv).as_deref(), Some("CLIENT OVERRIDE ONLY"));
            switch_model(&reloaded, true).await;
            let conv = reloaded.chat_state_handle.get_conversation().await;
            assert_eq!(head_text(&conv).as_deref(), Some("CLIENT OVERRIDE ONLY"));
            let _ = std::fs::remove_dir_all(crate::session::persistence::session_dir(&info));
        })
        .await;
}

async fn create_test_actor_plain() -> SessionActor {
    let (gateway_tx, _grx) =
        tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
    let (persistence_tx, _prx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await
}

// ---- u36: a model switch keeps the trailing memory-context block ----

fn memory_block() -> String {
    format!(
        "{}\nremembered fact\n{}",
        fuigo_chat_state::memory_context_open_tag(crate::session::helpers::memory_context::memory_context_nonce()),
        fuigo_chat_state::memory_context_close_tag(crate::session::helpers::memory_context::memory_context_nonce())
    )
}

#[tokio::test(flavor = "current_thread")]
async fn set_model_keeps_the_memory_block() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for use_concise in [false, true] {
                let actor = actor_with_rules(true).await;
                let mut conv = actor.chat_state_handle.get_conversation().await;
                let head = head_text(&conv).unwrap();
                conv[0] = ConversationItem::system(format!("{head}\n\n{}", memory_block()));
                actor.chat_state_handle.replace_conversation(conv);
                switch_model(&actor, use_concise).await;
                let switched = head_text(&actor.chat_state_handle.get_conversation().await).unwrap();
                // A never-switched control composed for the new model, with the same turn's memory block
                let template = if use_concise {
                    fuigo_agent::prompt::template::COMPACT_SYSTEM_PROMPT.to_owned()
                } else {
                    actor.agent.borrow().system_prompt().to_owned()
                };
                let mut control = template;
                crate::session::human_rules::append_human_rules(&mut control, CANARY);
                let control = format!("{}\n\n{}", control.trim_end_matches('\n'), memory_block());
                assert_eq!(switched, control, "concise={use_concise}");
                assert_eq!(switched.matches(crate::session::helpers::memory_context::memory_context_nonce()).count(), 2);
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn set_model_without_a_memory_block_is_unchanged() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(true).await;
            switch_model(&actor, false).await;
            let switched = head_text(&actor.chat_state_handle.get_conversation().await).unwrap();
            let mut control = actor.agent.borrow().system_prompt().to_owned();
            crate::session::human_rules::append_human_rules(&mut control, CANARY);
            assert_eq!(switched, control);
        })
        .await;
}

fn installation_block(body: &str) -> String {
    let nonce = crate::session::helpers::memory_context::memory_context_nonce();
    format!(
        "{}\n{body}\n{}",
        fuigo_chat_state::memory_context_open_tag(nonce),
        fuigo_chat_state::memory_context_close_tag(nonce)
    )
}

/// A client override ending in a complete block with a foreign nonce is override text, not memory: set_mode and a model
/// switch leave it exactly once, and only the installation block the turn appended is carried.
#[tokio::test(flavor = "current_thread")]
async fn an_override_ending_in_a_foreign_nonce_block_is_not_duplicated() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            for use_concise in [false, true] {
                let actor = actor_with_rules(false).await;
                let foreign = format!(
                    "{}\nforeign\n{}",
                    fuigo_chat_state::memory_context_open_tag("x"),
                    fuigo_chat_state::memory_context_close_tag("x")
                );
                let override_prompt = format!("client override\n\n{foreign}");
                *actor.system_prompt_override.borrow_mut() = Some(override_prompt.clone());
                let mut conv = actor.chat_state_handle.get_conversation().await;
                let stored = format!("{override_prompt}\n\n{}", installation_block("fact"));
                conv[0] = ConversationItem::system(stored.clone());
                actor.chat_state_handle.replace_conversation(conv);
                actor
                    .handle_session_mode(agent_client_protocol::SessionModeId::new("default"))
                    .await;
                switch_model(&actor, use_concise).await;
                let head = head_text(&actor.chat_state_handle.get_conversation().await).unwrap();
                assert_eq!(head, stored, "concise={use_concise}");
                assert_eq!(head.matches("foreign").count(), 1);
            }
        })
        .await;
}

/// A zero-turn harness rebuild keeps rules and the installation memory block, equal to a never-switched control head
/// composed on the new template.
#[tokio::test(flavor = "current_thread")]
async fn harness_rebuild_keeps_rules_and_memory_like_the_control() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let actor = actor_with_rules(true).await;
            let block = installation_block("fact");
            let mut conv = actor.chat_state_handle.get_conversation().await;
            let head = head_text(&conv).unwrap();
            conv[0] = ConversationItem::system(format!("{head}\n\n{block}"));
            actor.chat_state_handle.replace_conversation(conv);
            actor
                .handle_rebuild_agent_for_definition(fuigo_agent::AgentDefinition::default_fuigo_build())
                .await
                .expect("rebuild");
            let rebuilt = head_text(&actor.chat_state_handle.get_conversation().await).unwrap();
            let mut control = actor.agent.borrow().system_prompt().to_owned();
            crate::session::human_rules::append_human_rules(&mut control, CANARY);
            let control = format!("{}\n\n{block}", control.trim_end_matches('\n'));
            assert_eq!(rebuilt, control);
            assert_eq!(rebuilt.matches("<memory-context").count(), 1);
        })
        .await;
}
