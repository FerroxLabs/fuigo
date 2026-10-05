//! P123 (K14, P104): while a load-time history repair still owes its `.pre-repair` backup, the history file is not
//! rewritten. A rewrite that is refused must never be lost silently: the user is told, once, in words that say the file was
//! not rewritten and why.

use std::sync::Arc;

use super::support::*;
use super::*;
use fuigo_sampler::{InferenceLatencyStats, RequestId, SamplingEvent, StripReason};
use fuigo_sampling_types::{ConversationItem, ConversationResponse};

/// Make `actor`'s session owe its backup: a directory sits where the `.pre-repair` copy belongs, so no copy can be
/// published, and the gate refuses every rewrite until the directory is cleared.
fn owe_backup(actor: &SessionActor) -> std::path::PathBuf {
    let dir = crate::session::persistence::session_dir(&actor.session_info);
    std::fs::create_dir_all(&dir).unwrap();
    let chat = dir.join(crate::session::storage::CHAT_HISTORY_FILE);
    std::fs::write(&chat, b"{}\n").unwrap();
    let blocker = dir.join("chat_history.jsonl.pre-repair");
    std::fs::create_dir(&blocker).unwrap();
    crate::session::storage::jsonl::load_repair::owe_backup_for_test(&chat);
    blocker
}

fn drain_gateway_debug(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<fuigo_acp_lib::AcpClientMessage>,
) -> String {
    let mut out = String::new();
    while let Ok(msg) = rx.try_recv() {
        out.push_str(&format!("{msg:?}\n"));
    }
    out
}

async fn settle() {
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), async {
        loop {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// A mode switch rewrites the system prompt in memory and asks for the history file to be rewritten, which is refused
/// while the backup is owed. The user is told once that the file was not rewritten and why; before, the refusal was only
/// logged.
#[tokio::test(flavor = "current_thread")]
async fn a_mode_switch_while_the_backup_is_owed_says_the_file_was_not_rewritten() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, mut gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let actor = Arc::new(create_test_actor(1_000, 200_000, 85, gateway_tx, persistence_tx).await);
            actor
                .chat_state_handle
                .replace_conversation(vec![ConversationItem::system("sys"), ConversationItem::user("hello")]);
            owe_backup(&actor);
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            actor.handle_session_mode(acp::SessionModeId::new("default")).await;
            actor.handle_session_mode(acp::SessionModeId::new("browser_use")).await;
            settle().await;
            let sent = drain_gateway_debug(&mut gateway_rx);
            assert_eq!(
                sent.matches("could not be backed up").count(),
                1,
                "one note for three switches while the backup is owed, sent: {sent}"
            );
            assert!(sent.contains("not rewritten"), "the note says the file was not rewritten, sent: {sent}");
        })
        .await;
}

/// An image strip that the history file cannot take (the write is refused while the backup is owed) already tells the
/// user the image was left out of the request. It must also say that the saved history still holds the image and why;
/// it must never claim the stored conversation changed.
#[tokio::test(flavor = "current_thread")]
async fn an_image_strip_refused_for_the_backup_says_the_saved_history_kept_the_image() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, mut gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let actor = Arc::new(create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await);
            owe_backup(&actor);
            let url = "data:image/png;base64,P123";
            let mut user = match ConversationItem::user("look at this") {
                ConversationItem::User(u) => u,
                _ => unreachable!(),
            };
            user.add_image(url);
            actor.chat_state_handle.push_user_message(ConversationItem::User(user));
            let rid = RequestId::from("req-p123");
            let (tx, _rx) = tokio::sync::oneshot::channel();
            actor.turn_stream_drained.lock().insert(rid.clone(), Some(tx));
            actor
                .handle_sampling_event(SamplingEvent::ImagesStripped {
                    request_id: rid.clone(),
                    stripped_urls: vec![Arc::<str>::from(url)],
                    reason: StripReason::ServerRejected,
                })
                .await;
            actor
                .handle_sampling_event(SamplingEvent::Completed {
                    request_id: rid.clone(),
                    response: Box::new(ConversationResponse {
                        items: vec![ConversationItem::assistant("recovered")],
                        stop_reason: None,
                        usage: None,
                        cost_usd_ticks: None,
                        message_chunks_emitted: 1,
                        doom_loop_signals: Vec::new(),
                        stop_message: None,
                        message_id: None,
                        raw_stop_reason: None,
                        stop_sequence: None,
                    }),
                    metrics: InferenceLatencyStats::default(),
                })
                .await;
            settle().await;
            let sent = drain_gateway_debug(&mut gateway_rx);
            assert!(
                !sent.contains("removed from the conversation"),
                "the saved history was not changed, so the note must not say it was, sent: {sent}"
            );
            assert!(
                sent.contains("could not be backed up") && sent.contains("still holds the image"),
                "the note says the saved history kept the image and why, sent: {sent}"
            );
        })
        .await;
}

/// A client's `systemPromptOverride` swaps the system message in memory, and the rewrite of the history file is refused
/// while the backup is owed (Astra P123 r1). It says so too.
#[tokio::test(flavor = "current_thread")]
async fn a_system_prompt_override_while_the_backup_is_owed_says_the_file_was_not_rewritten() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, mut gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) = tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let actor = Arc::new(create_test_actor(1_000, 200_000, 85, gateway_tx, persistence_tx).await);
            actor
                .chat_state_handle
                .replace_conversation(vec![ConversationItem::system("old prompt"), ConversationItem::user("hello")]);
            owe_backup(&actor);
            actor.handle_replace_system_prompt("a new system prompt".to_string()).await;
            settle().await;
            let sent = drain_gateway_debug(&mut gateway_rx);
            assert!(
                sent.contains("could not be backed up") && sent.contains("system prompt override"),
                "the override says its file rewrite was refused, sent: {sent}"
            );
        })
        .await;
}
