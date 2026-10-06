//! P135 (K17, HIGH-1): an invalid prompt echoes before it is parsed and then returns an error. The snapshot lock taken for
//! its echo must not outlive that turn, or every fork of the session waits 10 s and fails until the next prompt.

use super::support::*;
use super::*;
use crate::session::persistence::test_seam;
use crate::session::storage::StorageAdapter as _;

#[tokio::test(flavor = "current_thread")]
async fn a_fork_succeeds_promptly_after_an_invalid_prompt() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let info = crate::session::info::Info { id: acp::SessionId::new("p135-invalid-prompt"), cwd: "/work".to_string() };
            let dir = crate::session::persistence::session_dir(&info);
            let storage = crate::session::storage::JsonlStorageAdapter::with_explicit_session_dir(dir.clone());
            storage.init_session(&info, crate::session::persistence::default_model_id()).await.unwrap();
            let persistence_tx = test_seam::spawn_actor(info.clone(), std::sync::Arc::new(storage));
            let (gateway_tx, mut gateway_rx) = tokio::sync::mpsc::unbounded_channel::<fuigo_acp_lib::AcpClientMessage>();
            tokio::task::spawn_local(async move { while gateway_rx.recv().await.is_some() {} });
            let actor = std::sync::Arc::new(
                create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx.clone()).await,
            );
            // A prompt block the parser refuses, after the echo has been sent.
            let invalid = vec![acp::ContentBlock::Audio(acp::AudioContent::new("AAAA", "audio/wav"))];
            let result = Box::pin(actor.handle_prompt(
                "p-invalid",
                invalid,
                PromptMode::Agent,
                None,
                None,
                None,
                None,
                false,
                false,
                None,
                None,
                None,
            ))
            .await;
            assert!(result.is_err(), "the prompt was meant to be invalid");
            // Everything the turn sent has been handled when this barrier answers.
            let (ack, flushed) = tokio::sync::oneshot::channel();
            persistence_tx.send(crate::session::persistence::PersistenceMsg::FlushAndAck { respond_to: ack }).unwrap();
            let _ = flushed.await;
            let lock_file = crate::session::storage::snapshot_lock::lock_path(&dir);
            let started = std::time::Instant::now();
            let fork = tokio::task::spawn_blocking(move || {
                crate::session::storage::snapshot_lock::acquire_blocking(&lock_file, &lock_file).map(drop)
            })
            .await
            .unwrap();
            assert!(fork.is_ok(), "the fork was refused after an invalid prompt: {fork:?}");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(3),
                "the fork waited {:?} for a turn that had already failed",
                started.elapsed()
            );
        })
        .await;
}
