//! `/context-window`: how a model switch resolves, applies, persists and forgets the session's window selection.
use super::support::*;
use super::*;
use crate::session::{ContextWindowSwitch, SwitchContextWindow};
use std::num::NonZeroU64;
use std::sync::Arc;
use tokio::sync::mpsc;

fn w(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}

fn target(model: &str, default_window: u64) -> fuigo_sampler::SamplerConfig {
    fuigo_sampler::SamplerConfig {
        api_key: Some("test-key".to_string()),
        base_url: "http://127.0.0.1:1".to_string(),
        model: model.to_string(),
        context_window: default_window,
        api_backend: crate::sampling::ApiBackend::Responses,
        ..Default::default()
    }
}

fn switch(selection: SwitchContextWindow, supported: &[u64]) -> ContextWindowSwitch {
    ContextWindowSwitch {
        selection,
        supported: supported.iter().copied().map(w).collect(),
    }
}

async fn window_of(actor: &Arc<SessionActor>) -> u64 {
    actor
        .chat_state_handle
        .get_sampling_config()
        .await
        .expect("sampling config")
        .context_window
        .get()
}

fn selection_of(actor: &Arc<SessionActor>) -> Option<NonZeroU64> {
    crate::session::handle::load_context_window_selection(
        &actor.compaction.context_window_selection,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn selection_applies_to_the_sampling_config_and_is_persisted() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = mpsc::unbounded_channel();
            let (persistence_tx, mut persistence_rx) = mpsc::unbounded_channel();
            let actor =
                Arc::new(create_test_actor(1_000, 100_000, 85, gateway_tx, persistence_tx).await);

            actor
                .handle_set_session_model(
                    target("m", 100_000),
                    false,
                    false,
                    false,
                    true,
                    85,
                    switch(SwitchContextWindow::Set(Some(w(400_000))), &[100_000, 400_000]),
                )
                .await
                .expect("switch");
            assert_eq!(window_of(&actor).await, 400_000);
            assert_eq!(selection_of(&actor), Some(w(400_000)));

            let mut persisted = None;
            while let Ok(msg) = persistence_rx.try_recv() {
                if let PersistenceMsg::CurrentModel { context_window, .. } = msg {
                    persisted = Some(context_window);
                }
            }
            assert_eq!(persisted, Some(Some(Some(w(400_000)))));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_window_the_model_does_not_list_is_refused_and_forgotten() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = mpsc::unbounded_channel();
            let actor =
                Arc::new(create_test_actor(1_000, 100_000, 85, gateway_tx, persistence_tx).await);

            actor
                .handle_set_session_model(
                    target("m", 100_000),
                    false,
                    false,
                    false,
                    true,
                    85,
                    switch(SwitchContextWindow::Set(Some(w(400_000))), &[100_000, 400_000]),
                )
                .await
                .expect("switch");
            assert_eq!(selection_of(&actor), Some(w(400_000)));

            // An explicit selection the new model does not list is dropped; the model default applies
            actor
                .handle_set_session_model(
                    target("m", 100_000),
                    false,
                    false,
                    false,
                    true,
                    85,
                    switch(SwitchContextWindow::Set(Some(w(900_000))), &[100_000, 400_000]),
                )
                .await
                .expect("switch");
            assert_eq!(selection_of(&actor), None);
            assert_eq!(window_of(&actor).await, 100_000);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_plain_switch_carries_the_selection_only_while_the_new_model_lists_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = mpsc::unbounded_channel();
            let (persistence_tx, _persistence_rx) = mpsc::unbounded_channel();
            let actor =
                Arc::new(create_test_actor(1_000, 100_000, 85, gateway_tx, persistence_tx).await);

            actor
                .handle_set_session_model(
                    target("a", 100_000),
                    false,
                    false,
                    false,
                    true,
                    85,
                    switch(SwitchContextWindow::Set(Some(w(400_000))), &[100_000, 400_000]),
                )
                .await
                .expect("switch");

            // Another model that lists 400k too: carried
            actor
                .handle_set_session_model(
                    target("b", 200_000),
                    false,
                    false,
                    false,
                    true,
                    85,
                    switch(SwitchContextWindow::Preserve, &[200_000, 400_000]),
                )
                .await
                .expect("switch");
            assert_eq!(window_of(&actor).await, 400_000);

            // A model that does not list it: its own default, the selection stays remembered for models that do
            actor
                .handle_set_session_model(
                    target("c", 128_000),
                    false,
                    false,
                    false,
                    true,
                    85,
                    switch(SwitchContextWindow::Preserve, &[128_000]),
                )
                .await
                .expect("switch");
            assert_eq!(window_of(&actor).await, 128_000);
        })
        .await;
}

/// The window drives the compaction threshold: the percentage applies to the selected window, not the default.
#[tokio::test(flavor = "current_thread")]
async fn selected_window_is_the_compaction_basis_and_survives_server_overflow_rules() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gateway_tx, _gateway_rx) = mpsc::unbounded_channel();
            let (persistence_tx, mut persistence_rx) = mpsc::unbounded_channel();
            let actor =
                Arc::new(create_test_actor(1_000, 100_000, 85, gateway_tx, persistence_tx).await);
            actor
                .handle_set_session_model(
                    target("m", 100_000),
                    false,
                    false,
                    false,
                    true,
                    80,
                    switch(SwitchContextWindow::Set(Some(w(400_000))), &[100_000, 400_000]),
                )
                .await
                .expect("switch");
            let cfg = actor.chat_state_handle.get_sampling_config().await.unwrap();
            assert_eq!(cfg.context_window.get() * u64::from(actor.compaction.threshold_percent.get()) / 100, 320_000);

            // The window the server reports is ignored while the selection is in use
            assert!(actor.is_context_window_fixed(cfg.context_window));
            // A server window at or above the selection keeps it
            assert_eq!(actor.context_window_after_overflow(&cfg, w(500_000)), w(400_000));
            // A server window below the selection wins and the selection is cleared and persisted as cleared
            assert_eq!(actor.context_window_after_overflow(&cfg, w(200_000)), w(200_000));
            assert_eq!(selection_of(&actor), None);
            let mut cleared = false;
            while let Ok(msg) = persistence_rx.try_recv() {
                if let PersistenceMsg::CurrentModel { context_window: Some(None), .. } = msg {
                    cleared = true;
                }
            }
            assert!(cleared);
        })
        .await;
}
