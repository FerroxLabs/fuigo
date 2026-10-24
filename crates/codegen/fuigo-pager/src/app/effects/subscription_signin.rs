//! Subscription sign-in from inside the TUI.
//!
//! The browser flow is the existing exact-recipient one (`fuigo_shell::auth::subscription`); this
//! module only carries the URL to the screen, a pasted xAI code to the flow, and the result to the
//! agent. Dropping the task (Esc) drops the attempt, which frees the callback port.
//!
//! There is a single sign-in at a time; `seq` ties every call to the attempt that made it, so a
//! late call from an abandoned attempt cannot reach the current one.

use super::helpers::send_authenticate;
use fuigo_acp_lib::{AcpAgentTx, acp_send};
use crate::app::actions::TaskResult;
use agent_client_protocol as acp;
use fuigo_shell::auth::subscription::{self, SubscriptionError, SubscriptionProvider};
use std::sync::Mutex;

struct Shared {
    seq: u64,
    provider: SubscriptionProvider,
    url: Option<String>,
    code_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

static SHARED: Mutex<Option<Shared>> = Mutex::new(None);

fn shared() -> std::sync::MutexGuard<'static, Option<Shared>> {
    SHARED.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The URL the attempt published, if it is the attempt `seq`.
pub(super) fn published_url(seq: u64) -> Option<String> {
    shared()
        .as_ref()
        .filter(|s| s.seq == seq)
        .and_then(|s| s.url.clone())
}

/// How the screen presents the attempt: xAI may show a code to paste; ChatGPT only redirects.
pub(super) fn url_mode(seq: u64) -> &'static str {
    match shared().as_ref().filter(|s| s.seq == seq).map(|s| s.provider) {
        Some(SubscriptionProvider::Chatgpt) => "command",
        _ => "loopback",
    }
}

/// Hand a pasted code to attempt `seq`. Anything for another attempt is dropped.
pub(super) fn send_code(seq: u64, code: String) {
    if let Some(s) = shared().as_ref().filter(|s| s.seq == seq)
        && let Some(tx) = &s.code_tx
    {
        let _ = tx.send(code);
    }
}

/// What the user is told when a sign-in ends without credentials. The text of a
/// [`SubscriptionError`] is fixed and carries no token, URL or response body.
pub(super) fn failure_text(provider: SubscriptionProvider, error: &SubscriptionError) -> String {
    match error {
        SubscriptionError::Cancelled | SubscriptionError::Timeout => {
            format!("{} sign-in did not finish. Choose it again to retry.", provider.label())
        }
        SubscriptionError::Listener => format!(
            "{} sign-in could not listen for the browser callback (is another Fuigo signing in?).",
            provider.label()
        ),
        other => format!("{} sign-in failed: {other}", provider.label()),
    }
}

pub(super) async fn run(tx: &AcpAgentTx, seq: u64, provider: SubscriptionProvider) -> TaskResult {
    let (code_tx, code_rx) = tokio::sync::mpsc::unbounded_channel();
    *shared() = Some(Shared {
        seq,
        provider,
        url: None,
        code_tx: Some(code_tx),
    });
    let result = subscription::sign_in_for_tui(
        provider,
        |url| {
            if let Some(s) = shared().as_mut().filter(|s| s.seq == seq) {
                s.url = Some(url);
            }
        },
        code_rx,
    )
    .await;
    {
        let mut guard = shared();
        if guard.as_ref().is_some_and(|s| s.seq == seq) {
            *guard = None;
        }
    }
    if let Err(error) = result {
        return TaskResult::AuthFailed {
            request_seq: seq,
            error: failure_text(provider, &error),
        };
    }
    // The agent built its model list before this sign-in existed: rebuild it from disk so the
    // subscription's models are there, then let the agent adopt the credential.
    let reload = acp::ExtRequest::new(
        "fuigo/internal/reload_models",
        serde_json::value::to_raw_value(&serde_json::json!({}))
            .expect("serialize reload params")
            .into(),
    );
    if let Err(e) = acp_send(reload, tx).await {
        tracing::warn!(error = ?e, "model reload after subscription sign-in failed");
    }
    send_authenticate(
        tx,
        seq,
        acp::AuthMethodId::new(fuigo_shell::agent::auth_method::FUIGO_API_KEY_METHOD_ID),
        false,
        false,
    )
    .await
}

/// Remove the provider's stored accounts (local only; nothing is revoked), then have the agent rebuild
/// its model list so the provider's models leave `/model`.
pub(super) async fn sign_out(tx: &AcpAgentTx, provider: SubscriptionProvider) -> TaskResult {
    let error = match subscription::default_store() {
        Ok(store) => store.logout(provider, None).await.err().map(|e| e.to_string()),
        Err(e) => Some(e.to_string()),
    };
    if error.is_none() {
        let reload = acp::ExtRequest::new(
            "fuigo/internal/reload_models",
            serde_json::value::to_raw_value(&serde_json::json!({}))
                .expect("serialize reload params")
                .into(),
        );
        if let Err(e) = acp_send(reload, tx).await {
            tracing::warn!(error = ?e, "model reload after subscription sign-out failed");
        }
    }
    TaskResult::SubscriptionSignedOut { provider, error }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial(subscription_signin_shared)]
    fn a_late_call_from_an_abandoned_attempt_is_ignored() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        *shared() = Some(Shared {
            seq: 7,
            provider: SubscriptionProvider::Xai,
            url: Some("https://auth.example/authorize".into()),
            code_tx: Some(tx),
        });
        assert_eq!(published_url(7).as_deref(), Some("https://auth.example/authorize"));
        assert_eq!(published_url(6), None);
        send_code(6, "stale".into());
        assert!(rx.try_recv().is_err(), "a code for another attempt must not arrive");
        send_code(7, "fresh".into());
        assert_eq!(rx.try_recv().unwrap(), "fresh");
        assert_eq!(url_mode(7), "loopback");
        *shared() = None;
    }

    #[test]
    #[serial_test::serial(subscription_signin_shared)]
    fn chatgpt_presents_as_a_browser_status_not_a_paste_box() {
        *shared() = Some(Shared {
            seq: 9,
            provider: SubscriptionProvider::Chatgpt,
            url: None,
            code_tx: None,
        });
        assert_eq!(url_mode(9), "command");
        *shared() = None;
    }

    #[test]
    fn failure_text_names_the_provider_and_never_a_secret() {
        for error in [
            SubscriptionError::Cancelled,
            SubscriptionError::Listener,
            SubscriptionError::Http(401),
            SubscriptionError::InvalidCredentials,
        ] {
            let text = failure_text(SubscriptionProvider::Xai, &error);
            assert!(text.contains("Grok subscription"), "{text}");
            assert!(!text.to_lowercase().contains("grok build"));
        }
    }
}
