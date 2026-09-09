//! Constant-space, local-only per-attempt receipts. Uses the existing sampling
//! log sink; no extra inference, prompt text, credentials, or background queue.
use fuigo_sampling_types::{ConversationRequest, RequestPurpose, TokenUsage};
use serde::Serialize;
use std::sync::{Arc, Mutex};

tokio::task_local! {
    static CURRENT: Arc<Mutex<Receipt>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Completed,
    Failed,
    Cancelled,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Receipt {
    #[serde(skip)]
    execution_admission: Option<Arc<dyn fuigo_sampling_types::ExecutionAdmission>>,
    logical_call_id: String,
    attempt_id: String,
    attempt: u32,
    purpose: RequestPurpose,
    session_id: Option<String>,
    turn: Option<u64>,
    dispatched: bool,
    outcome: Option<Outcome>,
    usage: Option<TokenUsage>,
    usage_complete: bool,
    cost_usd_ticks: Option<i64>,
    #[serde(skip)]
    settled: bool,
}

/// Unknown/non-UUID identifiers are omitted rather than logging arbitrary input.
fn safe_id(id: Option<&str>) -> Option<String> {
    id.and_then(|id| uuid::Uuid::parse_str(id).ok())
        .map(|id| id.to_string())
}

pub(crate) struct Attempt {
    state: Arc<Mutex<Receipt>>,
}

impl Attempt {
    pub(crate) fn new(request: &ConversationRequest, logical_id: &str, attempt: u32) -> Self {
        Self {
            state: Arc::new(Mutex::new(Receipt {
                execution_admission: request.execution_admission.clone(),
                logical_call_id: safe_id(Some(logical_id))
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                attempt_id: uuid::Uuid::new_v4().to_string(),
                attempt,
                purpose: request.purpose,
                session_id: safe_id(request.x_fuigo_session_id.as_deref()),
                turn: request
                    .x_fuigo_turn_idx
                    .as_deref()
                    .and_then(|s| s.parse().ok()),
                dispatched: false,
                outcome: None,
                usage: None,
                usage_complete: false,
                cost_usd_ticks: None,
                settled: false,
            })),
        }
    }

    pub(crate) async fn scope<F: std::future::Future>(&self, future: F) -> F::Output {
        CURRENT.scope(Arc::clone(&self.state), future).await
    }

    /// Settle only a definitive provider completion. A failure to persist keeps
    /// the debit conservative and is surfaced separately from provider usage.
    pub(crate) async fn settle_execution(&self) -> Result<(), String> {
        let (admission, id, dispatched, usage) = {
            let receipt = self.state.lock().unwrap_or_else(|e| e.into_inner());
            (
                receipt.execution_admission.clone(),
                receipt.attempt_id.clone(),
                receipt.dispatched,
                receipt.usage.clone(),
            )
        };
        if dispatched && let Some(admission) = admission {
            admission.settle(id, usage).await?;
        }
        Ok(())
    }

    pub(crate) fn finish(&self, outcome: Outcome, usage: Option<TokenUsage>, cost: Option<i64>) {
        let mut receipt = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if receipt.settled {
            return;
        }
        receipt.settled = true;
        receipt.outcome = Some(if !receipt.dispatched && outcome == Outcome::Failed {
            Outcome::Denied
        } else {
            outcome
        });
        receipt.usage_complete = outcome == Outcome::Completed && usage.is_some();
        receipt.usage = usage;
        receipt.cost_usd_ticks = cost;
        if tracing::enabled!(target: crate::sampling_log::TARGET, tracing::Level::INFO) {
            match serde_json::to_string(&*receipt) {
                Ok(json) => tracing::info!(target: crate::sampling_log::TARGET,
                    event = "request_attempt_receipt", receipt = %json),
                Err(_) => tracing::warn!(target: crate::sampling_log::TARGET,
                    event = "request_attempt_receipt_unavailable"),
            }
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled, None, None);
    }
}

/// Called only after admission succeeds, immediately before the transport dispatch.
/// This counts transport attempts, not proof of provider receipt or invoice liability.
pub(crate) fn dispatched() {
    let _ = CURRENT.try_with(|state| {
        state.lock().unwrap_or_else(|e| e.into_inner()).dispatched = true;
    });
}

pub(crate) fn is_scoped() -> bool {
    CURRENT.try_with(|_| ()).is_ok()
}

pub(crate) fn current_policy() -> (RequestPurpose, Option<String>) {
    CURRENT
        .try_with(|state| {
            let receipt = state.lock().unwrap_or_else(|e| e.into_inner());
            (
                receipt.purpose,
                receipt
                    .execution_admission
                    .as_ref()
                    .map(|a| a.scope_id().to_owned()),
            )
        })
        .unwrap_or((RequestPurpose::Unknown, None))
}

pub(crate) async fn admit_current() -> Result<(), String> {
    let admission = CURRENT
        .try_with(|state| {
            let receipt = state.lock().unwrap_or_else(|e| e.into_inner());
            receipt
                .execution_admission
                .clone()
                .map(|admission| (admission, receipt.purpose, receipt.attempt_id.clone()))
        })
        .ok()
        .flatten();
    if let Some((admission, purpose, id)) = admission {
        admission.admit(purpose, id).await?;
    }
    Ok(())
}

pub(crate) fn remaining_time() -> fuigo_sampling_types::Result<Option<std::time::Duration>> {
    let scoped = CURRENT
        .try_with(|state| {
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .execution_admission
                .clone()
        })
        .ok()
        .flatten()
        .and_then(|scope| scope.remaining_time());
    let process = crate::execution_budget::process_budget()
        .map_err(fuigo_sampling_types::SamplingError::InvalidConfiguration)?
        .and_then(|budget| budget.remaining());
    Ok(match (scoped, process) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    })
}

/// Clamp immediately before transport, including after subscription refresh.
pub(crate) fn clamp_deadline(request: &mut reqwest::Request) -> fuigo_sampling_types::Result<()> {
    if let Some(remaining) = remaining_time()? {
        if remaining.is_zero() {
            return Err(fuigo_sampling_types::SamplingError::InvalidConfiguration(
                "execution deadline exhausted before transport",
            ));
        }
        let timeout = request
            .timeout()
            .copied()
            .map_or(remaining, |existing| existing.min(remaining));
        *request.timeout_mut() = Some(timeout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedRemaining(std::time::Duration);
    impl fuigo_sampling_types::ExecutionAdmission for FixedRemaining {
        fn scope_id(&self) -> &str {
            "deadline-test"
        }
        fn remaining_time(&self) -> Option<std::time::Duration> {
            Some(self.0)
        }
        fn admit(&self, _: RequestPurpose, _: String) -> fuigo_sampling_types::AdmissionFuture<'_> {
            Box::pin(async { Ok(()) })
        }
        fn settle(
            &self,
            _: String,
            _: Option<TokenUsage>,
        ) -> fuigo_sampling_types::AdmissionFuture<'_> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn durable_deadline_clamps_transport_without_renewing_existing_timeout() {
        use std::time::Duration;
        for (remaining, timeout, expected) in [
            (
                Duration::from_secs(2),
                Duration::from_secs(30),
                Duration::from_secs(2),
            ),
            (
                Duration::from_secs(30),
                Duration::from_secs(2),
                Duration::from_secs(2),
            ),
        ] {
            let mut input = ConversationRequest::new();
            input.execution_admission = Some(Arc::new(FixedRemaining(remaining)));
            let attempt = Attempt::new(&input, &uuid::Uuid::new_v4().to_string(), 1);
            attempt
                .scope(async {
                    let mut request = reqwest::Request::new(
                        reqwest::Method::POST,
                        "https://example.test".parse().unwrap(),
                    );
                    *request.timeout_mut() = Some(timeout);
                    clamp_deadline(&mut request).unwrap();
                    assert_eq!(request.timeout().copied(), Some(expected));
                })
                .await;
        }
        let mut input = ConversationRequest::new();
        input.execution_admission = Some(Arc::new(FixedRemaining(Duration::ZERO)));
        Attempt::new(&input, &uuid::Uuid::new_v4().to_string(), 1)
            .scope(async {
                let mut request = reqwest::Request::new(
                    reqwest::Method::POST,
                    "https://example.test".parse().unwrap(),
                );
                assert!(clamp_deadline(&mut request).is_err());
            })
            .await;
    }

    #[derive(Debug)]
    struct RejectAdmission;

    impl fuigo_sampling_types::ExecutionAdmission for RejectAdmission {
        fn scope_id(&self) -> &str {
            "test-scope"
        }
        fn admit(&self, _: RequestPurpose, _: String) -> fuigo_sampling_types::AdmissionFuture<'_> {
            Box::pin(async { Err("not durable".into()) })
        }
        fn settle(
            &self,
            _: String,
            _: Option<TokenUsage>,
        ) -> fuigo_sampling_types::AdmissionFuture<'_> {
            Box::pin(async { panic!("denied request must not settle") })
        }
    }

    #[tokio::test]
    async fn rejected_durable_admission_never_reaches_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = crate::SamplingClient::new(crate::SamplerConfig {
            base_url: format!("http://{}", listener.local_addr().unwrap()),
            model: "local-test".into(),
            ..Default::default()
        })
        .unwrap();
        let mut request =
            ConversationRequest::from_items(vec![fuigo_sampling_types::ConversationItem::user(
                "test",
            )]);
        request.execution_admission = Some(Arc::new(RejectAdmission));
        assert!(matches!(
            client.conversation_collect(request).await,
            Err(fuigo_sampling_types::SamplingError::InvalidConfiguration(_))
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn purposes_outcomes_and_denied_admissions_are_separate() {
        let id = uuid::Uuid::new_v4().to_string();
        let title = Attempt::new(
            &ConversationRequest::new().with_purpose(RequestPurpose::Title),
            &id,
            1,
        );
        title
            .scope(async {
                dispatched();
            })
            .await;
        title.finish(Outcome::Failed, None, None);
        title.finish(Outcome::Completed, Some(TokenUsage::default()), Some(1));
        let r = title.state.lock().unwrap().clone();
        assert!(r.dispatched);
        assert_eq!(r.purpose, RequestPurpose::Title);
        assert_eq!(r.outcome, Some(Outcome::Failed));
        assert!(!r.usage_complete);
        let denied = Attempt::new(&ConversationRequest::new(), &id, 2);
        denied.finish(Outcome::Failed, None, None);
        let r = denied.state.lock().unwrap();
        assert!(!r.dispatched);
        assert_eq!(r.outcome, Some(Outcome::Denied));
    }

    #[tokio::test]
    async fn retry_identity_and_cancelled_liability_are_retained() {
        let id = uuid::Uuid::new_v4().to_string();
        let request = ConversationRequest::new().with_purpose(RequestPurpose::Work);
        let first = Attempt::new(&request, &id, 1);
        let second = Attempt::new(&request, &id, 2);
        assert_eq!(
            first.state.lock().unwrap().logical_call_id,
            second.state.lock().unwrap().logical_call_id
        );
        assert_ne!(
            first.state.lock().unwrap().attempt_id,
            second.state.lock().unwrap().attempt_id
        );
        let state = Arc::clone(&second.state);
        second
            .scope(async {
                dispatched();
            })
            .await;
        drop(second);
        assert_eq!(state.lock().unwrap().outcome, Some(Outcome::Cancelled));
        assert!(!state.lock().unwrap().usage_complete);
    }

    #[tokio::test]
    async fn scopes_do_not_mix_and_identifiers_cannot_log_secrets() {
        let mut request = ConversationRequest::new();
        request.x_fuigo_session_id = Some("sk-secret-must-not-appear".into());
        request.x_fuigo_turn_idx = Some("secret".into());
        let a = Attempt::new(&request, "also-secret", 1);
        let b = Attempt::new(&ConversationRequest::new(), "", 1);
        a.scope(async {
            b.scope(async {
                dispatched();
            })
            .await;
        })
        .await;
        assert!(!a.state.lock().unwrap().dispatched);
        assert!(b.state.lock().unwrap().dispatched);
        assert!(
            !serde_json::to_string(&*a.state.lock().unwrap())
                .unwrap()
                .contains("secret")
        );
    }
}
