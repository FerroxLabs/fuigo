//! `fuigo/btw` extension handler: dispatch a side question to the active session via `SessionCommand::SideQuestion` and return the answer.

use agent_client_protocol as acp;
use tokio::sync::oneshot;

use super::{ExtResult, parse_params};
use crate::agent::MvpAgent;
use crate::session::{SessionCommand, SideQuestionError};

/// Same bound as the pager. A non-pager client must not grow the side-question payload without a limit.
const SIDE_QUESTION_IMAGE_CAP: usize = 50_000_000;

fn estimated_decoded_len(data: &str) -> usize {
    let b64 = data.rsplit(',').next().unwrap_or(data);
    let padding = b64.bytes().rev().take_while(|byte| *byte == b'=').count();
    (b64.len().saturating_mul(3) / 4).saturating_sub(padding)
}

pub(crate) fn cap_side_question_images(
    images: Vec<acp::ImageContent>,
) -> (Vec<acp::ImageContent>, usize) {
    cap_side_question_images_to(images, SIDE_QUESTION_IMAGE_CAP)
}

fn cap_side_question_images_to(
    images: Vec<acp::ImageContent>,
    cap: usize,
) -> (Vec<acp::ImageContent>, usize) {
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut omitted = 0usize;
    for image in images {
        let size = estimated_decoded_len(&image.data);
        if size > cap || total.saturating_add(size) > cap {
            omitted += 1;
            continue;
        }
        total += size;
        kept.push(image);
    }
    (kept, omitted)
}

pub(crate) fn side_question_omit_notice(omitted: usize) -> String {
    format!("{omitted} attached image(s) were not included (over the 50MB side-question limit).")
}

/// Side questions in flight that the client gave a `requestId`, so `fuigo/btw/cancel` can stop one.
static IN_FLIGHT: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Notify>>>,
> = std::sync::LazyLock::new(Default::default);

/// Registers a request id for its lifetime; dropping it (answered, cancelled or abandoned) unregisters it.
struct InFlight {
    id: String,
    cancel: std::sync::Arc<tokio::sync::Notify>,
}

impl InFlight {
    fn register(id: String) -> Self {
        let cancel = std::sync::Arc::new(tokio::sync::Notify::new());
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), cancel.clone());
        Self { id, cancel }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

/// Cancel the side question registered under `id`; false when none is in flight (already answered, or never started).
fn cancel_in_flight(id: &str) -> bool {
    let cancel = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned();
    match cancel {
        Some(cancel) => {
            // `notify_one` stores a permit, so a cancel that lands before the waiter polls is not lost
            cancel.notify_one();
            true
        }
        None => false,
    }
}

/// Handle `fuigo/btw/cancel`: stop the side question the client started with this `requestId`.
/// Best-effort and idempotent; the dropped request's own reply is a request-cancelled error nobody is waiting on.
pub(super) async fn handle_btw_cancel(args: &acp::ExtRequest) -> ExtResult {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CancelRequest {
        request_id: String,
    }
    let req: CancelRequest = parse_params(args)?;
    let cancelled = cancel_in_flight(&req.request_id);
    super::to_ext_response(Ok(serde_json::json!({ "cancelled": cancelled })))
}

/// Handle `fuigo/btw`, a side question that doesn't interrupt the current turn.
pub(super) async fn handle_btw(agent: &MvpAgent, args: &acp::ExtRequest) -> ExtResult {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BtwRequest {
        session_id: String,
        question: String,
        /// Optional text + image blocks. Absent = legacy text-only wire.
        #[serde(default)]
        content: Vec<acp::ContentBlock>,
        /// Client-chosen id that `fuigo/btw/cancel` names. Absent = not cancellable.
        #[serde(default)]
        request_id: Option<String>,
    }

    let req: BtwRequest = parse_params(args)?;
    let sid: acp::SessionId = req.session_id.clone().into();
    let session_handle = agent.resident_handle(&sid);
    let Some(session) = session_handle else {
        return Err(crate::acp_error::invalid_params(format!(
            "session not found: {}",
            req.session_id
        )));
    };
    let (text_override, images) = super::content::split_content(req.content);
    let (images, omitted) = cap_side_question_images(images);
    let mut question = text_override.unwrap_or(req.question);
    if omitted > 0 {
        question.push_str("\n\n");
        question.push_str(&side_question_omit_notice(omitted));
    }
    let (tx, rx) = oneshot::channel();
    let _ = session.cmd_tx.send(SessionCommand::SideQuestion {
        question,
        images,
        respond_to: tx,
    });
    let in_flight = req.request_id.map(InFlight::register);
    let result = match &in_flight {
        Some(in_flight) => tokio::select! {
            result = rx => result,
            // Returning drops `rx`, which tells the session to abandon the model call
            _ = in_flight.cancel.notified() => {
                return Err(side_question_error_to_acp(SideQuestionError::Sampling(
                    fuigo_sampler::events::request_cancelled_error(),
                )));
            }
        },
        None => rx.await,
    }
    .map_err(|_| crate::acp_error::session_unavailable("session failed to respond"))?;
    match result {
        Ok(answer) => super::to_ext_response(Ok(serde_json::json!({
            "answer": answer,
        }))),
        Err(e) => Err(side_question_error_to_acp(e)),
    }
}

/// The `fuigo/btw` error reply for a failed side question; typed like every shell error, a cancel is request-cancelled (`-32800`).
fn side_question_error_to_acp(err: SideQuestionError) -> acp::Error {
    match err {
        SideQuestionError::Sampling(e) => crate::sampling::error::map_sampling_err_to_acp(e),
        SideQuestionError::BudgetDenied(denial) => denial.to_acp_error(),
        e @ SideQuestionError::PrepareClient(_) => crate::acp_error::internal_error(e.to_string()),
        e @ SideQuestionError::EmptyResponse => crate::acp_error::typed(
            acp::Error::internal_error(),
            crate::acp_error::AcpErrorKind::Sampling(
                fuigo_sampler::SamplingErrorKind::EmptyResponse,
            ),
            e.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_question_cap_keeps_one_small_image_and_drops_the_rest() {
        let small = acp::ImageContent::new("aGVsbG8=", "image/png");
        let huge = acp::ImageContent::new("A".repeat(32), "image/png");
        let (kept, omitted) = cap_side_question_images_to(vec![small, huge], 8);
        assert_eq!(kept.len(), 1);
        assert_eq!(omitted, 1);
        assert!(side_question_omit_notice(omitted).contains("not included"));
    }

    #[test]
    fn estimated_decoded_len_does_not_underflow_on_padding() {
        assert_eq!(estimated_decoded_len(""), 0);
        assert_eq!(estimated_decoded_len("="), 0);
        assert_eq!(estimated_decoded_len("=="), 0);
        assert_eq!(estimated_decoded_len("===="), 0);
        assert_eq!(estimated_decoded_len("aGVsbG8="), 5);
    }

    #[test]
    fn cancel_in_flight_wakes_the_registered_request_once() {
        let flight = InFlight::register("test-cancel-wakes".into());
        assert!(!cancel_in_flight("test-cancel-unknown"), "an unknown id cancels nothing");
        assert!(cancel_in_flight("test-cancel-wakes"));
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            // The permit stored by the cancel completes the wait even though it was sent first
            tokio::time::timeout(std::time::Duration::from_secs(5), flight.cancel.notified())
                .await
                .expect("cancel must wake the waiter");
        });
        drop(flight);
        assert!(!cancel_in_flight("test-cancel-wakes"), "dropping unregisters the id");
    }

    /// A /btw whose side call was cancelled answers JSON-RPC request-cancelled with `error_kind: cancelled`, never an auth error.
    #[test]
    fn cancelled_btw_is_request_cancelled_not_auth() {
        let err = side_question_error_to_acp(SideQuestionError::Sampling(
            fuigo_sampler::events::request_cancelled_error(),
        ));
        assert_eq!(i32::from(err.code), -32800, "{err:?}");
        assert_eq!(
            crate::sampling::error::error_kind_str_from_error(&err),
            Some("cancelled")
        );
    }

    /// The non-sampling side-question failures reach the client as typed objects too.
    #[test]
    fn non_sampling_btw_failures_carry_typed_data() {
        for (err, kind) in [
            (
                SideQuestionError::PrepareClient("no model configured".into()),
                "internal",
            ),
            (SideQuestionError::EmptyResponse, "empty_response"),
        ] {
            let text = err.to_string();
            let acp_err = side_question_error_to_acp(err);
            let data = acp_err.data.clone().unwrap_or_default();
            assert_eq!(data["message"], text.as_str(), "{acp_err:?}");
            assert_eq!(data["error_kind"], kind, "{acp_err:?}");
        }
    }

    /// Contract D.4: a side question the token-budget guard refused reaches the client as the same
    /// typed denial a refused prompt does, not as an `api` failure.
    #[test]
    fn a_budget_denied_side_question_is_the_typed_denial() {
        use crate::acp_error::{ExecutionBudgetDenial, ExecutionBudgetRule};
        let denial = ExecutionBudgetDenial {
            rule: ExecutionBudgetRule::TokenUsageUnknown,
            total_token_limit: Some(10),
            total_tokens_used: 0,
            output_token_limit: None,
            output_tokens_used: 0,
            unknown_usage: true,
        };
        let acp_err = side_question_error_to_acp(SideQuestionError::BudgetDenied(denial.clone()));
        assert_eq!(
            serde_json::to_value(&acp_err).unwrap(),
            serde_json::to_value(denial.to_acp_error()).unwrap()
        );
        assert_eq!(ExecutionBudgetDenial::from_acp_error(&acp_err), Some(denial));
    }
}
