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
    let result = rx
        .await
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
}
