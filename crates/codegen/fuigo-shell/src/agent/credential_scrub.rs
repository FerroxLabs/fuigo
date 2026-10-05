//! P70b display sink on the ACP reply rail: every `acp::Error` the agent returns to a client has the credentials this
//! process sent upstream replaced (exact match, [`fuigo_telemetry::sent_credentials`]).
//!
//! An upstream that echoes a key back puts it in the error text the sampler hands the shell. The shell classifies that
//! text as it arrived (retry, compact, re-auth) and builds the `acp::Error` from it; this wrapper scrubs the error
//! only as it leaves the agent, after every decision has been made. It is the one place every reply passes through,
//! whatever method produced the error and whichever transport (stdio, the relay bridge, the in-process leader) carries
//! it. Successful results are not touched: some carry data a client acts on.

use agent_client_protocol::{self as acp};
use fuigo_acp_lib::LineBufferedRead;
use fuigo_telemetry::sent_credentials;

/// Replace every credential this process sent upstream in the HUMAN TEXT of `err`: its `message`, a bare-string
/// `data`, and `data.message` (the detail clients show, see `crate::acp_error::typed_error_data`).
///
/// Nothing else in `data` is touched. The other members (`error_kind`, `code`, `rule`, `http_status`, ...) are
/// discriminators this agent wrote and clients decide on; rewriting one because a credential happened to spell it
/// would change behaviour, not just display.
pub fn scrub_acp_error(mut err: acp::Error) -> acp::Error {
    if sent_credentials::is_empty() {
        // Nothing was sent, so nothing in the text can have been replaced: the reply stays byte-for-byte what the
        // agent built (frozen wire goldens pin it) and a client reads the text, as before.
        return err;
    }
    stamp_error_verdicts(&mut err);
    sent_credentials::scrub_in_place(&mut err.message);
    match err.data.as_mut() {
        Some(serde_json::Value::String(text)) => {
            sent_credentials::scrub_in_place(text);
        }
        Some(serde_json::Value::Object(map)) => {
            if let Some(serde_json::Value::String(text)) = map.get_mut("message") {
                sent_credentials::scrub_in_place(text);
            }
        }
        _ => {}
    }
    err
}

/// P119: put the typed verdicts a client decides on into `data.verdicts` of a model-request failure, computed from
/// the human text as it stands NOW, which is before [`scrub_acp_error`] replaces anything in it. After this the
/// pager (and any other client) never has to read the words of the text to decide: the text is for display only.
///
/// Every error with an object `data` and a string `message` is stamped (that is every typed error the shell builds,
/// see `crate::acp_error`; a persistence failure that is a disk-full needs its verdict as much as a model failure
/// does). An existing `verdicts` is kept.
fn stamp_error_verdicts(err: &mut acp::Error) {
    use crate::sampling::error_verdicts::{ERROR_VERDICTS_DATA_KEY, ErrorVerdicts};
    let Some(serde_json::Value::Object(map)) = err.data.as_mut() else {
        return;
    };
    if map.contains_key(ERROR_VERDICTS_DATA_KEY) {
        return;
    }
    let kind = map
        .get(crate::acp_error::ERROR_KIND_DATA_KEY)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let Some(text) = map.get("message").and_then(serde_json::Value::as_str) else {
        return;
    };
    let status = map
        .get("http_status")
        .and_then(serde_json::Value::as_u64)
        .and_then(|status| u16::try_from(status).ok());
    let verdicts = ErrorVerdicts::for_error(status, kind.as_deref(), text);
    if let Ok(value) = serde_json::to_value(verdicts) {
        map.insert(ERROR_VERDICTS_DATA_KEY.to_owned(), value);
    }
}

/// An [`acp::Agent`] whose errors go through [`scrub_acp_error`]. Results pass through unchanged.
pub struct ScrubSentCredentials<A>(pub A);

#[async_trait::async_trait(?Send)]
impl<A: acp::Agent> acp::Agent for ScrubSentCredentials<A> {
    async fn initialize(
        &self,
        args: acp::InitializeRequest,
    ) -> acp::Result<acp::InitializeResponse> {
        self.0.initialize(args).await.map_err(scrub_acp_error)
    }
    async fn authenticate(
        &self,
        args: acp::AuthenticateRequest,
    ) -> acp::Result<acp::AuthenticateResponse> {
        self.0.authenticate(args).await.map_err(scrub_acp_error)
    }
    async fn logout(&self, args: acp::LogoutRequest) -> acp::Result<acp::LogoutResponse> {
        self.0.logout(args).await.map_err(scrub_acp_error)
    }
    async fn new_session(
        &self,
        args: acp::NewSessionRequest,
    ) -> acp::Result<acp::NewSessionResponse> {
        self.0.new_session(args).await.map_err(scrub_acp_error)
    }
    async fn prompt(&self, args: acp::PromptRequest) -> acp::Result<acp::PromptResponse> {
        self.0.prompt(args).await.map_err(scrub_acp_error)
    }
    async fn cancel(&self, args: acp::CancelNotification) -> acp::Result<()> {
        self.0.cancel(args).await.map_err(scrub_acp_error)
    }
    async fn load_session(
        &self,
        args: acp::LoadSessionRequest,
    ) -> acp::Result<acp::LoadSessionResponse> {
        self.0.load_session(args).await.map_err(scrub_acp_error)
    }
    async fn set_session_mode(
        &self,
        args: acp::SetSessionModeRequest,
    ) -> acp::Result<acp::SetSessionModeResponse> {
        self.0.set_session_mode(args).await.map_err(scrub_acp_error)
    }
    async fn set_session_model(
        &self,
        args: acp::SetSessionModelRequest,
    ) -> acp::Result<acp::SetSessionModelResponse> {
        self.0
            .set_session_model(args)
            .await
            .map_err(scrub_acp_error)
    }
    async fn set_session_config_option(
        &self,
        args: acp::SetSessionConfigOptionRequest,
    ) -> acp::Result<acp::SetSessionConfigOptionResponse> {
        self.0
            .set_session_config_option(args)
            .await
            .map_err(scrub_acp_error)
    }
    async fn list_sessions(
        &self,
        args: acp::ListSessionsRequest,
    ) -> acp::Result<acp::ListSessionsResponse> {
        self.0.list_sessions(args).await.map_err(scrub_acp_error)
    }
    async fn fork_session(
        &self,
        args: acp::ForkSessionRequest,
    ) -> acp::Result<acp::ForkSessionResponse> {
        self.0.fork_session(args).await.map_err(scrub_acp_error)
    }
    async fn resume_session(
        &self,
        args: acp::ResumeSessionRequest,
    ) -> acp::Result<acp::ResumeSessionResponse> {
        self.0.resume_session(args).await.map_err(scrub_acp_error)
    }
    async fn close_session(
        &self,
        args: acp::CloseSessionRequest,
    ) -> acp::Result<acp::CloseSessionResponse> {
        self.0.close_session(args).await.map_err(scrub_acp_error)
    }
    async fn ext_method(&self, args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        self.0.ext_method(args).await.map_err(scrub_acp_error)
    }
    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        self.0.ext_notification(args).await.map_err(scrub_acp_error)
    }
}

/// The agent side of an ACP connection, as every production transport builds it: `incoming` line-buffered,
/// `agent` wrapped in [`ScrubSentCredentials`], tasks spawned on the current `LocalSet`.
/// Returns the connection and its I/O future, as [`acp::AgentSideConnection::new`] does.
pub fn agent_side_connection<A>(
    agent: A,
    outgoing: impl futures::AsyncWrite + Unpin + 'static,
    incoming: impl futures::AsyncRead + Unpin + 'static,
) -> (
    acp::AgentSideConnection,
    impl std::future::Future<Output = acp::Result<()>>,
)
where
    A: acp::Agent + 'static,
{
    let incoming = LineBufferedRead::spawn_local(incoming);
    acp::AgentSideConnection::new(ScrubSentCredentials(agent), outgoing, incoming, |fut| {
        tokio::task::spawn_local(fut);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No lock: these tests record unique values and assert only on them.
    #[test]
    fn the_message_and_the_human_detail_are_scrubbed_and_discriminators_are_not() {
        sent_credentials::record("p70b-unit-cred-0001");
        // A credential that happens to spell a discriminator must not rewrite it.
        sent_credentials::record("execution_budget_denied");
        let mut err = acp::Error::internal_error().data(serde_json::json!({
            "message": "API error (status 401): bad key p70b-unit-cred-0001",
            "code": "execution_budget_denied",
            "error_kind": "auth",
            "rule": "p70b-unit-cred-0001",
            "http_status": 401,
        }));
        err.message = "Unauthorized: p70b-unit-cred-0001".to_owned();
        let out = scrub_acp_error(err);
        assert_eq!(out.message, "Unauthorized: <redacted>");
        let data = out.data.expect("data kept");
        assert_eq!(
            data["message"],
            "API error (status 401): bad key <redacted>"
        );
        assert_eq!(data["code"], "execution_budget_denied");
        assert_eq!(data["error_kind"], "auth");
        assert_eq!(data["rule"], "p70b-unit-cred-0001");
        assert_eq!(data["http_status"], 401);
    }

    #[test]
    fn a_bare_string_data_is_scrubbed() {
        sent_credentials::record("p70b-unit-cred-0003");
        let err = acp::Error::internal_error().data("upstream said p70b-unit-cred-0003");
        let out = scrub_acp_error(err);
        assert_eq!(
            out.data,
            Some(serde_json::json!("upstream said <redacted>"))
        );
    }

    #[test]
    fn an_error_without_a_credential_is_unchanged_but_for_its_verdicts() {
        sent_credentials::record("p70b-unit-cred-0002");
        let err = acp::Error::invalid_params().data(serde_json::json!({"message": "nothing here"}));
        let mut before = serde_json::to_value(&err).unwrap();
        let mut after = serde_json::to_value(scrub_acp_error(err)).unwrap();
        // P119: the verdicts are the only addition, and they carry nothing for text like this.
        let verdicts = after["data"].as_object_mut().unwrap().remove("verdicts");
        assert!(verdicts.is_some());
        before["data"].as_object_mut().unwrap();
        assert_eq!(after, before);
    }
}
