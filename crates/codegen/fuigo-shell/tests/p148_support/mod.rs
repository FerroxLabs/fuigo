//! P148 shared test support: an ACP handshake whose `initialize` client-capability `_meta` and `authenticate` `_meta`
//! the test chooses (the shared `acp_harness::connect_client` fixes both), and a recorder of config notices.

use std::cell::RefCell;
use std::rc::Rc;

use agent_client_protocol::{self as acp, Agent as _};
use fuigo_acp_lib::LineBufferedRead;
use serde_json::{Value, json};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::acp_harness::{AgentPipes, RPC_TIMEOUT};

/// `initialize` (non-interactive start hints, plus `caps_meta` as the client capabilities' `_meta`) and
/// `authenticate` with `fuigo.api_key` and `auth_meta`. Returns the connection and the `authenticate` result.
pub async fn connect_with_meta<C>(
    client: C,
    client_type: &str,
    pipes: AgentPipes,
    caps_meta: Option<Value>,
    auth_meta: Value,
) -> (acp::ClientSideConnection, acp::Result<acp::AuthenticateResponse>)
where
    C: acp::Client + 'static,
{
    let AgentPipes {
        to_agent,
        from_agent,
    } = pipes;
    let client_incoming = LineBufferedRead::spawn_local(from_agent.compat());
    let (client_conn, client_io) =
        acp::ClientSideConnection::new(client, to_agent.compat_write(), client_incoming, |fut| {
            tokio::task::spawn_local(fut);
        });
    tokio::task::spawn_local(client_io);

    let mut caps = acp::ClientCapabilities::new()
        .fs(acp::FileSystemCapabilities::new())
        .terminal(false);
    if let Some(meta) = caps_meta.and_then(|m| m.as_object().cloned()) {
        caps = caps.meta(meta);
    }
    let init = tokio::time::timeout(
        RPC_TIMEOUT,
        client_conn.initialize(
            acp::InitializeRequest::new(acp::ProtocolVersion::V1)
                .client_capabilities(caps)
                .meta(
                    json!({
                        "startupHints": {
                            "nonInteractive": true,
                            "skipGitStatus": true,
                            "skipProjectLayout": true,
                        },
                        "clientType": client_type,
                        "clientVersion": "0.0-test",
                    })
                    .as_object()
                    .cloned(),
                ),
        ),
    )
    .await
    .expect("initialize timed out")
    .expect("initialize failed");
    // By id, not from the advertised list: with no ambient key `fuigo.api_key` is not advertised, yet a client that
    // brings its own key in `_meta["fuigo/apiKey"]` authenticates with it (the P08 channel, advertised under
    // `agentCapabilities._meta["fuigo/capabilities"].authenticateApiKey`).
    let _ = init;
    let auth = tokio::time::timeout(
        RPC_TIMEOUT,
        client_conn.authenticate(
            acp::AuthenticateRequest::new(acp::AuthMethodId::new("fuigo.api_key"))
                .meta(auth_meta.as_object().cloned()),
        ),
    )
    .await
    .expect("authenticate timed out");
    (client_conn, auth)
}

/// Every `config_notice` a client was sent, as `(sessionId, message)`.
#[derive(Clone, Default)]
pub struct Notices(pub Rc<RefCell<Vec<(String, String)>>>);

impl Notices {
    /// Record `params` if it is a `fuigo/session_notification` carrying a config notice.
    pub fn record(&self, params: &Value) {
        if params["update"]["sessionUpdate"] == "config_notice" {
            self.0.borrow_mut().push((
                params["sessionId"].as_str().unwrap_or_default().to_owned(),
                params["update"]["message"].as_str().unwrap_or_default().to_owned(),
            ));
        }
    }

    /// The messages that contain `needle`.
    pub fn matching(&self, needle: &str) -> Vec<String> {
        self.0
            .borrow()
            .iter()
            .filter(|(_, m)| m.contains(needle))
            .map(|(_, m)| m.clone())
            .collect()
    }
}
