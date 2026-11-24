//! A real agent behind a leader server, in this process rather than a child.

use std::sync::Arc;

use fuigo_acp_lib::AcpAgentGatewaySender as GatewaySender;
use tokio::io::{AsyncBufReadExt as _, BufReader, simplex};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

use crate::agent::config::Config as AgentConfig;
use crate::agent::mvp_agent::MvpAgent;

const SIMPLEX_BUF: usize = 8 * 1024 * 1024;

/// Spawns an agent on the current `LocalSet`, reading requests from `to_agent` and writing responses to `from_agent`.
/// Returns the task handles so a caller can end the agent.
/// Panics if the ambient configuration cannot build one.
pub fn spawn_agent(
    mut to_agent: UnboundedReceiver<String>,
    from_agent: UnboundedSender<String>,
) -> Vec<JoinHandle<()>> {
    let (agent_in_read, mut agent_in_write) = simplex(SIMPLEX_BUF);
    let (agent_out_read, agent_out_write) = simplex(SIMPLEX_BUF);

    let agent = tokio::task::spawn_local(async move {
        let config = AgentConfig::default();
        let auth_manager = Arc::new(config.create_auth_manager());
        let (gateway_tx, gateway_rx) = tokio::sync::mpsc::unbounded_channel();
        let agent = MvpAgent::new(GatewaySender::new(gateway_tx), &config, auth_manager, None)
            .expect("valid agent config");
        let park_hold = agent.park_hold.clone();
        let (conn, handle_io) = crate::agent::credential_scrub::agent_side_connection(
            agent,
            agent_out_write.compat_write(),
            agent_in_read.compat(),
        );
        tokio::task::spawn_local(
            fuigo_acp_lib::AcpGatewayReceiver::<agent_client_protocol::AgentSide, _>::new(
                gateway_rx,
                crate::agent::park_hold::ParkHoldClient::new(conn, park_hold),
            )
            .with_on_meta(fuigo_file_utils::trace_context::span_from_meta_traceparent)
            .run(),
        );
        let _ = handle_io.await;
    });

    let requests = tokio::task::spawn_local(async move {
        while let Some(msg) = to_agent.recv().await {
            if crate::agent::credential_scrub::write_client_line(&mut agent_in_write, &msg)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let responses = tokio::task::spawn_local(async move {
        let mut reader = BufReader::new(agent_out_read);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let msg = line.trim_end_matches(['\r', '\n']).to_string();
                    if !msg.is_empty() {
                        let _ = from_agent.send(msg);
                    }
                }
            }
        }
    });

    vec![agent, requests, responses]
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::{Value, json};

    fn initialize(id: u64) -> String {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": 1,
                "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                "_meta": { "startupHints": { "nonInteractive": true, "skipGitStatus": true, "skipProjectLayout": true } },
            },
        })
        .to_string()
    }

    /// The leader forwards an unparseable or unmutated payload raw. One with an embedded line break must not become a
    /// second, ungated request at the agent: only the single-line request is answered.
    #[tokio::test(flavor = "current_thread")]
    async fn a_multi_line_client_payload_never_reaches_the_agent() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (to_agent, to_agent_rx) = tokio::sync::mpsc::unbounded_channel();
                let (from_agent_tx, mut from_agent) = tokio::sync::mpsc::unbounded_channel();
                let tasks = super::spawn_agent(to_agent_rx, from_agent_tx);
                to_agent.send(format!("junk\n{}", initialize(7))).unwrap();
                to_agent.send(format!("junk\r{}", initialize(8))).unwrap();
                to_agent
                    .send(format!("junk\r\n{}", initialize(10)))
                    .unwrap();
                to_agent.send(initialize(9)).unwrap();
                let mut answered = Vec::new();
                let mut wait = Duration::from_secs(60);
                // After the single-line answer, a short grace catches an inner request answered out of order.
                while let Ok(Some(line)) = tokio::time::timeout(wait, from_agent.recv()).await {
                    let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if msg.get("method").is_none()
                        && let Some(id) = msg.get("id")
                    {
                        answered.push(id.clone());
                        if id == &json!(9) {
                            wait = Duration::from_millis(500);
                        }
                    }
                }
                for task in tasks {
                    task.abort();
                }
                assert_eq!(
                    answered,
                    vec![json!(9)],
                    "only the single-line request may reach the agent"
                );
            })
            .await;
    }
}
