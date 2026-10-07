//! P188 wire contract MurageMobile consumes, read off the raw JSON-RPC bytes the agent writes.
//!
//! A Responses stream that dies after "A1" is resent; the client must see, in order: the A1 `agent_message_chunk`,
//! then `_fuigo/session_notification` `retry_state` `retrying` with `discardEmitted: true` and the attempt's
//! `streamStartMs`, then the stock-ACP mirror thought chunk, then the resend's "A3". The mirror is never itself
//! voidable output, `response_completed` is the per-response boundary, and `initialize` advertises
//! `agentCapabilities._meta["fuigo/capabilities"].retryDiscard = {"version": 1}`.
#[allow(dead_code)]
mod acp_harness;

use acp_harness::{AutoApproveClient, AgentPipes, RPC_TIMEOUT, connect_client, prompt_turn, run_agent_test, spawn_agent_local};
use agent_client_protocol as acp;
use fuigo_test_support::{MockModelEntry, ScriptedResponse, sse};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MODEL: &str = "p188-responses-model";

fn truncated(text: &str) -> ScriptedResponse {
    let mut events = sse::responses_api_script_exact(text, MODEL);
    events.truncate(events.len() - 2);
    ScriptedResponse::sse(events)
}

#[test]
fn p188_retry_discard_wire_contract() {
    run_agent_test(|cwd, mock| async move {
        mock.set_models(vec![MockModelEntry::new(MODEL).with_api_backend("responses")]);
        mock.enqueue_response("/v1/responses", truncated("A1"));
        // A resend that dies before any output: it follows only the mirror, so it must owe no discard
        let mut no_output = sse::responses_api_script_exact("A2", MODEL);
        no_output.truncate(1);
        mock.enqueue_response("/v1/responses", ScriptedResponse::sse(no_output));
        mock.enqueue_response("/v1/responses", ScriptedResponse::sse(sse::responses_api_script_exact("A3", MODEL)));

        // Tee the agent's output: every byte goes to the client and into `raw`
        let AgentPipes { to_agent, mut from_agent } = spawn_agent_local();
        let (mut tee_in, tee_out) = tokio::io::duplex(acp_harness::DUPLEX_BUFFER_BYTES);
        let raw = Rc::new(RefCell::new(Vec::<u8>::new()));
        let sink = Rc::clone(&raw);
        tokio::task::spawn_local(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match from_agent.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        sink.borrow_mut().extend_from_slice(&buf[..n]);
                        if tee_in.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let (conn, init) =
            connect_client(AutoApproveClient, "p188-wire", AgentPipes { to_agent, from_agent: tee_out }).await;

        // (4) the capability Murage gates its reset on
        let caps = serde_json::to_value(&init.agent_capabilities).expect("capabilities");
        assert_eq!(caps["_meta"]["fuigo/capabilities"]["retryDiscard"], json!({ "version": 1 }), "{caps}");
        assert!(caps["_meta"]["fuigo/capabilities"]["toolOverrides"].is_object(), "the shared object keeps its keys: {caps}");

        let session = tokio::time::timeout(
            RPC_TIMEOUT,
            acp::Agent::new_session(
                &conn,
                acp::NewSessionRequest::new(cwd.clone()).meta(json!({ "modelId": MODEL }).as_object().cloned()),
            ),
        )
        .await
        .expect("session/new timed out")
        .expect("session/new failed")
        .session_id;
        prompt_turn(&conn, &session, "say hi").await;
        // The mirror and trailing notifications are fire-and-forget; give them a moment to drain
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let lines: Vec<Value> = String::from_utf8(raw.borrow().clone())
            .expect("utf8")
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v.get("method").is_some())
            .collect();
        let pos = |pred: &dyn Fn(&Value) -> bool, what: &str| -> usize {
            lines.iter().position(pred).unwrap_or_else(|| panic!("no {what} on the wire: {lines:#?}"))
        };
        let text_chunk = |needle: &'static str| {
            move |l: &Value| {
                l["method"] == "session/update"
                    && l["params"]["update"]["sessionUpdate"] == "agent_message_chunk"
                    && l["params"]["update"]["content"]["text"].as_str().is_some_and(|t| t.contains(needle))
            }
        };
        let a1 = pos(&text_chunk("A1"), "A1 chunk");
        let a3 = pos(&text_chunk("A3"), "A3 chunk");
        // (1) the exact carrier: `_fuigo/session_notification`, `params.update.sessionUpdate == "retry_state"`
        let discard = pos(
            &|l: &Value| {
                l["method"] == "_fuigo/session_notification"
                    && l["params"]["update"]["sessionUpdate"] == "retry_state"
                    && l["params"]["update"]["type"] == "retrying"
                    && l["params"]["update"]["discardEmitted"] == true
            },
            "discarding retry_state",
        );
        assert!(a1 < discard && discard < a3, "A1, then the discard, then A3: {lines:#?}");
        // `streamStartMs` names the dead attempt: the one the A1 chunk carried
        assert_eq!(
            lines[discard]["params"]["update"]["streamStartMs"], lines[a1]["params"]["_meta"]["streamStartMs"],
            "{lines:#?}"
        );
        assert_ne!(lines[a1]["params"]["_meta"]["streamStartMs"], lines[a3]["params"]["_meta"]["streamStartMs"]);
        // (3) the stock-ACP mirror comes after the retry_state, and before the resend's output
        let mirror = pos(
            &|l: &Value| {
                l["method"] == "session/update"
                    && l["params"]["update"]["sessionUpdate"] == "agent_thought_chunk"
                    && l["params"]["update"]["_meta"]["fuigo/retryStatus"]["discardEmitted"] == true
            },
            "retry mirror",
        );
        assert!(discard < mirror && mirror < a3, "{lines:#?}");
        // One dead attempt, one discard: the mirror never counts as output for a later discard window
        let discards = lines
            .iter()
            .filter(|l| l["params"]["update"]["discardEmitted"] == true && l["method"] == "_fuigo/session_notification")
            .count();
        assert_eq!(discards, 1, "{lines:#?}");
        let retries = lines
            .iter()
            .filter(|l| {
                l["method"] == "_fuigo/session_notification"
                    && l["params"]["update"]["sessionUpdate"] == "retry_state"
                    && l["params"]["update"]["type"] == "retrying"
            })
            .count();
        assert_eq!(retries, 2, "the second resend is announced, without a discard: {lines:#?}");
        // (5) the per-response boundary: `_fuigo/session_notification` `response_completed`, after the reply
        let completed = pos(
            &|l: &Value| {
                l["method"] == "_fuigo/session_notification" && l["params"]["update"]["sessionUpdate"] == "response_completed"
            },
            "response_completed",
        );
        assert!(a3 < completed, "{lines:#?}");
    });
}
