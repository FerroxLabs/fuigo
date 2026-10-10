//! P195 (U17): consecutive thinking blocks stay separate, and `redacted_thinking` blocks are kept in order.
//! The P160 follow-up: the sampler and the session already carry every block, each with its own signature; the reducer
//! used to merge consecutive signed thinking blocks into one and had no wire shape for a redacted block.

use super::*;
use pretty_assertions::assert_eq;

fn signed(thought: &str, signature: &str) -> [StreamEvent; 2] {
    [
        StreamEvent::AgentThought(thought.into()),
        StreamEvent::ReasoningCompleted {
            signature: Some(signature.into()),
        },
    ]
}

fn types(blocks: &[Value]) -> Vec<&str> {
    blocks.iter().map(|b| b["type"].as_str().unwrap()).collect()
}

#[test]
fn consecutive_thinking_blocks_stay_separate_each_with_its_own_signature() {
    let mut r = messages(false);
    for event in signed("first think", "sig-1").into_iter().chain(signed("second think", "sig-2")) {
        r.reduce(event);
    }
    r.reduce(StreamEvent::AgentMessage("answer".into()));
    r.reduce(response_completed("msg_a", "end_turn"));
    let msg = r.flush_assistant(Some("end_turn")).expect("assistant frame");
    let blocks = msg["message"]["content"].as_array().unwrap();
    assert_eq!(types(blocks), vec!["thinking", "thinking", "text"], "{msg}");
    assert_eq!(blocks[0]["thinking"], "first think");
    assert_eq!(blocks[0]["signature"], "sig-1");
    assert_eq!(blocks[1]["thinking"], "second think");
    assert_eq!(blocks[1]["signature"], "sig-2");
}

#[test]
fn three_consecutive_signed_thinking_blocks_keep_every_signature() {
    let mut r = messages(false);
    for (text, sig) in [("a", "s1"), ("b", "s2"), ("c", "s3")] {
        for event in signed(text, sig) {
            r.reduce(event);
        }
    }
    let msg = r.flush_assistant(Some("end_turn")).expect("assistant frame");
    let blocks = msg["message"]["content"].as_array().unwrap();
    let got: Vec<(&str, &str)> = blocks
        .iter()
        .map(|b| (b["thinking"].as_str().unwrap(), b["signature"].as_str().unwrap()))
        .collect();
    assert_eq!(got, vec![("a", "s1"), ("b", "s2"), ("c", "s3")]);
}

#[test]
fn thinking_chunks_of_one_unsigned_block_still_merge() {
    // The control: chunks of ONE block (no signature between them) are one block, as before.
    let mut r = messages(false);
    r.reduce(StreamEvent::AgentThought("hel".into()));
    r.reduce(StreamEvent::AgentThought("lo".into()));
    r.reduce(StreamEvent::ReasoningCompleted {
        signature: Some("sig-1".into()),
    });
    let msg = r.flush_assistant(Some("end_turn")).expect("assistant frame");
    let blocks = msg["message"]["content"].as_array().unwrap();
    assert_eq!(blocks.len(), 1, "{msg}");
    assert_eq!(blocks[0]["thinking"], "hello");
    assert_eq!(blocks[0]["signature"], "sig-1");
}

#[test]
fn partial_framing_opens_a_block_per_consecutive_thinking_block() {
    let mut r = messages(true);
    let mut out = Vec::new();
    out.extend(r.reduce(response_started("msg_a", Some("grok-4"), 5)));
    for event in signed("first think", "sig-1").into_iter().chain(signed("second think", "sig-2")) {
        out.extend(r.reduce(event));
    }
    out.extend(r.reduce(response_completed("msg_a", "end_turn")));
    out.extend(r.finish(&end_turn()));
    let starts: Vec<u64> = out
        .iter()
        .filter(|m| {
            m["event"]["type"] == "content_block_start" && m["event"]["content_block"]["type"] == "thinking"
        })
        .map(|m| m["event"]["index"].as_u64().unwrap())
        .collect();
    assert_eq!(starts, vec![0, 1], "one content_block_start per thinking block");
    let kinds: Vec<String> = out
        .iter()
        .filter_map(|m| match m["event"]["type"].as_str()? {
            "content_block_start" => Some(format!("start{}", m["event"]["index"])),
            "content_block_stop" => Some(format!("stop{}", m["event"]["index"])),
            "content_block_delta" => match m["event"]["delta"]["type"].as_str()? {
                "signature_delta" => Some(format!("sig:{}", m["event"]["delta"]["signature"].as_str()?)),
                "thinking_delta" => Some(format!("think:{}", m["event"]["delta"]["thinking"].as_str()?)),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "start0", "think:first think", "sig:sig-1", "stop0",
            "start1", "think:second think", "sig:sig-2", "stop1",
        ],
        "each block is closed with its own signature before the next opens: {out:?}"
    );
    let frame = out.iter().find(|m| m["type"] == "assistant").expect("frame");
    let blocks = frame["message"]["content"].as_array().unwrap();
    assert_eq!(types(blocks), vec!["thinking", "thinking"]);
    assert_eq!(blocks[1]["signature"], "sig-2");
}

#[test]
fn a_redacted_thinking_block_is_kept_in_order() {
    let mut r = messages(false);
    for event in signed("first think", "sig-1") {
        r.reduce(event);
    }
    r.reduce(StreamEvent::RedactedThinking {
        data: "opaque-blob".into(),
    });
    for event in signed("second think", "sig-2") {
        r.reduce(event);
    }
    r.reduce(StreamEvent::AgentMessage("answer".into()));
    r.reduce(response_completed("msg_a", "end_turn"));
    let msg = r.flush_assistant(Some("end_turn")).expect("assistant frame");
    let blocks = msg["message"]["content"].as_array().unwrap();
    assert_eq!(
        types(blocks),
        vec!["thinking", "redacted_thinking", "thinking", "text"],
        "{msg}"
    );
    assert_eq!(blocks[1]["data"], "opaque-blob");
    assert!(blocks[1].get("signature").is_none() && blocks[1].get("thinking").is_none(), "{msg}");
    assert_eq!(blocks[0]["signature"], "sig-1");
    assert_eq!(blocks[2]["signature"], "sig-2");
}

#[test]
fn a_redacted_thinking_block_closes_unsigned_thinking_text_before_it() {
    let mut r = messages(false);
    r.reduce(StreamEvent::AgentThought("unsigned".into()));
    r.reduce(StreamEvent::RedactedThinking { data: "blob".into() });
    r.reduce(StreamEvent::AgentMessage("answer".into()));
    let msg = r.flush_assistant(Some("end_turn")).expect("assistant frame");
    let blocks = msg["message"]["content"].as_array().unwrap();
    assert_eq!(types(blocks), vec!["thinking", "redacted_thinking", "text"], "{msg}");
    assert_eq!(blocks[0]["thinking"], "unsigned");
}

#[test]
fn a_response_of_only_a_redacted_thinking_block_still_gets_its_frame() {
    let mut r = messages(false);
    r.reduce(StreamEvent::RedactedThinking { data: "blob".into() });
    let msg = r.flush_assistant(Some("end_turn")).expect("a frame for a response with one redacted block");
    let blocks = msg["message"]["content"].as_array().unwrap();
    assert_eq!(types(blocks), vec!["redacted_thinking"]);
    assert_eq!(blocks[0]["data"], "blob");
}

#[test]
fn the_last_signature_never_lands_on_a_redacted_block() {
    // `ResponseCompleted` carries the LAST signature; with no signed thinking block to take it, it must not
    // be stamped onto (or invent a signature for) the redacted block.
    let mut r = messages(false);
    r.reduce(StreamEvent::RedactedThinking { data: "blob".into() });
    r.reduce(StreamEvent::AgentMessage("answer".into()));
    r.reduce(StreamEvent::ResponseCompleted {
        message_id: Some("msg_a".into()),
        stop_reason: Some("end_turn".into()),
        usage: None,
        signature: Some("late-sig".into()),
        stop_sequence: None,
    });
    let msg = r.flush_assistant(Some("end_turn")).expect("assistant frame");
    let blocks = msg["message"]["content"].as_array().unwrap();
    assert_eq!(types(blocks), vec!["redacted_thinking", "text"]);
    assert_eq!(blocks[0]["data"], "blob");
    assert!(blocks[0].get("signature").is_none(), "{msg}");
}

#[test]
fn partial_framing_emits_a_redacted_thinking_block_between_its_neighbours() {
    let mut r = messages(true);
    let mut out = Vec::new();
    out.extend(r.reduce(response_started("msg_a", Some("grok-4"), 5)));
    for event in signed("first think", "sig-1") {
        out.extend(r.reduce(event));
    }
    out.extend(r.reduce(StreamEvent::RedactedThinking {
        data: "opaque-blob".into(),
    }));
    out.extend(r.reduce(StreamEvent::AgentMessage("answer".into())));
    out.extend(r.reduce(response_completed("msg_a", "end_turn")));
    out.extend(r.finish(&end_turn()));
    let shape: Vec<String> = out
        .iter()
        .filter_map(|m| match m["event"]["type"].as_str()? {
            "content_block_start" => {
                let block = &m["event"]["content_block"];
                Some(format!(
                    "start{}:{}{}",
                    m["event"]["index"],
                    block["type"].as_str()?,
                    block["data"].as_str().map(|d| format!("={d}")).unwrap_or_default()
                ))
            }
            "content_block_stop" => Some(format!("stop{}", m["event"]["index"])),
            _ => None,
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            "start0:thinking", "stop0",
            "start1:redacted_thinking=opaque-blob", "stop1",
            "start2:text", "stop2",
        ],
        "{out:?}"
    );
    let frame = out.iter().find(|m| m["type"] == "assistant").expect("frame");
    let blocks = frame["message"]["content"].as_array().unwrap();
    assert_eq!(types(blocks), vec!["thinking", "redacted_thinking", "text"]);
}

/// P195 x P201: a discarded attempt that streamed a signed thinking block and a redacted one leaves neither in the
/// transcript; the frame holds the accepted attempt only.
#[test]
fn a_discarded_attempt_leaves_no_thinking_or_redacted_thinking_in_the_transcript() {
    for partials in [false, true] {
        let mut r = messages(partials);
        let mut out = Vec::new();
        for event in signed("dead think", "dead-sig") {
            out.extend(r.reduce(event));
        }
        out.extend(r.reduce(StreamEvent::RedactedThinking { data: "dead-blob".into() }));
        out.extend(r.reduce(StreamEvent::AgentMessage("dead answer".into())));
        out.extend(r.reduce(StreamEvent::ResponseDiscarded {
            message_id: Some("msg_dead".into()),
            stream_start_ms: None,
        }));
        for event in signed("live think", "live-sig") {
            out.extend(r.reduce(event));
        }
        out.extend(r.reduce(StreamEvent::AgentMessage("live answer".into())));
        out.extend(r.reduce(response_completed("msg_live", "end_turn")));
        out.extend(r.flush_assistant(Some("end_turn")));
        let frames: Vec<&Value> = out.iter().filter(|l| l["type"] == "assistant").collect();
        assert_eq!(frames.len(), 1, "partials={partials}: {out:#?}");
        let blocks = frames[0]["message"]["content"].as_array().unwrap();
        assert_eq!(types(blocks), vec!["thinking", "text"], "partials={partials}: {blocks:#?}");
        assert_eq!(blocks[0]["thinking"], "live think");
        assert_eq!(blocks[0]["signature"], "live-sig");
        let all = serde_json::to_string(frames[0]).unwrap();
        assert!(!all.contains("dead"), "partials={partials}: the discarded attempt leaked: {all}");
    }
}
