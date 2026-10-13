# R-1026 - laundering live follow-ups (26-4 L-EMPTY, 26-5 L-AUTOREFUSE)

Base `hub/strike/integration` at `dd2978d5`. Branch `strike/b26-4`.

## What `strike/laundering-live` (3c374944) contained
One commit on `6bfb89b4`: a test runner only, NO product change. `crates/codegen/fuigo-pager/tests/peer_laundering_live.rs`
(one `#[ignore]` Linux-only test; 20 prompts, a real `fuigo-pager` per prompt, a stamped peer message, `/peers release`, a
per-prompt JSON result), `tests/README-laundering-live.md`, `scripts/strike/laundering-live.sh` (driver), and a `sha2`
dev-dependency (`fuigo-pager/Cargo.toml`, `Cargo.lock`). Neither follow-up was in it.

## Ported
The commit was cherry-picked unchanged onto the base (no conflicts). It stays out of the normal test run: the test is
`#[ignore = "live model: needs LAUNDERING_KEY_FILE and PAGER_BINARY ..."]`; without `LAUNDERING_MOCK` and without a key file
it does not start; the driver script refuses to run without `LAUNDERING_KEY_FILE` (no key, no run). It was not run here.

## 26-4 L-EMPTY (user notice)
A turn started by a peer message that completes with an empty model reply (no text, no tool call) or with the provider's
refusal stop (content filter, `acp::StopReason::Refusal`) puts ONE notice in the user's stream:
`The model ended the turn started by a message from <name> [<ref>] without a reply.` or
`The model declined to act on the message from <name> [<ref>].` Name and ref are the sender's claim, escaped with
`fuigo_peer::host::display_escape` (64 characters each). Carried by the existing peer notice ring and pump
(`PeerNotice`, `extensions/peer.rs::notice_event`), emitted as the existing `peer_warning` event (`text`, empty `subject`):
no new wire message type. The TUI and the ACP hosts read the same event. The pager shows it as
`Warning from a peer notice: "<text>"` (existing rendering of `peer_warning`; not changed). A human-typed turn is unchanged.

## 26-5 L-AUTOREFUSE
Condition (all of): feature flag on; the turn's origin is `PromptOrigin::PeerMessage`; the turn completed (`EndTurn` or a
provider `Refusal` stop; not cancelled, failed, cut at the token limit, removed from the queue or blocked at start); the turn
made zero tool calls of any kind (every model reply of the turn counted: ordinary tool calls plus backend-hosted tool calls);
the model did not call `refuse_peer_message` in the turn. An empty reply, a refusal stop and a text-only reply all qualify.
Effect: `PeerAdmissionState::finish_peer_turn` runs the shared `refuse_locked(.., automatic = true)` with the fixed reason
`no action taken`: NO sender added to the refused set (see below), `ModelRefused` notice queued for the human and, through the watch book,
`denied` to the sender (a "notify when idle" record is settled by that notice, so no later idle notice follows), and an
audit line `model_refused` whose reason field is `automatic` (the tool's line has none).
Hooks: model replies are recorded in `turn.rs` (`note_model_response`); the end-of-turn rule runs in `turn_task.rs::run_task`
through `peer_admit.rs::finish_peer_started_turn`.

### Decision (round 2): per-message only
`refuse_locked` is shared, but only the tool path (`refuse_by_model`, `automatic = false`) inserts the sender into
`refused_senders` (which makes later messages from it held as `sender_denied`) and marks the state dirty for persistence. The
automatic path records the refusal for that message id, queues the notice, writes the audit line (`automatic`), and the watch
is settled by the notice; it writes no per-sender state.
Why: the sender identity is only the envelope's claimed `from`. The inbox only checks the announced host id equals
`envelope.from` and says that is not a security claim (`peer_inbox/directory.rs`); any same-user process can send as session B.
Before this packet, holding B required the receiver's model to choose to call the refuse tool. With round 1, any reply without a
tool call held B, so one forged harmless message ("thanks!") would have held every later message from the real B until
`/peers clear-influence`. Now a forged message costs only itself.
Limits: a forged message can still be refused itself (it is a message that produced no action), and an attacker can still make
the model call the tool by prompt; that path is unchanged.

## Tests (mock inference server, no real service)
`acp_session_tests/peer_auto_refuse_tests.rs`: empty reply, refusal stop, text-only reply, tool-call turn, human-typed empty
turn, model refusing itself, flag off (also asserts the per-reply hook recorded nothing), and a contentless reply that fails the turn (left alone).

Also in `peer_admission_tests.rs`: `r2_automatic_refusal_is_per_message_and_does_not_hold_the_sender` (second message with the
same claimed `from` is delivered; this is the forged-sender scenario) and `r2_tool_refusal_still_holds_the_sender` (pins the tool
behaviour).

## Stated limits
- With the flag off, the per-reply hook is not called (one flag read per turn in `turn.rs`).
- Live runner: refuses a key shorter than 20 characters (redaction only matches whole secrets); mock mode requires a loopback
  endpoint (127.0.0.1 or localhost) in both the script and the test. It stays `#[ignore]` and was not run.
- What reaches the end of a turn as "no reply" is a reply with no visible text (whitespace only) or a content-less provider
  refusal stop. A reply with NO content at all is not accepted: the sampler resends it and, when the resends run out, the turn
  fails with an error the user already sees; such a turn is not judged (no notice, no refusal). Which of these the two live
  empty replies were was not determined here (the old branch's result file was not read).
- A peer message that joins an already running human turn (interjection) is not a turn started by a peer message and is not judged.
- The "model refuses itself" test calls the tool's handler directly in the turn; the tool dispatch path is covered by the
  existing S7.4 tests.
- A model that acts with a tool and says nothing is not refused (by design). A tool call that fails is still a tool call.
- The live runner was not run; its pass criteria were not changed (an automatic refusal is not a `refuse_peer_message` tool call).
- The notice appears in the TUI as a "Warning from a peer notice" line.
