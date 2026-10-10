# R-w3b: three TUI text fixes (1.0.24, owner decision 25a)

Branch `strike/w3b-text`, base integration `cd9d3eab`. Trailer Sonnet 5.5.

## Item 1: duplicated retry advice - done
- Site: `fuigo-pager/src/app/error_display.rs` `compose_detail` (+ new `is_retry_advice`). Bridge texts unchanged
  (`STALE_REQUEST_ERROR_MESSAGE` made `pub(crate)` for the test).
- Before: "Request failed: The Fuigo leader restarted ... nothing was sent. Try again. Try sending again."
- After: "...nothing was sent. Try again." (detail kept, generic action dropped when both are retry advice,
  i.e. both contain the words "try" and "again").
- Tests: `leader_restart_messages_carry_retry_advice_once` (red first, both bridge messages, exactly one sentence
  starting "Try"), `detail_without_retry_advice_still_gets_try_sending_again` (guard).
- Identity table (`clean_input_renders_exactly_as_on_integration`): not present at this base; no rows changed.

## Item 2: site not found (no code changed)
Traced: a submit while `reconnect_pending` returns at `dispatch/prompt.rs:482` (`dispatch_send_prompt_inner`) with a
toast, BEFORE the composer is consumed (comment at ~859-861 says so on purpose). The text therefore stays in the
composer untouched; a second submit just resubmits the whole composer content, so two texts are never joined.
Other gates: `prompt.rs:1029` (bash command), `queue.rs:1229` (edited queued command; row stays queued),
`prompt.rs:1568` / `1730` (drain skipped, no text). The transport-loss branch (`prompt.rs` ~1220) does not touch the
composer either (it prints the text in a system line). `append_text` only in `rewind.rs:503` (adds a newline).
Possible repro for a real TUI: while reconnecting, type "one", Enter (toast), keep typing " two" and Enter again,
then look at the composer after the reconnect; and try `Ctrl+R`-style restore / rewind with a held draft. If the
report is "two prompts glued together", it may come from the rewind path or from typing after the toast without
clearing; needs a real repro. Item 2: site not found.

## Item 3: queued prompt dropped silently - done
- Site: `dispatch/prompt.rs` ~1220, new `else if let Err` branch after the transport-loss branch.
- The text CANNOT go back to the composer (the transport-loss branch does not do that either; it prints the text in
  the line), so I mirrored it: one system line with the text on a second line.
- Text: "Your message was not sent: <detail>.\n<message text>" with detail from `format_request_failure(..).message()`
  through `untrusted`. The user's own message text is shown raw like the transport-loss branch (untrusted would cap
  it at 2048 columns and lose recoverability).
- Detail reads e.g. "Request failed: unknown session id. Try sending again" (trailing period trimmed, then re-added).
- Test: `p152_a_lost_queued_prompt_is_reported_not_dropped` changed. Before: `Request removed from queue` error
  expected silence. After: error `unknown session id` yields exactly one "Your message was not sent" line with the
  detail and text; transport-loss keeps its own wording (guard). Expectation changed on purpose: it pinned the bug.
- Not touched: `event_loop.rs` ~3456 clears `reconnect_pending` before `init_ok` is checked; possible root cause for a
  later packet.

## Unverified
No live TUI run. Proof table: see report (commit and exit codes filled by coordinator report).

## Round 2 (audit HIGH + LOW)
- HIGH: queue text (maybe from another client) was printed raw after a newline. New private `queued_text_rows` in
  `dispatch/prompt.rs`: each line through `untrusted`, indented two spaces (first too), max 20 rows then
  "  … (N more lines)". Used in BOTH branches. Format is now "…not sent: <detail>.\n  <line1>\n  <line2>".
- `{message}` in the transport-loss branch: `is_transport_loss_error` matches by `contains`, so it can carry outside
  text; now passed through `untrusted`.
- Tests: `queued_text_rows_are_indented_and_filtered_in_both_branches`, `queued_text_rows_are_capped_at_twenty_in_both_branches`.
  Existing tests used `contains` on the text, so none needed changing.
- LOW: `is_retry_advice` replaced by exact phrase set (`RETRY_PHRASES`): suppress the action only when the detail's
  last sentence AND the whole action are in the set. Test `compose_detail_keeps_the_action_unless_both_are_plain_retry_advice`.
