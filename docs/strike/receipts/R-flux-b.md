# R-flux-b: a 401 on /v1/models no longer keeps the background refresh going

Branch `strike/flux-b-models`, base integration `ac124b5a`. Red commit `6e8f78a7`, fix commit `3f1e91eb` (+ follow-ups, see the report).

## Every code path that fetches the model list
| Trigger | Period | Before, on 401 | Now, on 401 |
|---|---|---|---|
| Startup prefetch (`agent/app.rs` 532, `agent/server.rs` 355) | once per process | one request, no state | unchanged (not throttled: process start) |
| Startup catalog ladder (`models.rs` `spawn_catalog_retry`, 5 tries, 5/10/20/40 s) | once per start | all 5 tries sent (5 requests) | try 2-4 are skipped, try 5 (75 s) sent |
| Auth-refresh watcher (`start_auth_refresh_watcher`, woken by each successful token refresh) | per refresh, unbounded | fetched every time | skipped while the wait runs |
| Etag refresh (`spawn_fetch`, after a good response with a new etag) | per response | fetched | skipped while the wait runs |
| `on_auth_changed` (login, config reload, subscription unblock) | per event | fetched, started a new ladder | goes through the same wait; a different key/token passes at once |
No fetch is user-driven: the model picker and starting a turn read the in-memory catalog. All paths end in `fetch_throttled` (`models.rs`), so no path can restart a fast loop. A 403 is NOT changed: it is `Unavailable`, as before (no wait, no note). Timeouts, 5xx, 429: unchanged.

## Cause of the 65 s
NOT reproduced. The only periodic code I found is the auth-refresh watcher (woken per successful token refresh) and the ladder; the ladder is bounded (5 tries over 75 s). With a stdio agent and with the TUI, against a 401 mock, the shell sent exactly 6 requests in 10 minutes and then none. 65 s is not a constant in the models code; the most likely source is a trigger that repeats about every minute (a token refresh cycle, or a host that restarts the agent: a ladder is 75 s long). Code in 1.0.20 `agent/models.rs` is the same as integration for these paths. The unit tests model it as a wake every 65 s.

## Backoff, reset, notice
- Wait after the 1st, 2nd, ... consecutive 401 for the same credential: 1, 2, 4, 8, 16, then 30 minutes (stays at 30).
- Reset only by: a different credential (fingerprint of env key + session token, in memory, never logged), which covers a new key and a token a refresh replaced; or a 200. A refresh that returns the same token does not reset (that would bring back the loop).
- Notice (fixed text, no outside value): "Fuigo could not load the model list: the API key or sign-in was rejected (401). Sign in again or check your API key. Fuigo will retry less often until then." Once per rejection run (re-armed by a 200). Shown through `SessionCommand::NotifyConfigNoticeIfNew` (the `ConfigNotice` session update) to every session, at its start or when it lands.

## Request counts
| Run | Before | After |
|---|---|---|
| Unit, 10 min, wake every 65 s + ladder | 15 | 4 (table max 4) |
| Unit, 24 h, same | 1335 | 52 (table max 52) |
| Stdio agent, mock 401, 10 min, fake key | 6 (gaps 0.1, 5, 10, 20, 40 s) | 3 (gaps 0.0, 75 s) |
| TUI in a pty, same | 6 (same gaps) | 3 (0.1, 75 s) |
| Stdio agent, no key | 0 | not rerun |

## Tests
`agent::models::tests::auth_reject::{ten_minutes_of_401_make_at_most_four_requests, a_day_of_401_makes_at_most_fifty_two_requests, the_sign_in_again_note_is_sent_once, a_new_credential_resets_the_wait_and_a_200_restores_the_refresh}` and `agent::mvp_agent::agent_ops::auth_notice_forward_tests`. The red commit fails by assertion (15 > 4, 1335 > 52). The fake endpoint in the fix commit gained a `fetch_models_outcome` override that answers 401 (test scaffolding, no existing expectation changed). Guard `cargo test -p fuigo-extra-ca` green (no pinned file changed).

## Unverified
No run against the real service (by rule). The "sign in again" note was not seen on a real ACP session wire (unit-tested to reach the session command channel). Version 1.0.20 itself was not run. The real 65 s source was not found.
