# R-mcp-startup-report: a headless run says when an MCP server failed to start

Base 7f3c5972 (strike/integration). Branch strike/mcp-startup-report. Owner decision 33, 1.0.25.

## Cause
- The shell records a failed start in `McpState::init_failed` (`fuigo-shell/src/session/acp_session_impl/mcp.rs`, spawn failures ~L1585-1600 and
  `record_init_failure` in the handshake results ~L2063), emits a session event, and (handshake failures only)
  pushes `fuigo/mcp/server_status` via the dispatcher (`session/mcp_dispatcher.rs` `build_payload`, `HandshakeFailed`).
- TUI: `fuigo-pager/src/app/acp_handler/mcp.rs:177` `handle_mcp_server_status` patches the `/mcps` row (Unavailable) and the modal reads
  `init_failed` for the cause. Nothing is printed outside that modal.
- Headless: `headless/ext_protocol.rs` `handle_ext_notification` had no arm for `fuigo/mcp/server_status` (`_ => ExtEvent::None`), the
  init line's server status is a constant `"connected"` (`headless.rs` `mcp_server_names`), and a missing binary (spawn failure) pushed no
  status event at all. So nothing reached stderr, stdout or streaming-json.

## Change
- Shell: `push_start_failed_status` sends `fuigo/mcp/server_status` (`unavailable`, `handshake_failed`, detail capped at 200 chars) for every
  non-auth start failure, including spawn failures (mcp.rs). A repeat of the dispatcher's push is harmless (same row patch).
- Pager: `ext_protocol.rs` decodes only `unavailable` + `handshake_failed` to `ExtEvent::McpStartFailed`. `HeadlessEmitter::on_mcp_start_failed`
  reports each server name once per run and reuses the existing `ConfigNotice` lifecycle path (stderr `warning:` line in plain/json/
  streaming-messages-json; a `config_notice` line in streaming-json). `Lifecycle::mcp_start_failed` builds the text: name and reason pass
  through `scrub_unsafe_display`, only the first line of the cause is kept, URL user info/query/fragment are dropped, the reason is capped at
  200 chars, the name at 80. The config (env, headers) is never read here.

## Line and event
stderr (plain, json):
`warning: MCP server "dead" failed to start: MCP server 'dead' handshake failed: Send message error Transport [fuigo_mcp::servers::SafeTokioChildProcess] error: Broken pipe (os error 32), when send initialize request. Run `fuigo mcp doctor`.`
`warning: MCP server "missing" failed to start: Failed to spawn MCP server 'missing': No such file or directory (os error 2). Run `fuigo mcp doctor`.`
`warning: MCP server "silent" failed to start: MCP server 'silent' timed out after 5s. Run `fuigo mcp doctor`.`
streaming-json (stdout, existing type): `{"type":"config_notice","message":"MCP server \"dead\" failed to start: ... Run `fuigo mcp doctor`."}`

## Red / green
- Red (base build 7f3c5972, binary `fuigo-base`, mock model 127.0.0.1, `unshare -n`): dead, missing, silent, multi: exit 0, stderr 0 lines in
  plain, json and streaming-json (no config_notice line).
- Green (22b0c147 binary): plain and json: exactly 1 stderr line each for dead, missing, silent; multi (dead + healthy) 1 line; healthy 0; none 0.
  streaming-json: 1 `config_notice` line in stdout for dead, missing, silent, multi; 0 stderr lines. Exit 0 everywhere, as before.
  Stdout: plain byte-identical (`cmp`) to the no-MCP run for every case; json identical to the no-MCP run after zeroing the per-run
  ids and durations. Run time unchanged (dead/missing ~0.65 s, silent ~5.7 s = the 5 s start-up timeout).
- Unit (`cargo test -p fuigo-pager --lib -- headless mcp_start`): 271 passed incl. the 5 new tests (decode only failed starts; line text for
  the three causes; inert name with ESC/BEL/newline/quote, URL secret and 2nd line dropped, 200-char cap; one streaming-json notice per server;
  no stdout bytes in plain/json). They did not compile on base (new symbols).
- `cargo test -p fuigo-shell --lib -- mcp` 330 ok; `-p fuigo-extra-ca` all ok; `-p fuigo-auth --test secret_debug_guard` 2 ok.
- clippy `-p fuigo-pager -p fuigo-shell --lib --tests`: exit 0; the only warning in a touched file (headless_tests.rs:1029) is pre-existing.

## Not verified
- TUI behaviour with the extra push (not run; the row patch is idempotent by construction).
- OAuth/needs-auth servers are deliberately not reported (status `needs_auth` is ignored).
- A server that dies after a successful start (transport_closed) is not reported.
- The full `fuigo-pager` and `fuigo-shell` suites were not run, only the filtered subsets above. No test of the shell push itself beyond the e2e run.
- The cause text repeats the server name ("MCP server 'dead' handshake failed: ...") because it is the shell's error string.

## Round 2 (audit findings r1a, r1b)
Design change: the headless line no longer prints any server error text. It prints one fixed reason chosen from a closed set,
decided from the error TYPE in the shell and carried in `fuigo/mcp/server_status` as the new optional field `failureKind`
(`McpServerStatusPayload.failure_kind`, `skip_serializing_if` none, `#[serde(default)]`). Neither side uses `deny_unknown_fields`;
tested: a payload with no `failureKind` and one with an unknown extra field both decode (`payload_carries_failure_kind_and_tolerates_its_absence`).
A push without a kind is not reported by headless.

| Finding | Fix |
|---|---|
| 200-byte cut before URL redaction leaks a password | raw text removed from the headless line; fixed reasons only |
| header values, bearer tokens, env strings not scrubbed | same: no raw text reaches the line |
| HIGH: sign-in / 401 handshake printed "failed to start" (dispatcher pushes full `e.to_string()` incl. auth) | `failure_kind = NeedsAuth` (from `McpError::is_auth_rejection`, the existing classifier) is carried by BOTH pushes; headless drops it. Tests: 401 and needs-OAuth statuses decode to `ExtEvent::None`; `failure_kind_marks_sign_in_servers` |
| dedup missed names equal after the 80-char cap | de-dup keyed on the name as printed (after scrub, cap, quote softening). Rule: a second raw name that prints alike prints nothing, so two identical lines never appear; `fuigo mcp doctor` lists all |
| handshake status pushed twice | idempotent for the TUI: `duplicate_start_failed_push_leaves_one_unavailable_row` (same payload twice: same single row, no effect queued) |
| tests missing | 80-char cap (and 80 not cut), `type` field of the streaming-json line, valid JSON for a name with quotes and backslashes |
| release note | rewritten: nested backticks fixed, no `warning:` prefix in the event, fixed reasons listed, sign-in servers not reported |
| landable | merged `hub/strike/integration` (kept its header and known-limits section, added the Headless section) |

Classification (error type, `fuigo-mcp/src/servers.rs` `McpError::failure_kind` and `handshake_failure_kind`):
| failure_kind | maps from | fixed reason |
|---|---|---|
| needs_auth (not printed) | `is_auth_rejection()`: `AuthRequired`, or 401/auth wording per the existing classifier | none |
| command_not_started | `McpError::SpawnFailed` | the command could not be started |
| exited_before_answer | `HandshakeFailed` with `ClientInitializeError::ConnectionClosed`, or `TransportError` whose `transport_type_id` is `SafeTokioChildProcess` | the server exited before it answered |
| timeout {secs} | `McpError::Timeout.timeout_secs` (the real start-up timeout) | the server did not answer within N s |
| unreachable | `McpError::Unreachable`, or `HandshakeFailed` where `init_error_is_connect_phase` (reqwest `is_connect()`) | the server could not be reached |
| other | everything else | the start-up handshake failed |
Emitters: shell spawn path `acp_session_impl/mcp.rs` (`push_start_failed_status`, spawn failures) and handshake-results path; dispatcher
path `McpClientEvent::HandshakeFailed.failure` set at `ensure_initialized` (`e.failure_kind()`). The raw string never reaches a new sink:
`ExtEvent::McpStartFailed` holds only name and kind; stderr line and `config_notice` use the fixed reason. The raw `detail` stays only where
it was (`mcp doctor`, TUI, model-facing reminder); not widened.

Red / green (Hetzner, lane mcpw, mock model 127.0.0.1, `unshare -n`):
- Red: round-1 binary (22b0c147) printed raw text ("handshake failed: Send message error Transport [...]"); base printed nothing (round 1).
- Green (c5122a86 code): plain/json each exactly 1 stderr line for dead, missing, silent, multi, url; 0 for none and healthy; streaming-json 1
  `config_notice` (`type` field present) for dead/missing/silent/multi/url, 0 stderr; exit 0 throughout; plain stdout `cmp`-identical to the no-MCP run.
  URL case `http://user:SEKRETPW@127.0.0.1:1/mcp?token=SEKRETTOK`: line is `... "web" failed to start: the server could not be reached ...`; the
  password and token appear in NO file of stdout/stderr (grep over all outputs: 0). Silent case waited 5 s, line says `within 5 s`.
- Unit: `-p fuigo-pager --lib -- headless mcp` 423 ok; `-p fuigo-shell --lib -- mcp` 331 ok; `-p fuigo-mcp --lib -- failure_kind` 2 ok;
  `-p fuigo-extra-ca` ok; `-p fuigo-auth --test secret_debug_guard` ok. clippy `-p fuigo-pager -p fuigo-shell --lib --tests`: exit 0; one new
  `clone_on_copy` in my test, fixed afterwards (test-only change, not re-linted); remaining warnings in touched files are pre-existing.

## Not verified (Round 2)
- A real HTTP 401 handshake and a real OAuth server were not run end to end; covered by the classifier unit tests and status decode tests only.
- `ConnectionClosed` on an HTTP transport would print "exited before it answered" (the variant carries no transport).
- A future `failureKind` variant unknown to an older pager would fail that payload's decode (the TUI warns and skips the push).
- The full `fuigo-pager`/`fuigo-shell`/`fuigo-mcp` suites were not run, only the filtered subsets. TUI not driven by hand.

## Round 3 (audit grok-mcpw-r2: classification by typed evidence only)
Finding: `failure_kind` asked the word-matching `is_auth_rejection()` first, so a dead server whose text said "unauthorized" was silent, an OAuth
timeout printed "failed to start", and the two pushes did not share a rule. Fix: one shared function, `McpClient::start_failure_kind`
(`fuigo-mcp/src/servers.rs`), used by the dispatcher push (`ensure_initialized`) AND the shell push (`acp_session_impl/mcp.rs`, handshake-results path,
which now gates its push on the kind, not on `needs_auth`). `McpError::failure_kind` is now type-only and never reads the text.
`is_auth_rejection()` and its other callers (TUI, auth flow, `init_failure_needs_auth` result) are unchanged.

Classification order (`classify_start_failure`, servers.rs):
| # | rule | result | typed? |
|---|---|---|---|
| 1 | `McpError::AuthRequired` (spawn-time gate) | needs_auth (silent) | yes |
| 2 | not an HTTP/SSE client (stdio, in-process) | type-only kind: command_not_started / exited_before_answer / timeout / other; never needs_auth | yes (client transport) |
| 3 | `oauth_failure_needs_auth` (client has OAuth, error not `Unreachable`: the typed half of `init_failure_needs_auth`) or `has_typed_http_auth_status` (rmcp `StreamableHttpError::AuthRequired` / `InsufficientScope`, or a reqwest error with numeric status 401/403) | needs_auth (silent) | yes |
| 4 | HTTP and `is_auth_rejection()` (words only) | NEW sixth reason `server_rejected`: "the server rejected the connection (it may need sign-in)" | no, so a line prints |
| 5 | anything else | type-only kind | yes |
Is an HTTP 401 typed in this code base? NO on this path. A real 401 from a 127.0.0.1 mock (header-auth server, no OAuth) arrives as
`unexpected server response: HTTP 401 Unauthorized` (`UnexpectedServerResponse(String)`), i.e. a string, so it is `server_rejected` and prints the sixth reason
(test `http_401_from_mock_without_oauth_is_classified_by_evidence`, run with output: `typed=false kind=ServerRejected`). The typed branches exist for the rmcp variants
and numeric reqwest statuses and are covered by `typed_http_status_is_needs_auth_but_a_string_is_not`; no real server was seen producing them.
Unknown `failureKind`: `McpServerStatusPayload.failure_kind` has a lenient decoder; an unknown string or struct value becomes `McpFailureKind::Unknown` and the rest
of the payload survives; headless prints "the start-up handshake failed". Release notes corrected, six reasons listed.

Red / green (Hetzner lane mcpw, `unshare -n`, mock model on 127.0.0.1):
- RED (round-2 binary c5122a86): stdio server answering `initialize` with a JSON-RPC error "401 Unauthorized authentication failed" (`authwords2.sh`): 0 stderr lines (silent) for plain and json.
  Old unit test asserted `ConnectionClosed("HTTP 401 Unauthorized").failure_kind() == NeedsAuth`; replaced by `failure_kind_marks_sign_in_servers_only_on_typed_evidence`.
- GREEN (this round): same case 1 line each for plain/json, 0 for streaming-json stderr (config_notice on stdout stream): `... "aw" failed to start: the start-up handshake failed.` (the error is a service error, so kind `other`, not `exited_before_answer`).
  A plain exit-1 stdio server that merely prints the words (`authwords.sh`) gives `the server exited before it answered` on both binaries (error text does not carry the output).
- Re-run e2e set (dead, missing, silent, healthy, multi, url, none): unchanged from round 2 (1 line for failures, 0 for none/healthy, exit 0, URL password/token appear in no output).
- Unit: `-p fuigo-mcp --lib` 308 ok (incl. `stdio_server_with_auth_words_is_not_needs_auth`, p151 OAuth client -> NeedsAuth via the shared function); `-p fuigo-pager --lib -- headless mcp` 424 ok;
  `-p fuigo-shell --lib -- mcp` 331 ok; `-p fuigo-extra-ca` and `-p fuigo-auth --test secret_debug_guard` ok. Clippy `-p fuigo-mcp -p fuigo-pager -p fuigo-shell --lib --tests` exit 0, no warnings in touched files.

## Not verified (Round 3)
- OAuth-timeout silence is covered by the pure-function test and the p151 real-client test (OAuth client, 401 mock); a real OAuth server timeout was not run end to end. Both pushes call the same function but no test drives both pushes for one failure.
- A `server_rejected` server that also sits in the shell's `auth_required` list is now pushed as Unavailable (with detail) to the TUI too; the TUI was not driven by hand.
- Typed 401/403 branches have no live producer in the tests.
