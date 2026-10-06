# P70b Astra round 1 (gpt-6-astra, read-only, codex 0.160)

Raw transcript (1114 KB, not committed): `hetzner-dsm:/root/fuigo-builds/p70b/p70b-astra-r1.raw.txt`, sha256 `cd411e920603515bd0a06ec0f6eab3f6fc865c7b467cecc7ff586cc9247a6b88`.

Audited: `e0145e0f..7bc6912a`. Verdict: **DO-NOT-LAND** (10 HIGH, 4 MEDIUM). What was done per finding: receipt R088 §5.

## Brief

```
Independent audit, round 1, of Fuigo packet P70b. Repo: /Volumes/Mando/WaylandBots/Fuigo/wt-p70b (read-only; do NOT run cargo or any build; do NOT read docs/strike/audits/). Branch strike/p70b, HEAD 7bc6912a. Audit `git diff e0145e0f..7bc6912a` (parent e0145e0f = strike/integration).

Threat: an upstream (model provider or proxy) echoes a credential the client sent back inside its error text, and that text is shown to the user, written to a log, or exported as telemetry. Sean accepted this design ("option A"); audit the code against it, not against a different design:
 (1) CLASSIFY FIRST: nothing is scrubbed before the error is classified. The sampler and the shell decide retry/compact/strip-images/re-auth/friendly-message on the error text exactly as it arrived; SamplingError and the in-process SamplingErrorInfo keep raw text.
 (2) SCRUB ONLY AT DISPLAY AND LOG SINKS.
 (3) EXACT-MATCH replacement of the credentials ACTUALLY SENT, 8 chars or more, with "<redacted>".
 (4) NO token-shaped heuristic in this path (the pre-existing telemetry regexes in fuigo-secrets stay as they were).
A previous attempt (P70, branch strike/p70-s20) scrubbed before classifying and never converged; do not re-propose that.

What the packet does:
- crates/codegen/fuigo-secrets/src/sent_credentials.rs: process-wide registry (record, record_header_value, scrub, scrub_bytes, scrub_in_place, scrub_json_strings, safe_cut, truncate_chars, ScrubWriter). Overlapping occurrences are unioned; postcondition: output contains no recorded credential (else WITHHELD, else ""). The JSON-escaped spelling is recorded too. Capacity 256, FIFO. redact_secrets (telemetry chokepoint used by OTLP internal/external, Sentry, Mixpanel) now applies the exact match first.
- Recording: crates/codegen/fuigo-sampler/src/sent_credentials.rs record_request, called in client.rs dispatch_request (all non-subscription sampler egress) and subscription.rs dispatch after authorize_request. Every header value except a fixed non-credential list, URL userinfo, every query value (raw and percent-decoded).
- Truncation before a sink never cuts through a recorded credential (cut moves PAST it): fuigo-sampling-types error.rs truncate_upstream_text (also provider_error.rs), sampler client.rs body_preview, shell unified-log fields (sampler_turn.rs log_terminal_failure, sampling_events.rs, compaction.rs, subagent/handle_request.rs).
- Log sinks: fuigo-telemetry appender.rs scrubbed_non_blocking used by every telemetry file log (debug_log, sampling_log, hooks_log, memory_log, instrumentation), unified_log.rs write_lines; fuigo-pager tracing.rs channel writer; fuigo-pager-bin main.rs stderr fmt writer.
- Display sinks (shell): agent/credential_scrub.rs ScrubSentCredentials wraps the acp::Agent so every acp::Error returned to a client (message + every data string) is scrubbed; agent_side_connection() is now how every production transport builds the connection (agent/server.rs, agent/app.rs x2, leader/in_process.rs; also the test harness). extensions/notification.rs SessionUpdate::scrub_sent_credentials (RetryState, AutoCompactFailed, AutoRecoveryStarted/Exhausted, SubagentFinished.error, MemoryFlush/DreamCompleted.result) applied at the top of send_fuigo_notification_with_extra_meta and send_fuigo_notification_transient (covers client, updates.jsonl, retry mirror, notification hooks).
- Tests: fuigo-shell tests/upstream_credential_echo_acp.rs (real MvpAgent + real SamplingClient + mock 400 echoing the key: no key in the error reply or any notification; FAILS at the parent), fuigo-sampler tests/upstream_credential_echo.rs (credential == classifier marker still classifies; SamplingErrorInfo keeps raw), unit tests in each touched module.

Tasks:
A. Classify-first: find ANY place where scrubbed text (or text altered by the new truncation) is later used to decide behaviour (retry, compaction, image stripping, re-auth, budget denial, suppress reasons, friendly messages, telemetry error_type), anywhere in the workspace. file:line and scenario.
B. Sink completeness: find every path by which upstream error text from the sampler (SamplingError / SamplingErrorInfo / stream error events / subscription errors) reaches (i) the user or an ACP client (any transport: stdio, relay bridge, leader/in-process, headless/pager output), (ii) a log file or stderr, (iii) telemetry, (iv) persisted session files, hook inputs or subagent results — and say whether the packet scrubs it. Also: other credentialed upstream requests (models list fetch, OIDC refresh, etc.) whose error text is shown/logged — in scope only as findings to rate.
C. Recording completeness and correctness: is every credential the sampler actually sends recorded (all auth schemes, bearer resolver, extra_headers, env_http_headers, header injector, subscription, query, userinfo, mTLS)? Is anything recorded at the wrong time (race: error displayed before record)? Can recording damage anything (over-recording a public value that then breaks behaviour rather than just display)?
D. Correctness of the scrub primitives: overlap/union, postcondition, char boundaries, JSON/Debug escaping, ScrubWriter framing (does every production log writer hand a whole record to one write() call? tracing_appender worker, fmt layer, pager channel, stderr), capacity/eviction, lock poisoning, performance on the hot logging path (every log line now takes a read lock and scans up to 256 needles).
E. Anything first-party that breaks: behaviour/byte changes when nothing was recorded or nothing matches; the ACP wrapper (all Agent methods delegated incl. defaults? Rc/leader paths); test isolation of the process-wide registry.
F. Name every behavioural mutation of the P70b production code that would survive the tests.
Severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
```

## Final report

P70b does not meet the accepted option-A contract. I found credential leaks at reachable sinks, classification after scrubbing, and credential-dependent truncation before classification.

This audit is pinned to **`e0145e0f..7bc6912a`**. No Cargo, builds, or Rust tests were run; `docs/strike/audits/` was not read. During inspection, another actor advanced HEAD to `39875b1d` with additional tests and modified another test file. Those changes were left untouched and excluded from this verdict.

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Round 1 independent source audit completed |
| A — Classification | ✅ Done | Behaviour-changing paths identified |
| B — Sinks | ✅ Done | Protected paths and concrete bypasses traced |
| C — Recording | ✅ Done | Dispatch coverage, omissions, and timing reviewed |
| D — Primitives | ✅ Done | Framing checked against pinned dependency source; correctness and cost reviewed |
| E — First-party compatibility | ✅ Done | Protocol-field corruption and test interference identified |
| F — Mutation coverage | ✅ Done | Source-predicted survivors listed; no executed mutation claim |

Paths below are under `crates/codegen/` unless stated otherwise.

1. **HIGH — The ACP wrapper changes machine-readable decisions, including headless budget-denial handling.**

   [`fuigo-shell/src/agent/credential_scrub.rs:21`](crates/codegen/fuigo-shell/src/agent/credential_scrub.rs:21) scrubs **every string value** in `Error.data`, including locally generated `code`, `rule`, and `error_kind`.

   Concrete scenario: a previous sampler request sends the credential `execution_budget_denied`. A subsequent budget refusal has `data.code` replaced with `<redacted>`. [`fuigo-pager/src/headless.rs:2394`](crates/codegen/fuigo-pager/src/headless.rs:2394) then misses `ExecutionBudgetDenial::is_budget_denial`, losing the documented exit-3/denial-record behaviour. Similarly, a credential equal to `empty_response` changes the pager’s interpretation of `error_kind`.

   **Change-induced. Tests:** the wrapper test uses an unrelated credential and checks only that `"auth"` remains unchanged. It does not test credential collisions with protocol discriminators.

2. **HIGH — Retry notifications are scrubbed before the pager makes behavioural decisions.**

   The new scrub at [`fuigo-shell/src/extensions/notification.rs:1183`](crates/codegen/fuigo-shell/src/extensions/notification.rs:1183) precedes these consumers:

   - [`fuigo-pager/src/app/acp_handler/session_notification.rs:1676`](crates/codegen/fuigo-pager/src/app/acp_handler/session_notification.rs:1676): credit blocking, free-usage blocking, and re-auth selection.
   - [`fuigo-pager/src/app/acp_handler/session_notification.rs:1716`](crates/codegen/fuigo-pager/src/app/acp_handler/session_notification.rs:1716): failed-notification credit blocking and re-auth.
   - [`fuigo-pager/src/app/error_display.rs:172`](crates/codegen/fuigo-pager/src/app/error_display.rs:172): status recovery, friendly-message selection, and detail suppression.
   - [`fuigo-pager/src/app/dispatch/prompt.rs:1238`](crates/codegen/fuigo-pager/src/app/dispatch/prompt.rs:1238): fallback credit handling and prompt retention for recovery.

   Concrete scenario: credential `run out of credits`, HTTP 403, with that phrase in the error. Scrubbing removes the phrase required by `is_credit_limit_error`; both notification and reply handling lose the legacy credit-block classification. Credential `subscription:free-usage-exhausted` similarly defeats the free-usage check. These decisions also determine whether `CreditLimitHit` telemetry is emitted.

   **Change-induced. Tests:** the marker regression stops at `SamplingErrorInfo`; it never drives the pager with a scrubbed classifier marker.

3. **HIGH — The new truncation changes text subsequently used for classification.**

   [`fuigo-sampling-types/src/error.rs:769`](crates/codegen/fuigo-sampling-types/src/error.rs:769) changes the message stored in `SamplingError::Api`, before classifiers run.

   Concrete example: a `server_error` envelope containing 275 `x` characters followed by credential `Could not process image`. The parent’s 280-character cap excludes the complete phrase; P70b extends through it. [`error.rs:448`](crates/codegen/fuigo-sampling-types/src/error.rs:448) therefore changes from false to true, potentially triggering image removal.

   The same dependency exists for context overflow, encrypted-content rejection, overload, and downstream compaction suppression. [`fuigo-shell/src/session/compaction.rs:1261`](crates/codegen/fuigo-shell/src/session/compaction.rs:1261) classifies the resulting message into suppression reasons.

   Preserving the old prefix does **not** preserve classification: added suffixes can complete a marker. `SamplingErrorInfo` preserves the resulting message, not the entire upstream text.

   **Change-induced. Tests:** the truncation test asserts extension; the classification test places its marker near the beginning. Neither tests their interaction.

4. **HIGH — Subagent errors bypass the notification scrub, persist raw, and escape in successful ACP responses.**

   The complete path is present:

   - [`fuigo-shell/src/agent/subagent/prompt_turn_result.rs:162`](crates/codegen/fuigo-shell/src/agent/subagent/prompt_turn_result.rs:162) copies the raw session error into `SubagentResult.error`.
   - [`fuigo-shell/src/agent/subagent/spawn.rs:359`](crates/codegen/fuigo-shell/src/agent/subagent/spawn.rs:359) puts it into `SubagentFinished`.
   - [`spawn.rs:527`](crates/codegen/fuigo-shell/src/agent/subagent/spawn.rs:527) serializes and forwards that notification directly, bypassing both scrubbed send helpers.
   - [`fuigo-shell/src/session/acp_session_impl/updates.rs:938`](crates/codegen/fuigo-shell/src/session/acp_session_impl/updates.rs:938) persists the forwarded notification without the credential scrub.
   - [`fuigo-shell/src/agent/subagent/mod.rs:2370`](crates/codegen/fuigo-shell/src/agent/subagent/mod.rs:2370) copies it into `meta.json`.
   - [`fuigo-shell/src/extensions/task.rs:337`](crates/codegen/fuigo-shell/src/extensions/task.rs:337) exposes it as `failure_error`; `fuigo/subagent/get` returns this inside **`Ok(ExtResponse)`**, which the ACP wrapper intentionally leaves untouched.

   A child receiving an ordinary 400 credential echo can therefore leak it through the parent connection and persisted session data.

   **Existing paths left unprotected. Tests:** the notification unit test calls `scrub_sent_credentials` directly; the ACP regression runs no subagent.

5. **HIGH — `StopFailure` hook inputs retain the credential.**

   [`fuigo-shell/src/session/acp_session_impl/turn.rs:1489`](crates/codegen/fuigo-shell/src/session/acp_session_impl/turn.rs:1489) constructs `error_details` and `last_assistant_message` from the raw error. [`turn_end_hooks.rs:54`](crates/codegen/fuigo-shell/src/session/acp_session_impl/turn_end_hooks.rs:54) clips them but does not scrub them.

   Command hooks receive serialized input at [`fuigo-hooks/src/runner/command.rs:244`](crates/codegen/fuigo-hooks/src/runner/command.rs:244); HTTP hooks serialize the same envelope at [`runner/http.rs:204`](crates/codegen/fuigo-hooks/src/runner/http.rs:204).

   The notification-hook protection does not cover this separate hook family.

   **Existing path left unprotected. Tests:** no credential-echo hook assertion.

6. **HIGH — Goal failure messages escape through ordinary message chunks and goal state.**

   [`fuigo-shell/src/session/acp_session_impl/turn_end.rs:538`](crates/codegen/fuigo-shell/src/session/acp_session_impl/turn_end.rs:538) uses raw error detail to pause an active goal and emit `Goal paused due to turn error: …`.

   [`fuigo-shell/src/session/acp_session.rs:1418`](crates/codegen/fuigo-shell/src/session/acp_session.rs:1418) sends this as an ordinary `AgentMessageChunk`. Goal state separately carries `pause_message`/event detail through [`goal_orchestrator.rs:81`](crates/codegen/fuigo-shell/src/session/goal_orchestrator.rs:81), which directly persists and forwards notifications.

   Concrete scenario: an active goal encounters an infrastructure-classified API failure containing its sent key. The error reply may be clean while the conversation message and goal snapshot contain it.

   **Existing paths left unprotected. Tests:** no active-goal fixture.

7. **HIGH — Several diagnostic persistence/export sinks remain raw.**

   | Sink | Source and scenario | Packet coverage |
   |---|---|---|
   | `btw_history.jsonl` | [`recap.rs:204`](crates/codegen/fuigo-shell/src/session/acp_session_impl/recap.rs:204): failed `/btw` persists `err.to_string()` | None |
   | `recap_requests/*.json` | [`recap.rs:366`](crates/codegen/fuigo-shell/src/session/acp_session_impl/recap.rs:366): failed recap stores sampler error | None |
   | `compaction_requests/*.json` | [`compaction.rs:2260`](crates/codegen/fuigo-shell/src/session/compaction.rs:2260): error and attempt diagnostics | None |
   | `turn_result.json` trace export | [`agent/mvp_agent/mod.rs:2378`](crates/codegen/fuigo-shell/src/agent/mvp_agent/mod.rs:2378), plus normal prompt and subagent upload arms | None |
   | Optional laziness debug log | [`laziness.rs:513`](crates/codegen/fuigo-shell/src/session/acp_session_impl/laziness.rs:513) → [`laziness.rs:215`](crates/codegen/fuigo-shell/src/session/acp_session_impl/laziness.rs:215): direct file write with `error_detail` | None |

   [`fuigo-shell/src/upload/trace.rs:730`](crates/codegen/fuigo-shell/src/upload/trace.rs:730) serializes turn-result metadata directly and sends it through artifact upload. It does not pass through OTLP/Sentry/Mixpanel’s redaction chokepoint.

   **Existing sinks left unprotected. Tests:** the packet’s ACP regression does not inspect these files, uploads, or optional log.

8. **HIGH — Normal JSON-in-JSON logging defeats the single escaped spelling.**

   [`fuigo-secrets/src/sent_credentials.rs:53`](crates/codegen/fuigo-secrets/src/sent_credentials.rs:53) records only raw and once-JSON-escaped forms.

   But [`fuigo-sampler/src/client.rs:1565`](crates/codegen/fuigo-sampler/src/client.rs:1565), `:1951`, and `:2263` log raw SSE JSON as a string field. [`fuigo-telemetry/src/sampling_log.rs:61`](crates/codegen/fuigo-telemetry/src/sampling_log.rs:61) JSON-encodes that string again.

   With a valid header credential such as synthetic `pa"ss\word-123`, neither recorded spelling occurs in the final log bytes. Parsing the log’s `data` and then the SSE JSON recovers the complete credential. I confirmed that spelling mismatch with a small ASCII JSON probe; this was not a Rust/runtime test.

   This is ordinary protocol and logger serialization, not a demand to support arbitrary upstream credential transformations.

   **Protection defect. Tests:** the escaping test covers one JSON encoding and one Debug rendering, not nested serialization.

9. **HIGH — Recording does not cover every credential actually transmitted.**

   Three concrete omissions:

   - **Excluded-header overrides:** [`fuigo-sampler/src/sent_credentials.rs:45`](crates/codegen/fuigo-sampler/src/sent_credentials.rs:45) skips names irrespective of provenance. `extra_headers`, `env_http_headers`, and the final injector can provide values for names such as `originator` or `tracestate`. A proxy credential configured there is sent but never recorded.
   - **Cookie components:** [`fuigo-secrets/src/sent_credentials.rs:76`](crates/codegen/fuigo-secrets/src/sent_credentials.rs:76) records the whole header and a space suffix. For `Cookie: session=plainword123`, a server echoing `plainword123` is not scrubbed. Parameterized auth headers have the same component problem.
   - **Transport-added proxy authentication:** recording occurs before `reqwest::Client::execute`. Pinned reqwest 0.12.24 adds proxy authentication inside `async_impl/client.rs:2502`. An HTTP proxy can echo the exact transmitted Basic token in a structured error, but that token was absent from the inspected `Request`.

   **Protection defects. Tests:** no excluded-name override or authenticated-proxy fixture; the cookie test asserts only the whole `session=…` header value.

10. **HIGH — Eviction can forget a credential before its error reaches any sink.**

    [`fuigo-secrets/src/sent_credentials.rs:69`](crates/codegen/fuigo-secrets/src/sent_credentials.rs:69) evicts without regard to outstanding requests or buffered records.

    Two concrete cases:

    - Request A remains pending while other requests register enough distinct values; A’s eventual error leaks.
    - One request records its auth headers, then 256 distinct query values. URL recording happens after headers, so the same request can evict its own authentication credential before dispatch.

    The capacity counts **spellings**, not credentials: bearer prefixes and escaped forms consume additional slots. Scrubbing in the appender worker, rather than before enqueue, extends the eviction window.

    **Protection defect. Tests:** the capacity test deliberately verifies forgetting; it does not verify in-flight or queued-error confidentiality.

11. **MEDIUM — Compaction still cuts or rewrites credentials before the protected sink.**

    [`fuigo-shell/src/session/helpers/session_compact.rs:93`](crates/codegen/fuigo-shell/src/session/helpers/session_compact.rs:93) collapses whitespace, rewrites service names, and applies an ordinary 300-byte truncation.

    A stream error whose credential straddles that boundary reaches the ACP wrapper or `AutoCompactFailed` with only a prefix remaining. Exact matching cannot remove it. The new credential-safe upstream cap does not protect this later cap.

    **Existing transformation left incompatible with the new scrub. Tests:** no compaction-boundary credential case.

12. **MEDIUM — Byte scrubbing can corrupt structured log records.**

    [`fuigo-secrets/src/sent_credentials.rs:145`](crates/codegen/fuigo-secrets/src/sent_credentials.rs:145) matches across JSON syntax.

    Concrete valid header credential: `"message"`, including the quotes. A log containing `{"message":"upstream error"}` becomes `{<redacted>:"upstream error"}`, invalid JSON. The WITHHELD fallback likewise replaces an entire JSONL record with unquoted text and drops its terminating newline.

    **Change-induced. Tests:** existing log tests use credentials inside values; they do not parse output after structural collisions or WITHHELD fallback.

13. **MEDIUM — The logging cost is not bounded by 256 in a useful worst-case sense.**

    [`sent_credentials.rs:146`](crates/codegen/fuigo-secrets/src/sent_credentials.rs:146) scans each needle across the entire buffer, collects every occurrence, sorts them, and checks the output again while retaining the read lock.

    `safe_cut` can also extend through arbitrarily long overlapping runs. Consequently, nominal 280/500-character limits no longer bound subsequent work.

    As a concrete complexity example, a 1 MiB repeated-`a` buffer with registered needles `a⁸` through `a²⁶³` produces **268,401,024 occurrence pairs**—approximately 4 GiB just for pair storage on a 64-bit target. This is arithmetic, not a measured production benchmark. Routine latency remains unmeasured.

    **Change-induced performance risk. Tests:** no adversarial-length, match-density, or contention coverage.

14. **MEDIUM — Registry tests can interfere with existing sanitizer tests.**

    [`fuigo-secrets/src/sent_credentials.rs:351`](crates/codegen/fuigo-secrets/src/sent_credentials.rs:351) registers `abcdefgh` under a module-local mutex. [`fuigo-secrets/src/sanitizer.rs:437`](crates/codegen/fuigo-secrets/src/sanitizer.rs:437) concurrently expects strings such as `disk-0123456789abcdefghijklmno` to remain unchanged, without that mutex.

    Those expectations now depend on test scheduling. The sampler’s test mutex likewise does not serialize every other test that dispatches a real mock request and consequently records credentials.

    **Change-induced. Tests:** this is a possible failure of existing tests, not an observed run result.

The remaining recording and primitive checks were as follows:

| Area | Result |
|---|---|
| Bearer and `x-api-key` | Final header values are recorded before dispatch |
| Bearer resolver and header injector | Ordering is correct for non-excluded headers: resolver/injector finish before recording |
| Subscription inference | Records after `authorize_request`; raw error classification remains internal |
| Query values | Raw, percent-decoded, and form-style `+` variants are implemented |
| URL userinfo | **MEDIUM coverage limitation:** production reqwest extracts userinfo into Basic auth before recording. The unit test constructs `Request` directly, bypassing this. Encoded Basic material is recorded; separate username/password spellings generally are not |
| mTLS | Private key is not transmitted and should not be described as a missed echoed secret. Public certificate material is outside this text registry |
| Recording race | No ordinary response-before-record race at the two dispatch sites. Eviction and transport-added auth remain problems |
| Unsent values | Subscription deadline/client construction and dispatch URL rejection can fail after recording; registry membership therefore means “prepared for dispatch,” not proven sent |
| Overlap and union | Correct by inspection, including overlapping occurrences and adjacent covered ranges |
| Postcondition | Correct for the registry snapshot held during `scrub_bytes`; not a lifetime guarantee after eviction |
| Character boundaries | Production `truncate_chars` supplies valid boundaries; matching UTF-8 needles preserves them |
| Poisoning | Locks recover their contents; no fail-open empty-registry substitution |
| Empty registry/no match | No unintended text/byte changes found in the reviewed production paths |
| ACP delegation | All methods in pinned ACP 0.10.4, including defaults and `Rc` forwarding, are delegated |
| Added heuristics | None found; existing telemetry regex definitions are unchanged |

For sink completeness, the protected and unprotected routes are distinguishable:

| Route | Assessment |
|---|---|
| Ordinary ACP error replies: stdio, relay bridge, leader/in-process, headless connection | Wrapper installed at all production construction sites inspected; subject to findings 1, 8–11 |
| Retry, recovery, memory-result and turn-completion notifications through the two modified helpers | Scrubbed before client/persistence/notification-hook fan-out |
| Standard ACP retry mirror | Receives scrubbed retry state |
| Stream errors / `SamplingErrorInfo` | Remain internal and unscrubbed; normal failure handling reaches the above sinks |
| Subscription inference errors | Same downstream coverage after subscription recording |
| Debug, sampling, hooks, memory and instrumentation **log-mode** files | Wrapped; nested serialization and eviction remain limitations |
| Unified log, pager tracing channel, tracing stderr | Scrubbed |
| Headless plain/JSON and pager rendering | Inherit protection from ACP; do not repair bypassed notifications or successful error-bearing results |
| Subagent notifications, status results, metadata | Unprotected paths confirmed |
| Goal messages and goal snapshots | Unprotected paths confirmed |
| `StopFailure` hooks | Unprotected |
| `/btw`, recap, compaction artifacts, turn-result uploads, laziness debug file | Unprotected |
| Internal/external OTLP, Sentry, Mixpanel | Exact pass reaches existing redaction paths; this does not cover separate trace-artifact uploads |

**Writer framing is not a confirmed defect in the wrapped production paths.** Pinned tracing-subscriber 0.3.23 formats an event into a buffer and calls `write_all` once; tracing-appender 0.2.4 preserves each submitted buffer. The custom debug router also submits complete formatted lines. `ScrubWriter` then consumes the whole input buffer. Its documented inability to join separate writes is real, but I did not find that fragmentation in these wrapped paths.

Chrome instrumentation uses a separate unwrapped writer at [`fuigo-telemetry/src/instrumentation.rs:324`](crates/codegen/fuigo-telemetry/src/instrumentation.rs:324). I did **not** establish an upstream-error-bearing event reaching that filtered writer, so this is a coverage limitation, not another proven leak.

Other credentialed requests have these **follow-up findings**, separate from sampler packet corrections:

| Severity | Location | Concrete exposure | Test coverage |
|---|---|---|---|
| HIGH | [`fuigo-shell/src/remote/model_source/oai.rs:51`](crates/codegen/fuigo-shell/src/remote/model_source/oai.rs:51), `:71` | Models fetch sends a bearer without recording it, then logs the response body. At startup no sampler registration need exist | No P70b coverage |
| HIGH | [`fuigo-shell/src/auth/oidc/protocol.rs:527`](crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:527) → [`oidc/refresh.rs:192`](crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:192) | Refresh token is sent in form data but never registered; echoed `error_description` reaches unified logging | No P70b coverage |

Subscription token-exchange failures differ: `auth/subscription/flow.rs:224` discards non-success bodies and returns a status-only error. I found no corresponding body-echo leak there.

For **F**, an exhaustive claim that mutants survive the entire suite would require execution, which you prohibited. These are concrete **source-predicted survivors of P70b’s added tests at `7bc6912a`**, not measured mutation results:

| Production mutation | Why the added tests do not distinguish it |
|---|---|
| Make `scrub_owned` return its input | No direct test or production caller exercises it at the audited commit |
| Return incorrect change booleans from `scrub_in_place` / `scrub_json_strings`, while still changing strings | Added callers/assertions inspect content, not those return values |
| Remove repeated stabilization from `safe_cut` | The tested two-needle chain follows insertion order; no reverse-order chain requires another pass |
| Stop merging adjacent, non-overlapping occurrences | Tests cover overlap, not adjacent replacement-count semantics |
| Remove `token.trim()` | Header test uses a simple single-space Bearer value |
| Remove query `+` normalization | URL test exercises `%2B`, not a literal form-encoded space |
| Change `CAPACITY` from 256 to 255 | Capacity test derives its loop from the same constant |
| Replace inner `write_all` with one `write`, ignoring a short write | Writer unit test uses `Vec`, which accepts the complete buffer |
| Break flush forwarding or poison recovery | No focused assertions for either |
| Bypass scrubbing in an ACP delegate other than `prompt` | Direct helper tests remain green; end-to-end echo test exercises `prompt` |
| Remove wrapping from a production app/server/leader construction site | Echo test uses the separately modified harness |
| Remove the transient notification helper’s scrub | Enum tests call the scrub directly; terminal-400 fixture does not establish this helper’s coverage |
| Restore ordinary truncation at shell unified-log preview sites | Boundary tests cover sampling-types and sampler preview, not these shell sites |
| Remove tracing-stderr wrapping | No credential-echo stderr assertion |
| Capture stale credentials before resolver/injector replacement | Added end-to-end fixture uses a static key; recording unit tests bypass those producers |
| Break actual subscription error delivery while retaining registration | Added subscription test checks successful dispatch and registry contents, not an echoed failure through a sink |

The added tests meaningfully cover ordinary replacement, overlaps, placeholder postconditions, one escaping layer, simple boundary extension, static-key classification, and one normal ACP failure. They do not establish the complete option-A contract.

The necessary corrections remain compatible with option A: preserve classification inputs and machine-readable decisions, capture the credentials actually used, and scrub the identified external/persistent sinks after classification.


DO-NOT-LAND
