# P70b Astra round 3, the last (gpt-6-astra, read-only, codex 0.160)

Raw transcript (637 KB, not committed): `hetzner-dsm:/root/fuigo-builds/p70b/p70b-astra-r3.raw.txt`, sha256 `7ff1f5a50e9a08de91acfa14bd28bd31904f28e9d35bdf557694918402a45460`.

Audited: `fef55ec8..49b716b8` (and the whole packet `e0145e0f..49b716b8`). Verdict: **DO-NOT-LAND**. The cap of three rounds is reached; the open HIGHs and what was changed after this round (not re-audited) are in receipt R088 §5.

## Brief

```
Independent audit, round 3 (the last round for this packet), of Fuigo packet P70b. Repo: /Volumes/Mando/WaylandBots/Fuigo/wt-p70b (read-only; do NOT run cargo or any build; do NOT read docs/strike/audits/). Branch strike/p70b, HEAD 49b716b8. Round 2 audited fef55ec8 and ended DO-NOT-LAND. Audit the fixes: `git diff fef55ec8..49b716b8`, and re-check each round-2 item against the code at 49b716b8. The whole packet is `git diff e0145e0f..49b716b8` (parent e0145e0f = strike/integration).

The accepted design ("option A", Sean's decision; audit against it): (1) CLASSIFY FIRST: error text is untouched while the sampler and the shell classify it; (2) SCRUB ONLY AT DISPLAY AND LOG SINKS; (3) EXACT-MATCH replacement of the credentials ACTUALLY SENT, 8 chars or more; (4) NO token-shaped heuristic.

What changed since round 2, by round-2 item:
- #2 (pager classifies scrubbed wire text): NOT FIXED, declared open; needs typed verdicts on the wire and a pager change (follow-up packet). Known; rate it but do not spend the round on it.
- #4 / C1 (child sampler errors through tool results, PostToolUseFailure hooks, task_output polling): agent/subagent/prompt_turn_result.rs now scrubs the child's session error where SubagentResult.error is built, the single source of the tool error, the tool-call content/raw_output, the hooks, the notifications, meta.json and the DTO. The child session has already classified its own error by then; nothing in production code string-matches SubagentResult.error.
- #9 / B1: record_header_value splits on `;`/`,` only outside double-quoted strings and records a quoted value both as written and with its quoted-pairs resolved (fuigo-secrets sent_credentials.rs split_outside_quotes, unescape_quoted_pairs).
- #9 / B2 / B4: SamplingClient::new no longer records anything. It snapshots what configuration put under each configured header name, keeps the values that are still in the final default headers after the client-composed ones (surviving_configured_values) in a new field `configured_header_values`, and dispatch_request records them on EVERY request (fresh retention; a configured value the client replaced, e.g. user-agent, is never recorded). The per-request recorder skips only: a value equal to a fixed protocol constant (STATIC_CLIENT_VALUES) and the value under a name the client itself always writes (CLIENT_WRITTEN_HEADERS: user-agent, traceparent, the x-fuigo-* names). `accept`, `originator`, `tracestate`, `content-type`, `anthropic-version` are no longer skipped by name.
- #9c proxy authentication: record_request also records the credentials of a proxy configured in the environment variables reqwest reads (record_proxy_url: userinfo raw and percent-decoded, the pair, and the Basic token built from it).
- #11: session_compact.rs normalize_compact_detail records the rewritten spelling (collapsed whitespace, renamed services) of every sent credential the raw text contains (sent_credentials::record_transformed), so the sinks' exact match finds it; the text itself is still not scrubbed there because it is classified afterwards. The cap is covered by the truncated-prefix rule.
- #12: unified_log.rs uses scrub_record (keeps the record's newline). A credential that is JSON syntax can still corrupt a structured record: declared limit.
- B3: MIN_TRUNCATED_PREFIX_CHARS is now 8 (same floor as a whole credential).
- B5: MAX_SPELLINGS = 4096 is a hard bound whatever the age.
- C2: apply_session_headers (remote/model_source/oai.rs) records the session bearer.
New tests: fuigo-secrets (quoted parameters, Basic alphabet/case/colons, proxy URL, record_transformed, scrub_record, longest truncated prefix, hard bound), fuigo-sampler (client-written names, proxy lookup, constructor + recorder in client.rs, a real-dispatch test in tests/upstream_credential_echo.rs), fuigo-shell session_compact p70b_tests.

Tasks:
A. For each round-2 item above (#2, #4/C1, #9 with B1/B2/B4 and 9c, #11, #12, B3, B5, C2): FIXED / PARTLY / NOT FIXED at 49b716b8, with file:line. Read the code; do not accept the claims.
B. New defects introduced by these fixes: is anything now scrubbed BEFORE a classifier reads it (in particular: does anything decide on SubagentResult.error or on the tool error text built from it)? does record_transformed or the proxy/env recording record something that then changes behaviour rather than display? is the new SamplingClient field ever logged or serialized? is `configured_header_values` correct when the same name is in both extra_headers and env_http_headers, or for a non-ASCII value?
C. Any remaining path by which sampler error text reaches the user/ACP client, a log, telemetry, a persisted file, a hook or an upload unscrubbed, that rounds 1-2 did not list.
D. The behavioural mutations of the P70b production code most likely to survive the tests at 49b716b8 (highest-value ones first; no need to repeat round 2's whole table).
Severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
```

## Final report

The fixes close several round-2 gaps, but **credential disclosure remains possible**, including an additional goal-evaluator path. These findings independently prevent landing; the acknowledged pager follow-up is not the sole reason.

Audited clean `strike/p70b` at `49b716b8601caa411a352f72915dbb3773a33788`, including both requested diffs. No files changed, no Cargo/builds ran, and `docs/strike/audits/` was not read. Test assessments below come from source inspection, not execution.

**A. Round-2 dispositions**

| Item | Result | Evidence and remaining issue |
|---|---|---|
| #2 — pager classification | **NOT FIXED — HIGH** | [error_display.rs:180](crates/codegen/fuigo-pager/src/app/error_display.rs:180) still recovers status from already-scrubbed wire text; line 229 also performs text-based truncation recovery. Retained as the declared follow-up. |
| #4 / C1 — child errors | **FIXED** | [prompt_turn_result.rs:173](crates/codegen/fuigo-shell/src/agent/subagent/prompt_turn_result.rs:173) scrubs before constructing the shared child error. Downstream task failure, polling, hooks and persistence inherit it. No new credential-specific reducer/tool/hook integration test covers this fix. |
| #9 / B1 — quoted parameters | **FIXED** | [secrets/sent_credentials.rs:144](crates/codegen/fuigo-secrets/src/sent_credentials.rs:144) uses quote-aware splitting; lines 152–154 record quoted content and resolved quoted-pairs. The added test exercises embedded separators and escapes. |
| #9 / B2 / B4 — configured headers and retention | **PARTLY — MEDIUM** | [client.rs:1139](crates/codegen/fuigo-sampler/src/client.rs:1139) refreshes recording on every dispatch. Constructor-time replacement is handled, but later replacement is not. The new constant-value exclusion also misses actual credentials. See findings 4–5. |
| #9c — proxy authentication | **PARTLY — HIGH** | [secrets/sent_credentials.rs:207](crates/codegen/fuigo-secrets/src/sent_credentials.rs:207) handles fully qualified proxy URLs, decoded userinfo and Basic tokens. It misses scheme-less proxy settings accepted by the pinned HTTP stack, and records unused proxies. |
| #11 — compaction normalization | **PARTLY — HIGH** | [session_compact.rs:103](crates/codegen/fuigo-shell/src/session/helpers/session_compact.rs:103) records transformed full credentials. It misses a credential already truncated before normalization. |
| #12 — unified records | **PARTLY — MEDIUM** | [unified_log.rs:311](crates/codegen/fuigo-telemetry/src/unified_log.rs:311) now preserves the terminal newline through `scrub_record`. The declared structured-record corruption remains: a credential equal to `"message"` including quotes can replace a JSON key with unquoted `<redacted>`. |
| B3 — truncated-prefix minimum | **FIXED** | [secrets/sent_credentials.rs:47](crates/codegen/fuigo-secrets/src/sent_credentials.rs:47) uses eight characters. Boundary and longest-prefix tests exist. |
| B5 — hard bound | **FIXED** | [secrets/sent_credentials.rs:114](crates/codegen/fuigo-secrets/src/sent_credentials.rs:114) enforces 4096 spellings regardless of age. Consequently, retention does not protect in-flight credentials above that bound; the test explicitly accepts that eviction. |
| C2 — session model bearer | **FIXED** | [oai.rs:148](crates/codegen/fuigo-shell/src/remote/model_source/oai.rs:148) records the bearer before sending. Existing tests verify headers, not credential-echo scrubbing. |

**B/C. Concrete defects and boundary checks**

1. **HIGH — Additional sink gap: goal-evaluator errors escape through goal state and notifications.**

   [goal.rs:128](crates/codegen/fuigo-shell/src/session/acp_session_impl/goal.rs:128) embeds the raw sampler error in `last_error`. After the bounded retry, [goal.rs:1280](crates/codegen/fuigo-shell/src/session/acp_session_impl/goal.rs:1280) copies it into history and the pause message.

   [goal_orchestrator.rs:39](crates/codegen/fuigo-shell/src/session/goal_orchestrator.rs:39) persists that snapshot; its notification path at line 81 forwards it without scrubbing. `pause_message` is copied at line 190. [storage/jsonl/mod.rs:1451](crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:1451) serializes the state unchanged.

   **Scenario:** an active goal’s evaluator receives two errors echoing its sent API key. The key reaches `goal/state.json`, persisted `GoalUpdated` notifications in `updates.jsonl`, and the ACP client. This bypasses `apply_infra_pause_after_turn_err`, where P70b added its scrub.

   **Tests:** not caught by the supplied foreground-prompt echo test. This is an existing path missed by the packet, additional to the supplied round-2 list.

2. **HIGH — Proxy recording rejects a supported proxy spelling.**

   [secrets/sent_credentials.rs:208](crates/codegen/fuigo-secrets/src/sent_credentials.rs:208) requires `url::Url::parse` to expose userinfo. The pinned reqwest stack’s [proxy matcher:333](~/.cargo/registry/hyper-util-0.1.20/src/client/proxy/matcher.rs:333) accepts an authority without a scheme and defaults to HTTP.

   **Scenario:** `HTTP_PROXY=p70buser:p70bpassword@proxy.example:3128`. The transport can send Basic authentication, while `record_proxy_url` records neither the password nor its Basic token. A proxy’s structured error echo can therefore pass through the scrubbers unchanged.

   **Tests:** not caught; both new proxy tests use `http://`. This leaves #9c incomplete.

3. **HIGH — An earlier truncation defeats the new compaction alias recording.**

   [error.rs:765](crates/codegen/fuigo-sampling-types/src/error.rs:765) caps structured error text at 280 characters. Later, [secrets/sent_credentials.rs:255](crates/codegen/fuigo-secrets/src/sent_credentials.rs:255) only creates aliases when a **complete** recorded spelling occurs.

   **Scenario:** sent credential `inference-api-abcdefgh-remaining`; upstream message is `"bad "` plus 252 spaces plus that credential. The first cap leaves `inference-api-abcdefgh-r…`. Normalization collapses the spaces and produces `inference backend-abcdefgh-r…`. No alias was registered, and this is no longer a prefix of the original credential. The sinks disclose it.

   **Tests:** not caught. The normalization test supplies a complete credential; the truncation test does not compose truncation with service-name rewriting. A synthetic character-level trace confirmed the example’s boundaries; Rust was not executed.

4. **MEDIUM — “Actually sent” provenance remains incorrect after constructor-time snapshots.**

   [sampler/sent_credentials.rs:64](crates/codegen/fuigo-sampler/src/sent_credentials.rs:64) records every cached configured value without comparing it to the final request.

   **Scenario:** configured `traceparent=overloaded_error` survives construction, then the [injector at client.rs:1215](crates/codegen/fuigo-sampler/src/client.rs:1215) replaces it. The unsent string is nevertheless registered and subsequently redacted. A live bearer resolver similarly removes/replaces configured authentication at line 1173.

   Proxy recording has the same provenance problem: [sampler/sent_credentials.rs:80](crates/codegen/fuigo-sampler/src/sent_credentials.rs:80) records all six variables, ignoring destination scheme, precedence and `NO_PROXY`. A bypassed proxy username such as `overloaded_error` still enters the registry.

   **Tests:** not caught. The configured-header dispatch test deliberately has no injector; the proxy test supplies one variable. These operations do not mutate the raw sampler error, but they alter sink text and can feed the already-known pager classification defect.

5. **MEDIUM — New regression: constant-value exclusions can expose genuine credentials.**

   [sampler/sent_credentials.rs:91](crates/codegen/fuigo-sampler/src/sent_credentials.rs:91) excludes fixed values under **every header name**. The configured-value filter at line 123 repeats this exclusion.

   **Scenario:** an `XApiKey` credential is `2023-06-01` or `application/json`. It is actually sent, exceeds eight characters, and is never recorded. An exact upstream echo remains visible.

   **Tests:** not caught. Tests establish that protocol constants remain visible, but do not send one as an authentication credential. Exemptions need header/provenance context.

The other requested boundary checks are sound:

- **Child classification:** I found no production string-based decision on `SubagentResult.error` or its resulting tool-error text. [TaskTool:761](crates/codegen/fuigo-tools/src/implementations/fuigo_build/task/mod.rs:761) wraps it after branching on `success`; [tool_calls.rs:1084](crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1084) follows the typed `Err` branch. Hooks and the parent model receive scrubbed text, as intended.
- **`record_transformed`:** it updates the registry and leaves classified text untouched. No additional native classification mutation was found.
- **New field exposure:** `SamplingClient` derives only `Clone`; its [manual Debug implementation:682](crates/codegen/fuigo-sampler/src/client.rs:682) omits `configured_header_values`. No serialization or logging of that field was found.
- **Duplicate configured names:** correct at construction. Environment headers are applied before the snapshot, so both name occurrences capture the surviving environment value. Duplicate registry entries are deduplicated.
- **Non-ASCII configuration:** valid UTF-8 is preserved by `from_utf8_lossy`; this path avoids `HeaderValue::to_str()`’s ASCII restriction. The eight-character threshold remains character-based.
- **Heuristics:** these fixes add no token-shaped heuristic. The existing telemetry shape sanitizer remains separate from the new exact-match pass.

**D. Highest-value likely surviving mutations**

These are predicted survivors from test inspection, not executed mutation results.

| Priority | Production mutation | Consequence and why tests likely miss it |
|---|---|---|
| HIGH | Remove the scrub at [prompt_turn_result.rs:173](crates/codegen/fuigo-shell/src/agent/subagent/prompt_turn_result.rs:173). | Child errors leak through tool content, polling and failure hooks. Existing reducer tests use ordinary error text; separate notification/meta scrubs conceal the omission elsewhere. |
| HIGH | Refresh configured credentials only on the first dispatch at [client.rs:1139](crates/codegen/fuigo-sampler/src/client.rs:1139). | Long-lived configured credentials can age out. Both added constructor/dispatch tests exercise one request. |
| HIGH | Remove session-bearer recording at [oai.rs:148](crates/codegen/fuigo-shell/src/remote/model_source/oai.rs:148). | Model-fetch error logs regain bearer disclosure. The header test uses `"token"`, below the recording threshold, and never checks a sink. |
| HIGH | Remove `evict` from [record:90](crates/codegen/fuigo-secrets/src/sent_credentials.rs:90). | The production registry becomes unbounded. The hard-bound test invokes `insert` and `evict` directly, bypassing `record`. |
| MEDIUM | Keep whitespace aliases but omit service-name rewriting from alias generation at [session_compact.rs:103](crates/codegen/fuigo-shell/src/session/helpers/session_compact.rs:103). | Rewritten service-name credentials leak. The added normalization regression covers whitespace only. |
| MEDIUM | Change [unified_log.rs:311](crates/codegen/fuigo-telemetry/src/unified_log.rs:311) back to `scrub_bytes`. | Withheld records lose their newline. Helper tests still pass; the unified-log test never triggers whole-record withholding. |

DO-NOT-LAND
