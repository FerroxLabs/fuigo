# P70b Astra round 2 (gpt-6-astra, read-only, codex 0.160)

Raw transcript (837 KB, not committed): `hetzner-dsm:/root/fuigo-builds/p70b/p70b-astra-r2.raw.txt`, sha256 `59c0a77e1104311cdaa8a90fb5c6fb2e229027e43d20e61278a097c71d653b85`.

Audited: `7bc6912a..fef55ec8` (and the whole packet `e0145e0f..fef55ec8`). Verdict: **DO-NOT-LAND**. What was done per finding: receipt R088 §5.

## Brief

```
Independent audit, round 2, of Fuigo packet P70b. Repo: /Volumes/Mando/WaylandBots/Fuigo/wt-p70b (read-only; do NOT run cargo or any build; do NOT read docs/strike/audits/). Branch strike/p70b, HEAD fef55ec8. Round 1 audited e0145e0f..7bc6912a and ended DO-NOT-LAND (10 HIGH, 4 MEDIUM). Audit the fixes: `git diff 7bc6912a..fef55ec8`, and re-check each round-1 finding against the code at fef55ec8. The whole packet is `git diff e0145e0f..fef55ec8` (parent e0145e0f = strike/integration).

The accepted design ("option A", Sean's decision; audit against it, do not re-propose scrubbing before classification): (1) CLASSIFY FIRST: error text is untouched while the sampler and the shell classify it; (2) SCRUB ONLY AT DISPLAY AND LOG SINKS; (3) EXACT-MATCH replacement of the credentials ACTUALLY SENT, 8 chars or more; (4) NO token-shaped heuristic.

What changed since round 1, per round-1 finding number:
1. agent/credential_scrub.rs scrub_acp_error now touches only the human text: err.message, a bare-string data, data.message. Discriminators (code, rule, error_kind, http_status) are never rewritten.
2. NOT FIXED, declared open: the first-party pager (another process in the default topology, so it cannot know which credentials the agent sent) classifies the retry/failure text it receives over ACP (credit limit, free usage, re-auth, friendly copy). That text has to be scrubbed agent-side because the same wire feeds relays, third-party clients, updates.jsonl and hooks. Fixing it needs typed verdicts on the wire and a pager change; proposed as a follow-up packet. Rate it, but it is a known open item.
3. The user-facing cap in fuigo-sampling-types (error.rs truncate_user_error, provider_error.rs truncate_provider_message) is byte-for-byte the parent's again (fuigo-secrets is only a dev-dependency there). Instead the scrub itself recognises the beginning of a credential cut off by the truncation mark U+2026 (fuigo-secrets sent_credentials.rs truncated_prefix_len, MIN_TRUNCATED_PREFIX_CHARS = 4). safe_cut/truncate_chars remain, used only for text on its way into a log (sampler body_preview, shell unified-log fields), never for text that is classified afterwards.
4. Subagent: agent/subagent/spawn.rs emit_subagent_notification scrubs the update; session/acp_session_impl/updates.rs handle_fuigo_session_notification scrubs before persisting; agent/subagent/mod.rs meta.json error; extensions/task.rs failure_error.
5. session/acp_session_impl/turn_end_hooks.rs: StopFailure error_details and last_assistant_message scrubbed before the clip.
6. session/acp_session_impl/turn_end.rs apply_infra_pause_after_turn_err scrubs the pause message (agent message chunk + goal snapshot).
7. recap.rs (btw_history.jsonl x2, recap_requests), compaction.rs (compaction_requests), laziness.rs (debug log line), upload/trace.rs upload_turn_result (turn_result.json error field).
8. record() also records the twice-JSON-escaped spelling.
9. (a) SamplingClient::new records every configured header value (extra_headers, env_http_headers) whatever its name (sampler sent_credentials.rs record_configured_headers); (b) record_header_value records `;`/`,`-separated parts, the value of name=value parts (quotes stripped), and for `Basic` the decoded pair and both halves; (c) proxy authentication added inside reqwest is NOT recorded: declared open.
10. Eviction: a spelling recorded within the last hour (RETAIN) is never forgotten; CAPACITY bounds only older ones.
11. Not changed: session_compact.rs normalize_compact_detail still collapses whitespace, rewrites service names and caps at 300 bytes with the U+2026 marker before the sinks. The cap is now covered by the truncated-prefix rule; the whitespace/service-name rewrites are declared open (they feed classification).
12. ScrubWriter keeps a trailing newline when the scrub (WITHHELD) removed it. A credential that is JSON syntax still corrupts a structured record: declared a limit.
13. Occurrences are merged per credential while scanning (one range per disjoint run).
14. fuigo-secrets test credentials are distinctive (p70b..., mixed-case runs); none occurs in the sanitizer tests.
Also: remote/model_source/oai.rs records the models-fetch bearer and auth/oidc/protocol.rs the refresh token, so the log writers scrub an echo. New tests: fuigo-secrets unit tests, sampler sent_credentials tests (configured header through SamplingClient::new, cookie, `+`), turn_end_hooks_tests.rs, spawn.rs p70b_tests, credential_scrub tests (discriminators), sampling-types cap test.

Tasks:
A. For each round-1 finding 1-14: FIXED / PARTLY / NOT FIXED at fef55ec8, with file:line. Do not accept a claim above without reading the code.
B. New defects introduced by the fixes (classification inputs changed? a sink now rewriting something a consumer decides on? the truncated-prefix rule matching text it should not, or missing a real truncation; Basic decoding; header-part splitting over-recording something that then breaks behaviour rather than display; eviction/retention memory growth; lock ordering).
C. Any remaining path by which sampler error text reaches the user/ACP client, a log, telemetry, a persisted file, a hook or an upload unscrubbed, that round 1 did not list.
D. Name every behavioural mutation of the P70b production code that would survive the tests at fef55ec8.
Severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
```

## Final report

Round 2 still has HIGH-severity failures: child sampler errors bypass the scrub through tool results, credential registration remains incomplete, and the acknowledged pager classification problem remains open.

Audited clean `strike/p70b` at `fef55ec8f090a84f97427e5d3354c77de22d3d42`, against both requested diffs. No files changed, no cargo/builds run, and no contents under `docs/strike/audits/` read. Test conclusions below are from source inspection, not execution.

**A — Round-1 findings**

“FIXED” means the described defect is corrected in source; it does not assert that tests passed.

| # | Status | Evidence at `fef55ec8` and coverage |
|---|---|---|
| 1 | **FIXED** | [credential_scrub.rs:20](crates/codegen/fuigo-shell/src/agent/credential_scrub.rs:20) changes only `message`, string `data`, and `data.message`. The discriminator test at line 159 explicitly preserves `code`, `rule`, `error_kind`, and `http_status`. |
| 2 | **NOT FIXED — HIGH** | [session_notification.rs:1676](crates/codegen/fuigo-pager/src/app/acp_handler/session_notification.rs:1676) still classifies scrubbed reasons for credit limits, free usage, and re-authentication; the failed-state branch repeats this at line 1716. A sent credential equal to `subscription:free-usage-exhausted` removes the marker before the pager checks it. No P70b test exercises this consumer. The declared follow-up does not close the finding. |
| 3 | **FIXED, with a new issue below** | [error.rs:759](crates/codegen/fuigo-sampling-types/src/error.rs:759) and [provider_error.rs:227](crates/codegen/fuigo-sampling-types/src/provider_error.rs:227) are byte-for-byte identical to their parent implementations. `fuigo-secrets` is dev-only there. The new cap test pins the old boundary. The replacement prefix rule has false positives; see B3. |
| 4 | **PARTLY — HIGH remains** | The named routes are scrubbed: [spawn.rs:535](crates/codegen/fuigo-shell/src/agent/subagent/spawn.rs:535), [updates.rs:753](crates/codegen/fuigo-shell/src/session/acp_session_impl/updates.rs:753), [subagent/mod.rs:2371](crates/codegen/fuigo-shell/src/agent/subagent/mod.rs:2371), and [task.rs:340](crates/codegen/fuigo-shell/src/extensions/task.rs:340). The new test covers the outgoing `SubagentFinished` notification. Ordinary tool results still leak the same child failure; see C1. |
| 5 | **FIXED** | [turn_end_hooks.rs:55](crates/codegen/fuigo-shell/src/session/acp_session_impl/turn_end_hooks.rs:55) scrubs both StopFailure strings before clipping. The test checks both strings, but its short inputs do **not** exercise the claimed clip-boundary case. |
| 6 | **FIXED** | [turn_end.rs:541](crates/codegen/fuigo-shell/src/session/acp_session_impl/turn_end.rs:541) scrubs before both the goal-pause operation and slash-command output. Infrastructure classification occurs beforehand, at lines 526–530. No credential-bearing test pins this path. |
| 7 | **FIXED for the named sinks** | Scrubs exist at [recap.rs:197](crates/codegen/fuigo-shell/src/session/acp_session_impl/recap.rs:197), `:216`, `:383`; [compaction.rs:2260](crates/codegen/fuigo-shell/src/session/compaction.rs:2260); [laziness.rs:207](crates/codegen/fuigo-shell/src/session/acp_session_impl/laziness.rs:207); and [trace.rs:732](crates/codegen/fuigo-shell/src/upload/trace.rs:732). The upload changes only the serialized error copy. These call sites lack dedicated credential-bearing sink assertions. |
| 8 | **FIXED for the stated encoding depth** | [sent_credentials.rs:77](crates/codegen/fuigo-secrets/src/sent_credentials.rs:77) records once- and twice-escaped spellings. The test at line 714 checks nested JSON and parses both resulting layers. This is synthetic coverage, not an actual SSE-to-log exercise. |
| 9 | **PARTLY — HIGH remains** | Configured names are recorded at [client.rs:1012](crates/codegen/fuigo-sampler/src/client.rs:1012); Basic and parameter extraction are at [sent_credentials.rs:122](crates/codegen/fuigo-secrets/src/sent_credentials.rs:122). Basic’s valid standard-alphabet decoding is sound by inspection. Proxy auth remains absent: registration precedes `execute`, while reqwest inserts proxy authorization internally. An HTTP proxy returning a structured error containing its password therefore bypasses registration. Quoted parameters and header lifetime also remain incomplete; see B1–B2. |
| 10 | **FIXED for the one-hour guarantee** | [sent_credentials.rs:106](crates/codegen/fuigo-secrets/src/sent_credentials.rs:106) cannot evict an entry whose recorded age is within `RETAIN`. The helper test covers the boundary and refresh ordering. Production registration/eviction integration and resource bounds are not covered. |
| 11 | **PARTLY — HIGH remains** | [session_compact.rs:93](crates/codegen/fuigo-shell/src/session/helpers/session_compact.rs:93) still collapses whitespace and rewrites service names before sink scrubbing. A sent value containing `cli-chat-proxy` or repeated spaces no longer matches after normalization. The ellipsis rule repairs only the unmodified-prefix truncation case. No recorded-credential test covers normalization. |
| 12 | **PARTLY — MEDIUM remains** | [sent_credentials.rs:395](crates/codegen/fuigo-secrets/src/sent_credentials.rs:395) restores the trailing newline in `ScrubWriter`, and its test checks that. However, [unified_log.rs:311](crates/codegen/fuigo-telemetry/src/unified_log.rs:311) uses `scrub_bytes` directly and does not restore it. A withheld record still joins the following record there. Replacing credential text that coincides with JSON syntax also still corrupts structured records. Neither case is covered. |
| 13 | **FIXED** | [sent_credentials.rs:247](crates/codegen/fuigo-secrets/src/sent_credentials.rs:247) merges overlapping/adjacent occurrences while scanning each credential. Dense exact matches no longer allocate one range per occurrence. Existing tests check output equivalence, not allocation growth. |
| 14 | **FIXED for the reported sanitizer collision** | The revised fixtures at [sent_credentials.rs:424](crates/codegen/fuigo-secrets/src/sent_credentials.rs:424) do not occur in the sanitizer test inputs I inspected. The registry remains global, but the specific cross-test collision is removed. No concurrent test run was performed. |

**B — Fix defects and incomplete edge cases**

1. **HIGH — Quoted header parameters containing delimiters leak.**  
   [sent_credentials.rs:139](crates/codegen/fuigo-secrets/src/sent_credentials.rs:139) splits on commas/semicolons before interpreting quotes. For a valid custom header:

   ```text
   X-Proxy-Auth: token="p70b-alpha,beta-gamma"
   ```

   the registry contains the whole header value and fragments with unmatched quotes. It does **not** contain `p70b-alpha,beta-gamma`. An upstream error saying `bad credential p70b-alpha,beta-gamma` survives unchanged. This is an incomplete fix to #9, rather than a newly created leak. The cookie test has no delimiter inside quotes and does not catch it.

2. **HIGH — Configured credentials under excluded names lose retention despite continued use.**  
   The constructor records them once, but [sampler/sent_credentials.rs:45](crates/codegen/fuigo-sampler/src/sent_credentials.rs:45) skips them on every request. After an hour and sufficient registry churn, an actively used configured `originator` credential can be evicted and never re-recorded by that client. Long-lived clients exist—for example, the auxiliary permission classifier reuses its client at [sampler_turn.rs:934](crates/codegen/fuigo-shell/src/session/acp_session_impl/sampler_turn.rs:934). Its next error echo reaches log sinks without replacement. Constructor and retention tests exercise these pieces separately and miss the interaction.

3. **MEDIUM — The prefix rule rewrites natural ellipses without evidence of truncation.**  
   [sent_credentials.rs:260](crates/codegen/fuigo-secrets/src/sent_credentials.rs:260) examines **every** `…`; line 297 accepts any matching proper prefix of at least four characters. Recording `Unauthorized (401)-secret-value` causes ordinary text `Unauthorized (401)… please sign in` to lose its entire authentication marker, although no credential was echoed or locally truncated. This violates the strict exact-match contract and can aggravate #2’s re-authentication failure. The tests cover a matching prefix and unrelated text, but not a natural ellipsis sharing a credential prefix.

4. **HIGH when combined with the current pager — Never-sent configuration can alter decisions.**  
   [client.rs:1012](crates/codegen/fuigo-sampler/src/client.rs:1012) records configured values before later overrides and before any dispatch. A configured `user-agent` value is then overwritten at line 1044. Set that discarded value to `subscription:free-usage-exhausted`: it enters the global registry despite never being sent, and later genuine quota errors lose their marker before reaching the pager. This newly violates “credentials ACTUALLY SENT.” The constructor test actually endorses pre-dispatch registration; it does not verify final wire provenance.

5. **MEDIUM — The retention fix removes a practical memory/work bound.**  
   [sent_credentials.rs:95](crates/codegen/fuigo-secrets/src/sent_credentials.rs:95) retains every fresh spelling without a byte/count limit. Each insertion searches the deque; each scrub scans all entries under the global read lock. A workload producing 100 distinct recorded values per second retains 360,000 raw entries over an hour, before header fragments and escaped variants. An idle registry is not pruned when entries age; eviction runs only during registration. This is a workload-dependent availability risk, not a measured slowdown. The retention test verifies preservation, not bounded resource use.

I found **no lock-order cycle** in the added code: operations holding `SENT` do not call logging or acquire the surrounding sink locks. Large scans can delay writers, but that is different from a demonstrated deadlock. I also found no valid-input arithmetic defect in the Basic decoder.

**C — Additional uncovered sinks**

**C1 — HIGH: child sampler errors escape through ordinary tool results and failure hooks.**

The complete source path is:

- [prompt_turn_result.rs:162](crates/codegen/fuigo-shell/src/agent/subagent/prompt_turn_result.rs:162) copies the raw ACP failure into `SubagentResult.error`.
- [task/mod.rs:761](crates/codegen/fuigo-tools/src/implementations/fuigo_build/task/mod.rs:761) returns that text as a foreground task `ToolError`.
- [tool_calls.rs:3052](crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:3052) places it in both ACP tool-call content and `raw_output.message`.
- [updates.rs:474](crates/codegen/fuigo-shell/src/session/acp_session_impl/updates.rs:474) persists and forwards those standard ACP notifications without credential scrubbing.
- [hook_dispatch.rs:356](crates/codegen/fuigo-shell/src/session/acp_session_impl/hook_dispatch.rs:356) independently sends the raw error in `PostToolUseFailure`.

Polling has a second entry into the same exposure: [task_output/mod.rs:936](crates/codegen/fuigo-tools/src/implementations/fuigo_build/task_output/mod.rs:936) copies the failed snapshot’s raw error into tool output.

A child provider rejecting a recorded key with `bad key <credential>` therefore exposes it to the parent’s ACP client, persisted tool update, and configured failure hooks. The scrubbed `SubagentFinished` notification and `meta.json` do not sanitize the live result object. No P70b test covers these paths.

**C2 — HIGH: the added models-fetch protection omits session authentication.**

The new registration at [oai.rs:52](crates/codegen/fuigo-shell/src/remote/model_source/oai.rs:52) exists only in `EndpointAuth::ApiKey`. The session branch calls `apply_session_headers`, which sends `auth.key` at [oai.rs:148](crates/codegen/fuigo-shell/src/remote/model_source/oai.rs:148) without recording it. A first catalogue fetch, before inference has registered that token, logs an echoed failure body verbatim at line 73.

This is outside sampler-error production itself, but directly contradicts the supplementary models-fetch fix claim in this packet. Its existing test checks identity-header routing, not credential registration or error-log output.

**D — Behavioural mutations the tests do not establish protection against**

These are **source-predicted surviving mutants**, not executed mutation results. Without running a defined mutation set, claiming an exhaustive list of *every possible* survivor would be fabricated. The following covers the concrete unprotected changes and branches identified in this audit.

Paths below are relative to `crates/codegen/`.

| Severity | Mutation / concrete consequence | Location and why the inspected tests miss it |
|---|---|---|
| HIGH | Remove scrubbing from any ACP wrapper method other than `prompt`; that method’s errors leak. | `fuigo-shell/src/agent/credential_scrub.rs:44–129`. Helper tests call `scrub_acp_error` directly; the credential-bearing ACP integration test exercises `prompt`. |
| HIGH | Restore unwrapped connection construction in one production transport. | `fuigo-shell/src/agent/app.rs:154,445,926`, `agent/server.rs:536`, `leader/in_process.rs:34`. The harness independently calls the wrapper helper; it does not launch those production entry points. |
| HIGH | Skip request registration for an untested dispatch combination, such as Messages, nonstreaming inference, or a refreshed bearer. | `fuigo-sampler/src/client.rs:1131`. The P70b sampler integration case covers streaming chat completions with one configured bearer; parser-unit coverage does not prove each dispatch combination. |
| HIGH | Register subscription credentials only for XAI, dropping ChatGPT registration. | `fuigo-sampler/src/subscription.rs:200`. The registration-specific test at `subscription/tests.rs:199` uses `SubscriptionKind::Xai`. |
| HIGH | Remove `env_http_headers` from constructor registration. | `fuigo-sampler/src/client.rs:1014`. The constructor scrub assertion supplies only `extra_headers`; direct helper tests cannot catch missing constructor provenance. |
| HIGH | Process only the first value of a repeated configured header. | `fuigo-sampler/src/sent_credentials.rs:66`. Fixtures use one value per name. |
| HIGH | Mishandle non-ASCII header decoding. | `fuigo-sampler/src/sent_credentials.rs:55`. Header-recording fixtures are ASCII. |
| HIGH | Break Basic’s `+` or `/` alphabet entries, make the scheme case-sensitive, or split decoded credentials at the last colon. | `fuigo-secrets/src/sent_credentials.rs:129,133,164`. Fixtures do not cover those alphabet characters, lowercase/mixed-case schemes, or a colon within the password. |
| MEDIUM | Remove registration of the decoded Basic pair while retaining both halves. | Same file, line 132. Tests assert each half and encoded token; they do not pin replacement of the complete decoded pair as one credential. |
| HIGH | Remove the production `evict` call, or stop refreshing registration timestamps. | Same file, lines 72–83. Retention tests directly exercise `insert`/`evict` on a local deque; ordinary registration tests do not age entries. |
| HIGH | Reduce the retention duration from an hour to seconds. | Same file, line 52. The retention test calculates its times from `RETAIN`, so it does not pin the promised wall-clock duration. |
| MEDIUM | Restore one allocation per overlapping occurrence. | Same file, line 247. Output remains identical; no resource assertion catches the regression. |
| MEDIUM | Select the shortest matching truncated prefix instead of the longest. | Same file, line 302. Existing keys lack a repeated-prefix example such as `abcdabcd…`, where the shorter match leaves an exposed prefix. |
| HIGH | Scrub notification discriminators such as `RetryState.error_type`, or skip selected variants only at the production send site. | `fuigo-shell/src/extensions/notification.rs:1183`; `session/acp_session_impl/updates.rs:1083`. Variant tests do not record discriminator-valued credentials; direct helper tests do not pin variant-specific production routing. |
| HIGH | Remove the inbound notification scrub. | `fuigo-shell/src/session/acp_session_impl/updates.rs:753`. The new subagent test uses no parent command channel and checks only the outgoing gateway notification. |
| HIGH | Remove either the `meta.json` scrub or DTO `failure_error` scrub. | `fuigo-shell/src/agent/subagent/mod.rs:2374`; `extensions/task.rs:340`. The DTO test uses unrecorded `"sampling error"`; the notification test covers neither sink. |
| MEDIUM | Move StopFailure scrubbing after clipping. | `fuigo-shell/src/session/acp_session_impl/turn_end_hooks.rs:55`. Both regression inputs are far shorter than the 1,000/32,768-character caps. |
| HIGH | Remove the infra-pause scrub. | `fuigo-shell/src/session/acp_session_impl/turn_end.rs:541`. No credential-bearing goal snapshot/output assertion. |
| HIGH | Remove any of the three recap/BTw persistence scrubs. | `fuigo-shell/src/session/acp_session_impl/recap.rs:197,216,383`. No corresponding registered-credential artifact assertion. |
| HIGH | Remove the compaction artifact or laziness-log scrub. | `fuigo-shell/src/session/compaction.rs:2263`; `session/acp_session_impl/laziness.rs:207`. No credential-bearing assertion pins either write. |
| HIGH | Serialize the original `TurnResultMetadata.error` instead of `clean_error`. | `fuigo-shell/src/upload/trace.rs:738`. No P70b upload-payload test catches it. |
| HIGH | Remove either new models-fetch or refresh-token registration. | `fuigo-shell/src/remote/model_source/oai.rs:52`; `auth/oidc/protocol.rs:526`. No new registration-and-echo test covers either call. |
| HIGH | Restore ordinary truncation at individual shell log fields. | `fuigo-shell/src/session/acp_session_impl/sampler_turn.rs:1244`, `sampling_events.rs:387,419`, `session/compaction.rs:768`, `agent/subagent/handle_request.rs:1970`. The sampler body-preview test does not exercise these separate cut boundaries. |
| HIGH | Bypass scrubbing in an individual sampling/hooks/memory/instrumentation file writer using an aliased raw appender. | `fuigo-telemetry/src/sampling_log.rs:55`, `hooks_log.rs:82`, `memory_log.rs:87`, `instrumentation.rs:259`. The source guard searches one literal spelling; the credential-bearing runtime-style test exercises the debug-log route. |
| HIGH | Remove the pager binary’s stderr wrapper. | `fuigo-pager-bin/src/main.rs:213`. The channel-writer test exercises a different writer. |
| MEDIUM | Suppress underlying writer errors or make `flush` a no-op. | `fuigo-secrets/src/sent_credentials.rs:398,405`. Writer tests use an infallible `Vec`, not failing/flush-sensitive writers. |
| MEDIUM | Run existing shape redaction before exact matching. | `fuigo-secrets/src/sanitizer.rs:95`. The exact-match telemetry test deliberately uses a credential with no recognized shape; it does not pin ordering when both passes match. |

The fixes substantially improve the named sinks, but C1 alone still violates the packet’s credential-disclosure acceptance criterion. The open classification failures and registration gaps provide additional independent reasons to withhold integration.

DO-NOT-LAND
