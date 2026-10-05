# P82 Astra round 1 (gpt-6-astra, read-only, codex 0.160)

Raw transcript (790 KB, not committed): `hetzner-dsm:/root/fuigo-builds/p82/p82-astra-r1.raw.txt`, sha256 `3756345e9cd316a549f078a8b8d65983c185eec16ad068641c9615a02d0e907d`.

## Brief

```
Independent audit, round 1, of Fuigo packet P82. Repo: /Volumes/Mando/WaylandBots/Fuigo/wt-p82 (read-only; do NOT run cargo or any build; do NOT read docs/strike/audits/). Branch strike/p82, HEAD f2eb90c6. Audit `git diff a31a24c2..f2eb90c6` (two commits: 07d26ab5 relay credentials, f2eb90c6 agent serve secret compare). Parent a31a24c2 is packet P81 (on P77, on integration 8b1a0192); P77/P81 are the identity filter in agent/relay.rs (relay_outbound_frame) and are context, not under audit, except where P82 interacts with them.

Rule: a credential (session bearer, API key, environment secrets, anything docs/destination-trust-policy.md classes as a credential) is handed over the relay bridge only to a FluxRouter-operated relay, decided on the URL the relay socket is opened to (fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_websocket_destination: wss to the FluxRouter API host). A FluxRouter relay must receive byte for byte what it received before, and its messages must reach the agent byte for byte as before. Local stdio / IPC clients must be byte-for-byte unchanged.

Context: agent/app.rs bridges the agent to the relay websocket (headless-relay ~line 470-512; leader ~956-1008, where the relay ALSO receives the agent's answers to local IPC clients' requests, whose ids the leader namespaced "client|id"). Messages the relay sends reach the agent's ACP input (agent-client-protocol 0.10.4: each line parsed with serde_json into a derived struct RawIncomingMessage{id,method,params,result,error}; ext methods arrive as "_fuigo/...", the crate strips one "_").

Claims:
1. Enumeration (both directions): credential-returning requests are fuigo/auth/getBearerToken (extensions/auth.rs:47, result.result.token) and fuigo/getApiKey (auth.rs:67, result.result.key). Credential fields in outbound frames: those two; cloud env list/create/update secrets[].value (acp_agent.rs ~2388-2500; prod/mc/cli-chat-proxy-types/src/sandbox_types.rs:542); MCP catalog stdio env[].value in fuigo/mcp/list (result.result.servers[].env[].value) and the fuigo/mcp/servers_updated notification (params.mcpServers[].env[].value) (extensions/mcp.rs:124, 480-492, 309-321). Declared NOT covered (proposals): git remote URLs with userinfo (fuigo/git/info remotes[], fuigo/git/status remoteUrl), MCP args/url with expanded variables, marketplace source URLs, fs/read_file of ~/.fuigo/auth.json and terminal commands (a relay can drive the agent's tools).
2. Request side (agent/relay_credentials.rs gate_relay_message, called from relay.rs run_websocket_session_with_liveness reader for text AND binary frames, only when the relay is not FluxRouter-operated): a request for a credential method (any number of leading "_") is answered on the relay socket with a JSON-RPC -32600 error carrying its id and never reaches the agent; a notification for one is dropped; a message that is not a JSON object is dropped (positional-array requests); every other message is forwarded as serde_json::Value::to_string() of the parsed value (so escapes, duplicate keys, raw newlines cannot make the agent read something other than what was decided). Binary frames are split on '\n' as the agent's line reader would split them. The refusal goes through the socket's single text writer (a new select arm) and through relay_outbound_frame.
3. Response side (withhold_credentials, first statement of relay_outbound_frame): for a non-FluxRouter relay, a frame containing "token"/"key"/"secrets"/"env" quoted, or any \u escape, is read one level at a time with a duplicate-key-rejecting object reader along the paths; the fields above are removed; a frame that cannot be decided (not an object, duplicate key on a path level) is not sent; everything else is raw text byte for byte.
4. agent/server.rs (fuigo agent serve): validate_auth now compares via secret_matches (SHA-256 both sides, fold over all 32 bytes) and an empty server secret admits nobody (before, `--secret ""` admitted an empty bearer / ?server-key=).
5. Tests (all RUN on the build host at this code and pass): agent::relay_credentials::tests::p82_* (gate, backstop from the real producers' types, escapes built at runtime, fail-closed duplicates, untouched frames, real socket session with assertions on the frames written to the relay socket, source pins), agent::server::server_tests::p82_*, and agent::mvp_agent::tests::p82_relay_credentials_bridge_tests (a REAL MvpAgent wired as leader mode, local client + relay on an in-memory websocket: local gets bearer and key, non-FluxRouter relay gets refusals and no credential bytes in any frame incl. mirrored local answers, FluxRouter relay gets the agent's lines byte for byte). P77 and P81 tests still pass.

Tasks:
A. Is the enumeration complete? Hunt independently for any other request/response/notification over the bridge that carries a credential or secret (ACP handlers in crates/codegen/fuigo-shell/src/extensions/*, agent/handlers/*, agent/mvp_agent/*, session/*; agent->client requests; initialize/authenticate _meta). For each hit: file:line, wire path, real value or redacted.
B. Bypasses of the request gate: any way a message from a non-FluxRouter relay can make the agent run getBearerToken/getApiKey (or another credential producer) — encodings, framing (text vs binary, newlines, \r, BOM, nested JSON), duplicate keys, the acp crate's parsing (positional arrays, field aliases, case), the leader server's id handling, relay sync (relay/sync.rs), declare_relay_client_capabilities, auth-error handling. Also: anything first-party that breaks (FluxRouter path byte for byte? local clients?).
C. Bypasses of the response backstop for the listed fields, and damage to unrelated frames (false positives on result.result.key/token in other methods' responses? search producers), output always valid JSON, interaction with P81's filter (order, fail-closed empties).
D. agent serve change: correctness; is a credential method reachable there without auth or via the weak compare? Severity of the remaining transport issues (plain ws, secret in query string, 12-hex auto secret).
E. Name every behavioural mutation of the P82 production code that would survive the tests.
Severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
```

## Final report

Round 1 found **one HIGH enumeration gap**: hook definitions can disclose literal credentials through both a response and a notification. I found no bypass of the two-method request gate or the backstop’s listed field paths.

Verified checkout: `strike/p82`, `f2eb90c656c01afe192a3be84fb650bd27cb8a35`. Reviewed `a31a24c2..f2eb90c6` and relevant callers read-only. No Cargo, builds, tests, or mutation runs; build-host passes remain your reported evidence. I did not read `docs/strike/audits/`.

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Independent source audit, round 1, completed |
| Enumeration and bridge analysis | ✅ Done | Findings and limitations below |
| Packet acceptance | ⬜ Pending | HIGH omission under the stated credential rule |
| Mutation execution | ⬜ Pending | Excluded; E contains static survivor predictions |

**A. Enumeration**

**HIGH — Hook credentials remain exposed.** [extensions/hooks.rs:85](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/hooks.rs:85) chooses `command_raw`/`url_raw`, falling back to resolved values, and copies them into `HookInfo` without credential redaction.

Concrete scenario: an existing HTTP hook uses:

```text
https://hooks.example/run?token=p82-synthetic-secret
```

A non-FluxRouter relay requests `_fuigo/hooks/list` for that session. The response contains the real URL at:

```text
result.result.hooks[].url
```

The handler is [extensions/hooks.rs:245](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/hooks.rs:245). The same DTO is emitted on hook reload through [hooks_plugins.rs:979](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/session/acp_session_impl/hooks_plugins.rs:979), with the actual notification method established at [updates.rs:1116](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/session/acp_session_impl/updates.rs:1116):

```text
_fuigo/session_notification
params.update.sessionUpdate = "hooks_changed"
params.update.hooks[].url
params.update.hooks[].command
```

P82 neither refuses the request nor removes these fields. A URL containing `token=...` does not even trigger the quoted-key precheck; triggering it through another field would still leave the hook fields intact.

This requires **no terminal execution or arbitrary file read**. It also leaks when a local client requests the list and its answer is mirrored. `${TOKEN}` remains an unexpanded placeholder when a raw template exists, but a literal token remains literal. The existing hook test checks placeholder preservation, not literal-secret removal.

**Classification:** pre-existing producer, newly claimed but incomplete P82 boundary; HIGH confidentiality impact. **Tests:** not caught by the reviewed P82 tests. This surface is absent from the supplied exclusion list.

The resulting inventory is:

| Producer | Wire path | Value delivered before relay filtering / P82 treatment |
|---|---|---|
| [auth.rs:47](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/auth.rs:47), `getBearerToken` | `result.result.token` | Real session/static credential, or null; runtime-authentication key excluded by producer. P82 covers it. |
| [auth.rs:67](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/auth.rs:67), `getApiKey` | `result.result.key` | Real environment key, including legacy fallback, or null. P82 covers it. |
| [acp_agent.rs:2389](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/mvp_agent/acp_agent.rs:2389), cloud list/create/update | `result.environments[].secrets[].value`; `result.environment.secrets[].value` | Backend-provided values; type explicitly permits real or redacted values. P82 removes either. |
| [mcp.rs:480](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/mcp.rs:480), MCP list/catalog notification | `result.result.servers[].env[].value`; `params.mcpServers[].env[].value` | Real resolved stdio environment values. P82 covers them. |
| Hook list/change notification, above | `result.result.hooks[].{url,command}`; `params.update.hooks[].{url,command}` | Literal credentials remain real; unfiltered. |
| [prompt_history.rs:91](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/prompt_history.rs:91) | `result.prompts[]` | Stored prompt text, unredacted here. A previously pasted credential can be returned without running a tool. |
| [session/acp_mcp.rs:83](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/session/acp_mcp.rs:83), reverse SDK request | `_fuigo/mcp/sdk_call`, `params.message` | Actual MCP message, including tool arguments; no general credential scrub. |
| [session/acp_session/hooks.rs:526](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/session/acp_session/hooks.rs:526), reverse hook request/event | `_fuigo/hooks/run` / `_fuigo/hooks/event`, flattened `params.toolInput` / `params.toolResult`, where applicable | Actual tool content, potentially credential-bearing; no P82 protection at these paths. |
| [acp_agent.rs:498](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/mvp_agent/acp_agent.rs:498), initialize | `result._meta.metadata` | Parsed `FUIGO_AGENT_METADATA` object, unredacted. Conditional content surface, not an automatic auth-store export. |

Prompt/history/tool payloads are **conditional content carriers**, not additional dedicated credential getters. They establish that the blanket statement “a non-FluxRouter relay is never handed a credential” is stronger than this implementation.

Additional checks:

- MCP HTTP/SSE authorization headers are **omitted from catalog DTOs**, not exposed through an overlooked `headers[]` field.
- MCP `setupValues` currently represents select-field preferences; I found no dedicated password/API-key setup field.
- `authenticate`’s supplied API key is not echoed: its response reports `persisted`. The normal authentication metadata builder contains account/status fields, not access or refresh tokens.
- `initialize` starts with an empty MCP catalog; the subsequent catalog notification is the covered producer.
- `auth/get_url` returns the login URL. The device flow exposes the user-facing verification URL/code, not its private polling `device_code`.
- The declared git URL, MCP args/URL, marketplace, file-read and terminal exclusions remain real. I have not reclassified those acknowledged exclusions as new P82 implementation defects.

**B. Request gate and compatibility**

No direct route to execute either blocked getter survived source tracing.

| Case | Result |
|---|---|
| Unicode escapes, escaped `/`, escaped `method` key | Decoded before comparison. |
| Duplicate `method` keys | `Value` chooses the last; only its serialization reaches ACP. ACP cannot independently choose the discarded value. |
| Text containing formatting newlines or nested JSON | Whole-frame parse followed by one-line serialization prevents line injection. Multiple independent text records fail the whole-frame parse. |
| Binary newline-separated records | Each record is parsed and gated. Credential requests cannot hide behind another line. |
| CR/CRLF, BOM, invalid UTF-8 | CR is JSON whitespace where legal; BOM/malformed JSON is rejected; invalid binary UTF-8 is skipped. No alternate method interpretation found. |
| Positional arrays/batches | Dropped before ACP, including the derived-struct positional-array case. |
| Aliases/case/prefixes | ACP’s `RawIncomingMessage` has no field aliases. Extension dispatch strips exactly one `_`; method matching is case-sensitive. P82 conservatively rejects additional leading underscores. |
| Leader `client|id` handling | Changes routing IDs, not methods. The response backstop is independent of ID ownership or spelling. |

The local ACP 0.10.4 source confirms line parsing and dispatch at `rpc.rs:185`, `rpc.rs:317`, and `lib.rs:285`.

Other seams:

- `declare_relay_client_capabilities` only adjusts `initialize` capabilities; it cannot turn a permitted method into a credential getter.
- Text-frame errors are handled before the gate: authentication errors end the session for recovery; other errors are skipped. Binary behavior remains different, but a binary message with a blocked method is still refused.
- Relay sync’s [sync.rs:541](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/relay/sync.rs:541) answers its own initialize handshake and does not dispatch arbitrary requests to `MvpAgent`.
- The destination decision and connection use the same `config.ws_url`. The proxy path wraps the tunnel in TLS for the target hostname.

**FluxRouter compatibility:** P82 preserves the previous text branch, including its pre-existing newline trimming and initialize-capability rewrite. Binary handling remains the previous branch. Outbound filtering returns the original string immediately.

**Local compatibility:** [app.rs:984](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/app.rs:984) sends separate copies to relay and IPC; relay filtering cannot mutate the IPC copy. The real-agent test exercises a reconstructed bridge, not the actual leader server/IPC implementation. Source inspection supports preservation; I did not independently execute it.

**C. Response backstop**

For the **listed paths**, I found no bypass:

- Escaped keys trigger parsing through `\u` detection.
- Duplicate keys are rejected at every visited object level.
- `RawValue` parsing consumes leading whitespace before storing the raw value, so `starts_with('{')` / `starts_with('[')` does not create a whitespace bypass.
- Every matching field is removed irrespective of its value type.
- Mixed rows and multiple credential locations are traversed without short-circuiting later locations.

I found **no current unrelated producer** returning a noncredential field at exactly `result.result.token` or `result.result.key`. Nested facet keys and MCP tool results occupy different paths.

The filter is nevertheless path-based, not correlated with request methods. A future noncredential producer using those exact paths would lose its field. That is a **LOW future compatibility risk**, not an observed current regression.

Two qualifications matter:

1. **“Output always valid JSON” is not a filter guarantee.** The fast path intentionally passes `"not json"` unchanged, and a test requires that behavior. Valid producer frames remain valid after rewriting; undecidable inspected frames become the empty sentinel and are not written.
2. Unrelated raw **values** survive rewriting, but visited object formatting/key escapes can be normalized. Entire untouched frames remain byte-for-byte unchanged.

P82 runs before P81 at [relay.rs:566](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay.rs:566). An empty fail-closed result remains empty and the writer skips it. P81 cannot restore removed credentials.

**D. `agent serve`**

The changed comparison is functionally correct on inspection:

- Both header and query authentication call `secret_matches`.
- An empty configured secret rejects everyone.
- A recognized Bearer header retains precedence over a query key.
- The handler authenticates before WebSocket upgrade at [server.rs:142](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/server.rs:142).
- I found no unauthenticated route to credential methods. Once authenticated, this server intentionally grants local-client capabilities, including the getters.

The implementation hashes both strings and folds across all 32 digest bytes. **LOW documentation overclaim:** [server.rs:120](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/server.rs:120) says timing does not depend on secret length; hashing work does depend on input length. Source inspection also does not establish compiler-level constant-time behavior.

Remaining transport issues are pre-existing:

| Severity | Evidence and concrete scenario | P82 tests |
|---|---|---|
| HIGH when exposed across an untrusted network | [server.rs:630](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/server.rs:630): plain HTTP/WebSocket listener. An observer who captures authentication can obtain full agent access. Default binding is loopback. | Not tested |
| MEDIUM | [main.rs:172](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-pager-bin/src/main.rs:172): startup prints the secret and credential-bearing URL. Query authentication can propagate the reusable secret into copied URLs or request logs. | Not tested |
| MEDIUM | [cli.rs:387](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-pager/src/app/cli.rs:387): first 12 UUID hex characters give 48 random bits. No authentication rate limiter is installed in this router. This is limited brute-force margin, not a demonstrated practical online bypass. | Not tested |

**E. Surviving behavioral mutations**

An exhaustive list of *every possible* mutation is not supportable without a defined mutation set. No mutants were executed. These are concrete source-derived survivors of the reviewed P82 assertions, rather than claims of measured mutation coverage:

| Severity if introduced | Mutation and location | Why the tests would miss it |
|---|---|---|
| MEDIUM | Add `if presented != expected_secret { return false; }` before hashing at [server.rs:124](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/server.rs:124). | Functional outcomes remain identical. The source pin rejects `==` spellings, not `!=`; the pinned digest/fold remains present. This reintroduces an ordinary early comparison. |
| HIGH | Exempt duplicate `params`, `servers`, or `environments` keys from rejection at [relay_credentials.rs:156](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:156). | Those duplicate spellings are absent from the fixtures. A credential-bearing first occurrence followed by an empty last occurrence can produce “unchanged,” returning the original leaking frame. |
| HIGH | Limit MCP server lists or individual `env` lists to two inspected entries at [relay_credentials.rs:209](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:209). | MCP fixtures reach two servers/two environment entries, not a credential in a third entry. Cloud-list coverage does not close a list-specific mutation. |
| LOW | Strip at most two leading underscores at [relay_credentials.rs:55](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:55). | Tests cover zero, one and two prefixes. Three would be forwarded, violating the gate contract, although ACP would not route that spelling to the getter. |
| MEDIUM | Drop ordinary objects containing `error` in `gate_relay_message` at line 90. | Gate tests’ “responses and errors” section actually supplies result responses. Socket fixtures contain no binary reverse-RPC error. Text errors already take another path. |
| MEDIUM | Fail to terminate the binary reader when `to_agent_tx.send` fails at [relay.rs:865](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay.rs:865). | Tests keep the agent receiver alive; they do not exercise this new shutdown branch. |
| LOW | Reject query authentication whenever any Authorization header exists at [server.rs:104](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/server.rs:104). | No case combines a malformed/non-Bearer header with a correct query. Current behavior permits that fallback. |
| LOW | Accept trailing whitespace by normalizing inputs before the pinned digest statements at `server.rs:124`. | Wrong-input tests include leading whitespace, not trailing whitespace. The hashing source pin would remain satisfied. |

Conversely, the tests do catch removing either gate, removing any listed withholding path, broad first-party withholding, forwarding positional arrays, common escape/duplicate bypasses, and replacing the multi-location traversal with short-circuiting logic.

The required correction is narrowly identified: cover credential-bearing hook display fields on **both** the list response and change notification, including mirrored local responses, with FluxRouter/local preservation assertions. The known exclusions remain separate follow-ups.

DO-NOT-LAND
