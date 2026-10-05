# P82 Astra round 2 (gpt-6-astra, read-only, codex 0.160)

Raw transcript (not committed): `hetzner-dsm:/root/fuigo-builds/p82/p82-astra-r2.raw.txt`, sha256 `03126701d4a8759edac687d32bfe374e379cd7192fc5b1e13883c8e291f1a4ad`.

## Brief

```
Independent audit, round 2, of Fuigo packet P82. Repo: /Volumes/Mando/WaylandBots/Fuigo/wt-p82 (read-only; do NOT run cargo or any build; do NOT read docs/strike/audits/). Branch strike/p82, HEAD cdf6b4fd. Audit the whole packet `git diff a31a24c2..cdf6b4fd`, with attention to the delta since round 1 `git diff f2eb90c6..cdf6b4fd` (3a16b7f2 tests; cdf6b4fd the round-1 fix). Parent a31a24c2 is packet P81 (identity filter in agent/relay.rs relay_outbound_frame, on P77, on integration 8b1a0192): context, not under audit, except where P82 interacts with it.

Rule: a credential (session bearer, API key, environment secrets, anything docs/destination-trust-policy.md classes as a credential, and configuration values that carry one) is handed over the relay bridge only to a FluxRouter-operated relay, decided on the URL the relay socket is opened to (IdentityDisclosure::for_websocket_destination: wss to the FluxRouter API host). A FluxRouter relay must receive byte for byte what it received before, and its messages must reach the agent byte for byte as before. Local stdio / IPC clients must be byte-for-byte unchanged.

Context: agent/app.rs bridges the agent to the relay websocket (headless-relay ~470-512; leader ~956-1008, where the relay ALSO receives the agent's answers to local IPC clients' requests). Relay messages reach the agent's ACP input (agent-client-protocol 0.10.4, RawIncomingMessage derived struct per line; ext methods arrive as "_fuigo/...", one "_" stripped).

Round 1 returned DO-NOT-LAND with one HIGH: hooks' command/url (fuigo/hooks/list result.result.hooks[]; hooks_changed session notification params.update.hooks[]) can carry a literal token. Fixed in cdf6b4fd: both fields withheld from every hook at both places; for the same reason MCP servers' args and url (expanded variables) are now withheld from result.result.servers[] and params.mcpServers[] beside env[].value. The pre-check keys are now "token","key","secrets","servers","mcpServers","hooks" plus any \u escape. Round 1's predicted surviving mutations each got a test: duplicate keys at every path level (params, servers, environments, hooks, update, args, command), three-entry lists with the credential in the third entry, three leading underscores, error messages forwarded by the gate, the binary reader stopping when the agent receiver is gone, the agent-serve secret_matches function pinned whole (no comparison can be inserted before hashing), trailing whitespace, a non-bearer Authorization header falling back to the query. The LOW comment overclaim in server.rs is corrected. Round 1's other observations (prompt history, MCP sdk_call / hook run reverse requests carrying tool content, initialize _meta.metadata, git remote URLs, marketplace URLs, fs/read_file, terminal) are declared as not covered (content or tool access, not credential fields) and listed as proposals; docs/destination-trust-policy.md "Credentials over the relay bridge (P82)" says so.

All P82 tests (11: agent::relay_credentials::tests::p82_*, agent::server::server_tests::p82_*, agent::mvp_agent::tests::p82_relay_credentials_bridge_tests with a real MvpAgent wired as leader mode and an in-memory relay websocket) and the P77/P81/agent::relay/agent::server suites have been RUN on the build host at this code and pass. A planned 58-mutant run (request gate, response backstop, agent serve) will be executed after this round.

Tasks:
A. Is the round-1 HIGH closed? Verify paths against the real producers (extensions/hooks.rs, session/acp_session_impl/{hooks_plugins,model_switch,run_loop}.rs, extensions/notification.rs HooksChanged, fuigo-hooks-plugins-types HookInfo; extensions/mcp.rs McpServerEntry / McpServerConfig). Any other producer of HookInfo or McpServerEntry, or any other place a hook/MCP definition reaches the bridge (e.g. plugins list, marketplace, session/new or initialize _meta, config dumps)?
B. Repeat the hunt for credential-bearing FIELDS (not free content) that reach the bridge and are not handled, in both directions. For each: file:line, wire path, real or redacted.
C. Correctness of the new code: paths, non-object rows, value kinds, interaction between the MCP field removals and env values, between params.mcpServers and params.update.hooks, with P81's filter; byte preservation of everything else; damage to unrelated frames (any other response with result.result.hooks / servers, or params.update.hooks / params.mcpServers, that is not a hook / MCP definition?).
D. Any bypass of the request gate or the backstop that round 1 did not cover.
E. Name every behavioural mutation of the P82 production code that would survive the tests now.
Severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
```

## Final report

The round-1 HIGH is closed, but **three HIGH credential-field leaks remain**. These are source-traced findings, not runtime reproductions. I audited `a31a24c2..cdf6b4fd`, including the round-2 delta, at the clean `strike/p82` checkout. I ran no builds, tests or mutants and did not read `docs/strike/audits/`.

1. **HIGH — MCP `command` still exports expanded environment credentials.**

   [relay_credentials.rs:114](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:114) removes MCP `args` and `url`, but preserves `command`.

   This is exploitable without reading files or terminal output. With a live session and an MCP allowlist permitting the entry, a relay can call `_fuigo/mcp/upsert` with `command: "${FUIGO_API_KEY}"`, then `_fuigo/mcp/list`. Upsert persists the configuration at [extensions/mcp.rs:2162](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/mcp.rs:2162). Listing reloads and expands it; [fuigo-config-types/src/mcp.rs:372](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-config-types/src/mcp.rs:372) explicitly expands `command`. Catalog construction copies it at [extensions/mcp.rs:482](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/mcp.rs:482). Successful executable startup is unnecessary for the catalog disclosure.

   **Wire paths:** `result.result.servers[].command`; also `params.mcpServers[].command` when that catalog is pushed. **Value: real, unredacted.**

   **Tests:** not caught. The fixtures use ordinary executable paths, and [relay_credentials_tests.rs:339](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials_tests.rs:339) explicitly requires `command` to remain.

2. **HIGH — MCP setup definitions provide another route for literal credentials.**

   The list handler exports unresolved setup schemas and saved values at [extensions/mcp.rs:944](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/mcp.rs:944). The auth-trigger handler separately exports the schema at [extensions/mcp.rs:1478](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/mcp.rs:1478). Neither path is filtered.

   A supported configuration can have an account selector, `setup.variables.AUTH.map.prod = "literal-api-key"`, and `headers.Authorization = "Bearer {{AUTH}}"`. The resolver selects that map value at [fuigo-config-types/src/mcp.rs:350](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-config-types/src/mcp.rs:350), and template rendering substitutes it into headers. Before setup is completed, listing or triggering authentication exposes the entire map—including credentials for unselected accounts.

   **Wire paths:** `result.result.servers[].setup.variables.*.map.*` and `result.result.setup.variables.*.map.*`. Setup `fields[].options[].value`, `fields[].default`, and `servers[].setupValues.*` also remain raw when configured with credential values. **Values: real, unredacted.**

   These are configuration values used to construct authentication, within the stated rule.

   **Tests:** not caught. P82’s MCP fixtures exercise `build_mcp_catalog`, whose entries have `setup: None` and `setup_values: None`; they do not exercise the list handler’s additional setup-entry producer or `mcp/auth_trigger`.

3. **HIGH — reverse `terminal/create` requests disclose session environment secrets.**

   [agent_ops.rs:3760](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/mvp_agent/agent_ops.rs:3760) loads session environment values from compatible settings and trusted `.envrc`. Both terminal implementations serialize those values into ACP:

   - [acp_terminal.rs:30](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell-terminal/src/acp_terminal.rs:30)
   - [adapter.rs:196](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell-terminal/src/adapter.rs:196)

   A local client using ACP terminal execution can run an ordinary `pwd` with `GITHUB_TOKEN` in its session environment. Leader mode mirrors that reverse request to the relay at [app.rs:996](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/app.rs:996). P82 handles MCP environment arrays only, leaving this array untouched.

   **Wire path:** `terminal/create` → `params.env[].value`. **Value: real, unredacted.**

   This differs from the excluded terminal-access observation: no command needs to read or print a credential. The agent supplies the credential field with an otherwise harmless command.

   **Tests:** not caught. No P82 fixture covers this reverse request; the real-agent bridge test initializes with `terminal(false)` at [p82_relay_credentials_bridge_tests.rs:220](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/mvp_agent/tests/p82_relay_credentials_bridge_tests.rs:220).

**A — The original hook finding is closed.** The producer at [extensions/hooks.rs:85](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/hooks.rs:85) preserves configured command/URL literals. All production `fuigo_hooks_plugins_types::HookInfo` creation goes through that conversion. The list response comes through `run_loop.rs:893`; notification producers are `hooks_plugins.rs:979`, `hooks_plugins.rs:1229`, and `model_switch.rs:254`. Their serialization matches both paths P82 now removes:

- `result.result.hooks[].{command,url}`
- `params.update.hooks[].{command,url}`

The new tests catch removal being omitted at either location.

Plugin lists and marketplace entries expose counts, status and component summaries, rather than another copy of these definitions. The separate workspace `HookInfo` contains no command/URL. `initialize._meta.mcpServers` is explicitly empty at [acp_agent.rs:442](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/mvp_agent/acp_agent.rs:442); discovery uses the covered notification afterward. Session-new/load metadata does not export the transport configuration. The additional credential-bearing MCP producers are the setup paths identified above.

**B — Credential-field disposition for other relays:**

| Field/path | Result |
|---|---|
| Requests for `getBearerToken` / `getApiKey` | Refused; credential notifications dropped |
| Mirrored `result.result.token` / `.key` | Removed, including non-string values |
| Cloud `result.environments[].secrets[].value` and `result.environment.secrets[].value` | Removed |
| MCP catalog/notification `args`, `url`, `env[].value` | Removed |
| Hook list/notification `command`, `url` | Removed |
| MCP `command`, setup values/schema value maps | **Real values survive** |
| Reverse terminal `params.env[].value` | **Real values survive** |
| MCP HTTP authentication headers / OAuth client secrets | Not exported by `McpServerEntry` |

Incoming key-setting/authentication requests carry values the relay already supplies; I found no additional direct credential-getter alias. The command-expansion sequence above is an indirect getter through permitted configuration methods. I retained the supplied exclusions for prompt/tool content, arbitrary metadata, repository/marketplace URLs and tool access.

**C — The new traversal is otherwise correct for its selected paths.**

- Both MCP removals and environment-value removal execute. Likewise, `params.mcpServers` cannot suppress `params.update.hooks`; the bitwise boolean combinations do not short-circuit.
- All object rows are visited. Non-object rows remain unchanged and do not stop later rows. Non-array containers are left unchanged.
- Removed fields are removed regardless of value kind. Duplicate keys in inspected objects fail closed; escaped keys reach the parser through the `\u` pre-check.
- P82 runs before P81. P81 does not restore removed credentials. FluxRouter takes the original-message fast path through both filters.
- Local IPC receives its separate original copy. FluxRouter inbound handling retains the prior newline trimming and capability-injection behavior.
- Untouched frames return the original string. In rewritten frames, retained **raw values** survive, but rewritten container whitespace and escaped key spellings can normalize. This is not literal preservation of every remaining byte.
- `mcp/auth_status` also returns `result.result.servers[]`, but its rows contain only `server_name` and `status`, so they are unaffected. I found no current unrelated producer whose fields collide with the new hook/MCP removals.

**D — No additional parser bypass was found in the current gate.** ACP 0.10.4 reads one derived `RawIncomingMessage` per line and strips one leading underscore. Parsing then forwarding the decided value prevents duplicate-key, escaped-method and newline reinterpretation; arrays are dropped. Both text and binary agent-delivery branches are gated. The remaining bypasses are the uncovered field/producers above.

One coverage distinction: “errors forwarded” is a **gate-unit-test** property. The socket’s text reader still intercepts error frames before the gate at `relay.rs:806`, as it did before P82.

**E — Concrete predicted surviving mutations follow.** These are source-review predictions, not executed mutation results. “Every possible behavioural mutation” is unbounded; without the proposed 58 concrete mutations, an exhaustive survival claim would be false.

| Mutation location | Predicted survivor and consequence | Severity of regression |
|---|---|---|
| [relay_credentials.rs:218](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:218) | Iterate `rows.iter_mut().take(3)`. Current credential lists have at most three entries; fourth-and-later credentials survive. | HIGH |
| [relay_credentials.rs:90](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:90) | Forward objects containing `result` or `error` before checking `method`. No credential-method fixture includes either sibling. A mixed binary request reaches ACP, which prioritizes its method. The response backstop still protects its ordinary credential answer. | MEDIUM |
| [server.rs:109](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/server.rs:109), `:113` | Insert an early byte comparison in either caller before the pinned `secret_matches` return. Functional assertions still pass; the whole-helper pin does not cover caller comparisons. | MEDIUM |
| [relay_credentials.rs:165](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:165) | Exempt duplicate `url` keys from rejection. Duplicate `command` and `args` are tested; duplicate `url` is not. This weakens fail-closed behavior. | LOW |
| [relay_credentials.rs:246](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:246) | Preserve `key` specifically when its value is `null`. The API-key fixture supplies a string; its synthetic variant supplies a number. The absent-environment-key response is untested. | LOW |
| [relay_credentials.rs:55](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:55) | Replace `trim_start_matches` with `trim_matches`. Trailing-underscore near misses become incorrectly refused; none is tested. | LOW |
| [relay_credentials.rs:219](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:219) | Reserialize unchanged object rows alongside edited rows. Fixtures lack a formatted/escaped-key unchanged row next to a credential-bearing row, so that byte-preservation regression can survive. | LOW |

Ordinary mutations inside `secret_matches` itself are now caught by the whole-function source pin. The added tests also catch the previously identified two-entry truncations, omitted hook/MCP removals, short-circuit combinations, missing path-level duplicate checks, binary receiver-close handling and trailing-secret whitespace changes.

The three current HIGH findings require closure independently of the planned mutant results.

DO-NOT-LAND
