# P82 Astra round 3 (gpt-6-astra, read-only, codex 0.160)

First attempt at HEAD fda8b717 stopped by the 30-minute background limit before reporting (inadmissible; raw `hetzner-dsm:/root/fuigo-builds/p82/p82-astra-r3-killed.raw.txt`, sha256 `60b2655e6152e989d3e181b65dda67f6a5e4d442965ac6bd5b60c70f40aa95f3`). Rerun at 148f0523 (one test fixture added): raw `hetzner-dsm:/root/fuigo-builds/p82/p82-astra-r3.raw.txt`, sha256 `9567bab593e4cae556e689be85fed4b1dc8479eaab140e9effc84f71236b7067`.

## Brief

```
Independent audit, round 3, of Fuigo packet P82. Repo: /Volumes/Mando/WaylandBots/Fuigo/wt-p82 (read-only; do NOT run cargo or any build; do NOT read docs/strike/audits/). Branch strike/p82, HEAD 148f0523. Audit the whole packet `git diff a31a24c2..148f0523`, with attention to the delta since round 2 `git diff cdf6b4fd..148f0523` (148f0523 adds one test fixture only). Parent a31a24c2 is packet P81 (identity filter in agent/relay.rs relay_outbound_frame, on P77, on integration 8b1a0192): context, not under audit, except where P82 interacts with it.

Rule: a credential (session bearer, API key, environment secrets, anything docs/destination-trust-policy.md classes as a credential, and configuration values that carry one) is handed over the relay bridge only to a FluxRouter-operated relay, decided on the URL the relay socket is opened to (IdentityDisclosure::for_websocket_destination: wss to the FluxRouter API host). A FluxRouter relay must receive byte for byte what it received before, and its messages must reach the agent byte for byte as before. Local stdio / IPC clients must be byte-for-byte unchanged. Declared NOT covered (content or tool access, listed as proposals): prompt history, tool input/output (incl. MCP sdk_call and hooks run/event reverse requests), initialize _meta.metadata, git remote URLs, marketplace source URLs, fs/read_file, terminal commands the relay runs; a relay that may drive the agent can use its tools.

Context: agent/app.rs bridges the agent to the relay websocket (headless-relay ~470-512; leader ~956-1008, where the relay ALSO receives the agent's answers to local IPC clients' requests and the agent's requests to them). Relay messages reach the agent's ACP input (agent-client-protocol 0.10.4).

Round 2 returned DO-NOT-LAND with three HIGH, fixed in fda8b717: (1) MCP `command` (expanded; readable back after a relay's mcp/upsert) now withheld with args/url; (2) MCP `setup` / `setupValues` per server and `result.result.setup` of fuigo/mcp/auth_trigger withheld; (3) the agent's own `terminal/create` requests lose `params.env` entirely (an entry without value is not a valid EnvVariable). Pre-check keys now "token","key","secrets","servers","mcpServers","hooks","setup","env" plus any \u. Its predicted survivors each got a test (five-entry lists, a credential method beside result/error, duplicate url/setup/env/method, null API key, trailing-underscore near misses, unchanged rows keeping their bytes, validate_auth pinned whole). All P82/P81/P77/agent::relay/agent::server tests RUN on the build host at fda8b717 and pass; a 73-mutant run is executing at fda8b717.

Tasks:
A. Are round 2's three HIGH closed? Verify against the producers (extensions/mcp.rs list / auth_trigger / setup entries / upsert, fuigo-config-types/src/mcp.rs expansion, fuigo-shell-terminal acp_terminal.rs and adapter.rs, agent_ops.rs session env).
B. Repeat the hunt for credential-bearing FIELDS or configuration values (not free content) that still reach the bridge, in both directions, including agent→client requests and notifications (fs/write_text_file? session/request_permission? other reverse requests?), and indirect getters (a relay writes configuration then reads an expanded value back through another field: plugins, hooks, skills, settings, models, endpoints, workspaces, cloud env create/update).
C. Correctness and damage: the terminal/create rule (method match, escapes, duplicates, non-object params); damage to unrelated frames from the new keys (setup, env); byte preservation; interaction with P81.
D. Any bypass of the request gate or the backstop not yet covered.
E. Concrete behavioural mutations of the P82 production code that would survive the tests now.
Severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
```

## Final report

The three specific round-2 HIGH findings are closed in source, but **two HIGH credential-disclosure paths remain**.

Reviewed `strike/p82` at `148f0523512fae8de1bf8397e5de037fd76812ae`, including the full production change and round-2 delta. No files changed; no builds, tests, or mutants ran. **Audit integrity limitation:** my initial unfiltered delta displayed `docs/strike/audits/p82-astra-r2.md`. I excluded that directory afterward, but cannot claim this review was fully blind.

1. **HIGH — skills configuration provides an environment-credential getter.**

   The backstop at [relay_credentials.rs:286](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:286) leaves skills configuration responses untouched.

   A non-FluxRouter relay can send these extension requests:

   ```json
   {"jsonrpc":"2.0","id":1,"method":"_fuigo/skills/add","params":{"path":"/tmp/p82-${FUIGO_API_KEY}","cwd":"/tmp"}}
   {"jsonrpc":"2.0","id":2,"method":"_fuigo/skills/config","params":{"cwd":"/tmp"}}
   ```

   The source chain is complete:

   - [skills.rs:148](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/skills.rs:148) resolves the path without expanding `${…}`. Failed canonicalization preserves the path; an existing directory is unnecessary.
   - [skills.rs:290](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/skills.rs:290) saves it into `skills.paths`.
   - [load.rs:51](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/util/config/load.rs:51) reloads effective configuration. [loader.rs:289](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-config/src/loader.rs:289) expands environment references throughout its string values.
   - [skills.rs:432](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/extensions/skills.rs:432) returns the expanded paths and repeats them in `message`.

   **Leaking fields:** `result.result.paths[]` and `result.result.message`. `${OTHER_SECRET}` works for other available process environment variables.

   Preconditions are an available environment credential and writable user configuration. This uses configuration methods, without prompting the model, reading a file through a tool, or executing a terminal command. Both methods pass the request gate. P81 does not remove either field.

   **Tests:** not caught. Neither P82 test file exercises skills configuration or this write–expand–read sequence.

2. **HIGH — cloud-environment configuration retains credential-bearing scripts.**

   [withhold_environment_secrets at relay_credentials.rs:256](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:256) removes only `secrets[].value`.

   The actual environment type also serializes `setupScript` and `maintenanceScript`, defined at [sandbox_types.rs:473](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/prod/mc/cli-chat-proxy-types/src/sandbox_types.rs:473). Cloud list returns the backend environments directly at [acp_agent.rs:2407](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/mvp_agent/acp_agent.rs:2407); create and update likewise return the environment at lines 2463 and 2522.

   Concrete scenario: an accessible environment has a setup script containing `curl -H 'Authorization: Bearer literal-key' …`. Listing that configuration transmits the literal credential through:

   - `result.environments[].environment.setupScript`
   - `result.environments[].environment.maintenanceScript`

   Create/update responses use `result.environment.environment.{setupScript,maintenanceScript}`. Leader mode also mirrors a local client’s responses.

   These are executable **configuration values**, analogous to the already-covered hook command. Disclosure occurs while reading configuration; the relay need not run the script.

   This finding is conditional on the backend returning the configured script. Fuigo’s response types and bridge apply no redaction to it. The sibling `environmentVariables[].value` also remains raw if someone stores an API key there; its “Non-secret” comment does not enforce that property.

   **Tests:** not caught. [environment_responses at relay_credentials_tests.rs:190](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials_tests.rs:190) leaves both scripts at their default and uses only `NODE_ENV=production` in ordinary environment variables.

**A — Round-2 closure**

| Finding | Source assessment | Test coverage |
|---|---|---|
| Expanded MCP `command` | Closed. Expansion at `fuigo-config-types/src/mcp.rs:372` reaches the catalog’s `command`; P82 removes it alongside `args` and `url`. Upsert does not provide a separate unfiltered catalog path. | Command-removal fixtures and socket tests catch omission. |
| MCP `setup` / `setupValues`, auth-trigger setup | Closed. The additional list producer at `extensions/mcp.rs:934` and auth-trigger producer at `:1478` match the removed paths. | Synthetic setup fixtures catch basic removal regressions. Actual setup-only server shape remains a coverage gap below. |
| Reverse terminal environment | Closed. Both terminal implementations produce `params.env`; P82 removes the whole field. Session settings/`.envrc` values originate at `agent_ops.rs:3760`. | A real `CreateTerminalRequest` serialization is covered through the socket fixture. The real-agent bridge fixture still disables terminal support. |

**B–D — Remaining producer, correctness, and bypass assessment**

- **Reverse requests:** `fs/write_text_file` forwards file content supplied to the filesystem adapters; `session/request_permission` forwards tool-call content and permission metadata. I found no additional automatic credential-field injection in those producers. Their arbitrary content remains within the stated exclusions. MCP SDK calls and hook reverse requests retain the same excluded-content boundary.
- **Other configuration getters:** plugin lists project summaries/counts, model lists project display/capability data rather than API keys or endpoint configuration, and workspace lists project identifiers/names. I found no additional concrete credential getter there. Skills configuration is the exception above.
- **Terminal matching:** [relay_credentials.rs:301](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs:301) decodes the method as a JSON string and compares exactly with `terminal/create`. Slash and Unicode escapes work. Duplicate method/params/env keys in inspected objects fail closed. Removal does not depend on the environment value’s type.
- **Non-object terminal params:** left unchanged. These cannot be emitted by the inspected typed terminal producers; I found no current producer-based leak through that case.
- **New pre-check keys:** `setup` and `env` trigger inspection, not indiscriminate recursive removal. Unchanged valid frames return their original bytes. I found no current unrelated producer whose normal fields are wrongly removed by the added paths.
- **Byte preservation:** FluxRouter takes the original-frame path; its inbound handling retains the pre-P82 trimming/capability behavior. Local IPC receives the separate original copy at [app.rs:996](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/app.rs:996). Edited non-FluxRouter containers can normalize whitespace/key spelling, while retained raw values and unchanged rows preserve their bytes.
- **P81:** P82 executes first; P81 cannot restore removed credentials. The destination decision remains tied to `config.ws_url`, used for the socket connection.
- **Request parsing:** the gate forwards the value it inspected, eliminating duplicate-method and newline reinterpretation. ACP 0.10.4’s actual line reader and method-first dispatch are consistent with this defense. Both text and binary delivery paths are gated. Existing text-frame error interception happens before the gate; it drops those frames rather than providing a credential bypass.
- **Agent-serve comparison:** no additional source defect identified. The whole-function pins cover both validation and hashing/comparison. This establishes neither compiled constant-time behavior nor timing-test evidence.

**E — Concrete predicted surviving mutations**

These are source-based predictions against the inspected tests, not results from the running 73-mutant job. Locations below refer to [relay_credentials.rs](/Volumes/Mando/WaylandBots/Fuigo/wt-p82/crates/codegen/fuigo-shell/src/agent/relay_credentials.rs).

| Severity of regression | Location | Mutation and why it survives |
|---|---|---|
| HIGH | `:272` | Remove `setup`/`setupValues` only when the server contains `command`, while always removing command/args/url. The sole successful server-setup fixture includes `command`; real setup-required entries use an HTTP placeholder without it. Those real entries would leak. |
| HIGH | `:236` | Iterate `rows.iter_mut().take(5)`. Inspected credential lists stop at five entries; sixth-and-later credentials would survive. Increasing one fixed fixture length cannot establish unbounded traversal. |
| MEDIUM | `:304` | Compare raw method text after replacing only `\/` with `/`, instead of JSON-decoding it. Literal and escaped-slash terminal fixtures pass, but `"terminal/\u0063reate"` leaks its environment. No terminal-method Unicode fixture exists. |
| LOW | `:304` | Replace equality with `starts_with("terminal/create")`. Existing `terminal/output` control passes, but `terminal/createExtra` wrongly loses its `env`. No prefix-near-miss fixture exists. |
| LOW | `:183` | Exempt duplicate `setupValues` from duplicate rejection. Duplicate setup/url/env/method cases remain caught; duplicate `setupValues` has no fixture. Fail-closed behavior regresses. |

The added `148f0523` mixed terminal/credential fixture does catch short-circuiting that skips terminal removal after another credential field was removed. The server whole-function pins also close the previously identified early-comparison mutation gap.

The two current HIGH findings independently prevent acceptance of the stated credential rule.

DO-NOT-LAND
