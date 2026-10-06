# Headless Mode and Scripting

Headless mode runs Fuigo non-interactively from the command line. It accepts a single prompt, executes it with full tool access, and returns the result. Use it to automate tasks, script workflows, build integrations, and parse output programmatically.

---

## Basic Usage

Passing a prompt non-interactively triggers headless mode. The most common way is the `-p` flag (short for `--single`); `--prompt-json` and `--prompt-file` also trigger it:

```bash
fuigo -p "Your prompt here"
```

Fuigo processes the prompt, runs any necessary tools, and prints the result to stdout. The process exits when the response is complete.

---

## Command-Line Options

| Flag                    | Description                                           |
| ----------------------- | ----------------------------------------------------- |
| `-p, --single <PROMPT>` | The prompt to send (or use `--prompt-json` / `--prompt-file`) |
| `-m, --model <MODEL>`   | Model to use (e.g., `grok-4.6`)              |
| `-s, --session-id <ID>` | Create a **new** session with this **UUID** (errors if invalid UUID or already in use under the target session directory; does not resume, use `-r`/`-c`) |
| `--fork-session`        | With `-r`/`-c`, fork into a new session ID instead of appending to the original |
| `-r, --resume <ID_OR_TITLE>` | Resume an existing session by ID, or by title for the current directory, ignoring letter case (a sole manually renamed match wins among duplicates; remaining duplicates error with their IDs; UUID-shaped values always take the ID path; scripts should prefer IDs) |
| `-c, --continue`        | Continue the most recent session in current directory  |
| `--cwd <PATH>`          | Set working directory                                 |
| `--output-format <FMT>` | Output format: `plain`, `json`, `streaming-json`, `streaming-messages-json` |
| `--include-partial-messages` | Emit raw `stream_event` deltas. Only affects `--output-format streaming-messages-json`; ignored (with a warning) otherwise. |
| `--yolo`                | Auto-approve all tool executions                      |
| `--rules <TEXT>`        | Custom rules for the system prompt                    |
| `--tools <TOOLS>`       | Allowlist of built-in tools (comma-separated). MCP meta-tools remain available unless denied. Headless only. |
| `--disallowed-tools <TOOLS>` | Denylist of built-in tools to remove (comma-separated). Supports `Agent` entries. Headless only. |
| `--max-turns <N>`       | Maximum number of agentic turns before stopping. Headless only. |
| `--reasoning-effort` / `--effort <LEVEL>` | Reasoning effort for reasoning models. Canonical levels: `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max` (each a distinct tier; a model only accepts the levels its menu advertises). Also accepts per-model menu option ids (e.g. `deep` → mapped wire value), same as `/effort`. Works in TUI and headless. |
| `--permission-mode <MODE>` | Permission mode. `bypassPermissions` enables always-approve (see [Permissions and safety](22-permissions-and-safety.md#permission-modes)); for deny-by-default use `defaultMode` in `.claude/settings.json`. |
| `--allow <RULE>`        | Permission allow rule with glob patterns (repeatable). Works in TUI and headless. |
| `--deny <RULE>`         | Permission deny rule with glob patterns (repeatable). Works in TUI and headless. |
| `--prompt-json <JSON>`  | Prompt as JSON content blocks                         |
| `--prompt-file <PATH>`  | Prompt from a file                                    |
| `--verbatim`            | Send prompt exactly as given                          |
| `--no-auto-update`      | Disable update checks for this session                |
| `--sandbox <PROFILE>`   | Sandbox profile for filesystem/network access         |
| `--timeout <SECS>`      | Hard cap on the whole run, in seconds. **Off by default.** Headless only (see [Run timeout](#run-timeout)). |

> **Note:** `--tools`, `--disallowed-tools`, `--max-turns`, and `--agents` are headless-only flags. If used in the interactive TUI, a warning is printed and the flag is ignored. `--reasoning-effort`/`--effort`, `--permission-mode`, `--allow`, and `--deny` work in both modes. For more flags (agents and worktrees), see [Additional Headless Flags](#additional-headless-flags).

### Run Timeout

`fuigo -p` waits for the agent as long as the agent takes. If the agent never produces an end
event — a wedged provider connection, a backend that accepts the prompt and then goes silent — the
run has nothing to fall back on and waits forever. `--timeout` puts a hard cap on the whole run:

```bash
fuigo -p "review this diff" --timeout 900
# or, for a whole CI job:
FUIGO_HEADLESS_TIMEOUT_SECS=900 fuigo -p "review this diff"
```

- **Off by default.** Without the flag (or the environment variable) nothing changes: existing runs
  keep waiting indefinitely, exactly as before.
- The value is whole seconds and must be at least `1`. The flag wins over the environment variable.
  An empty, zero or unparsable `FUIGO_HEADLESS_TIMEOUT_SECS` is ignored with a warning and the run
  proceeds uncapped — a bad value exported into a shell must never break unrelated `fuigo`
  invocations, and the variable has no effect on the interactive TUI at all.
- The clock starts before the agent spawns and covers the whole run: `initialize`, `authenticate`,
  `session/new` / `session/load` / `fuigo/session/fork`, the model and effort application, the
  turn itself, and `--memory-flush`. Each of those is an ACP request that otherwise waits for a
  reply with no deadline; under `--timeout` every one of them is bounded by whatever the run has
  left, and the failure names the step (`timed out after 900s waiting for session/new`).
- On elapse Fuigo kills any background tasks and subagents the run started, reports the timeout and
  exits non-zero — so a CI step fails rather than hanging a runner.
- **A turn that already answered is still reported, in the same one terminal document.** The cap
  often lands during the wait for background work — a `monitor(persistent: true)` never completes
  and always waits out `--background-wait-timeout`. When that happens the completed turn's text,
  its `usage` and its structured output are reported together with the cap, on a single terminal
  record: `--output-format json` stays exactly one JSON object (`"stopReason": "cancelled"` plus an
  `"error"` field), and the streaming formats emit exactly one terminal line (`stream-json` a
  single `result` with `is_error: true`, `streaming-json` a single `end` carrying `error`). A
  machine consumer never sees two terminal records for one run, so a reader that stops at the first
  cannot mistake a capped run for a success, and one that reads to EOF cannot double-count `usage`.
  The exit code is still non-zero, because background work was killed.
- It is a cap on the run, not a budget for the model: it is unrelated to `--max-turns`,
  `FUIGO_MAX_RUNTIME_SECS` and `FUIGO_MAX_MODEL_CALLS`, which gate how much work is admitted rather
  than how long the process may live.
- `--background-wait-timeout` only bounds the wait for background work *after* the first turn ends;
  `--timeout` bounds everything, including a turn that never ends.

Without `--timeout`, the `initialize` and `authenticate` handshakes are still capped at 120 seconds
on their own, so a backend that never answers them fails startup with an error instead of hanging.
This is the one part of the feature that is *not* off by default, so it has its own escape hatch:
`FUIGO_HEADLESS_LIFECYCLE_TIMEOUT_SECS` raises the cap (whole seconds) and `0` removes it entirely,
restoring the unbounded 1.0.16 startup. Set it if a cold `FUIGO_HOME` on a slow or network
filesystem legitimately needs longer than two minutes to answer `initialize`. An empty or
unparsable value keeps the 120 second default with a warning.

### Tool Filtering

Use `--tools` to restrict the agent to an explicit set of tools (allowlist), or `--disallowed-tools` to remove specific tools from the default set (denylist). Both accept comma-separated tool names.

Tool names are internal tool IDs (e.g. the shell tool is `run_terminal_cmd`, not `bash`).

```bash
# Only allow read-only tools
fuigo -p "Explain this codebase" --tools "read_file,grep,list_dir"

# Remove web access and file editing
fuigo -p "Review this code" --disallowed-tools "web_search,web_fetch,search_replace"

# Remove shell access
fuigo -p "Review this code" --disallowed-tools "run_terminal_cmd"
```

`--disallowed-tools` also supports special `Agent` entries to control subagent spawning:

| Entry                  | Effect                                  |
| ---------------------- | --------------------------------------- |
| `Agent`                | Block all subagent spawning             |
| `Agent(explore)`       | Block the `explore` subagent type only  |
| `Agent(explore, plan)` | Block multiple specific types           |

```bash
# Prevent the agent from spawning any subagents
fuigo -p "Fix this bug" --disallowed-tools "Agent"

# Block only the explore subagent
fuigo -p "Refactor this module" --disallowed-tools "Agent(explore)"
```

`--tools` preserves the selected agent profile's injection policy: stock profiles inject enabled optional tools before applying the allowlist, while curated profiles remain strict. The final toolset retains requested tools plus always-on MCP meta-tools. When both flags are present, `--disallowed-tools` wins.

### Permission Rules (`--allow` / `--deny`)

Permission rules control whether specific tool invocations are auto-approved, denied, or require user confirmation. Unlike `--disallowed-tools` (which removes tools entirely), permission rules leave tools available but gate their execution.

Rules use `ToolPrefix(glob_pattern)` syntax:

| Prefix        | What it controls                   |
| ------------- | ---------------------------------- |
| `Bash(...)`   | Shell command execution            |
| `Edit(...)`   | File editing (path glob)           |
| `Write(...)`  | File writing (path glob)           |
| `Read(...)`   | File reading (path glob)           |
| `Grep(...)`   | Search operations (path glob)      |
| `WebFetch(...)` | URL fetching (glob or `domain:host`) |
| `MCPTool(...)` | MCP tool invocations              |

For path rules (`Read`, `Edit`, `Write`, `Grep`), `*` is a single-level wildcard and `**` is recursive. For `Bash` rules, `*` matches any characters including spaces. A bare prefix without parentheses matches all invocations of that type, and `Bash(cmd:*)` is equivalent to prefix matching on `cmd`. See [22-permissions-and-safety.md](22-permissions-and-safety.md#rule-matching-reference) for the full matching semantics.

```bash
# Deny shell commands matching "rm*"
fuigo -p "Clean up this project" --deny "Bash(rm*)"

# Allow npm commands, deny sudo
fuigo -p "Set up the project" --allow "Bash(npm*)" --deny "Bash(sudo*)"

# Allow bash commands without prompting (see the note below for what this cannot cover)
fuigo -p "Build the project" --allow "Bash"
```

`--allow` and `--deny` can be repeated. Deny rules take precedence over allow rules.

An allow rule matches the words of a shell command, so it cannot vouch for a write the words do not
show. A shell command that writes a file through a redirect (`echo x > notes.txt`, `cmd >> log`) still
asks for approval under every `--allow` rule, `Bash` included; in headless mode nobody can give it, so
the run is blocked (exit `3`). Run such commands with `--always-approve` (deny rules still apply), or
have the model write files with its file tools, which `Write(...)`/`Edit(...)` rules do cover.
Redirects to `/dev/null` are not writes and are covered as usual.

---

## Output Formats

Headless mode supports four output formats, selected with `--output-format`.

### plain (default)

Human-readable text, suitable for direct display or piping:

```
Here's a summary of the codebase...
```

### json

A single JSON object emitted after the response completes: response text,
stop reason, session ID, request ID (plus `thought` when reasoning is present).
When the prompt reached the model, the same object also carries spend fields
(`usage`, `num_turns`, `modelUsage`, cost). `stopReason` is the snake_case
ACP/Messages token (`end_turn`, `max_tokens`, …). When a tool permission was
refused, it also carries a `permissionDenied` record (see
[The denial record, per format](#the-denial-record-per-format)).

```json
{
  "text": "Here's a summary of the codebase...",
  "stopReason": "end_turn",
  "sessionId": "abc123",
  "requestId": "xyz789",
  "num_turns": 7,
  "usage": {
    "input_tokens": 7210,
    "cache_read_input_tokens": 41000,
    "cache_creation_input_tokens": 0,
    "output_tokens": 1893,
    "reasoning_tokens": 412,
    "total_tokens": 50103
  },
  "modelUsage": {
    "grok-4.6": {
      "inputTokens": 7210,
      "outputTokens": 1893,
      "cacheReadInputTokens": 41000,
      "modelCalls": 7,
      "costUSD": 0.01268905
    }
  },
  "total_cost_usd": 0.01268905,
  "total_cost_usd_ticks": 126890500
}
```

Usage notes:

- `usage` sums tokens for the prompt, including subagents that finished
  before turn end (also under their own `modelUsage` keys). Compaction and
  other side-model calls are excluded.
- **Token field policy (headless result / `end` / error spend):**
  - `usage.input_tokens` and `modelUsage.*.inputTokens` are **uncached only**.
  - `cache_read_input_tokens` / `cacheReadInputTokens` are cache hits.
  - `total_tokens` is full input + output (includes both cache buckets):
    `total_tokens = input_tokens + cache_read_input_tokens + cache_creation_input_tokens + output_tokens`.
  - ACP `_meta.usage.inputTokens` (PromptUsage) is still the **full** prompt
    sum; only the headless projector subtracts cache. Prefer headless fields
    for spend automation.
- `num_turns` counts main-agent model rounds recorded on the prompt ledger
  (tool-loop rounds that reported usage). Subagent sampler calls do not
  increase it. Per-model call counts (including subagents) stay on
  `modelUsage.*.modelCalls`. This is the same counter family as `--max-turns`,
  not a guarantee of exact equality when rounds lack usage or hit gates.
- `total_cost_usd` appears only when the server reported a **complete** cost.
  Absence means unreported or incomplete, never free. Cost is stamped for
  API-key traffic today; pool/OAuth paths often omit it until the server
  stamps cost. When some calls lacked cost, `cost_is_partial` is true and
  **all** cost floats are omitted (`total_cost_usd` and every
  `modelUsage.*.costUSD`) so consumers cannot sum model rows into a fake
  complete bill.
- `total_cost_usd_ticks` is the same value in exact integer ticks
  (1 USD = 10^10 ticks) and appears under the same conditions. Use it for
  billing reconciliation: summing per-invocation ticks matches the server's
  usage export exactly, which float dollars cannot guarantee.
- When subagent usage could not be applied, nested subagent usage was incomplete,
  or the success-path drain timed out (up to 120s on the turn task),
  `usage_is_incomplete` is true and cost floats are omitted the same way
  (token totals may under-count subagents). Cancel snapshots without that long
  drain and marks incomplete while subagents are still live. Incomplete with
  no recorded tokens emits only `usage_is_incomplete` (no zero `usage` object).
- A prompt that never reached the model omits the spend fields.

The `sessionId` field is useful for resuming the conversation later.

On failure, Fuigo emits an error object (process exit non-zero). Prompt-level
failures may also include frozen spend fields when usage was recorded:

```json
{"type":"error","message":"Couldn't start session: ..."}
```

### streaming-json

Newline-delimited JSON, one `type`-tagged object per line, derived from the agent's ACP session updates. Leaf field names (`toolCallId`, `kind`, `rawInput`, `rawOutput`) follow ACP; `toolName` and the `usage` line are Ferrox Labs additions. Consume it by switching on `type`.

```json
{"type":"thought","data":"Analyzing the directory structure..."}
{"type":"tool_call","toolCallId":"call_1","title":"Read","kind":"read","status":"in_progress","toolName":"read_file","rawInput":{"path":"src/main.rs"},"content":[],"locations":[]}
{"type":"tool_call_update","toolCallId":"call_1","status":"completed","content":[],"rawOutput":{"lines":42},"locations":[]}
{"type":"text","data":"Here's a summary"}
{"type":"usage","messageId":"resp_1","stopReason":"end_turn","usage":{"input_tokens":812,"output_tokens":45,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"reasoning_tokens":0},"signature":"..."}
{"type":"end","stopReason":"end_turn","sessionId":"abc123","requestId":"xyz789","usage":{...},"num_turns":7,"modelUsage":{...}}
```

Event types:

| Type               | Description                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------- |
| `text`             | A chunk of the agent's response text                                                          |
| `thought`          | Internal reasoning (thinking tokens)                                                          |
| `tool_call`        | A tool call the agent started (`toolCallId`, `toolName`, `kind`, `status`, `rawInput`, `content`, `locations`) |
| `tool_call_update` | Progress or result for a tool call (`status`, `rawOutput`, `content`, `locations`)            |
| `usage`            | Per-response boundary (`messageId`, `stopReason`, `usage`, `signature`), one per model response |
| `plan`             | The agent's current plan (`entries`)                                                          |
| `available_commands` | Tool and slash command lists (`tools`, `commands`)                                          |
| `end`              | Final event with metadata and spend fields when available, plus `permissionDenied` when a permission was refused |
| `error`            | An error occurred (carries `message`, spend fields if any, and `permissionDenied` when a permission was refused) |

`end` is always the last event. Spend fields on `end` match the json object
shape (snake_case uncached `input_tokens`, safe cost floats). `end.stopReason`
is the turn stop reason in snake_case (`end_turn`, `max_tokens`,
`max_turn_requests`, `refusal`, `cancelled`); the verbatim per-response provider
reason (e.g. `tool_use`, `pause_turn`) is on the `usage` line's `stopReason`.
Per-response `message_id`/`stopReason`/`signature` are populated on the Messages
API backend; other backends report what they carry.

Fuigo may also emit `max_turns_reached` and `auto_compact_*` events; treat the list as non-exhaustive and switch on `type`.

### streaming-messages-json

Newline-delimited JSON in the Messages API `stream-json` wire format. The data-bearing surface matches the Messages shape exactly. This includes the `assistant`/`user` message bodies, `usage`, `tool_use`/`tool_result`, inline web search, `stop_reason`, and the `--include-partial-messages` event framing. A consumer that reconstructs messages, reads spend, or detects errors works without changes.

The `system`/`init` and terminal `result` lines carry metadata. Fuigo emits the fields it has real data for and omits pure-placeholder fields it cannot fill, rather than zero-filling them. As a result, those two lines may not pass strict `init`/`result` schema validation. The individual fields are listed below. Read the fidelity notes before treating any one field as authoritative. For a clean Ferrox Labs-native stream with no placeholder shape, use `streaming-json`.

The stream opens with a `system`/`init` line, then `assistant` messages whose `message.content[]` holds `text`, `thinking`, and `tool_use` blocks, `user` messages carrying `tool_result` blocks, and a terminal `result`:

```json
{"type":"system","subtype":"init","session_id":"abc123","apiKeySource":"user","model":"grok-4.6","cwd":"/repo","permissionMode":"default","tools":["read_file","bash"],"slash_commands":["review"],"mcp_servers":[{"name":"linear","status":"connected"}],"skills":[],"uuid":"..."}
{"type":"assistant","message":{"id":"msg_0","type":"message","role":"assistant","model":"grok-4.6","content":[{"type":"text","text":"Let me read the file."},{"type":"tool_use","id":"call_1","name":"read_file","input":{"path":"src/main.rs"}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{...}},"parent_tool_use_id":null,"session_id":"abc123","uuid":"..."}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"fn main() {}","is_error":false}]},"parent_tool_use_id":null,"session_id":"abc123","uuid":"..."}
{"type":"result","subtype":"success","is_error":false,"duration_ms":0,"duration_api_ms":0,"num_turns":7,"result":"Here's a summary...","stop_reason":"end_turn","total_cost_usd":0.0127,"usage":{"input_tokens":812,"output_tokens":210,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"server_tool_use":{"web_search_requests":0}},"modelUsage":{},"session_id":"abc123","uuid":"..."}
```

Message types:

| Type        | Description                                                              |
| ----------- | ---------------------------------------------------------------------- |
| `system`    | Session preamble (`subtype: "init"`) with model, cwd, permission mode, tools, slash commands, and MCP servers. `subtype: "compact_boundary"` marks an auto compaction |
| `assistant` | A model message; `message.content[]` holds `text`/`thinking`/`tool_use`, plus `server_tool_use`/`web_search_tool_result` for inline backend web search |
| `user`      | Tool results, as `tool_result` blocks inside `message.content[]`         |
| `result`    | Terminal message with final text, stop reason, and spend fields         |

The `assistant` and `user` messages carry `session_id`, `uuid`, and `parent_tool_use_id` (`null` for the main conversation). The `system`/`init` and terminal `result` lines carry `session_id` and `uuid` but no `parent_tool_use_id`.

The `uuid` on each line is freshly generated per emitted line. It is not a provider, message, or event id, and not a correlation key. It does not match the provider `message.id` (that value rides `assistant.message.id`). It is unique per line, even for lines that describe the same message, and it carries no cross-line or cross-run identity. Do not use it to correlate or deduplicate.

Text and reasoning chunks are grouped into one assistant message per model response. A response's parallel `tool_result` blocks are grouped into a single `user` message. `result.result` is the final assistant message text. A model response that produces no content blocks emits no `assistant` line in the default mode. Only `--include-partial-messages` surfaces such a response, as its empty `message_start` … `message_stop` envelope.

On `init`, `skills` is live. It lists the session's user-invocable skill names, a subset of `slash_commands` sourced from the session's advertised commands, or `[]` when the session surfaces no skills. The `init` line is emitted once, deferred to the first output line so it captures the session's advertised `tools`, `slash_commands`, and `skills`. The Messages schema defines no second `init`, so a command list that changes after streaming begins is not re-advertised.

The other `init` fields carry real data:

- `apiKeySource` is `user` for API-key auth and `oauth` otherwise. Fuigo does not distinguish the schema's `project`, `org`, and `temporary` sources.
- `permissionMode` is the effective headless mode mapped to the Messages enum: the `--permission-mode` value, or `bypassPermissions` under `--yolo`, else `default`. Fuigo-only modes such as `auto` collapse to `default`.
- `mcp_servers[].status` reflects configuration, not live connection state. A configured server always reports `"connected"`, because per-server handshake state is not resolved by the time `init` is emitted.

Fuigo omits the schema's pure-placeholder `init` fields it has no data for, rather than emitting dummy values: `claude_code_version`, `output_style`, and `plugins`.

`result` includes `duration_ms`, `duration_api_ms`, `num_turns`, `stop_reason`, `total_cost_usd`, `usage` (Messages API `message.usage` shape), and `modelUsage`. It also includes `errors[]` on the error subtypes. `permission_denials` is the schema's own field, in the schema's own entry shape (`tool_name`, `tool_use_id`, `tool_input`). Fuigo includes it when headless mode refused a permission request, and omits it otherwise; see [The denial record, per format](#the-denial-record-per-format). `structured_output` (with `--json-schema`) is snake_case, matching the schema.

`model` appears on `init` and every `assistant` frame. It is the real model id when known, and the literal `"unknown"` only when no model is known at emit time.

The assistant frame's `stop_sequence` is wired end-to-end. It carries the provider's matched stop sequence when the model stopped on a configured one (`stop_reason: "stop_sequence"`), and is `null` on every other stop reason and backend. In `--include-partial-messages` framing, the matched sequence rides both the flushed `assistant` frame and the partial `message_delta.stop_sequence`, so a partial rebuild matches the frame. Only the partial `message_start.stop_sequence` stays `null`, because the matched sequence is not known at message open.

The emitted error subtypes are `error_max_turns`, `error_during_execution`, and `error_max_structured_output_retries`. The schema's `error_max_budget_usd` subtype is never emitted, because fuigo has no budget feature.

`result.usage` reports the Messages `message.usage` shape with the three token buckets disjoint: `input_tokens` (uncached), `cache_read_input_tokens`, and `cache_creation_input_tokens`. Fuigo derives these from the turn's aggregate ledger, reshaped into those buckets. Subagent cache creation is included in `cache_creation_input_tokens`. The aggregate ledger tracks it as its own bucket, so it is no longer folded into `input_tokens`.

`result.usage` always emits numeric buckets, even when data is missing. This happens when the turn's usage ledger is incomplete (the same condition that surfaces `usage_is_incomplete` in the `json` format), or when no aggregate ledger reached the reducer at all. Any bucket fuigo cannot account for falls back to `0`, because the Messages API schema has no marker for incomplete or absent usage. The reducer logs a warning to stderr in both cases. Read an all-zero `usage` here as "unknown", not "free".

The nested `server_tool_use` counter is populated. `web_search_requests` is the number of *successful* backend web searches emitted this run. Failed searches and non-search `WebSearch` actions such as open_page are excluded, matching the Messages API, which does not bill errored searches. A failed backend search still emits a `web_search_tool_result` in the error shape (`content.type: "web_search_tool_result_error"`), but is not counted. Its `error_code` is a fixed `"unavailable"` placeholder, not a code forwarded from the backend. There is no `web_fetch_requests` key, because fuigo has no server-side `web_fetch`, so the placeholder is omitted.

Backend web search is inline. It folds into the same `assistant` frame as the surrounding text. The frame carries a `server_tool_use` block (`name: "web_search"`, `input.query`) immediately followed by a `web_search_tool_result` block. That result block's `tool_use_id` matches the `server_tool_use.id`, and its `content` is a `web_search_result` hit array of `{type, url, title}`. This matches the Messages API's inline server-tool shape rather than splitting the response across frames.

X search and code interpreter are a documented divergence. They stay generic, surfaced as a client `tool_use` block plus a `user` `tool_result`, because the Messages API defines no inline block type for them. Every other client tool likewise keeps the `tool_use`/`tool_result` split.

`--include-partial-messages` emits the raw event framing so a consumer can rebuild each message with the Messages streaming accumulator. The framing is `message_start`, `content_block_start`/`content_block_delta`/`content_block_stop`, `message_delta`, and `message_stop`. It carries the structural events an accumulator needs. The deltas are coarser than the Messages API's token-level streaming: tool input arrives as a single `input_json_delta`, and `citations_delta` is never produced (see below). The result is a faithful reconstruction of each message rather than a token-by-token replay.

On the Messages API backend, the framing is faithful. `message_start` carries the real provider `message.id` and the input-side `usage`. A thinking block emits its `signature_delta` in order, before the block's `content_block_stop`. The `message_start.usage` input side reports all three prompt-side buckets known at message open: `input_tokens` (the uncached portion), `cache_read_input_tokens`, and `cache_creation_input_tokens`. A cache hit is therefore visible on `message_start`, rather than only appearing later on `message_delta`/`result`. `output_tokens` seeds `0` there and is finalized on `message_delta`. A response that starts but produces no content still emits the `message_start` … `message_stop` envelope with no content blocks.

Some backends surface per-response metadata only at end of turn. Those backends fall back to a synthesized `message_start.id` and zero-seeded input `usage`. They defer the reasoning `signature` to the final `assistant` line, which is authoritative in that case.

Tool-call input is emitted as a single `input_json_delta` carrying the complete arguments JSON, followed by `content_block_stop`. It is not a sequence of token-level fragments. This is a deliberate divergence from the Messages API's incremental `partial_json` streaming. Fuigo's ACP tool-call path delivers each tool call as one validated JSON object once the arguments are fully parsed, so a single delta is the accurate representation. A consumer that concatenates `partial_json` reassembles the identical object either way. The backend web-search `server_tool_use` block's `input.query` is emitted the same way, as one `input_json_delta`.

The Messages API `citations_delta` carries inline citations for cited text spans, such as those from web search. This stream does not produce it. Fuigo's Messages content deltas are limited to text, thinking, signature, and tool-input JSON, so there is no citation data to surface as a `citations_delta`. Backend web-search source URLs are reported inline on the completed `web_search_tool_result` block instead (see above), not as per-span text citations.

Fidelity caveats apply to a few fields.

`duration_ms` is the prompt-execution wall clock. `duration_api_ms` is the summed *reported* per-call model time. A model call that does not report its own duration contributes `0`, so `duration_api_ms` can under-count the true API time.

`num_turns` and `total_cost_usd` are authoritative when known. When they are not, `num_turns` falls back to the count of completed model responses this turn, and `total_cost_usd` falls back to `0`. A completed but contentless response emits no `assistant` line, yet still counts as a turn. Spend is never overreported.

`modelUsage` carries the per-model token and cost fields fuigo tracks, plus `webSearchRequests` attributed to the active model. The reducer tracks a single global web-search count rather than per-model, so the whole count lands on the current or last model and other rows stay `0`. A per-model `modelUsage.*.costUSD` is `0` when that model's cost is unknown or withheld. This is the same fail-closed-to-zero behavior as the top-level `total_cost_usd`. The `json` format omits cost floats entirely when partial, but this stream keeps the field present and `0`. `contextWindow` is the current model's real total context window (the same value fuigo uses for auto-compaction), and it appears only on the current model's row. Other rows omit it, and so does the current row when the window is unknown. `maxOutputTokens` has no fuigo catalog, so that key is omitted entirely. `modelUsage` is `{}` when no per-model breakdown is available.

Like `streaming-json`, this stream is read only. Tool approvals and other bidirectional flows use the ACP interface (`fuigo agent`).

---

## Session Management in Headless Mode

By default, each `fuigo -p` invocation creates a fresh session. To maintain context across calls, use session flags.

### Named Sessions (`-s`)

To carry context across headless calls, use `-r/--resume` or `-c/--continue`. Use `-s/--session-id` only for a **new** session with a **UUID** (errors if not a UUID or already in use under the target directory). Older hidden `-s` upsert/resume behavior is gone. Use `-r`/`-c` to continue. With `-r`/`-c`, `-s` requires `--fork-session`:

```bash
# Start a headless session and capture its ID
fuigo -p "Review the changes in this PR" --output-format json | jq -r '.sessionId'

# Continue in the same session
fuigo -p "Now check for security issues" --resume "<id>"

# Optional: create with a client-chosen UUID (must not already exist)
fuigo -p "hello" --session-id "$(uuidgen | tr '[:upper:]' '[:lower:]')" --output-format json
```

> **Note:** `-s/--session-id` creates a new session only (valid UUID; errors if already in use). Use `-r` to resume.

### Resume (`-r`)

The `-r/--resume` flag resumes a specific session by ID, or by title for the current directory when the value is not an ID, ignoring letter case (a sole manually renamed match wins among duplicates; remaining duplicates error with their IDs; UUID-shaped values always take the ID path, so scripts should prefer IDs). It errors if the session does not exist:

```bash
# Get the session ID from a previous JSON response
fuigo -p "Remember: the secret number is 42" --output-format json
# Output includes "sessionId": "abc123"

# Resume that exact session
fuigo -p "What's the secret number?" --resume abc123
```

### Continue (`-c`)

The `-c/--continue` flag continues the most recent session in the current working directory:

```bash
fuigo -p "Continue where we left off" -c
```

### Extracting Session IDs

Use `--output-format json` and parse the `sessionId` field:

```bash
fuigo -p "Hello" --output-format json | jq -r '.sessionId'
```

---

## Piping Input and Output

Headless mode works naturally with Unix pipes and redirection.

### Standard Output

```bash
# Pipe output to a file
fuigo -p "Generate a README" > README.md

# Parse JSON output with jq
fuigo -p "List files" --output-format json | jq -r '.text'
```

### Standard Input

Headless mode does not read piped stdin into the prompt. Pass external content through command substitution or `--prompt-file`:

```bash
# Include git diff as context via command substitution
fuigo -p "Write a concise commit message for these changes:

$(git diff --staged)"

# Or read the prompt from a file
fuigo --prompt-file ./prompt.txt
```

---

## CI/CD Integration Examples

### Automated Code Review

```bash
fuigo -p "Review changes for bugs and security issues." \
  --output-format json --yolo | jq -r '.text' > review.md
```

### Pre-Commit Hook

```bash
fuigo -p "Review staged changes for obvious bugs. Reply OK if fine, or list issues." \
  --yolo --output-format json | jq -r '.text' | grep -q "^OK" || exit 1
```

### Batch Processing

```bash
for file in src/*.js; do
  fuigo -p "Migrate $file from CommonJS to ES modules." --yolo
done
```

---

## Scripting Patterns

### Python Wrapper

Fuigo's headless mode can be wrapped as an OpenAI-compatible chat completion API:

```python
import asyncio
import json
import os

class FuigoChat:
    """Simple OpenAI-compatible wrapper using headless mode."""

    def __init__(self, cwd="."):
        self.cwd = cwd
        self.env = {**os.environ}

    def _build_cmd(self, prompt, model, stream):
        return ["fuigo", "-p", prompt, "-m", model, "--cwd", self.cwd,
                "--output-format", "streaming-json" if stream else "json",
                "--yolo"]

    async def create(self, messages, model="grok-4.6", stream=False):
        prompt = messages[-1]["content"] if len(messages) == 1 else "\n".join(
            f"{m['role']}: {m['content']}" for m in messages
        )
        cmd = self._build_cmd(prompt, model, stream)

        if stream:
            return self._stream(cmd)

        proc = await asyncio.create_subprocess_exec(
            *cmd, env=self.env, stdout=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        data = json.loads(stdout.decode()) if stdout else {"text": ""}
        return {
            "choices": [{
                "message": {"role": "assistant", "content": data.get("text", "")},
                "finish_reason": "stop"
            }]
        }

    async def _stream(self, cmd):
        proc = await asyncio.create_subprocess_exec(
            *cmd, env=self.env, stdout=asyncio.subprocess.PIPE
        )
        async for line in proc.stdout:
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("type") == "text":
                yield {"choices": [{"delta": {"content": event["data"]}}]}
            elif event.get("type") == "end":
                yield {"choices": [{"delta": {}, "finish_reason": "stop"}]}


async def main():
    client = FuigoChat(cwd=".")
    response = await client.create(
        [{"role": "user", "content": "What files are here?"}]
    )
    print(response["choices"][0]["message"]["content"])

asyncio.run(main())
```

### Shell Script

```bash
#!/bin/bash
# Run a code review and exit with failure if issues are found

RESULT=$(fuigo -p "Review this PR for bugs. Output JSON with 'issues' array." \
  --output-format json --yolo | jq -r '.text')

ISSUE_COUNT=$(echo "$RESULT" | jq '.issues | length' 2>/dev/null || echo "0")

if [ "$ISSUE_COUNT" -gt 0 ]; then
  echo "Found $ISSUE_COUNT issues"
  echo "$RESULT" | jq '.issues[]'
  exit 1
fi

echo "No issues found"
```

---

## Folder Trust in Headless Runs

Project instructions (`AGENTS.md`, `CLAUDE.md`, `.fuigo/rules/`), project skills and commands (`.fuigo/skills/`, `.fuigo/commands/`, and their `.agents` / `.claude` / `.cursor` equivalents), project hooks, plugins, permission rules, and repo-local MCP/LSP servers load only from a trusted folder. An interactive session asks once. A headless run cannot ask, so in an untrusted folder that ships any of these it starts without them.

For CI jobs and benchmark harnesses running against a checkout you trust, pass `--trust`:

```bash
fuigo --trust -p "Run the test suite and fix failures"
```

`--trust` records the current folder's workspace (its git root) in `~/.fuigo/trusted_folders.toml` before the session starts, so later runs in the same checkout are trusted as well. In a disposable container you can instead turn the gate off for the process with `FUIGO_FOLDER_TRUST=0`. Instructions and skills under `~/.fuigo/` always load. See [10-hooks.md](10-hooks.md) for the full trust model.

## Always-approve for automation

`--always-approve` (alias `--yolo`, same as `--permission-mode bypassPermissions`) runs tool calls without interactive permission prompts. Deny rules, hooks, and admin locks still apply (see [Permissions and safety](22-permissions-and-safety.md#permission-modes)).

```bash
fuigo -p "Format all files" --always-approve
fuigo -p "Run the tests and fix any failures" --cwd ~/projects/my-app --always-approve
```

For agent servers and SDKs, see [Agent mode](15-agent-mode.md#automation-and-sdks).
---

## Environment Variables for Headless

Key environment variables that affect headless mode:

| Variable                        | Description                                                   |
| ------------------------------- | ------------------------------------------------------------- |
| `FUIGO_API_KEY`        | API key for authentication (required when no browser login)   |
| `FUIGO_DISABLE_PARENT_DEATH_WATCH` | Disable the Linux/Windows binding that ends a stdio agent when the process that started it exits. See [Parent-Process Binding](#parent-process-binding) |
| `FUIGO_HEADLESS_TIMEOUT_SECS`   | Fallback for `--timeout`: hard cap on the whole headless run, in whole seconds. Unset, empty, `0` or unparsable means no cap. Ignored by the interactive TUI. See [Run timeout](#run-timeout) |
| `FUIGO_HEADLESS_LIFECYCLE_TIMEOUT_SECS` | Cap on the `initialize`/`authenticate` handshakes, in whole seconds (default `120`). `0` removes the cap; empty or unparsable keeps the default. Headless only. See [Run timeout](#run-timeout) |
| `FUIGO_HOME`                    | Override config directory (default: `~/.fuigo`)                |
| `FUIGO_LOG_FILE`                | Path to a log file (used verbatim as the path; works in headless and TUI, honors `RUST_LOG`) |
| `RUST_LOG`                     | Log level filter (e.g. `debug`). Headless logs to stderr.     |

For CI environments, set `FUIGO_API_KEY` to your FluxRouter API key (from your FluxRouter dashboard):

```bash
export FUIGO_API_KEY="fuigo-..."
fuigo -p "Run the test suite" --yolo
```

---

## Exit Codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| `0`  | Success. The prompt completed normally |
| `1`  | Error. Authentication failure, network error, or runtime error |
| `2`  | A managed-policy requirement is not met. Fuigo refused to start; update Fuigo or ask your administrator to fix the managed requirements |
| `3`  | **Blocked.** The run ended because a tool permission was denied and headless mode had nobody to ask, or because an execution budget (a token budget, `FUIGO_MAX_MODEL_CALLS`, `FUIGO_MAX_RUNTIME_SECS`) refused the next model request (see [Blocked by a Permission](#blocked-by-a-permission)) |
| `4`  | The tokio runtime could not be created (Fuigo never started; nothing was run). No other start-up failure uses this code |
| `130` | Interrupted by SIGINT (Ctrl+C)                                   |
| `143` | Terminated by SIGTERM, or torn down because the process that started Fuigo exited (see [Parent-Process Binding](#parent-process-binding)) |

These codes are a compatibility commitment: scripts branch on them, so they are not renumbered.
They describe `fuigo -p` / `--print` runs. `fuigo wrap <command>` is different — it exits with
**the wrapped command's own** exit code, whatever that is.

### Blocked by a Permission

Headless mode has no operator to ask, so it never approves a permission request. A run that **ends**
because of such a refusal exits **`3`**, not `0` and not `1`. So does a run that an execution budget
ended (a goal's `--budget`, a workflow child's output grant, or the `FUIGO_MAX_MODEL_CALLS` /
`FUIGO_MAX_RUNTIME_SECS` limits): the budget refused the next model request, the model-call limit
left only the final answer's call (whether the model answered in that call or tried to act), or the runtime limit passed while a model request was in
flight. That is the same outcome, reported through the same record, with a budget `rule`. That distinction is the point: `0`
would make a blocked run look finished, and `1` would make it look like a crash, so a CI job could
not tell which had happened.

**Stability.** `3` is part of the exit-code commitment above: it means "blocked by a permission" in
every release and will not be renumbered or reused. The `rule` identifiers below are stable too,
and are never localized. New rules may be added as new denial sites appear; treat an unknown
`rule` as a denial all the same.

A refusal that ends the run is reported in two ways: one English line on stderr, and a structured record on
stdout that a script can read without parsing that English.

#### The stderr line

One line on stderr, for every `--output-format` and whether or not a terminal is attached:

```
fuigo: blocked — permission denied in headless mode: Write src/main.rs (tool call tc-17).
Denied by rule `headless_never_approves`. Remedy: pre-approve it before the run — pass
--allow, raise --permission-mode, or trust a folder whose project config allows it; headless
mode has nobody to ask. No --allow rule covers a shell command that writes a file by redirect
(`> file`); --always-approve runs one (--permission-mode auto runs it only if its classifier
approves), and deny rules still apply. Exiting 3.
```

For a refusal the run carried past, the line instead reads
`fuigo: a permission was denied in headless mode and the run continued: …`, with the same rule and
remedy and no exit code (see [When exit `3` does *not* fire](#when-exit-3-does-not-fire)).

#### The denial record, per format

The record rides on the **terminal** record each format already has, so every consumer still reads
exactly one terminal record. No format gains a new line type.

| `--output-format` | Where the denial appears |
| --- | --- |
| `plain` (default) | stdout is only the model's text. The denial is the stderr line above, plus the exit code |
| `json` | A `permissionDenied` object on the single terminal JSON document. The document is still exactly one JSON value |
| `streaming-json` | The same `permissionDenied` object, under the same key, on the terminal `end` line, or on the `error` line when the run failed |
| `streaming-messages-json` | The schema's own `permission_denials` array on the terminal `result` line. A blocked run's `result` is `is_error: true` and `subtype: "error_during_execution"`. `stop_reason` is `"cancelled"` for a permission refusal and `null` for a budget denial |

The `permissionDenied` object, for `json` and `streaming-json`:

```json
{
  "text": "...",
  "stopReason": "cancelled",
  "sessionId": "...",
  "requestId": "...",
  "permissionDenied": {
    "rule": "headless_never_approves",
    "toolCallId": "tc-17",
    "toolTitle": "Write src/main.rs",
    "offeredOptionKinds": ["allow_once", "reject_once"],
    "remedy": "pre-approve it before the run — ...",
    "endedRun": true,
    "exitCode": 3
  }
}
```

| Field | Meaning |
| --- | --- |
| `rule` | Which rule refused it. Stable identifier, never localized |
| `toolCallId` | The ACP tool-call id. On `streaming-json` it matches the `tool_call` line for the same call. `null` for a budget denial, which refused a model request rather than a tool call |
| `toolTitle` | The agent's title for the call, or `null` when it sent none |
| `offeredOptionKinds` | The permission options the request offered, in order. This is the evidence for `yolo_had_no_allow_option` |
| `remedy` | What to change so the run is not refused. Data, not a hint to parse |
| `endedRun` | `true` when the turn ended at this refusal |
| `exitCode` | `3`. Present **only** when `endedRun` is `true` |

The `streaming-messages-json` entry uses only the schema's three keys. Fuigo does not add its own
keys to a format it does not own, so `rule` and `remedy` are not on this line; read them from the
stderr line, or use `streaming-json`:

```json
{"type":"result","subtype":"error_during_execution","is_error":true,"stop_reason":"cancelled","errors":["cancelled"],"permission_denials":[{"tool_name":"search_replace","tool_use_id":"call_1","tool_input":{"file_path":"src/main.rs","old_string":"a","new_string":"b"}}],"session_id":"abc123","uuid":"...",...}
```

`tool_name` and `tool_input` are the ones on the `tool_use` block for the same `tool_use_id`, earlier
in the stream. A budget denial adds **no** `permission_denials` entry, because no tool was refused.
Its `result` is `is_error: true`, and `errors[]` carries the agent's message, which names the rule and
the remedy. When the refused call never streamed a `tool_use`, `tool_name` is the agent's title for
it and `tool_input` is `{}`.

Only the **first** permission refusal of a run is reported; later ones are its consequences. A
budget denial is the exception: it is what ended the run, so it replaces an earlier permission
refusal in the record, and the earlier refusal gets its own stderr notice. Absence of the
record does not prove nothing was refused. A `--deny` rule, a deny-by-default `defaultMode`, or a
`pre_tool_use` hook is decided inside the agent before any
permission request reaches headless mode. Those refusals are reported to the model as a failed tool
call and the run continues. They never trigger exit `3` on their own, so the run exits however it
ends (`0`, or `1` if it later fails). They produce no record and no stderr line.

#### The rules and their remedies

| `rule` | When | Remedy |
| --- | --- | --- |
| `headless_never_approves` | Nothing pre-approved the request, so headless mode refused it | Pre-approve it before the run: pass `--allow`, or raise `--permission-mode`. Trusting the folder helps only when its project config (permission rules) allows the call. Trust alone approves nothing |
| `yolo_had_no_allow_option` | `--yolo` was passed, but a deny rule or protected path left the request with no allow option to select | Remove the matching entry from `--deny` or from the permissions config |
| `execution_token_budget_exhausted` | The execution's total-token budget is spent | Raise the goal's token budget (`/goal <objective> --budget <tokens>`) or clear the goal (`/goal clear`). Tokens already spent are not refunded |
| `execution_output_token_budget_exhausted` | The output-token budget granted to this workflow child is spent | Raise `output_token_budget` for the child. Output tokens already spent are not refunded |
| `execution_token_usage_unknown` | A token budget is set, but the provider reported no usage for an earlier request, so the budget fails closed | Use a model that reports usage, or run without a token budget |
| `execution_model_call_limit` | `FUIGO_MAX_MODEL_CALLS` has no model call left for the request (spent, or the last one reserved for the final answer, or a subagent's share of its parent's calls spent) | Raise `FUIGO_MAX_MODEL_CALLS` for the next run. Calls already made are not refunded; under a goal, clear the goal (`/goal clear`) |
| `execution_runtime_limit` | `FUIGO_MAX_RUNTIME_SECS` has passed | Raise `FUIGO_MAX_RUNTIME_SECS` for the next run. It counts from agent start and cannot be extended in a running agent; under a goal, clear the goal (`/goal clear`) |
| `execution_budget_denied` | A budget denial under a rule this build does not know (a newer agent) | Read the agent's error message, which names the rule and its remedy |

The budget rules come from the agent's typed error (`data.code: "execution_budget_denied"`, see the
agent-mode guide, "Errors"). Their stderr line reads `fuigo: blocked — an execution budget
refused the next model request. Denied by rule … Remedy: … Exiting 3.` For a rule this build does
not know, `plain` writes two stderr lines: first the agent's own message, which names the rule and
its remedy, then that line.

#### What a refusal leaves behind

A refused tool call never runs. The permission request comes before the tool executes, and a
refusal ends the turn without executing it, so the refused edit, command or write is not started and
nothing of it is half-applied. The conversation records the call as not executed. Everything the run
did **before** the refusal stays done, including earlier tool calls in the same turn and the files
they wrote. Fuigo rolls nothing back on a refusal, because nothing of the refused call was applied.

#### Branching on it

```bash
fuigo -p "Refactor src/auth.rs" --output-format json > out.json
case $? in
  0) echo "done" ;;
  3) echo "blocked: $(jq -r '.permissionDenied.remedy' out.json)" ; exit 1 ;;
  *) echo "failed" ; exit 1 ;;
esac
```

The exit code is the authority. The record says what was refused and why; `$?` says how the run
ended.

#### When exit `3` does *not* fire

The code marks a run that *ended* at the refusal, and only that:

- Something was refused and the run **carried on and finished anyway**, for example a subagent whose
  own turn was cancelled while the parent's continued. The exit code is `0`, because the prompt did
  complete. The record is present with `endedRun: false` and no `exitCode`.
- The refusal came **after** the terminal record was written. The main case is the post-turn memory
  flush, which runs after the answer and its terminal record. The exit code is `0`. Only the stderr
  line reports it, because the terminal record has already been written.
- The run **failed for its own reason** after a refusal: a crash, a `--timeout`, or `--max-turns`.
  That is `1`, the same as it would have been without the refusal. A refusal does not relabel a
  failure, or the remedy would send you off to pre-approve something that was never the problem. The
  record, if the failure still wrote a terminal record, has `endedRun: false` and no `exitCode`.
- A budget ended the run on one of the paths not yet typed in this release, so the exit is not `3`:
  a goal's token `--budget` reached when an answer completes (the goal stops budget-limited and
  the run exits `0`); the output grant spent on the last salvaged truncated (`max_tokens`)
  response (exit `1`, an untyped partial receipt); a completion requirement with `maxRetries` of
  `2` or more retrying past the model-call limit's final answer (exit `1`). These end with an
  ordinary error or a finished answer, not a budget refusal, so no denial record or refusal line is
  written for them.
- The provider answered the model request with an error of its own (a status, an authentication
  refusal, a rate limit, a stream error) and the runtime limit passed while that failure was being
  reported. The run fails with the provider's error (exit `1`): the limit did not end that request.
- The post-turn memory flush **fails** after a run that did end at a refusal. The record already
  says `endedRun: true`, `exitCode: 3`, but the process exits `1`. Trust `$?`.

In each of these cases where a refusal happened, it is still reported on stderr, whatever the exit
code turns out to be. There is one exception, which exits `1`: if stdout itself cannot be written, the write
error is what is reported. If the agent connection closes unexpectedly mid-turn, the exit is `1` and
stderr carries both the refusal line and the closed-connection error.

To avoid a permission `3`, pre-approve the work: `--allow`, a higher `--permission-mode`, `--yolo`,
or a trusted folder whose project permission rules allow it. None of these lifts a budget. A
budget denial needs the budget raised or cleared, as its remedy says. See [Always-approve for automation](#always-approve-for-automation) and
[22-permissions-and-safety.md](22-permissions-and-safety.md).

---

## Authentication for Headless Environments

For headless use, authenticate with one of:

- **`FUIGO_API_KEY`**: simplest for CI. See [Environment Variables](#environment-variables-for-headless) above.
- **`fuigo login --device-auth`** (or `--device-code`): no browser needed on the target machine.
  See [Authentication > Device Code Flow](02-authentication.md#device-code-flow).
- **`fuigo login`**: browser-based OAuth2 on machines with a GUI.

If you've previously logged in, cached credentials are used automatically.

---

## Tips

- Headless mode starts a **fresh session by default**. Use `-r/--resume` or `-c/--continue` to maintain context across calls.
- The `--output-format json` response always includes a `sessionId` you can use with `--resume` for follow-up calls.
- Combine `--yolo` with `--rules` to set guardrails: `fuigo -p "..." --yolo --rules "Never delete files"`.
- For debugging, raise the log level and capture stderr: `RUST_LOG=debug fuigo -p "..." 2> debug.log`.

---

## Project Root Discovery

When Fuigo starts, it discovers the project root by walking upward from `--cwd`
(or the current directory) until it finds a `.git` directory.

Note: If `--cwd` is nested inside a large repository (such as a monorepo),
Fuigo discovers that repository as the project root and scopes its discovery (AGENTS.md, skills, git history) to it, which can make
startup slow. Point `--cwd` at the specific subproject you want to work in to keep
the scope small.

---

## File Locations

Fuigo stores data in `~/.fuigo` (override with `FUIGO_HOME`; see [Environment Variables for Headless](#environment-variables-for-headless)):

| Path                     | Contents                              |
| ------------------------ | ------------------------------------- |
| `config.toml`            | User configuration                    |
| `auth.json`              | Cached OAuth2/API credentials         |
| `version.json`           | Version cache for update checks       |
| `sessions/`              | Session transcripts (SQLite)          |
| `memory/`                | Cross-session memory store            |
| `logs/`                  | Internal log files (for example `unified.jsonl`) |
| `logs/mcp/`              | MCP server logs                       |
| `skills/`                | User skill definitions                |
| `personas/`              | User-scoped agent personas            |
| `crash/`                 | Crash reports                         |
| `trace-exports/`         | Session trace exports                 |
| `worktrees/`             | Git worktree metadata                 |

### Read-Only `~/.fuigo`

For containers or CI, mount `~/.fuigo` read-only:

- Pre-populate `auth.json` or use `FUIGO_API_KEY`
- Session persistence fails silently (ephemeral)
- Update checks log a warning and skip

```bash
export FUIGO_API_KEY="fuigo-..."
export FUIGO_DISABLE_AUTOUPDATER=1
fuigo -p "..." --no-auto-update
```

---

## Update Check Suppression

| Method                          | Scope     |
| ------------------------------- | --------- |
| `--no-auto-update`              | Session   |
| `FUIGO_DISABLE_AUTOUPDATER=1`    | Process   |
| Non-TTY stderr (auto-detected)  | Automatic |
| `[cli] auto_update = false`     | Persistent|

`FUIGO_DISABLE_AUTOUPDATER` set to a falsy value (`0`, `false`, `off`, `no`, or empty, any
case) counts as not set. The agent SDKs
inject `FUIGO_DISABLE_AUTOUPDATER=1` for the non-leader agents they spawn (a falsy value in
the SDK's isolation env keeps updates on), and the stdio agent skips its background update
unless it runs from the managed install (`$FUIGO_HOME/bin/fuigo`).

Update messages go to **stderr**. Stdout stays clean for `--output-format json`. See also [Environment Variables for Headless](#environment-variables-for-headless).

---

## Additional Headless Flags

These flags supplement the [Command-Line Options](#command-line-options) table above. Flags already listed there (`--prompt-json`, `--prompt-file`, `--verbatim`, `--sandbox`, `--no-auto-update`) are not repeated here.

| Flag                          | Description                                       |
| ----------------------------- | ------------------------------------------------- |
| `--agent <NAME>`              | Agent name or definition file path                |
| `--agents <JSON>`             | Inline subagent definitions as JSON               |
| `--system-prompt-override`    | Override the agent's system prompt                |
| `--no-plan`                   | Disable plan mode                                 |
| `--no-subagents`              | Disable subagent spawning                         |
| `FUIGO_MEMORY=0`                | Disable cross-session memory for the process      |
| `--disable-web-search`        | Disable web search and fetch tools                |
| `--no-alt-screen`             | Run inline (no alternate screen)                  |
| `--worktree [NAME]`           | Start session in a new git worktree               |
| `--ref <REF>` / `--worktree-ref <REF>` | Branch/tag/commit to base the worktree on (with `--worktree`) |

---

## Interrupted Headless Runs

On SIGINT/SIGTERM:

- Session state saved up to the last completed tool call
- File modifications by tools are **not rolled back**
- Exit code is **130** for SIGINT (`128 + 2`) and **143** for SIGTERM (`128 + 15`); CI pipelines can distinguish these from a normal error (exit code `1`)
- **143 has a second cause**: the process that started `fuigo agent … stdio` exited, so the
  agent was torn down with it. See [Parent-Process Binding](#parent-process-binding) below,
  including the environment variable that turns that off.
- Resume: `fuigo -p "continue" --resume "<id>"` or `fuigo -p "continue" --continue`

See [Session Management in Headless Mode](#session-management-in-headless-mode) for details on named sessions and the `-s`/`-r`/`-c` flags.

---

## Parent-Process Binding

A `fuigo agent … stdio` process binds its own lifetime to whatever started it, so an agent
cannot outlive a crashed or killed client and pile up on a shared host:

- **Linux**: `PR_SET_PDEATHSIG(SIGTERM)` — the kernel signals the agent when its parent dies.
- **Windows**: a watcher thread on a handle to the parent; when the parent exits, the agent
  flushes telemetry, terminates its own child processes and exits.
- **macOS**: no binding (the platform has no equivalent); stdin EOF is the only cleanup.

Either way the agent exits **143**, the same code as SIGTERM. What you can observe differs by
platform:

- **Linux**: nothing beyond the exit code. The kernel delivers a real SIGTERM, so the agent takes
  its ordinary SIGTERM shutdown and the logs look exactly like any other SIGTERM — there is no
  line saying the parent was the cause.
- **Windows**: the agent logs `parent process exited; terminating` (the debug log, and the unified
  log under `FUIGO_HOME`) before it flushes telemetry and exits. There is no SIGTERM on Windows,
  so this line is the record of what happened.
- **macOS**: nothing — there is no binding, and the agent exits when stdin closes.

A parent that was already gone before the agent started never triggers any of this, for a different
reason on each platform: on **Windows** the binding refuses to arm (the parent's process object is
already signalled, or its pid has been recycled), while on **Linux** `PR_SET_PDEATHSIG` arms
normally and then simply never fires — the death it would signal has already happened. Either way
the outcome is the same: stdin EOF remains the cleanup.

**Turning it off.** Set `FUIGO_DISABLE_PARENT_DEATH_WATCH=1` to disable the binding on both
Linux and Windows; the agent then lives until stdin closes, as it did before the Windows
watcher existed. Use it when a launcher deliberately starts the agent and returns straight
away, so the agent has no lasting parent. Any value except a falsy spelling (`0`, `false`,
`off`, `no`, or empty, any case) disables it; unset leaves the binding on.

```bash
# Launcher exits immediately; the agent must survive on stdin instead.
FUIGO_DISABLE_PARENT_DEATH_WATCH=1 fuigo agent stdio
```

