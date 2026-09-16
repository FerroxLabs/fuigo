# Agent mode (ACP) and IDE integration

Agent mode runs Fuigo as a long-lived server that clients talk to over [ACP](https://agentclientprotocol.com) (JSON-RPC). Use it from IDEs, SDKs, eval harnesses, and custom apps. For a one-shot prompt that prints and exits, use `fuigo -p` instead ([headless mode](14-headless-mode.md)).

---

## Automation and SDKs

For scripts, CI, evals, and agent servers, start with always-approve so tools run without interactive permission prompts. Deny rules and hooks still apply.

```bash
# stdio (local process / many SDKs)
fuigo agent --always-approve stdio

# WebSocket server
fuigo agent --always-approve serve --bind 127.0.0.1:2419 --secret <token>
```

You can also set always-approve per session on `session/new`:

```json
{
  "cwd": "/path/to/project",
  "mcpServers": [],
  "_meta": { "yoloMode": true }
}
```

Interactive TUI users typically leave the default ask mode (or use auto). See [Permissions and safety](22-permissions-and-safety.md).

---

## What is ACP?

The [Agent Client Protocol (ACP)](https://agentclientprotocol.com) defines how clients talk to coding agents over JSON-RPC. With Fuigo it covers:

- Sessions (create, load, resume)
- Prompts and streamed replies
- Tool call updates
- Reasoning / thought streams
- Permission prompts when the session is not always-approve

---

## stdio transport

### Bounded private jobs (development version)

For a host-owned job, launch a private process with explicit limits:

```bash
FUIGO_MAX_MODEL_CALLS=20 FUIGO_MAX_RUNTIME_SECS=300 \
  fuigo --max-turns 8 agent --no-leader stdio
```

The aggregate dispatch counter is shared across this process's sessions, model
switches, subagents and auxiliary model requests through the sampler. Failed
attempts consume admissions; retries do not refund them. `--max-turns` separately
limits primary turns, and a subagent can tighten but cannot raise its parent's
turn ceiling.

The monotonic wall deadline starts when the private agent initializes. Expiry
blocks new prompts and model dispatches and cancels resident sessions, including
their subagents and background commands, through normal cancellation. Cancellation
is asynchronous; allow a short cleanup grace after the deadline.

Both variables require positive integers. Unset means no corresponding aggregate
limit. Configured budgets force a private agent and reject explicit leader mode.
They last for the process lifetime, not across restarts: the host must authorize a
new job before starting another budgeted process. Do not treat these as dollar
caps, persistent accounting, or limits on embedding, image, and external-tool API
charges outside the model sampler. Those need separate host policy.

stdio is the common local integration path. The agent speaks JSON-RPC on stdin and stdout:

```bash
fuigo agent --always-approve stdio
```

Typical clients: IDE extensions (Zed, Neovim, Emacs), custom tools, and ACP SDKs.

### Options

Agent options apply to every transport (`stdio`, `serve`, `headless`, `leader`). They go after `agent` and before the mode name. Mode-specific flags go after the mode (for example `serve --bind`).

```bash
fuigo agent --always-approve --model grok-4.6 stdio
fuigo agent --always-approve serve --bind 127.0.0.1:2419 --secret <token>
```

| Flag | Description |
| ---- | ----------- |
| `-m, --model <MODEL>` | Model ID (for example `grok-4.6`). |
| `--always-approve` | Run without interactive tool-permission prompts. Alias: `--yolo`. |
| `--reauth` | Authenticate before the agent starts. |
| `--agent-profile <PATH>` | Load an agent profile from a file. |
| `--leader` / `--no-leader` | Connect to a shared leader process, or force a local agent. When a non-`off` sandbox profile is requested, leader mode is refused so tools stay in-process (see [Sandbox Mode](18-sandbox.md)). |

---

## Server mode

```bash
fuigo agent --always-approve serve --bind 127.0.0.1:2419 --secret <token>
```

Clients connect over WebSocket and authenticate with the secret token. If you omit `--secret`, the agent prints a generated token at startup, or set `FUIGO_AGENT_SECRET`. The process keeps state across client reconnects. Permissions match other entry points; see [Permissions and safety](22-permissions-and-safety.md).

This is a server you run yourself — Fuigo's hosted cloud sandboxes do not run `fuigo agent serve`.

---

## WebSocket relay

To reach the agent over the internet, connect the agent to a relay and point browsers at the same relay:

```bash
fuigo agent --always-approve headless --fuigo-ws-url wss://your-relay.example.com/ws
```

---

## ACP protocol basics

Communication follows the JSON-RPC 2.0 format. A typical session lifecycle:

1. **Initialize** -- client sends `initialize` with capabilities
2. **Create session** -- client sends `session/new` with working directory
3. **Send prompts** -- client sends `session/prompt` with user messages
4. **Receive updates** -- agent sends `session/update` notifications with streamed content
5. **Handle permissions** -- agent may request tool execution approval (or allow or deny based on permission mode)

### Errors

A failed request gets a JSON-RPC error reply. `code` is the error class and `message` is usually only the class name (for example `Internal error`), so never show `message` on its own. The detail is in `data`.

Every error reply the agent itself produces carries `data` as an object. The exceptions are rejections the protocol layer makes before any agent code runs; they are listed in the notes on the class below, and they are the only replies this table does not describe:

| `data` field  | Present                         | Meaning                                                                                  |
| ------------- | ------------------------------- | ---------------------------------------------------------------------------------------- |
| `message`     | always, in an agent-built reply | What went wrong, in words. Show this to the user.                                        |
| `error_kind`  | always, in an agent-built reply | Stable machine tag for the failure (see below).                                          |
| `http_status` | when the provider returned one  | Upstream HTTP status, for example `503`.                                                 |
| `promptUsage` | when usage was recorded         | Tokens and spend the failed prompt still consumed.                                       |
| `code`        | on some failures                | A finer machine code a client can match on, for example `local_workspace_chat_only` or `FS_DISK_QUOTA_EXCEEDED`. |

Some failures add more structured fields next to these, for example the execution receipt (`partial`, `reason`, `pending_tool_calls`, ...) when a budgeted execution ends early.

`error_kind` values for a failed model request: `empty_response` (the model returned no visible output, for example reasoning only), `idle_timeout` (the model stopped streaming), `http` (transport failure), `api` (the provider rejected the request), `auth`, `rate_limited`, `serialization`, `max_tokens_truncation`, `doom_loop_detected`, and `cancelled` (the request was cancelled before it produced a result).

`error_kind` values for failures inside the agent:

| `error_kind`           | Meaning                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| `session_unavailable`  | The agent could not hand the request to its session or to the peer, or it never answered.      |
| `invalid_request`      | The request itself is wrong: bad or missing parameters, an unknown session or method, an unsupported operation. |
| `not_found`            | The named resource, for example a session, does not exist.                                       |
| `session_storage`      | Reading or writing the session's files failed (session directory, history, durable execution state). |
| `compaction`           | Context compaction failed.                                                                       |
| `execution_incomplete` | A budgeted execution (a workflow child, a goal) stopped before its work finished.                |
| `internal`             | Any other failure inside the agent.                                                              |

New values can be added in later releases, so treat an unknown `error_kind` as a generic failure.

`code` stays the JSON-RPC class: `-32603` internal error, `-32000` authentication required, `-32602` invalid params, `-32600` invalid request, `-32601` method not found, `-32002` resource not found, `-32003` rate limited, `-32800` request cancelled.

Four notes on the class:

- A `fuigo/*` extension method this build does not implement answers `-32601` with the object above, naming the method in `data.message` exactly as you sent it, `_` prefix included (`unknown ACP extension method: _fuigo/skills/whatever`), so you can match it against your own request string. Before 1.0.18 the name came back without the `_`. Two kinds of request are rejected by the protocol layer before the agent sees them, and both still come back as `-32601 Method not found` with no `data`, because no part of the agent runs: an unknown top-level JSON-RPC method, one that is not an extension call, and `session/cancel` -- a notification-only method -- sent as a request instead of as a notification. Sent the way the protocol specifies, as a notification, `session/cancel` cancels the turn normally.
- Since 1.0.18 a failure to serialize the agent's OWN data answers `-32603` (`internal`) where it used to answer `-32602` (`invalid params`). The parameters the client sent were fine; the fault was inside the agent, so the class now says so. Five replies changed class, in two files: the agent's tool input while a prompt is running (`fuigo-shell` `session/acp_session_impl/tool_calls.rs`, two sites) and the `fuigo/commands/list` response (`fuigo-shell` `extensions/session_admin.rs`, three sites). Nothing the client sends can reach them; a malformed request still answers `-32602`.
- Since 1.0.18 a failed `authenticate` puts its reason in `data.message` and leaves `message` as the class name `Authentication required`. Before 1.0.18 the reply carried no `data` at all and `message` held the reason (`bad credentials`, `Authentication cancelled`), so a client that renders only object-shaped `data` showed the user nothing on a failed login. The class and the code (`-32000`) are unchanged. Every embedding client calls `authenticate` on connect, so a client that reads only `message` sees the class name where it used to see the reason: read `data.message`.
- Malformed parameters on a **core** ACP method are rejected by the protocol layer while the request is still being decoded, before any agent code runs, so they do not follow the table above: the reply is `-32602 Invalid params` with `data` as a **bare string** -- the deserializer's own complaint, for example `unknown variant`. Measured on 1.0.18 this covers `session/prompt`, `session/new`, `session/load`, `session/set_mode`, `session/set_model` and `authenticate`; 1.0.17 answers identically, so nothing changed here. It matters because it is the one `data` shape a live client can provoke by accident: a content-block shape your ACP client version sends and this build's schema does not accept lands here, and a client that renders only object `data` shows the user `Invalid params` and nothing else. Read `data` as a string when it is one, and fall back to `message` when it is neither a string nor an object. A code fix (decoding requests through a wrapper that re-shapes the rejection) is planned for 1.0.19.

A prompt that failed on an empty model response:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": {
      "message": "empty response from model (reasoning_only)",
      "error_kind": "empty_response"
    }
  }
}
```

Before 1.0.18 most of these failures sent `data` as a bare string. A client that also talks to older agents should read `data.message` when `data` is an object and show `data` itself when it is a string.

### Architecture

```
+------------------------------------------+
|           ACP Client                     |
|  (IDE, Editor, Custom Application)       |
+-------------------+----------------------+
                    | JSON-RPC over stdio
+-------------------v----------------------+
|           fuigo agent stdio               |
|                                          |
|  +---------+  +---------+  +---------+   |
|  | Session |  |  Tools  |  |   MCP   |   |
|  | Manager |  | Registry|  | Servers |   |
|  +---------+  +---------+  +---------+   |
+------------------------------------------+
```

---

## Streaming updates

ACP streams structured events. Each `session/update` notification carries a `sessionUpdate` field that identifies the update type:

| `sessionUpdate` value | Description                                            |
| --------------------- | ----------------------------------------------------- |
| `agent_message_chunk` | A chunk of the agent's response text.                 |
| `agent_thought_chunk` | A chunk of the agent's internal reasoning.            |
| `tool_call`           | A new tool invocation (title, kind, status, input).   |
| `tool_call_update`    | A status or result update for an in-flight tool call. |
| `plan`                | The agent's execution plan.                           |

Each update names its type, so a client can render distinct panels for reasoning, tool calls, and response text.

**Retry progress.** While a model request is being retried, and once when it finally fails, the agent also sends a live-only `agent_thought_chunk` such as `Retrying the model (1/3): empty response from model (reasoning_only)`, `The model request failed after 3 attempts: ...` when a retry budget ran out, or `The model request failed: ...` for a terminal failure with no budget behind it. (A failure that is not the model's - running out of disk while saving the session - names its own subject instead.) Clients that render only the standard updates therefore show progress in their thinking area instead of silence, and the text never becomes part of the answer: retry progress is never sent as `agent_message_chunk`. It arrives in order with the rest of the stream, after any answer text generated before the retry, and opens its own paragraph when it follows streamed reasoning. The chunk's `_meta["fuigo/retryStatus"]` holds the structured retry state (the same object as the `retry_state` session notification). A client that already renders `fuigo/session_notification` retry state should skip chunks carrying that key. These chunks are never persisted, so they do not replay on `session/load`.

An empty reply from the model (reasoning tokens but no text or tool call, or nothing at all) is resent at most twice, 2 s apart, on one budget of three attempts shared by every empty reply of a request, far below `max_retries`, because resending the identical request rarely answers differently and each resend is billed. The progress line's denominator is that cap, lowered when the configured retry budget cannot fund it, and spending it closes with the exhaustion line naming the attempts made (`The model request failed after 3 attempts: ...`), as a spent rate-limit budget does.

---

## Extension methods

Beyond the base ACP protocol, Fuigo defines extension methods under the `fuigo/` prefix for Ferrox Labs-specific functionality. These cover:

| Category                   | Prefix               | Examples                                         |
| -------------------------- | -------------------- | ------------------------------------------------ |
| **Filesystem**             | `fuigo/fs/*`          | `list`, `exists`, `read_file`, `write_file`      |
| **Git**                    | `fuigo/git/*`         | `status`, `stage`, `commit`, `diffs`, `discard`  |
| **Git Worktree**           | `fuigo/git/worktree/*`| `create`, `remove`, `apply`, `list`, `gc`        |
| **Search**                 | `fuigo/search/*`      | `fuzzy/open`, `fuzzy/change`, `content`          |
| **Terminal**               | `fuigo/terminal/*`    | `create`, `kill`, `output`, `wait_for_exit`      |
| **Session Management**     | `fuigo/session/*`     | `fork`, `resolve_local_for_worktree_resume`      |
| **Conversation & History** | `fuigo/*`             | `prompt_history`, `rewind/*`, `compact_conversation` |
| **Authentication**         | `fuigo/auth/*`        | `get_url`, `submit_code`                         |
| **Feedback & Telemetry**   | `fuigo/*`             | `feedback`, `telemetry/*`                        |

The tables here show representative methods in each category. The `fuigo/*` set is Ferrox Labs-specific and may expand across releases, so treat it as non-exhaustive and discover the available methods from the agent's `initialize` response.

### Notifications (agent to client)

The agent sends push notifications to clients for real-time updates:

| Notification               | Description                          |
| -------------------------- | ------------------------------------ |
| `fuigo/search/fuzzy/status` | Fuzzy search results update          |
| `fuigo/git/worktree/status` | Worktree creation progress           |
| `fuigo/fs_notify`           | Filesystem change notification       |
| `fuigo/fs/index`            | Full file index update               |
| `fuigo/fs/index/delta`      | Incremental file index update        |
| `fuigo/session_notification`| Session-specific updates (diff review, retry state, auto-compact) |
| `fuigo/session/update`      | Session update (tool calls, content) |

---

## Session `_meta` options

Optional fields on `session/new`:

| Field | Description |
| ----- | ----------- |
| `rules` | Extra rules appended to the system prompt. |
| `systemPromptOverride` | Replacement system prompt. |
| `agentProfile` | Agent profile name or JSON object. |
| `yoloMode` | When `true`, always-approve for this session. |
| `autoMode` | When `true`, auto permission mode for this session. Superseded when always-approve is already on. |

```json
{
  "cwd": "/path/to/project",
  "mcpServers": [],
  "_meta": { "yoloMode": true }
}
```

---

## ACP SDKs

Official SDK libraries are available for multiple languages:

| Language   | Package                                                                                  |
| ---------- | ---------------------------------------------------------------------------------------- |
| TypeScript | [`@agentclientprotocol/sdk`](https://www.npmjs.com/package/@agentclientprotocol/sdk)     |
| Rust       | [`agent-client-protocol`](https://crates.io/crates/agent-client-protocol)                |
| Python     | [`agent-client-protocol-python`](https://github.com/PsiACE/agent-client-protocol-python) |
| Go         | [`acp-go-sdk`](https://github.com/coder/acp-go-sdk)                                     |
| Kotlin     | [`acp`](https://github.com/agentclientprotocol/kotlin-sdk)                               |

---

## Compatible clients

| Client                                                   | Status      |
| -------------------------------------------------------- | ----------- |
| [Zed](https://zed.dev/docs/ai/external-agents)           | Supported   |
| [Neovim](https://neovim.io) (CodeCompanion, avante.nvim) | Supported   |
| [Emacs](https://github.com/xenodium/agent-shell)         | Supported   |
| [marimo notebook](https://github.com/marimo-team/marimo) | Supported   |
| JetBrains                                                | Coming soon |

---

## Integration example: a TypeScript ACP client

```typescript
import { spawn, ChildProcess } from "child_process";
import * as readline from "readline";

class FuigoACPChat {
  private proc!: ChildProcess;
  private sessionId!: string;
  private rl!: readline.Interface;

  constructor(private cwd = ".") {}

  async init() {
    this.proc = spawn("fuigo", ["agent", "--always-approve", "stdio"]);
    this.rl = readline.createInterface({ input: this.proc.stdout! });

    await this.request("initialize", {
      protocolVersion: 1,
      clientCapabilities: {
        fs: { readTextFile: true, writeTextFile: true },
        terminal: true,
      },
    });

    const { sessionId } = await this.request("session/new", {
      cwd: this.cwd,
      mcpServers: [],
      _meta: { yoloMode: true },
    });
    this.sessionId = sessionId;
    return this;
  }

  private async request(method: string, params: any): Promise<any> {
    return new Promise((resolve) => {
      const msg = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
      this.proc.stdin!.write(msg + "\n");

      this.rl.once("line", (line) => {
        resolve(JSON.parse(line).result || {});
      });
    });
  }

  async *streamPrompt(text: string) {
    const msg = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "session/prompt",
      params: {
        sessionId: this.sessionId,
        prompt: [{ type: "text", text }],
      },
    });
    this.proc.stdin!.write(msg + "\n");

    for await (const line of this.rl) {
      const data = JSON.parse(line);

      if (data.method === "session/update") {
        const update = data.params.update;
        yield update; // { sessionUpdate, content, title, ... }
      } else if (data.result) {
        break; // Final response
      }
    }
  }
}

// Usage
const client = await new FuigoACPChat(".").init();

for await (const update of client.streamPrompt("List the files in this project")) {
  switch (update.sessionUpdate) {
    case "agent_message_chunk":
      process.stdout.write(update.content?.text || "");
      break;
    case "agent_thought_chunk":
      console.log(`\n[Thinking: ${update.content?.text}]`);
      break;
    case "tool_call":
      console.log(`\n[Tool: ${update.title}]`);
      break;
  }
}
```

---

## Resources

- [ACP Specification](https://agentclientprotocol.com/protocol/prompt-turn)
- [Protocol Introduction](https://agentclientprotocol.com/overview/introduction)
