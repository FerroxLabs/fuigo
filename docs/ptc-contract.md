# OpenAI Responses "Programmatic Tool Calling" (PTC) — wire contract

Researched 2026-09-11 for Fuigo's opt-in PTC support (`programmatic_tool_calling = true` per model entry, or `FUIGO_PROGRAMMATIC_TOOL_CALLING=1`).

Sources (fetched 2026-09-11):

- Guide: https://developers.openai.com/api/docs/guides/tools-programmatic-tool-calling
- Changelog: https://developers.openai.com/api/docs/changelog ("GPT-5.6 adds Programmatic Tool Calling"; Responses API and Chat Completions; GPT-5.6 Sol/Terra/Luna; also listed as a supported capability for GPT-6 Astra in the Codex-bundled `upgrading-to-gpt-6-astra.md`)
- Pricing: https://developers.openai.com/api/docs/pricing
- openai-python types (branch `main`):
  - https://raw.githubusercontent.com/openai/openai-python/main/src/openai/types/responses/response_output_item.py (`Program`, `ProgramOutput`)
  - https://raw.githubusercontent.com/openai/openai-python/main/src/openai/types/responses/response_function_tool_call.py (`caller`, `CallerDirect`, `CallerProgram`)
  - https://raw.githubusercontent.com/openai/openai-python/main/src/openai/types/responses/response_input_item_param.py (`FunctionCallOutput.caller`, `Program`, `ProgramOutput` as input items)
  - https://raw.githubusercontent.com/openai/openai-python/main/src/openai/types/responses/response_stream_event.py (no program-specific stream events)
- openai-node `src/resources/responses/responses.ts` (`SpecificProgrammaticToolCallingParam`, `allowed_callers`, `ResponseOutputItem.Program` / `.ProgramOutput`)
- Codex CLI `rust-v0.154.0`: does **not** implement PTC. Its "code mode" (`codex-rs/core/src/tools/code_mode/`) is a *client-side* JS runtime (`codex-code-mode-host`) exposed to the model as an `exec`/`wait` function tool; the model calls `exec(code)` and Codex runs the nested tool calls locally. It only touches `allowed_callers` for its own `/v1/alpha/search` settings (`codex-api/src/search.rs`, `AllowedCaller::Direct`). It is useful as a reference for *dispatching nested tool calls through the normal tool router* (`CodeModeDispatchBroker` -> `ToolCallRuntime`, `ToolCallSource`), not for the server-side PTC wire format.

## 1. Request side

### 1.1 Enable the hosted runtime

Add the hosted tool entry to `tools`:

```json
{ "type": "programmatic_tool_calling" }
```

No `container`, runtime, or option fields are documented (openai-node: `SpecificProgrammaticToolCallingParam { type: 'programmatic_tool_calling' }`).

### 1.2 Opt client tools into programmatic invocation

Function (and custom, mcp, apply_patch, shell, code_interpreter) tools take an `allowed_callers` array:

| `allowed_callers` | meaning |
|---|---|
| omitted / `["direct"]` | the model may only call the tool directly (today's behaviour) |
| `["programmatic"]` | only generated code may call it |
| `["direct", "programmatic"]` | either |

Exact enum values (openai-node): `Array<'direct' | 'programmatic'>`. **Note:** the task brief said `["programmatic", "model"]`; the documented value for the direct path is `"direct"`, not `"model"`. Fuigo sends `["direct", "programmatic"]` on every function tool when PTC is on.

Example function tool with PTC enabled:

```json
{
  "type": "function",
  "name": "read_file",
  "description": "...",
  "parameters": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] },
  "allowed_callers": ["direct", "programmatic"]
}
```

## 2. Output items

The runtime is an isolated V8 (no Node, fs, network, subprocess, console, persistent state). Generated code calls tools as `tools.<name>(args)` (top-level `await` allowed) and returns via `text(...)` / `image(...)`. Intermediate tool outputs are consumed by the program, not by the model.

### 2.1 `program` (the model wrote a program)

```json
{
  "type": "program",
  "id": "<item id>",
  "call_id": "<stable program call id>",
  "code": "<JavaScript source>",
  "fingerprint": "<opaque replay fingerprint; must be round-tripped>"
}
```

openai-python `Program`: `id: str`, `call_id: str`, `code: str`, `fingerprint: str` ("Opaque program replay fingerprint that must be round-tripped"), `type: Literal["program"]`.

### 2.2 `function_call` emitted *by the program* (client tool the program needs)

Same shape as a normal function call plus a `caller`:

```json
{
  "type": "function_call",
  "id": "fc_...",
  "call_id": "call_...",
  "name": "read_file",
  "arguments": "{\"path\":\"a.txt\"}",
  "status": "completed",
  "caller": { "type": "program", "caller_id": "<program.call_id>" }
}
```

`caller` union (openai-python): `CallerDirect { type: "direct" }` | `CallerProgram { type: "program", caller_id: str }` ("The call ID of the program item that produced this tool call"). Direct calls carry `caller: {type:"direct"}` or omit it.

The program is **paused** while these outstanding calls wait for the client. The response ends (`response.completed`) with the `program` item followed by its `function_call` items; there is no assistant `message` yet.

### 2.3 `program_output` (the program finished)

```json
{
  "type": "program_output",
  "id": "<item id>",
  "call_id": "<program.call_id>",
  "result": "<string; the program's text(...) result>",
  "status": "completed" | "incomplete"
}
```

The response that carries it normally also carries the final assistant `message`.

## 3. Returning client tool outputs and resuming the program

Return each result as a normal `function_call_output` **with the `caller` copied from the `function_call`**:

```json
{
  "type": "function_call_output",
  "call_id": "call_...",
  "output": "<string or content list>",
  "caller": { "type": "program", "caller_id": "<program.call_id>" }
}
```

Two continuation modes (guide):

- stored responses: `previous_response_id` + the new `function_call_output` items;
- `store: false` / manual context (what Fuigo does): replay **all** prior output items (including the `program` item with its `fingerprint`, the program-originated `function_call` items with `caller`, and later `program_output` items) in `input`, then append the new `function_call_output` items.

Loop until the response contains a final assistant `message`. A single program may pause several times (each pause is one round trip that returns outputs and resumes); it may also call several tools in one pause (parallel), which is the "ten file reads cost one model turn" case: one `program` -> N `function_call` (caller=program) -> N `function_call_output` -> `program_output` + `message`.

## 4. Streaming

There are **no program-specific stream events** in the SDK union (`response_stream_event.py`). `program` / `program_output` items arrive through the generic item events:

- `response.output_item.added` with `item.type == "program"` (code may be complete or partial at this point; treat `output_item.done` as authoritative)
- `response.output_item.done` with the full `program` item
- `response.output_item.added/done` with `program_output`
- program-originated `function_call` items stream exactly like direct ones (`response.output_item.added` -> `response.function_call_arguments.delta/done` -> `response.output_item.done`), only with the extra `caller` field on the item
- `response.completed` / `response.incomplete` carry the full `output` array including the new item types

Assumption (not stated in the guide): no `response.program.code.delta`-style event exists today; Fuigo therefore does not stream program code and shows the program on `output_item.added` / `.done`.

## 5. Model support

Changelog: GPT-5.6 family (Sol, Terra, Luna). Fuigo gates the feature on `api_backend = "responses"` and an OpenAI-family model (`ModelInfo::is_openai_model`), and leaves it to the operator to enable it only on 5.6+ entries; an older model would reject the unknown tool type with a 400.

## 6. Pricing

- The pricing page does **not** mention programmatic tool calling or any runtime/container charge for it (checked 2026-09-11). The only tool charges listed are Code Interpreter containers ("1 GB $0.03, 4 GB $0.12, 16 GB $0.48, 64 GB $1.92 per 20-minute session"), Web Search ("$10.00 / 1k calls + Search content tokens billed at model rates") and File Search.
- The guide contains no pricing statement either.
- General rule on the pricing page: "Tokens used for built-in tools are billed at the chosen model's per-token rates."

Statement for the benchmark: **as of 2026-09-11 OpenAI documents no separate charge for the PTC runtime**; the observable cost is the model tokens for the `program` item (output tokens for the generated code), the `program_output` and the replayed items on later turns (input tokens). Client tool outputs consumed inside the program are **not** returned to the model, so they are not billed as input unless the program surfaces them in its `text(...)` result. Treat "no runtime charge" as UNVERIFIED-by-absence: re-check the pricing page before quoting it externally.

## 7. What the docs do not say (implemented against SDK types, labelled assumptions)

1. **Program item order on replay.** Assumed: replay exactly the output order (`reasoning`, `program`, `function_call`...) as with every other item; Fuigo already replays byte-stable order for cache reuse.
2. **`caller` on `function_call` replay.** The SDK input type `ResponseFunctionToolCallParam` carries `caller`; Fuigo replays it on both the `function_call` and the `function_call_output` so the server can bind the output to the paused program.
3. **`program_output.status: "incomplete"`.** Assumed to mean the runtime stopped early (timeout / error); Fuigo surfaces it as a failed backend tool call and still lets the model's final message through.
4. **Timeouts / execution limits.** Not documented. Nothing to implement client-side; the idle-timeout that already guards the SSE stream applies.
5. **Tool types eligible for `allowed_callers`.** Guide lists function, custom, mcp, apply_patch, shell, code_interpreter. Fuigo marks its `function` tools only (that is the only client tool type it sends on the Responses backend today).
6. **Mixing direct and programmatic calls in one response.** Not documented; Fuigo handles it (direct calls carry no `caller` and are replayed as before).

## 8. How Fuigo maps this (implementation summary)

- `HostedTool::ProgrammaticToolCalling` rides the existing raw-JSON hosted-tool channel and emits `{"type":"programmatic_tool_calling"}`.
- `fuigo_sampling_types::responses_ptc::patch_request_body` runs on the serialized body (next to `patch_reasoning_text_types`): it rewrites the typed carrier items back into `program` / `program_output` wire items, adds `caller` to the `function_call` / `function_call_output` items that belong to a program, and stamps `allowed_callers: ["direct","programmatic"]` on function tools when the PTC tool is present. With the flag off the pass is a byte-for-byte no-op (tested).
- Inbound, `fuigo_sampler::stream::responses_ptc::transcode_sse` rewrites `program` / `program_output` items into a typed carrier (`custom_tool_call` named `__fuigo_ptc_program` / `__fuigo_ptc_program_output`, `input` = the raw item JSON, with the program's produced `call_id`s collected from the sibling `function_call.caller` fields) so the vendored `async-openai` `OutputItem` enum (which has no catch-all variant) keeps parsing. The stream layer turns the carriers into `BackendToolCallStarted/Completed` events (name `programmatic_tool_calling`) and the conversation layer into `BackendToolKind::Program` / `BackendToolKind::ProgramOutput` items, which persist and replay.
- Program-originated `function_call` items are ordinary `ToolCall`s: they go through the normal tool dispatch (permissions, logging, ACP UI) and their `ToolResult` is replayed as `function_call_output` with the `caller` re-attached from the program item's `call_ids`.
