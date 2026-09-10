# Experimental compact tool descriptions

This worktree adds an opt-in presentation layer to the normal agent:

```sh
FUIGO_TOOL_PRESENTATION=compact fuigo
```

New sessions default to full descriptions. The mode is saved with a session;
set `FUIGO_TOOL_PRESENTATION=full` to override it on resume. An explicit process
setting takes precedence over saved preferences; unknown values mean full.
It does not select the separate
`fuigo-build-concise` agent or disable AGENTS.md.

Only13 verified built-in top-level descriptions are shortened. Matching requires
the exact native name, original description and parameter schema. Custom tools,
changed schemas and unmatched dynamic descriptions retain their original text.
Every tool name, parameter validation rule, registered implementation, permission,
hook, result and hosted-tool configuration remains unchanged. Full original
descriptions are retained in the source catalog and tool registry.

`FUIGO_TOOL_PRESENTATION=adaptive` additionally defers eligible media-generation
schemas until `search_tool` with `scope: "native"` discovers them. Coding, job-control,
workflow, memory and MCP tools remain visible. Host-declared delivery tools stay pinned.
The full registry remains available; call discovered native tools by their original
names on the next request, never via `use_tool`. Discovery grants no permission.
Ordinary finalization and child restrictions apply before exposure. Memory-only
classification uses the full eligible set, not its smaller advertised subset.
Changed/removed schemas invalidate activation. Oversize results or eight activations
switch to full eligible presentation; schemas are never silently truncated.
Bounded selection fingerprints and mode are saved through the session persistence
actor. On reload they are intersected with currently eligible definitions; changed
schemas are rediscovered. Invalid/oversized hints are ignored with a warning.
These hints are never permission state and cannot restore old authority.
The function is idempotent for already-presented fork/mirror tool definitions.

Status: experimental candidate, not part of published1.0.10. Predicted description
reduction is not a measured total-token saving. Adoption awaits structural and
actual-ACP parity checks, followed by the plan's workload measurement gates.
