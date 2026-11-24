# Contract E: downstream embedder compatibility

This document states what Fuigo promises to programs that embed it: a host application that
spawns a `fuigo` binary and drives it as an ACP agent over stdio. The conformance suite
(`crates/codegen/fuigo-shell/tests/murage_conformance_acp.rs`) is the executable form of every
clause. The suite's reference embedder is named Murage; the promises below are not specific to it.

Every clause is behavioural. Each one says what is guaranteed and which tests pin it. Changing
any of them is a breaking change for embedders and is made only deliberately and with notice,
never as a side effect of another change.

The suite spawns the REAL `fuigo` binary with the embedder's argv and speaks raw newline-delimited
JSON-RPC to it. Only the inference endpoint is mocked. Each test runs in its own sandbox (own
`HOME`, `FUIGO_HOME`, `TMPDIR`, cleared environment) and asserts that the child used it.

## E.1 Process spawn surface

An embedder launches Fuigo with this exact argv:

    --permission-mode {bypassPermissions|default}
    [--trust]                  # only when the embedder knows the human trusted the folder
    --no-memory                # the embedder owns persistent memory
    agent
    --no-leader                # never attach to a shared leader socket
    [-m <model>]
    [--reasoning-effort <effort>]
    stdio

**Guarantee.** These flags, their spellings, their aliases (`stdio` is an alias an embedder may
rely on) and their effects are stable:

- `--permission-mode` governs tool approval; an embedder that passes it is never silently
  upgraded or downgraded.
- `--no-leader` keeps the agent standalone even when configuration enables a leader. Attaching to
  a leader would bypass the explicit permission mode and bill the turn to a different identity,
  so this flag is security-relevant.
- `--no-memory` means nothing memory-shaped is written and no memory tools are offered.
- `-m` and `--reasoning-effort` reach the inference request.

**Tests.** `murage_exact_argv_is_accepted`, `murage_argv_flags_still_exist_with_their_spellings`,
`permission_mode_flag_governs_tool_approval`, `model_and_reasoning_effort_flags_reach_inference`,
`no_leader_flag_keeps_the_agent_standalone_when_config_enables_leader`,
`no_memory_flag_withholds_memory_tools` (the last also in `no_memory_writes_acp.rs`).

## E.2 Credential injection

**Guarantee.** `FUIGO_API_KEY` read from the spawned process's own environment at startup is a
supported, first-class credential source. Fuigo may keep keys out of the environments of the
children it spawns (shell, LSP, MCP, client terminals), and may accept a key at runtime, but it
never stops honouring the key it was started with:

- An injected environment key authenticates the session and is not written to disk.
- An injected environment key outranks a key saved in `auth.json`.
- A key supplied at runtime in `authenticate` `_meta["fuigo/apiKey"]` authenticates with no
  environment or config key. It is written to disk only if the client opts in (`persist`), leaves an
  existing `auth.json` byte-identical otherwise, never enters the agent's environment, is invisible to
  child processes, and never reaches errors, logs (including trace and debug logging) or disk.
  `set_api_key` with a clear request drops it again.
- A key saved in `auth.json` is held in memory and is never placed in the environment of a tool or
  client-terminal child.

**Tests.** `injected_fuigo_api_key_authenticates`,
`injected_env_key_still_authenticates_and_is_not_persisted`, `injected_env_key_outranks_the_auth_json_key`,
`runtime_api_key_*`, `set_api_key_clear_drops_the_runtime_key`,
`set_api_key_clear_with_a_mapped_model_hands_out_nothing`, `malformed_wire_lines_carrying_the_key_reach_no_log`,
`auth_json_key_authenticates_and_reaches_no_tool_child`, `set_api_key_key_authenticates_and_reaches_no_tool_child`,
`client_terminal_child_does_not_inherit_the_saved_key`, `session_new_mcp_header_and_env_secrets_reach_no_log`,
`p08_auth_wire_matches_golden`.

## E.3 Auth negotiation

At `initialize`, Fuigo advertises `authMethods` and `_meta.defaultAuthMethodId`.

**Guarantee.**

- Whenever an API key is usable, `fuigo.api_key` is advertised under that exact id, and
  `_meta.defaultAuthMethodId` names the method that honours the injected key. `authenticate`
  with `methodId: "fuigo.api_key"` returns `{}`.
- With no credential at all, `authMethods` is empty, and both `authenticate` and `session/new`
  fail with JSON-RPC error `-32000` and the message `Authentication required`.
- Further methods (for example subscription sign-in) may be added. The key method is never
  renamed, removed or reordered behind another method, because an embedder that falls back to
  the first listed method would otherwise authenticate as a different identity than the key it
  injected and bill the wrong account.

**Tests.** `initialize_advertises_fuigo_api_key_and_names_it_default`,
`no_credential_yields_empty_auth_methods_and_minus_32000`, `p08_auth_wire_matches_golden`.

## E.4 ACP protocol version

**Guarantee.** Fuigo accepts `protocolVersion: 1` in `initialize`. An embedder that sends the
literal and does no negotiation keeps working.

**Test.** `protocol_version_one_is_accepted`.

## E.5 Extension namespace and folder trust

**Guarantee.** The `fuigo/*` and `_fuigo/*` extension methods an embedder binds to are a public
interface and are not renamed without notice. Folder trust in particular:

- A client advertising `clientCapabilities._meta` `{"fuigo/folderTrust": {"interactive": true}}`
  (the round-trip needs the `fuigo/folderTrust.v2` capability) is asked via `fuigo/folder_trust/request`
  and answers it.
- With `--trust` the request is not sent.
- A client that did not advertise the v2 capability is never asked, and commands that need trust ask the user instead.
- An ACP host that answers `session/request_permission` but is not a recognised Fuigo client declares
  `initialize` `_meta` `{"fuigo/permissionPrompts": true}`; changes outside the workspace that the user did not name are then
  asked of it in every mode, bypass included, instead of refused (1.0.47; the client type is unchanged).

**Tests.** `folder_trust_round_trip_without_trust_flag`, `trust_flag_suppresses_the_round_trip`,
`v1_only_client_is_never_asked_and_commands_ask`, `ds04_headless_bypass_keeps_the_outside_database_and_the_control_runs`
(permission prompts).

### E.5a Wire names and the leading underscore

An extension method has one spelling in source and one on the wire: the wire name carries a
leading `_` (source `fuigo/mcp_initialized`, wire `_fuigo/mcp_initialized`). A change to the ACP
library or to any call site that alters that mapping silently renames every extension method by
one character, and every embedder binding stops working without any error on Fuigo's side.

**Guarantee.** Tests read raw wire JSON, not the typed client (which hides the prefix), and pin the
exact on-the-wire name of every extension method embedders bind to.

**Tests.** the E.6 tests below, plus `ask_user_question_round_trip_wire_name_is_pinned`.

## E.6 MCP readiness and other bound extension names

**Guarantee.** Fuigo emits the MCP-ready notification under its pinned wire name once MCP servers
have initialised, and the MCP server, elicitation and `ask_user_question` round-trips keep their
wire names. `ask_user_question` waits for a human-in-the-loop embedder beyond the 30 second cap
that applies when no operator is present.

**Tests.** `mcp_ready_notification_wire_name_is_pinned`, `murage_mcp_server_elicit_and_ready_wire_names`,
`ask_user_question_round_trip_wire_name_is_pinned`,
`ask_user_question_waits_for_murage_past_the_non_interactive_cap`.

## E.7 Model state

**Guarantee.** The `initialize` response keeps `_meta.modelState` with its exact JSON shape:
`currentModelId`, and `availableModels[].modelId` at those paths, with the other keys of each entry
unchanged. A hand-rolled replacement type must serialize identically, because the drift of a single
key degrades the embedder's model reporting without any error.

**Test.** `meta_model_state_matches_golden` compares the live response with
`tests/fixtures/murage_model_state_golden.json` as JSON values, so key order is irrelevant and any
added, removed or renamed key fails.

### E.7a Goldens come off the wire

A golden fixture is captured from the raw output of the real binary, never written by hand, and it
asserts the real key spelling (`_meta`, not `meta`). A test that builds its own input with the same
mistake as the code under test passes forever and proves nothing. The same rule applies to
`p08_auth_wire_golden.json` (the authentication surface) and `u36_unset_wire_v1035.json` (the unset
launch-policy surface).

## E.8 The rest of the v1 wire

**Guarantee.** The fields embedders read in session updates, tool calls, content blocks, prompt
responses and stop reasons keep their names and tagging; the test drives them through a real session and asserts the wire paths an embedder reads.

**Test.** `murage_wire_path_fields_round_trip`.

## Release acceptance

The conformance suite must pass on the exact commit a release ships. Breaking any clause above
is a deliberate, announced decision, never a side effect.
