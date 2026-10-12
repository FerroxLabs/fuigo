# R-bang-controls: `!` lines obey denials and never prompt (decision 40, option D)

Branch `strike/bang-controls` on base `9d57c315`. Paths under `crates/codegen/`.

## Order of checks (all before `terminal.run`)
0. `turn.rs` ~600: a `!` line runs only when `policy.authority.is_human_intent()`; any other authority ignores the meta.
1. `tool_dispatch.rs` `handle_direct_bash_command` calls `bang_refusal` after the Execute tool-call block is shown and before the `TerminalRunRequest`:
   a. `UserPromptSubmit` (`dispatch_prompt_submit_hook`, payload gains `shellCommand`): Block refuses; added context unused.
   b. `PreToolUse` (`dispatch_pre_tool_use`, tool name = the toolset's Execute tool, `toolInput` = BashToolInput + `"userTyped": true`): Deny refuses; Ask = allow; `updated_input` and context ignored (never read).
   c. `PermissionHandle::configured_deny(AccessKind::Bash(cmd), cwd)`: Reject refuses.
2. Run as before. `bang_post_tool_use` fires `PostToolUse` observe-only (result and context ignored).
3. Ticket binding: `session/cron_fire_tickets.rs` `canonical_text` accepts a single text block whose `_meta` keys are only `displayText` / `displayAsCron` (what the pager cron drain sends, `fuigo-pager/src/app/dispatch/queue.rs:656-667`). Any other key: ticket burned, prompt is `User`.

## Decide-only entry
`PermissionHandle::configured_deny` (`fuigo-workspace/src/permission/manager/mod.rs`) sends the new `PermissionCommand::DecideOnly` (`permission/types.rs`) to the actor, which runs `GatePreflight::evaluate(compiled_policy, &access, cwd, auto_mode=false).policy_decision()` and answers `Some(reason)` only for `Decision::Reject`. This is the same evaluation `request` runs before YOLO (Bash deny rules, managed lock-down = a deny-any rule, the shell-access/shell-file gate Reject verdicts). Ask, `dontAsk` (`prompt_policy`), plan mode and auto mode yield `None`. No prompt, no grant, no state change. `AllowAll` handle: `None`. Manager gone: fails closed with a reason.

Lines touched in `permission/manager/mod.rs`: one new method `configured_deny` inserted immediately before `pub async fn request` (about +20 lines), and one new match arm `PermissionCommand::DecideOnly {..}` inserted immediately before the `SetYoloMode` arm in the actor loop (+13 lines). No existing line changed. `permission/types.rs`: one new enum variant (+6 lines).
Other touched files: `fuigo-hooks/src/event.rs` (+`shell_command` on `UserPromptSubmit`, serde skip when absent) and its one test constructor `fuigo-hooks/src/dispatcher.rs`; `acp_session.rs` (+1 `mod` line); tests.

## Refusal text
- rule or policy: `Refused: Denied by permission policy: deny rule on bash matching "<pattern>"` (a lock-down reads `deny rule on any tool`).
- `Refused: a PreToolUse hook (<hook display name>) denied this command: <message>`
- `Refused: a UserPromptSubmit hook (<hook display name>) blocked this command: <message>`
Hook name and message pass `flatten_spoofable` (controls and spoofing characters become spaces) and `clip_reason`.
Shown as the tool block's output (`BashOutput.output`, exit 126, status Failed), where the command output would have appeared.

## What the model sees on a refusal
One fixed user item: ``I tried to run a terminal command, but it was refused by policy and did not run: `<cmd>```. The tool-result `content` (used when chat history is rebuilt from updates) is the fixed text "The command was refused by policy and did not run." Neither the hook message nor the rule is in either copy (pinned by test). The turn ends normally. An ACP host with client terminals (`AcpTerminalRunner`) sees nothing: the refusal happens before `terminal.run`, so no terminal is created.

## Deviations / not verified
- Rule SOURCE (user / project / managed) is not named: `PermissionConfig` rules carry no provenance at the manager (`PermissionRule` has no source). The text names the rule (tool + pattern) only. Naming the source needs a source field through the policy merge in `resolution.rs`: left for a follow-up.
- Session "always deny" grants (persisted `denied bash` state) are not consulted (they are user choices stored in the manager state, not configured rules).
- SDK client-registered hooks (`client_hooks`) are not run for a `!` line; only the on-disk hook registry. The peer-influenced guard does not exist on this base; no code for it (comment only here).
- `PostToolUse` now fires for `!` lines where a hook matches Bash: a stated part of the packet.
- Sender audit: the only non-test builders of `_meta.bash_command` are the pager `!` mode (`fuigo-pager/src/app/effects/mod.rs`) and the queued-edit path (`prompt_queue.rs`), both human. No shipped sender attaches it to a non-human prompt. Pager wire for a typed `!` line is unchanged.
- Windows and the Murage conformance suite: see the test totals in the report for what ran.
