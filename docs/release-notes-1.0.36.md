# Fuigo 1.0.36 release notes

## A permission policy for one launch

A program that launches Fuigo (an editor, a CI job, an embedding app) can now hand it a permission policy for that
run. See [Launch Policy](../crates/codegen/fuigo-pager/docs/user-guide/22-permissions-and-safety.md#4-launch-policy-fuigo_policy_path).

- **Set it with two variables.** `FUIGO_POLICY_PATH` names the policy file (an absolute path) and
  `FUIGO_POLICY_SHA256` must give its sha256. The file holds only a `[permission]` section in `config.toml` syntax
  (`allow`, `deny`, `ask`, `rules`).
- **Per session too.** An ACP client can add a policy to one session with `_meta["fuigo/permissionPolicyPath"]` and
  `_meta["fuigo/permissionPolicySha256"]` on `session/new`, and sends both again on every load, resume and fork it
  wants governed. The response confirms it in `_meta["fuigo/permissionPolicy"]`.
- **Its deny and ask win in every mode**, always-approve included. An `ask` from the policy always reaches your client
  as a permission request; remembered approvals don't answer it and answering it remembers nothing. An `allow` acts
  like your own config: it can remove a default prompt, never a deny or an ask.
- **A bad policy stops Fuigo before it starts.** Unknown keys, malformed rules, a relative path, a symlink, a file over
  256 KiB, or a missing or wrong hash: Fuigo prints one JSON line on stderr (`{"policy_error": ...}`) and exits with
  code 78. `fuigo policy check <file> [--json]` tests a file the same way and prints its sha256.
- **The file is pinned for the life of the process**, and the agent cannot edit it. To change it, start a new process.
- **A governed process runs standalone**: no shared leader, and hub routing is refused.
- **Nothing changes when the variables are unset.**

## Browser mode gives the session back when you leave it

- **Leaving `browser_use` restores the session's own instructions.** Picking `default`, `ask` or `plan` after
  `browser_use` now gives back the session's own system prompt, its session rules and the client's system prompt,
  exactly as they were. Before, browser mode replaced them and leaving it did not put them back.
- **Browser mode adds to the prompt instead of replacing it.** While it is on, the browsing instructions are added
  after the session's own prompt on each request; nothing is stored, and approvals are unchanged.
- **`browser_use` is reported truthfully.** `session/set_mode`, `current_mode_update` and `modes.currentModeId` on a
  live session now say `browser_use` instead of `default`.
- **A reloaded session starts in its normal mode.** Browser mode lasts for the running session; after a restart the
  session loads in its normal mode (its history replay still shows the earlier switch to Browser).
- **Sessions saved in browser mode by 1.0.35 load with their normal instructions.** Session rules that 1.0.35 dropped
  when it entered browser mode were never stored anywhere and cannot be recovered.

## Session rules and memory survive mode and model changes

- **Switching model keeps your remembered context.** A model switch, or anything else that rebuilds the session's
  instructions, now keeps the memory context and your session rules. Before, the memory context could be lost until
  a restart.
- **Picking `default` or `ask` keeps the session's instructions.** A `default.md` or `ask.md` file now supplies only
  the mode's template: your session rules, the client's system prompt and the memory context stay.

## A bare `Read` rule means file reads

- **`Read` in `allow`, `deny` or `ask` covers file reads and listings** (reading files, listing folders, grep, LSP,
  memory files). It no longer reaches the pure bookkeeping tools (`todo_write`, `ask_user_question`,
  `scheduler_list`, `search_tool`, `refuse_peer_message`), so `ask = ["Read"]` no longer asks on every to-do update
  and `deny = ["Read"]` no longer blocks them. Every tool that can touch files is still covered; a rule with
  `tool = "any"` still reaches everything.

## Worktree copies report what they could not copy

- **A tracked file that fails to copy stops the worktree.** Creating or forking a worktree used to drop such a file
  silently and report success; now the create stops with an error (a full disk says so) and the partial worktree is
  removed.
- **Untracked and ignored files that fail to copy are a warning.** One short line ("Worktree created, but 1 file had a
  copy problem: ...") gives the count and the first file; the details are in the log. The same line shows when a
  session is forked or resumed into a worktree, and headless runs print it on stderr.

## MCP tools work with more Chat Completions providers

- **Fuigo fills in what MCP tool schemas leave out** when it sends them to a custom model over Chat Completions: a
  missing `type`, an object without `properties`, an array without `items`. Some providers rejected those tools.
  Complete schemas are sent unchanged, other API paths and built-in tools are untouched, and a tool is never dropped.
