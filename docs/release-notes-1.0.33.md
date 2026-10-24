# Fuigo 1.0.33 release notes

## Models and sampling

- One switch for embedding apps: `FUIGO_DISABLE_MODEL_REFRESH` (any non-empty value except `0`) now turns off every background model-list fetch. Before, it only stopped the daily refresh of your ChatGPT and Grok subscription lists; a provider API key in the environment still made Fuigo ask that provider for its model list about once a day. With the switch on, neither happens: Fuigo makes no request, uses the cached list if there is one, and otherwise the built-in list. It applies in the terminal app, headless `-p` and ACP alike. Asking explicitly, with `fuigo login --provider <id>`, still fetches.
- A web search that arrives without its details no longer ends the turn. When a Responses API backend sent a search step with no `action` (for example while the search was still in progress), Fuigo failed with "Failed to deserialize ResponseStreamEvent" and the turn errored. Fuigo now treats that one omission as a search with no query and carries on; nothing is shown as a search query. Any other malformed event still fails loudly, as before.
- A regression test now pins that a zsh startup file which redefines `run-help` (as an alias or a function) and aliases `grep` does not break the persistent shell: the command you run still works and the shell state keeps replaying on later commands.

## Hooks

- Untrusted folders now run only managed hooks from your organization. Before, your own hooks (`~/.fuigo/hooks`, `~/.claude`, `~/.cursor`, and the hooks in your `config.toml`) and the hooks of user-scope plugins and agents still ran in a folder you had not trusted; now user, project, plugin and agent hooks all stay off until you trust the folder (`/hooks-trust` or `--trust`), and Fuigo logs once per folder that it skipped them. Headless (`-p`) sessions treat your own hooks as trusted; their project, plugin and agent hooks still wait for folder trust.

## Worktrees

- A worktree ref or name that starts with `-` is refused up front, with "git ref may not begin with '-'" (or "worktree name may not begin with '-'"), instead of being handed to git as an option. This covers `fuigo -w --worktree-ref`, `fuigo worktree create --ref`, worktree forks and subagent worktrees, and the library layer that runs `git checkout` and `git worktree add`, which now also pass the ref after `--`.
- Worktree names typed in the interface keep Unicode letters and digits: "café" stays "café" instead of becoming "caf". Long non-ASCII names are cut on a character boundary rather than panicking.
- A worktree name you type that is already taken is refused, with a message that names it ("A worktree named 'feature-x' already exists..."). Before, Fuigo quietly created `feature-x-2`, so you ended up in a worktree you did not ask for. A name whose folder you deleted by hand can be reused. Generated names still get a numeric suffix.
- Checked, no change: worktrees under `FUIGO_SANDBOX_MODE=enforce`. Fuigo creates worktrees itself, not through a sandboxed shell command, and a session served from inside `~/.fuigo/worktrees/` is already the one writable tree under the Fuigo home, so `fuigo -w`, `fuigo worktree create`, `/fork` worktrees and subagent worktrees keep working and their options stay visible. The sandbox guide now says so.

## Terminal interface
- /fork now keeps the parent session's current model and effort. Before, a fork came up on the model and effort you launched with (`-m` and `--effort`), so switching the parent to another model and `/effort low` and then forking gave a fork on the launch model.
- A plan review can no longer be approved by a stray keypress. A key that reaches the review as it opens (for example the first letter of "add tests" while you were typing) goes into the review notes as text instead of firing the `a` approve shortcut; the same holds for `a` and `q` in the plan preview.
- A plan review that arrives while a question, an MCP elicitation, a `/feedback` dialog, a queued-prompt edit or the cancel-turn confirm is open now waits for it and appears when the last one closes. Before, it closed or covered the dialog you were answering.
- A session that fails to start no longer eats what you typed. When `session/new` or the worktree create fails (an auth error, for instance), your message and any queued prompts come back into the prompt you land on (welcome, dashboard input or the session you fall back to) instead of being dropped with the failed session.

## Startup

- On a Mac you are logged into over SSH with nobody at the console, `fuigo` no longer hangs on its first modifier-key check. Fuigo now asks macOS whether the session has window-server access before it reads the keyboard modifiers, and when it does not, it treats no modifiers as held instead of calling the call that could block forever.
- `fuigo --permission-mode plan` now starts the session in plan mode, as the docs say. Before, the flag was accepted but the session started in ask mode. `fuigo -p ... --permission-mode plan` is now refused with a clear error before anything is sent to the model, because plan mode ends by asking you to approve the plan and a headless run has nobody to ask. Before, it quietly ran in another mode.
