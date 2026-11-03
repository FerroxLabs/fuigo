# Fuigo 1.0.39 release notes

## Subagents

- **Forked subagents no longer get the project instructions twice.** A child forked from a session that already holds
  the folder's `AGENTS.md` and other instruction files now recognises them and does not add a second copy.
- **Subagents get the plugins of the folder they work in.** A subagent in another folder (a worktree, or a session
  opened elsewhere) now gets that folder's plugins, not those of the folder Fuigo was launched in, and a plugin edited
  since the last `/plugins reload` shows up. The check of which agent types exist, and the skills a subagent inherits,
  now use the parent session's own plugins, so they match the agent types the parent offers.
- **A subagent worktree that cannot be created now says why.** When a tracked file fails to copy into a new subagent
  worktree, or the disk is full, the subagent stops with that error instead of quietly running in the shared folder.
  Other worktree errors behave as before.

## Scheduled tasks

- **Scheduled tasks keep working after a model switch made before the first turn.** Before, that switch left the session
  talking to a stopped scheduler, so parking the session and the scheduled tasks of new subagents did not reach it.
- **A scheduled task fires once.** Two schedulers sharing one session's state, for example around a model switch, could
  both fire the same task. Each fire is now admitted once. A loop task whose subagent is still running is not started
  again, and that subagent keeps running across a model switch; the loop's next iteration after it starts a fresh
  chain.
- Shutdown behaves as in 1.0.38.

## Settings and commands

- **New `[keys] vim` setting.** `vim = "nav"` turns on vim-style navigation and `vim = "off"` turns it off. If
  `[ui].vim_mode` is also set, it wins, so existing configs behave exactly as before. `/vim-mode` still changes the
  current session only.
- **`fuigo worktree list` and `show` mark a worktree whose folder is missing.**

## Releases

- The macOS release build may now run for up to 6 hours, GitHub's limit for hosted runners.
