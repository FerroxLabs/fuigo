# Parallel Work: Worktrees

Want Fuigo working on a feature while you (or another Fuigo session) work on
something else in the same repo? **Git worktrees** give each session its own
isolated checkout — no stepping on each other's changes, no stashing.

## Start a session in a worktree

- **From anywhere:** press `Ctrl+N` (twice to confirm) for a new session,
  then choose the worktree option.
- **From the welcome screen:** press `Ctrl+W` (inside a git repo) to open
  the New Worktree dialog.
- **From the shell:**

  ```bash
  fuigo --worktree=my-feature "refactor the auth module"
  ```

  (Use `=` — otherwise the prompt is taken as the worktree name.)

## Names and refs

- A worktree name keeps Unicode letters and digits (`café` stays `café`); spaces and underscores become hyphens, and other punctuation is dropped.
- A name you type that is already taken is refused, with a message naming it; Fuigo no longer quietly makes `name-2`. If you deleted that worktree's folder by hand, the name is free again. Names Fuigo generates for you (no name typed) still get a numeric suffix when they collide.
- `--worktree-ref` (alias `--ref`) and `fuigo worktree create --ref` take a branch, tag or commit. A ref or a name that starts with `-` is refused with "may not begin with '-'", because git would read it as an option.

## Why this is great

- Run two or three Fuigo sessions on the same repo simultaneously.
- Experiments stay isolated — if a change doesn't work out, your main
  checkout is untouched.
- When the work is done, apply the changes back like any git branch.

**`/fork`** copies your current conversation into a parallel session —
add a directive to point it at a task: `/fork try the async approach`.

Running several agents? The **dashboard** (`/dashboard` or `Ctrl+\`) shows
every session grouped by state — who needs input, who's working, who's done.

*Go deeper: `/docs Session Management`*
