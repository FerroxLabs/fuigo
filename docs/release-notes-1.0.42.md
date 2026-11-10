# Fuigo 1.0.42 release notes

## Editing the prompt

- **Vim editing in the prompt.** `/vim-mode all` (or `[keys] vim = "all"`) gives the prompt NORMAL and INSERT modes,
  with motions, operators, counts, undo and redo. Enter still submits from either mode. The shortcuts sheet lists the
  NORMAL-mode keys while it is on. In NORMAL mode `Ctrl+R` is redo, so open the sessions list from INSERT mode. The
  `/settings` switch "Disable vim input mode" (`[ui] simple_mode`) now turns this same prompt vim on and off.
- **More ways to mention a file with `@`.** `@~/` reaches files in your home folder, `@!` reaches hidden files, and a
  `:N` suffix points at one line. The picker also lists files outside the workspace
  (`ui.at_picker_outside_workspace`, on by default). Typing at the end of a file chip edits it in place.
- **Quit with one `Ctrl+C`.** With `ui.single_ctrl_c_quit` on, one press quits when nothing would be lost: no turn
  running, no draft, no queued prompt and no open question. Off by default.
- **`/doctor` warns about a slow tmux escape time.** Inside tmux, an `escape-time` above 50 ms is reported with the
  command that fixes it.

## Transcript

- **Dragging selects text across blocks.** A drag that starts on text now runs on into the next blocks, and copy gives
  plain text without colours, borders or buttons. A drag that starts outside text still selects whole blocks.
- **Copy buttons work while a menu is open**, and while a queued prompt is being edited.
- **Text stays readable in an 8-colour tmux session.** Bright colours fold onto the eight normal ones there.
- **Markdown links that contain `$` or LaTeX characters render as links** instead of switching into math. A `$` inside
  a link's address is shown as `%24`, which is the same address.
- **Mermaid diagrams break lines on `\n` and `<br>`** instead of printing them.
- **Warp opens the whole of a wrapped URL.**

## Keys and input

- **`Ctrl+E` in minimal mode moves to the end of the line** while you are editing a draft.
- **`Ctrl+Y` on a question card no longer closes it unanswered.**
- **Esc on an unanswered `/btw` cancels it**, and `/btw` starts a side question only at the start of a message.
- **A slash menu closed with Esc stays closed** when the command list refreshes.
- **Typing while the transcript has focus goes to the prompt**, including non-ASCII text, and leaves an open card alone.
- **Windows: Shift-held symbols and AZERTY digits work in shortcuts.**
- **Double-clicking a view's close button no longer presses what was underneath it**, such as a stop button.
- **Long pastes delivered as keystrokes no longer freeze** while the plan-mode tip is shown.

## Background work and the dashboard

- **Dock stop buttons work while that run's approval card is open.**
- **Dashboard rows stay Working while background subagents and workflows run**, and stopping a row ends them.
- **The footer's context use is right after a rewind.**

## Sessions

- **Delete, rename and copy refusals show their full text**, and session load errors give the whole reason.
- **A deleted or renamed session no longer appears in resume lists or title searches.**
- **A session with an unknown reasoning effort resumes** with the default effort.
- **`--resume <id>` reads only that session**, so it starts faster with many sessions.
- **A resumed session shows a background command's real run time** in the turn that ran it.
- **`fuigo export` is faster and uses less memory** on sessions with large shell output.

## Hooks

- **Opt-in fail-closed hooks.** A `PreToolUse` or `UserPromptSubmit` hook entry can set `"failClosed": true`. If that
  hook times out, crashes, fails to start, exits non-zero without a decision, or prints output that is cut off,
  unreadable or carries a key Fuigo does not recognise, the tool call is denied or the prompt is blocked. Hooks without
  the flag still fail open, as before. A prompt block applies only to a prompt you typed, as for any block.
- **A `!` shell line now honours a hook's stop** (`"continue": false`), as tool calls already did.

## Updates and startup

- **Automatic update stops retrying a version that fails to start.** Only a real launch failure counts: a slow first
  run or a busy file does not.
- **`fuigo update` runs when a sandbox profile is set**, unless Fuigo is already confined. A confined session never
  auto-updates and tells you to run `fuigo update` instead.
- **`--restore-code` is safer.** A failure leaves your uncommitted and untracked files in the tree, it restores its own
  stash when another worktree changed the stash list, and it keeps changes stashed if a post-checkout hook fails.
- **Rejecting a change keeps edits you saved**, even when the save was missed.
- **Non-UTF-8 environment variables no longer stop startup.**
- **macOS: the full-screen app no longer freezes in a sandbox that blocks the window server.**
- **Typing does not lag when ffmpeg is missing and `PATH` is slow**: the check runs off the drawing path, once.
- **Exiting is reliable.** `Ctrl+U` update-and-quit exits within its deadline, and on Windows Fuigo exits fully after a
  startup error, `/minimal`, `/fullscreen` or a signal.
- **Opening links and files no longer leaves a zombie process per click.**
- **Short terminals: the cancel-turn prompt and rewind confirmation no longer crash the full-screen app.**
- **Kitty graphics: hidden images are freed in the terminal.**

## Other fixes

- **MCP stdio servers no longer lose part of a long line** when a read is interrupted.
- **`!` mode Tab completion offers symlinked commands.**
- **Custom agent files with a UTF-8 byte order mark load.**
- **Sign-in error messages no longer repeat the underlying cause.**
- **The always-approve help text says the setting is saved to config.** The macOS docs recommend `Ctrl+V` to paste
  screenshots. Auto-review mode tints the whole prompt bar, like plan and ask. Editing a queued prompt labels and dims
  its row.

## From 1.0.41

- **The strict sandbox starts for a non-root user when a container socket sits in a root-only folder** (for example
  `/run/podman`). Such a socket is skipped only when the folder that blocks it belongs to another user. This shipped in
  1.0.41 but was missing from its notes.
