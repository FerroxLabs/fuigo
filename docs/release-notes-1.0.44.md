# Fuigo 1.0.44 release notes

## Sandbox: a read-only launch folder

- **New built-in `minimal` profile.** `fuigo --sandbox minimal` runs with the strict profile's reads and network
  policy, keeps session state, temp files and devices writable, and makes the folder Fuigo was launched in read-only.
  Use it for a checkout you do not trust.
- **New `workspace_write` setting.** Any custom profile can set `workspace_write = false` to make the launch folder
  read-only. Leaving it out keeps the base profile's behaviour, so existing profiles are unchanged. The read-only
  launch folder wins over any write grant inside it, including relative paths, which are never created there.
- **Enforced, or Fuigo does not start.** On Linux a read-only launch folder needs bwrap: if bwrap cannot run, Fuigo
  and the workspace server refuse to start with a clear message instead of falling back to a weaker sandbox. A Linux
  build without sandbox enforcement refuses `minimal` the same way. macOS uses Seatbelt. Windows warns and continues.
- **No new aliases.** The sandboxed process cannot create a hard link to a launch-folder file in a writable
  directory, on the same filesystem or another one, or move a launch-folder file out.
- **Profile names you did not write cannot weaken it.** A project's own `.fuigo/sandbox.toml` cannot redefine a
  built-in name (`minimal`, `workspace`, `devbox`, `read-only`, `strict`, `off`): the built-in applies and a warning
  names the file. Your own `~/.fuigo/sandbox.toml` can still define `[profiles.minimal]`, which keeps working as before
  and prints a warning that it shadows the built-in.
- **Warnings instead of silent surprises.** Unknown keys inside `[profiles.*]` and session storage that would sit inside
  a read-only launch folder each print one warning; Fuigo keeps starting.
- **Deny entries written with `./` now work on macOS.** A `deny = ["./.env"]` entry (or any path containing `/./`)
  was not enforced on macOS, so the file stayed readable. It is now denied like `.env`. Linux was not affected.
- **`~` in a deny entry means your home everywhere.** `deny = ["~/.aws"]` already protected the home path for
  sandboxed commands; Fuigo's own process now applies it to the home path too, instead of a `~` folder inside the
  workspace.
- **Known limit.** Like any path-based sandbox, it cannot see links that already exist before launch: a hard link or a
  writable bind mount of a launch-folder file created outside the sandbox keeps that path's own access.

## Folder trust and consent

- **No answer before the question is on screen.** A follow-up click after accepting the consent notice or trusting a
  folder no longer acts on the next screen before it is drawn, and keys typed before the trust question appears are
  ignored. "On screen" means the terminal has finished writing the frame that shows the question. Ctrl+C and Ctrl+D
  always work.
- **Short terminals.** The trust question accepts answers whenever its line is visible, even when the menu has no room.
- **Tiny terminals.** Welcome, consent and trust screens and MCP elicitation cards draw without crashing or overflowing
  at any size down to 1x1.

## Sign-in

- **Sign-in finishes against the login stored now.** If another window logs out, signs in again or switches account
  while a browser or device-code sign-in is open, completing it writes nothing and says the login changed in another
  window. Token refreshes and account details loading during the sign-in do not count as a change.
- **Logout is reliable.** A logout that cannot remove the stored login reports an error and keeps the session instead
  of reporting success. Logout no longer freezes the screen while it waits for another window.
- **An unreadable `auth.json` does not block sign-in.** If the file cannot be read (for example a permission error), the
  new login works for this session only and is not saved, with a warning; that session leaves `auth.json` alone
  until Fuigo restarts, so an older stored login cannot take its place. A corrupt file is backed up and replaced, as
  before. If the auth file stays locked by another window, sign-in stops instead of keeping an unchecked login.
- **Token refreshes never overwrite another window's login.** A refresh that finishes after another window logged out,
  signed in again or switched account keeps its token in memory and leaves the stored login alone. This also covers
  the workspace server's refresh.
- **Sign-in screen starts fresh** after logout or a cancelled login.
- **One retry in rare cases.** With a 1.0.43 window open, or when a failed token refresh removes the stored login while
  a sign-in is open, that sign-in can report a change once; signing in again works.

## Startup, paste and headless

- **Faster startup when the Linux system bus is slow.** The power listener connects in the background; startup no longer
  waits for it. If it cannot connect within its deadline, power events are reported unavailable with one warning.
- **Faster startup when the terminal never answers the keyboard query.** The probe has one 200 ms deadline, then falls
  back to classic key handling.
- **Large pastes without bracketed paste no longer stall.** A 200 KB paste reaches the prompt in under a second instead
  of more than ten. A burst of 256 or more single-line key events arriving within 1 ms of each other is treated as one
  paste; a trailing Enter stays a key.
- **`fuigo -p --resume` needs an id or title.** An empty or missing value is refused up front; `--continue` resumes the
  most recent session.

## Display and input

- Narrow and wide terminals: the usage modal, dashboard (compact rows at 40-43 columns), dashboard peek, plan review
  buttons, pickers, list panes, numbered lists past 10, terminal titles and CLI tables fit by display width, including
  CJK and emoji, and use one ellipsis style.
- Failed web fetches show the real error when expanded; grep results expand tabs; open folds point down; empty pickers
  say what is empty.
- Copying a table keeps inline-code backticks; Shift+drag beside the scrollbar copies no scrollbar glyph (also with
  `NO_COLOR`); drag selection scrolls straight away at the pane edge; Up on the first line of a question's text answer
  returns to the options unless a dropdown is open.
- Legacy Windows consoles get plain fallbacks for the pending todo glyph and scrollback glyphs.
- The composer draft is kept when a queued row being edited disappears under an open question; labels say "1 hook",
  "1 page" and so on.
