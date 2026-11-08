# Fuigo 1.0.41 release notes

## Folder trust

- **Trusting a folder mid-session now reloads the session.** After you trust a folder, the session loads that folder's
  hooks, plugins and MCP servers. MCP servers whose settings did not change keep running.
- **`/trust` opens the trust screens in the full-screen app.** **This folder** shows the session folder, its trust key
  and whether it is trusted: `t` trusts it and `u` stops trusting it. **Trusted folders** (`Tab`) lists every folder
  you trusted, and `u` stops trusting the selected one. Each change asks you to confirm.
- **A resumed or forked session asks about its own folder.** The trust question now names the folder the session was
  recorded in, not the folder you launched from.

## Sessions

- **`--no-session-persistence` keeps a headless run off disk.** Nothing is saved under `~/.fuigo/sessions`: no session
  folder, prompt history or search index entry. The JSON output still names a session ID, but it cannot be resumed.
  Combined with `--resume` or `--continue` it exits 2. An interactive session warns and is saved as usual.
- **One process at a time writes a session.** Deleting, renaming or copying a session that is open in another window
  is refused with a clear message instead of racing the other process.
- **`/delete` starts on Cancel.** Pressing Enter once no longer deletes a session.
- **A headless `--resume` that fails says why.** With JSON output, it prints one JSON error that gives the reason.

## Hooks

- **`SessionEnd` command hooks run when a session closes.** The end reason is available to the hook's matcher.
- **Project hooks can be disabled per repository.** A new disable applies only to the repository you set it in. A
  disable saved by an earlier version keeps applying everywhere, as before. Enabling the hook in a repository removes
  both.

## Permissions

- **A permission file that does not load is reported at session start.** If a `.claude` settings file (yours, or a
  trusted project's) exists but cannot be read or is not valid JSON, Fuigo names the file and says its rules did not
  load. Rules that do not parse are listed by file. The session still opens, and every rule that did load applies.

## Startup

- **A non-UTF-8 argument no longer crashes startup.** This includes a non-UTF-8 `--cwd` path and the Linux sandbox
  re-launch.
