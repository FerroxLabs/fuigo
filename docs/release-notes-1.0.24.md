# Fuigo 1.0.24 release notes

This release follows 1.0.23. It is a security and reliability release: permission and admin-policy rules hold in
more places, Fuigo works properly on Windows when several windows are open, and Fuigo sends far fewer requests when
an API key or sign-in has stopped working.

## Upgrading

- Run `npm install -g fuigo@latest`, or `fuigo update`. The Windows and macOS programs are signed as in 1.0.23.
- **Administrators of a managed fleet:** read "Admin policy changes" below before you roll this out. A broken or
  mistyped policy file now blocks instead of being skipped.

## Summary

- **Admins:** a broken, empty-list or mistyped admin policy now blocks instead of being skipped, and `$VAR` is no
  longer expanded in admin files. Read "Admin policy changes" before you roll this out to a managed fleet.
- **Users:** deny and ask rules now apply through symlinks. `grep`, `glob` and `list_dir` hide paths for deny rules
  only; hub reads judge deny and ask rules. A failed session load refuses input instead of leaving a half-open tab.
- **You may notice:** a branch switch after a write into `.git` (also in a linked worktree) asks again; `fuigo -p`
  exits 3 when a permission denial or a budget rule stops it (token budget, output-token budget, unknown usage,
  `FUIGO_MAX_MODEL_CALLS`, `FUIGO_MAX_RUNTIME_SECS`), exits 1 on a timeout or max-turns, and exits 4 when the
  open-file limit is under 64 or the runtime cannot start; a retried request no longer leaves a spinning search row; and
  session and config locks no longer stay held after a child process starts.
- **Windows:** two Fuigo windows no longer fail sign-in or token refresh because of each other's file locks, and a
  window only connects to a background process of the same user account (see "Windows fixes").
- **Fewer requests with a bad key:** after a rejected API key or sign-in, Fuigo no longer asks for the model list
  every minute, and it checks a key at most once an hour (see "Terminal messages" and "API key check").
- Small fixes: one retry hint, a visible "Your message was not sent" line, the package name in the update-check
  error, and owner-only modes for the crash directory and session index files.

## Admin policy changes

These apply only when an administrator has set managed policy (`/etc/fuigo/requirements.toml`,
`/etc/fuigo/managed_config.toml`, MDM, or the Claude `managed-settings.json`). Without managed policy nothing in this
section changes. Every change makes policy stricter or makes a broken policy block instead of being ignored, so
check these before you roll 1.0.24 out to a managed fleet.

1. **An empty allow list now means "allow nothing".** `allowedMcpServers: []` blocks every MCP server and
   `strictKnownMarketplaces: []` blocks every marketplace. 1.0.22 read an empty list as "no restriction". Remove the
   key if you want no restriction.
2. **A broken or writable admin policy file now locks down instead of being skipped.** If an admin policy file
   exists but does not parse, is not owned by root, or is writable by group or others, Fuigo blocks MCP servers and
   marketplaces, applies both pins, and (for requirements and MDM) makes no model selectable until the file is
   fixed. A broken policy file in the user's own `~/.fuigo` is still skipped with a warning.
3. **A `deniedMcpServers` entry that cannot be enforced fails the whole source closed.** 1.0.22 warned and skipped
   the entry.
4. **`strictKnownMarketplaces`: installs.** Local marketplace sources are dropped. A direct install from a URL that
   is not on the list, or from any local path, is refused. A plugin with no Fuigo install record (for example one
   imported from Claude) cannot be enabled.
5. **Managed-hooks-only: hooks in `~/.fuigo/managed_config.toml` do not run.** That file is user-writable, so it is
   not managed policy. Only hooks under `/etc/fuigo` run when `allow_managed_hooks_only` is set.
6. **`strictKnownMarketplaces`: loading.** Only plugins installed from an allowed source load, and only when
   enabled by their full plugin id. Project, user-directory, Claude-installed, `[plugins].paths`, `--plugin-dir` and
   session `pluginDirs` plugins do not load, so their hooks, MCP servers and skills are gone. Claude
   `enabledPlugins` is not merged. **An existing bare-name entry in `[plugins].enabled` no longer enables an
   allowed install: enable the plugin again and Fuigo writes its full id.**
7. **`[models] allowed_models` binds subagents.** Under a fleet pin, a subagent model outside the pin (from
   `[subagents.models]`, an agent definition, a goal or persona override, or an alias) inherits the parent's model.
   Resuming a subagent whose model the pin excludes is refused with the policy reason. A user-only
   `allowed_models` list does not bind subagents.
8. **In-process SDK MCP servers follow MCP policy.** Servers passed in `_meta["fuigo/mcp/servers"]` run only when
   no `serverName` deny matches and every restricted source allows them by `serverName`. Any MCP lockdown drops
   them.
9. **`[models] allowed_models` binds helper models.** Under a fleet pin, session titles, image description, the
   auto-mode classifier, prompt and shell suggestions, memory flush, memory-note rewrite, the laziness classifier
   and the goal evaluator send only a model the pin allows. When the configured helper model is not allowed they
   use the session's model, or skip the call. **Web search is turned off under a pin unless the pin allows the
   web-search model**; add that model to `allowed_models` to keep web search.
10. **`strictKnownMarketplaces` checks the checkout, not the install record.** A plugin loads, can be enabled and
    can be updated only if its checkout is inside the install directory (symlinks resolved, including the plugin's
    own sub-directory) and, for a git install, the checkout's `origin` is an allowed URL. A local copy with no git
    origin has no identity under this setting and does not load.
11. **A broken admin policy file never weakens enforcement.** The admin sources are the root-owned
    `/etc/fuigo/requirements.toml` and `managed_config.toml`, the MDM payload and the Claude `managed-settings.json`.
    When one is broken (does not parse, an invalid `[[version_overrides]]`, not owned by root,
    writable by group or others, or an MDM payload that does not decode; a key of the wrong type is the exception, see 12), Fuigo keeps enforcing the last valid policy
    for a running session, including after the file is deleted (all of its keys, such as the hooks pin and the Claude
    file's Bash denies, stay in force; a new valid file written afterwards replaces it) or caught empty while an editor
    or crash is rewriting it. Only a file that stays empty on a second look, from its owner, clears the policy. If it never saw a valid copy, it blocks every tool call
    and locks MCP servers, marketplaces and hooks, turns off the sandbox-relaxing and always-approve options, remote
    features, telemetry, memory, subagents and background loops, and allows no model, until the file is fixed. A
    repair is picked up by the next session without a restart. A requirements file in your own `~/.fuigo` that does
    not parse is skipped with a warning. One that parses but has a mistyped key (for example `web_fetch = "no"`
    under `[features]`) is refused with a message naming the file and the key and how to fix it; if it becomes
    mistyped during a session, Fuigo keeps the last valid copy of that file, or blocks every tool call if it had none.
    An admin file is trusted only if it is a regular file owned by root and not writable by group or others, and the
    directory that holds it (for example `/etc/fuigo`, also when reached through a root-owned symlink) is owned by root
    and not writable by group or others. A device, pipe, directory or dangling link put in its place, or a writable
    `/etc/fuigo`, counts as a broken file, never as "no policy". The message names the file, the owner and mode found, and
    says to ask your administrator. Known limit: on
    NFS with root-squash the root-deployed file shows an unmapped owner and is treated as untrusted; deploy admin
    policy on a local file system or through MDM.
12. **A running session locks down, and keeps running, when a new version of an admin policy file has a setting
    of the wrong type.** A new session with a broken admin file refuses to start ("refusing to start without its
    policy"). For `requirements.toml`, `managed_config.toml` and the Claude `managed-settings.json`, a new
    version that parses but has a pinned setting of the wrong type (for example a yes/no setting written as `"yes"` or
    `1`; in `managed-settings.json` also `null`) no longer leaves the session on the old copy with the file's other new rules dropped. Every tool is
    blocked, and at its next turn the session shows one message naming the file and the setting
    (once per broken version, in each session). When the file is fixed the session says so once and the lock-down
    lifts by itself, with no restart. If the next version is instead emptied, the session says the file is now empty and sets no policy; if it is unparseable or the file is removed, the session says the
    lock-down has ended and the last valid policy is in force again, and says once when the file is valid again (also after the "now empty" message). A file that is half-written, unparseable, missing, or not owned by root is
    still handled as described in 11 (the old copy stays; a file that stays empty clears the policy). In the two TOML files a `null` value does not parse, so the last valid copy stays. A running session also says so when an admin file is broken and no earlier valid version is held, in which case all tools are denied until it is fixed.
    The session checks the admin files at the start of each turn, with a 200 ms limit. If an admin path is slow to
    answer, the notice waits for a later turn; the lock-down itself is not delayed.
13. **Environment variables are no longer expanded in admin policy files.** `$VAR` and `${VAR}` in
    `requirements.toml`, `managed_config.toml`, the Claude `managed-settings.json` and the MDM payload are used
    literally. For `requirements.toml` and `managed_config.toml`, Fuigo warns once per file and key; the MDM payload and
    `managed-settings.json` are used literally without a warning. Replace any variable with its value before you roll out 1.0.24.

Known limit: a user who can write both the plugin install directory and its `registry.json` can still place a
checkout whose `origin` names an allowed repository. Closing that needs an install ledger the user cannot write.

## Permissions

### Shell command permissions

- **A write into `.git` before a branch switch keeps the prompt (P175).** A command line that writes into the
  repository's `.git` directory in a way Fuigo can see (`cp`, `mv`, a redirect, `tee`, `install`, `ln`) and then
  switches branch (for example
  `cp x .git/refs/heads/main && git checkout main`) now keeps the protected-file prompt for the switch, because the
  switch can no longer be judged against the tree Fuigo read beforehand. Command lines that do not write into `.git`
  (for example `npm test && git checkout main`) are unchanged. A script that rewrites refs without naming `.git` does
  not keep the prompt.
- **Linked worktrees and submodules count as `.git` (P175).** When `.git` is a file that points to the git directory
  (a linked worktree or a submodule), Fuigo follows one `gitdir:` line and that directory's `commondir`, so the same prompt applies.
  A symlinked `commondir` is followed, and a git directory whose `HEAD` is a symlink counts. A chain of pointer files
  is not followed.
- **More branch-switch cases keep the prompt (P175).** A switch keeps the prompt when an earlier git command on the
  same line can move refs (for example `fetch` or `commit`), when the tree is over the 16 MiB or 2 s check cap, when the
  whole check takes more than 8 s, or when the check cannot settle a ref name. The check never starts a lazy fetch.

### Rules written through a symlink

- **Deny and ask rules apply to the real path too (P175).** A rule with an absolute path through a symlinked
  directory (for example `Deny(Read(/tmp/secrets/**))` where `/tmp` links to `/private/tmp`) now also applies to the
  physical spelling of the same file, also when the file does not exist yet. A link retargeted later is judged on the
  next check. Allow rules are not widened. An absolute deny or ask rule whose path has `..` or `//` now also matches in its
  resolved form, when that path resolves. A missing file still matches.

### Read rules

- **Hub-routed reads and `list_dir` honour read rules (P198).** Hub-routed reads judge the spelled
  path, the symlink target, and a unique sibling file whose name differs only by U+00A0 or U+202F, within 5 s.
  `image_edit`, `image_to_video` and `reference_to_video` judge the spelled path and its symlink target only.
  `image_gen` opens no local file. `list_dir` omits names under a denied path. It hides the directory itself only for
  a total rule (`dir/**` or `dir/**/*`), not for `dir/*`.
- **`grep` and `glob` honour read rules (P198).** With a read rule present, `grep` and `glob` no longer return lines,
  names or counts from a denied path (also through a symlinked directory or a different-case spelling), and never show
  ripgrep's file-error text. An invalid pattern still shows ripgrep's own pattern error in `grep`; `glob` shows "No
  files found".
- **Read rules written through a symlink also hide results.** `list_dir`, `grep` and `glob` hide results under the
  physical path of a file hidden by an absolute deny rule spelled through a link. Fuigo adds the physical path only if
  resolving finishes inside one 250 ms budget for the whole filter; after that, or while a resolver is stuck, the
  remaining rules are not matched by their physical path.

## Sessions and reliability

- **Session and config file locks are released reliably.** The rewind, snapshot, fork-copy, history-append, sweep,
  live-mark and config-write locks used to be released only by closing the file. If another thread started a child
  process at that moment, the child kept a copy of the file and the lock stayed held after Fuigo let go. For rewind
  this meant recovery after a kill in the middle of a rewind was skipped until a later load, and a new rewind could be
  refused for a short time. Nothing on disk was damaged. The locks are now unlocked explicitly first.
- **Replacing an old background process has a time limit.** When a newer Fuigo starts and an older Fuigo background
  process (the leader) holds the lock, the new one asks it to restart or exit. If the old one never does, Fuigo used to
  wait for ever. It now stops after 30 seconds with: "could not replace the old Fuigo leader ... Close the other Fuigo
  windows and try again."
- **A session is never merged into a folder that took its place.** The clean-up of old sessions moves a session aside
  and, if it turns out to be still needed, puts it back without replacing anything. On a file system that cannot do that
  in one step, Fuigo used to fall back to a plain move, which could replace an empty folder created in the meantime. It
  now leaves the session where it is, under `.fuigo-sweep-kept-<session>-<pid>` in the sessions folder, intact, and
  writes a warning to the log. Such a session is not listed until you move it back by hand. Linux ext4 and macOS APFS
  are not affected.
- **A session that failed to open refuses input (P193).** When a session load or a remote restore fails, the tab shows
  "Couldn't load session: ..." and refuses prompts, `!`
  commands, `/btw` and queued slash commands. When you try to send, the refusal reads
  "This session didn't open. Open it again with /resume, or start a new one with /new." (a toast; in `--minimal`, a
  line in the scrollback). A failed reconnect prints that sentence in the transcript at once. Text typed while the load was running is returned to the composer or
  listed as not sent, once. On success it is sent once, in order. A slow `/resume` that fails after a reconnect no
  longer breaks the reconnected tab. After a failed reconnect the tab is unbound and refused; the transcript stays and
  `/resume` reopens it.
- **A busy agent no longer starves the screen timers (P196).** Recovery, scroll, deferred redraw, resize and status
  line timers keep running while many agent messages arrive. A cancel-resend or a turn-end reconcile waits until the
  messages buffered when it came due have been handled.
- **A retried request no longer leaves a spinning row (P201).** After a failed request that is retried, a hosted
  `web_search`, `x_search` or `code_interpreter` row no longer spins forever and is not shown twice. The terminal scrollback still keeps the failed row beside the retry.
- **MCP.** `--minimal` shows the MCP elicitation card; a declined, dismissed, timed-out or superseded request leaves a
  notice naming the server. `/mcps` shows "Sign-in needed, refresh refused: <reason>" ("sign-in needed, refresh
  refused: <reason>" in `--minimal`). A token endpoint that redirects a request that carries credentials is refused for
  the life of that OAuth client. The `/mcps` reason is dropped when a later token request for that server succeeds. A dropped or timed-out MCP tool call sends one
  `notifications/cancelled` to the server (best effort, 3 s). A stdio server that stops reading is closed and stays
  closed until restart. A symlinked MCP stderr log is no longer archived.
- **Archived logs are trimmed (P194).** The per-turn archive keeps each terminal or MCP stderr log whole up to 1 MiB; a longer log is cut to its
  first and last 512 KiB around a marker. It keeps at most 16 MiB of terminal logs per archive.
- **Compaction sends the session's reasoning effort (P194).** On all three backends. Cost and the summary can change.

- **The background process only talks to windows of the same user account (macOS and Linux).** Its local socket is now
  private to your account, and both sides check who is on the other end before anything is sent. A Fuigo started
  with `sudo`, or as another user, no longer joins your background process; it says that a Fuigo it cannot confirm
  as yours is already running.

### Headless mode (`fuigo -p`)

- **Budget and call-limit exits are typed (P195).** A goal whose completing answer spends `--budget` exits 3 with the
  `execution_token_budget_exhausted` denial (it exited 0) and the answer is kept in every output format. A
  completion-requirement retry past the call limit exits 3 with the call-limit denial (it exited 1). A `/btw` side
  question refused by the call counter or the runtime clock returns the typed `execution_model_call_limit` or `execution_runtime_limit`
  denial. The same completing answer that spends `--budget` in an interactive session is still a success, and the goal
  stops budget-limited.
- **Low open-file limit.** An open-file limit under 64, after Fuigo raised it, prints one line to stderr and exits 4
  before anything starts, also for `login`, `models` and `logout`. `--version` and `doctor` are not affected.
- **Thinking blocks stay separate.** The headless transcript keeps consecutive thinking blocks apart, each with its own
  signature, and keeps `redacted_thinking` blocks in place.

## Terminal messages

- **One retry hint, not two.** When a message is lost to a leader restart, the error now says "Try again." once instead of adding "Try sending again." after it.
- **A queued message that fails is no longer dropped silently.** If sending it fails because the leader restarted or the connection was lost, a line says "A queued message may not have been sent". For any other failure, a line says "Your message was not sent", gives the reason and repeats the message text (indented). The text is filtered like other outside text, and at most 20 lines show, then "… (N more lines)".
- **A rejected API key or sign-in no longer makes Fuigo ask for the model list every minute.** After the API answers 401, Fuigo says once that you need to sign in again (or check your API key) and then retries rarely: after 1, 2, 4, 8, 16 and then every 30 minutes, starting over as soon as the key or sign-in changes or a request succeeds (signing in again, also from another window, makes Fuigo try at once). This also holds when Fuigo is started again: a new Fuigo process started inside the wait sends nothing to the model list. In a test that starts Fuigo once every 65 seconds for an hour with a rejected key (56 starts), the requests to the model list drop from 112 to 6, and the key check from 56 to 1; with 6 real starts the model-list requests drop from 12 to 3.
- **Middle-click paste on Linux (X11) picks the right helper.** Fuigo chose between `xclip` and `xsel` in a way that
  could report the primary selection as unavailable when `xclip` was installed. It now chooses by the tool's name.

## Plugins

- **`fuigo inspect` shows a disabled plugin as disabled (W3-E).** A trusted plugin that `[plugins].disabled` turns off
  was listed as enabled; the display only. The plugin was never loaded. The listing also honours a plugin disabled only in a project `.fuigo/config.toml`, and a disabled plugin no longer shows hook or LSP rows.

## Updates

- **The update-check error names the package.** When `fuigo update` cannot read the version from npm, the message now
  reads `npm view fuigo@<tag> failed: ...` instead of `npm view @<tag> failed: ...`.

## File permissions

The crash directory, the active-sessions lock and index, and the managed-config lock are now readable only by you (directory 0700, files 0600 on Linux and macOS). Older, wider-mode copies are tightened as follows. The crash directory is tightened to 0700 when it is a directory you own; a symlink is not followed. The active-sessions lock and the managed-config lock are tightened on open only when the opened file is a regular file you own and the path is that same file. The active-sessions index becomes 0600 the next time it is written. Windows access rules are unchanged.

## Windows fixes

Found by running the test suite on Windows itself for this release.

- **Two Fuigo processes no longer trip over each other's file locks.** A file lock held by another Fuigo process was
  treated as an error on Windows. Sign-in or a token refresh could fail at once where it should wait; the same for the
  first-run plugin marketplace setup, the plugin cache and the list of active sessions. They now wait, as on macOS and
  Linux.
- **Replacing an old background process is safe and works.** On Windows the new process could not read which process
  held the lock. It now asks Windows which process serves the connection, checks that it is a Fuigo program, and only
  then stops it.
- **Session file check.** The check that an opened session file is the expected one compares names exactly, with the
  Windows rule for upper and lower case.
- **The background process only talks to windows of the same user account.** On a computer shared by several accounts, a Fuigo window now connects only to a background process that belongs to the same account, and says so when it does not.

## API key check

Fuigo now checks an API key against the server's key-information route at most once an hour per key, and no longer asks at every start. When a server answers that the route does not exist (404 or 405), Fuigo does not ask that server again for 24 hours. The remembered answers are kept in `api-key-probe-state.json` in the Fuigo home folder (readable only by you; it holds hashes, never your key or the server address).

## Known limits

These are limits of earlier work that stand in this release.

- **Sandbox, when Fuigo runs as root (P177).** A sandboxed command can still write a protected file in your home
  through `/proc/<pid>/root` of another root process that holds no capabilities and runs outside the sandbox. The
  init process is not reachable this way. This does not affect Fuigo run as an ordinary user. This limit stands in
  this release: do not run Fuigo as root next to capability-less root services.
- **Branch switch after a script that moves refs (P175).** Fuigo sees a write into `.git` only when the command line
  names it (`cp`, `mv`, a redirect, `tee`, `install`, `ln`, or an option that names a write path in a command whose
  options Fuigo knows, such as `rsync --log-file`). A script or tool that rewrites refs itself and is followed
  by a branch switch in the same command line is not detected. That remains; it is not closed by any sandbox for a
  default install. A
  symlink created on the same command line to a different repository's `.git`, then used as `git -C link`, is also
  not seen, because the link does not exist yet when the switch is judged.
  Also not seen: a symlink into `.git` created on the same command line by anything other than `ln` (for example
  `cp -s` or a script); a chain of `.git` pointer files (a pointer file that names a
  directory that is itself a pointer); and a write whose target the command line only reveals at run time (a variable, a
  command substitution, a glob). The write check does not resolve `GIT_DIR` or `GIT_COMMON_DIR`; a command that
  assigns either is prompted as a risky command. The write-destination analysis does not model every option of every write command
  (for example rsync's `--log-file`); per-command option tables are not in this release.
  One extra prompt, by design: `ln -s .git mylink && git checkout main` keeps the prompt even though nothing is
  written through the link.
- **Search output under read rules (P198).** When a `Deny(Read(...))` rule is present, a matching line longer than 1000
  bytes is cut at 1000 bytes; without read rules it is cut at 1000 characters. Lines in non-ASCII text can therefore be
  shown shorter under read rules. In tools that do not sort results themselves, files can also be listed in a different
  order than without read rules. The content, names and counts shown for files you may read are otherwise the same.
- **Notices that include an outside value with a line break (P181 follow-up).** Fuigo removes escape and control
  characters from outside text before it reaches the terminal. A filtered outside field has its line breaks replaced
  by spaces. Whole-line notices keep line breaks, so an outside value inside such a notice can still start a new row
  that looks as if Fuigo wrote it. Known cases: a
  configuration key or file name in a configuration notice; a session path or error text in a history-repair or
  rewind notice; text in the result of some slash commands; prompts shown from a shared queue. Read a notice row
  that asks you to do something (for example to paste a key or run a command) with that in mind. The values are
  still filtered for escape sequences.

Limits found by this release's own work and not closed:

- **Rule paths on a hung mount.** A deny or ask rule whose path starts on a hung or very slow mount can stall the
  permission check for as long as the mount stalls. For searches the wait is capped: with an absolute read-deny rule,
  a search has one 250 ms budget for every read-deny rule with a literal directory prefix, then skips the link
  spelling of the remaining rules.
- **Branch switch after a `git pull` or a merge with rerere.** The check judges the upstream as it was before the
  fetch; merge and rebase with rerere are not modelled.
- **Read rules do not cover everything yet.** Ask rules are not applied to `grep`, `glob` and `list_dir`
  (deny rules are). Hub `memory_get`, `lsp` and workflow-script reads are judged in one spelling of the path only.
- **Admin-policy notices.** The notice appears at the next turn, not at once. A hung admin path can delay the notice
  until a later turn; the turn waits at most 200 ms.
- **Retried requests.** A hosted search or code row whose request finished before the attempt failed is still kept in
  history; a hosted row of a request that fails with no retry, or is cancelled, can stay in progress. The terminal
  keeps the failed row in its scrollback.
- **Stopped-reading MCP servers.** A stdio MCP server that stops reading is closed after a cancel write times out and
  stays closed until restart. A call made in the instant after a timeout can still wait on a dead server.
- **Held input after a failed load.** A `/btw` typed after other text with an image first can be stored mangled; a
  held side question is sent as soon as the session is open, without waiting for a running turn; with two held side questions in `--minimal`, the first answer is
  dropped; a load that dies without a result leaves the tab "loading".
- **Timers under heavy output.** A completion that arrives after the cancel recovery has started can still lose the race, as before
  this release.
- **Headless budget result.** In `json` output after a budget stop, `requestId` is `""` only when the answer had already completed;
  otherwise the document is `{"type":"error",...}` with no `requestId` field.
- **Standalone workspace server: diagnostics socket in `/tmp`.** The separate `fuigo-workspace-server` program, which
  is not part of the npm package, opens its diagnostics socket at `/tmp/workspace-server.sock` by default. On a
  computer shared with other users, start it with `--diag-socket` set to a path in a folder only you can open.
- **Headless runs and MCP servers that fail to start.** In a headless run, an MCP server that fails to start is not
  reported; run `fuigo mcp doctor`.

### On Windows

- **Shell-command path completion is off.** Completing file paths while typing a shell command is disabled on
  Windows on purpose, because the completion quotes paths the POSIX way. `@` file mentions are not affected.
- **Peak memory is reported as 0.** The peak-memory figure in session telemetry is always 0 on Windows.
- **Stale staging directories are not cleaned up.** The check that a config writer has died exists on macOS and Linux
  only, so a staging directory left by a crashed writer stays until you remove it. Windows never takes over another
  writer's lock.
- **The holder of the sign-in lock is not named.** While another Fuigo process holds the sign-in lock, messages on
  Windows cannot say which process it is.
- **Stale background-process entries stay listed.** After a Fuigo background process is killed on Windows, its lock file
  stays and it is still shown as stale in the list of background processes. It does no harm: a start that needs that
  same lock file takes it over, and the other stale entries are ignored by a normal start.
