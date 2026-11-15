# Fuigo 1.0.45 release notes

## Folder trust and consent

- **A nested repository no longer borrows its parent's trust.** A folder whose own git metadata points at a trusted
  ancestor (through `core.worktree`) is asked about like any other folder instead of being treated as trusted with no
  question. The same holds for the folder a session works in when a `core.worktree` ancestor has no `.git`.
- **Task children are judged in the folder they were launched from.** A subagent started with a `cwd` is checked
  against its parent's launch folder as well, so it cannot move a session from an untrusted folder under a trusted
  folder's shell rules. A relative `cwd` is resolved against the parent's `cwd`, not the process's.
- **No git status scans in untrusted folders.** The in-process change tracker waits for the folder-trust decision, so a
  repository-configured content filter cannot run before you have answered.
- **No language servers in untrusted folders.** User- and plugin-configured language servers start only after the
  folder is trusted.

## MCP servers and plugins

- **Untrusted folders cannot start MCP servers under a different name.** A project server whose name needed
  sanitising, or that was forwarded under a renamed copy, is now dropped in an untrusted folder like any other project
  server.
- **Project plugin settings in an untrusted folder cannot touch your plugins.** A project's `[plugins].disabled` no
  longer switches off your own plugins, and a project plugin with the same name no longer displaces yours.
- **Marketplace plugins do not refresh themselves at startup.** The spawn-time local refresh skips installs that came
  from the marketplace cache, so a plugin changes only through an update command.
- **Bounded `tools/list` pagination.** A server that returns endless pages, endless tools or a repeating cursor stops
  at a fixed cap instead of looping.

## Sandbox

- **Custom sandbox profiles work in the workspace server.** The workspace server resolves your custom profiles the
  same way the main binary does instead of replacing them with `workspace` and possibly continuing unsandboxed.
- **A bad `[sandbox]` field is reported.** `sandbox.profile` is read on its own, and a type error in another
  `[sandbox]` field prints a message on stderr instead of silently turning the sandbox off.
- **Project profiles in untrusted folders are ignored, and built-in names ignore letter case.** A project
  `sandbox.toml` in an untrusted folder cannot select the profile, and `Minimal` or `STRICT` are treated as the
  built-in names.
- **The workspace `.mcp.json` and imported MCP config files are protected** from sandboxed writes under `enforce`.
- **Missing protected entries are denied in every letter case on macOS**, not only the spelling you wrote.

## Editing and files

- **Edit tools never follow a look-alike filename.** A file name that only resembles an existing one (for example with
  look-alike Unicode characters) is no longer silently redirected onto a symlink or another file.
- **Non-UTF-8 files are no longer corrupted.** `apply_patch` and the other edit tools refuse to
  rewrite a non-UTF-8 file. Deleting such a file still works, reported without a snapshot.
- **`apply_patch` is safer with moves and adds.** A Move onto the same file updates it in place instead of deleting
  it, and Add and Move report the destination's prior state.
- **Rewind restores the right content.** `write` and `search_replace` report the true prior state of the file, so a
  rewind brings back what was there.
- **PPTX reads are bounded.** Extraction has a total decompressed-size budget and a slide cap.

## web_fetch

- **Hostile pages no longer hang or crash a fetch.** Converting a page to text is bounded in time and memory: deeply
  nested markup, huge attribute counts, quadratic inline merges, long runs of newlines and nested tables are handled
  within fixed limits, and a page that would cost too much falls back to plain text.
- **Tables render without padding, with correct headers.** Header rows come from the table head, cells are
  normalised, and captions are not pipe-escaped.

## Sign-in and sharing

- **A huge `expires_in` or `interval` no longer aborts.** A token response with an oversized value no longer stops
  sign-in or refresh.
- **Logout reports a real error.** When the stored login cannot be read, `fuigo logout` says so and keeps the file
  instead of reporting that there was nothing to log out of.
- **Saved API key helpers follow `FUIGO_AUTH_PATH`.**
- **Shared sessions are scrubbed before upload.** The session body sent to the share backend gets the same secret
  scrub as the copy kept in storage.

## Terminal, links and media

- **File links reveal launcher-type and executable files** instead of opening them, so a modifier-click on a path in
  repository content cannot run it.
- **Network-share paths are not probed.** Paths found in model or tool text are never stat'ed or read when they name a
  network share.
- **Image reads are capped.** Inline images over the size cap are skipped and remembered as too large, and `ffmpeg`,
  `ffprobe` and `sips` calls have time limits.
- **`fuigo wrap`:** one host-image read at a time, at most one per interval, with a bounded write queue.
- **Image paste through `fuigo wrap` over SSH:** a new local `fuigo wrap` now authenticates image-paste requests with a
  per-session nonce, so pasting an image into an older `fuigo` on the remote side no longer works until that remote is
  updated. Commands Fuigo runs no longer inherit the nonce.
- **Permission cards opened while you type hold the next Enter and digit,** so a keystroke meant for the composer does
  not answer the card.

## Release, update and serving

- **`agent serve` warns on a non-loopback address.** Binding beyond loopback over plain `ws://` prints a loud warning.
- **Updater temp file is private.** The temporary `.npmrc` is created exclusively, mode 0600, in an owner-only
  directory.
- **Install scan skips empty and relative `PATH` entries,** so `fuigo --version` is not run from the current folder.
- **Release workflow is stricter.** A real publish is refused off a tag or without macOS signing, and the in-tree
  leftover upstream install scripts, which downloaded from hosts Fuigo does not control, are removed with their README
  line.

## Campaigns

- **Campaign patches cannot move trusted API origins.** The session bearer and `FUIGO_API_KEY` stay with the origins
  you configured.
- **Campaign patches cannot set where a model connects or what it sends.** Hosts, headers, query parameters, providers
  and keys of every model stay the ones you configured.
- **Campaign-added MCP servers are untrusted and carry no secrets:** no saved-key references, and no environment,
  header or OAuth secret fields.
- **Stored MCP tokens survive a damaged or unreadable `mcp_credentials.json`.** A file that cannot be read is left
  alone and the save fails; a damaged one is copied aside first. Every write, including removing a server, is locked
  on every platform.
- **Campaign patches cannot set execution policy or where data and code come from.** `[sandbox]`, web fetch local
  access and proxy, the shell environment policy and command prefix, the hub, telemetry destinations and exporters,
  web search routing, session trace upload and the telemetry switch it follows, the agent definition and agent
  name, which plugins are enabled, whether language servers start, which MCP servers you disabled, subagent role
  and persona files, and the sources of updates, plugins, skills and rules stay as you configured them. Campaign
  values are never expanded from environment variables. Administrators set these in their own managed or
  requirements layer, not inside a campaign.
- **Campaigns can now set only what campaign features use.** A campaign can set the default model and the helper
  models (a nudge your own `/model` pick always overrides), a model's display name and context window, add new
  MCP servers (without secrets), and turn managed MCP servers off. Everything else in a campaign is ignored, and
  Fuigo shows a note naming the settings it ignored.

- **Campaign model nudges cannot reach your own endpoints or keys.** A campaign may name a catalog model or one with
  no route of its own, not only a built-in one. It cannot point the default, image-description or
  session-summary model at a model whose endpoint, provider or credential your own configuration sets; such a setting
  is ignored with a note. A context window outside 1,024 to 10,000,000 is ignored, and a change to a helper model is
  announced once.
- **A program-running MCP server added by a campaign waits for you.** It is listed as off until you turn it on in
  `/mcp` or with `fuigo mcp enable <name>`, and if the campaign later changes its program, arguments, folder or the setup choice that picks the program, it needs
  your approval again. This wait covers program-running (stdio) servers only: a campaign HTTP server does not wait
  for approval, and your own servers are unchanged.
- **Campaign notices are cleaned and capped,** name only the sub-settings that were ignored, and show the program a
  campaign MCP server would run.

## More fixes

### Shell and tools
- When a model sends several JSON objects in one tool call, Fuigo runs the one that fits the tool.
- Output a command prints after it exits or is stopped no longer grows memory or the log file without limit; the
  short drain after a background task exits keeps at most 8 MiB.
- Two shell calls that share one call id no longer share a log file or overwrite each other's background task.
- In the persistent shell, programs a command starts (bash 4+ and zsh) can no longer write to the channel Fuigo uses
  to save shell state. Two limits remain by design: builtins running in the same shell can still write to it, and
  bash 3.2 (the stock macOS `/bin/bash`) hands the saved copy of the channel to the programs it starts.
- The login start-up capture runs in your home directory in untrusted folders; trusted folders behave as before.
- Hook command output is read with a running size cap.
- The internal `use_tool` bridge reaches only MCP tools.
- With the persistent shell and sandbox auto-allow both on, a command the shell would start in an untrusted folder
  asks for approval instead of being auto-approved.

### Files and sessions
- Writing to a pipe with no reader, or one whose reader stopped, gives up with an error instead of hanging.
- The edit tools refuse files over 256 MB instead of loading them whole; the `write` tool overwrites such a file with
  a warning that no rewind snapshot is kept.
- Editing a file with mixed CRLF/LF line endings keeps the endings of the lines you did not edit. On very large files
  the restore step stops refining after 2 seconds, and past that point the preservation is approximate: a replaced
  span can change the endings of untouched lines inside it.
- `apply_patch` creates destination folders first, removes the ones it created if the patch fails, lists applied and
  not-applied files when a write fails midway, and is serialised per file with single-file edits.
- Session files refuse a symlink, special file or named pipe planted at their name; a lasting session-lock error is
  retried a limited number of times, and a passing one no longer turns the cross-window lock off.
- Turn completion flushes chat history to disk; resuming after an interrupted compaction removes invalid images.
- Startup and opening a session no longer hang when another Fuigo process holds the active-sessions lock.
- Goal mode no longer follows links or hangs on special files when inlining skeptic reports.

### MCP servers, plugins and agents
- A damaged saved MCP sign-in file shows a notice, only the newest two backups are kept, and an unreadable file is
  reported as an error naming the file instead of looking like "not signed in". A removed server whose sign-in cannot
  be deleted gets a warning.
- Fuigo warns, in the session notices too, when an MCP server you gave "always allow" is later defined with a
  different command or URL under the same name. The grant still works. Fresh ports in a server's arguments do not
  count as a change.
- Plugin and marketplace git calls use only https, http, ssh, git and file transports; unknown URL schemes are
  refused, and an `ext::` source never starts its helper.
- Plugin install keys use SHA-256, so a toolchain change cannot make an installed plugin look missing; existing
  installs keep working. `plugin update` asks git whether a ref is a tag or a branch.
- A bare name in `enabled` no longer lets a repository's same-named project plugin replace yours; use the full id to
  enable the project one.
- A local plugin edited without changing its file length is picked up at session start.
- An agent file that runs with `permissionMode: bypassPermissions` while your session asks for approval shows a
  one-time notice.
- The subagent bundle download is capped at 64 MB and written atomically, never through a symlink. A bundle-folder
  workflow that replaces a built-in one and is not the unedited copy prints a one-time warning.
- `/import-claude` imports per-project MCP servers as project servers.

### Sandbox and display
- Linux: the bwrap launcher is taken from `/usr/bin`, `/bin` or `/usr/local/bin` before `PATH`, so a stray `bwrap`
  earlier on `PATH` is not used.
- macOS: a deny path that does not exist yet also denies everything under it if it is later created as a folder, and
  the terminal-device rules match only whole `/dev/ttysNNN` names.
- A saved deny rule whose folder was later replaced by a symlink is kept.
- Escape bytes, bidi overrides and invisible fillers in denied command output, permission cards, the pattern editor
  and the folder-trust question are shown escaped or removed; the trust question shortens long paths from the left.
- `fuigo wrap` clipboard-image requests carry a per-session secret, and the reply no longer ends with Enter.

### Network and web_fetch
- web_fetch checks the address it actually connects to, including for requests that bypass a proxy, and blocks more
  IPv6 forms that hide private addresses (NAT64, 6to4, Teredo, IPv4-compatible, site-local). A host reached directly
  through `NO_PROXY` is now held to the same private-address rule unless local access is allowed.
- A web_fetch pre-approved for one path does not follow a redirect to another path on that site without asking;
  redirect hosts are compared without regard to case.
- The command network proxy no longer cuts off slow downloads, holds a slot forever for a client that stops reading,
  keeps dead tunnels open, or stops on a transient accept error; it also listens on IPv6 loopback and starts on IPv4
  alone if that port is taken.
- Signed-URL uploads and downloads use https on a storage host, refuse a private address at connection time, look
  each host up once per upload, and work behind a proxy that resolves the host for them.
- The diagnostics server's `/logs` endpoint refuses a Host header that is not a loopback name.

### Sign-in and credentials
- The browser sign-in callback ignores any request without the correct state value; a provider error sent without a
  state is shown and ends the wait. A pasted callback URL must include its state.
- Clearing a saved API key reports an error, and keeps the key, when the login file cannot be read or deleted; logout
  removes leftover corrupt backups and temp copies and says when a saved API key is still stored.
- The login file's temporary copy is created exclusively, never through a symlink, and is never published with loose
  permissions; on Windows the old file is no longer deleted before the new one is saved.
- Session sign-in is never sent to `localhost.`, `*.localhost`, `0.0.0.0` or `::`; sign-in discovery checks the
  issuer and requires https endpoints.
- A model stream that never ends is cut off at 256 MiB with an error.
- Credentials are scrubbed from logs, uploads and error reports in more forms: env-style names, JSON-quoted keys,
  Basic headers, more vendor token formats, and the exact values of OAuth tokens, MCP header values, the agent serve
  secret, the relay bearer and the hub session token. Code such as `GITHUB_TOKEN=$GITHUB_TOKEN` or
  `auth_token: Option<String>` is no longer mistaken for a secret.
- Feedback and diagnostic logs are created owner-only. Crash reporting does not follow planted symlinks, discards
  malformed crash files, and trace sampling is off.
- The auto-generated `agent serve` secret is 128 bits, failed handshakes wait 250 ms, and the help text recommends
  `FUIGO_AGENT_SECRET` over `--secret`. Agent serve and the leader no longer queue unlimited messages from one fast
  peer. A request refused because the queue is full now gets `-32003` "Rate limited" with
  `data.error_kind: "busy"` and a `data.message` (it was `-32000`, the sign-in code, with a bare string), so a client
  that maps errors by code no longer reads it as a sign-in failure.

### Managed policy
- An older signed policy cannot be replayed over a newer one for the same deployment or team (needs the server to
  send a revision); switching to another deployment with lower revisions is accepted, and two processes applying
  policy at once cannot leave a good policy flagged as rolled back.

### Update and npm
- The npm launcher cleans up old binaries the way the updater does (skipping fresh, linked and in-use ones), checks
  them with one short `lsof` call on macOS, and no longer runs npm through a shell or triggers DEP0190 on Windows.
- `gh` and `node` are found only on absolute `PATH` entries; a missing one is reported as missing.
- A copy with no update source says how to update. Symlinked shell completions inside your home folder are refreshed
  through the link; others get a one-time notice. The version cache uses a unique temp file, and the Windows
  "current copy" check compares contents.
- Internal: release workflow actions are pinned to reviewed commits, the release build restores no cache, the
  published packages' signatures are checked before the GitHub release, the release layout checks macOS and Windows
  signatures, and RELEASE.md describes the signing, checksum and per-binary digest pipeline.
