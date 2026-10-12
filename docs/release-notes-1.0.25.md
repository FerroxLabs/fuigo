# Fuigo 1.0.25 release notes

This release follows 1.0.24. Its headline is named sessions that work together: Fuigo sessions on one machine, under one user account, can list each other and send each other messages, on Linux, macOS and Windows. The feature is off by default; see Named sessions below. The release also tightens admin policy for prompts you did not type, lets host applications park an idle session, warns when an MCP server fails to start in a headless run, and makes a same-version npm reinstall replace a changed binary.

## Headless

- A headless run (`fuigo -p`) now prints one line on stderr for each MCP server that failed to start: ``warning: MCP server "<name>" failed to start: <reason>. Run `fuigo mcp doctor`.`` The reason is one of a fixed set, chosen from the kind of failure and never from the server's own error text: "the command could not be started", "the server exited before it answered", "the server did not answer within N s" (N is the start-up timeout), "the server could not be reached", "the server rejected the connection (it may need sign-in)", or "the start-up handshake failed". With `--output-format streaming-json` the event is a `config_notice` line whose `message` carries the same text without the `warning:` prefix. Each server is reported once per run. Servers that are known to need sign-in (an OAuth-configured server, or a server that answered with an HTTP 401 or 403 status) are not reported by this line. A server that rejects the connection in a way Fuigo cannot tell apart from a plain failure is reported with the sixth reason, "the server rejected the connection (it may need sign-in)". A local (stdio) server is never treated as waiting for sign-in. Stdout of the text and json formats and the exit code are unchanged. The full error stays in `fuigo mcp doctor` and the `/mcps` view.

## Standalone workspace server

- **Stricter diagnostics socket.** The separate `fuigo-workspace-server` program (not part of the npm package) now
  creates its diagnostics socket with owner-only access from the first moment it exists, instead of setting that
  after binding. If the access cannot be set, the server does not serve and reports the bind failure. An existing
  file, folder or link at the socket path, or a socket owned by another user, is no longer deleted: the bind fails
  with a clear error. A stale socket left by a crashed earlier run of the same user is still replaced.
- **Known limit from 1.0.24, narrowed.** The `/tmp/workspace-server.sock` default is unchanged, so on a shared
  computer another user can still occupy that name first and make the bind fail (the server will not delete it);
  pass `--diag-socket` with a path in a folder only you can open. Other users can no longer read the socket or
  have it replaced by the server. `/logs` has no per-connection user check.
- **Two edge cases.** A custom socket path in a shared folder that is not "sticky" (a sticky folder such as `/tmp`
  stops other users from replacing your files) is not protected against other local users. A socket path within a
  few characters of the system's path-length limit may no longer bind, because the server briefly uses a longer
  temporary name next to it.

## Admin policy

- **Client prompts are always the user's own.** A prompt sent by a client program is now always treated as the
  user's own prompt for prompt hooks, whatever identifier the client attaches to it. Scheduled `/loop` runs started
  by the shell keep working. A client program from before this release that sends a scheduled run is treated as an unverified scheduled prompt (only `/compact` and skills resolve; other slash commands and `!` lines are plain text; no `@file` expansion) until it is updated. A scheduled run counts as the shell's own only if the prompt is exactly the text the
  shell announced; a scheduled prompt you edit while it waits in the queue is no longer a verified scheduled run: the edited text is treated as an unverified scheduled prompt (see below).
- **`UserPromptSubmit` hook payloads name the origin of prompts that were not typed.** The payload now carries an
  `origin` field (`scheduled`, `unverified_scheduled`, `task_completed`, `subagent_completed`, `workflow_completed`,
  `notification`, `goal_summary`, `goal_classifier_nudge`, `plan_resume`, `subagent_task`,
  `peer_message`) for such prompts. It is unchanged for prompts you type.
- **Subagent task text is not typed input.** Slash commands that change permissions or configuration can no longer be
  run from inside a subagent, and the task text given to a subagent is treated as written by the model, not typed by you. `@file` mentions in the task text given to a subagent are no longer expanded automatically; the subagent reads the file itself, under the usual permission rules.
- **`@file` mentions are expanded only in prompts you type.** Text that arrives from a scheduled task, a finished task or subagent, or a notification is no longer scanned for them, and a scheduled prompt that cannot be verified is treated as model-written text: only `/compact` and skills resolve; other slash commands and `!` lines are treated as plain text. It still goes through your `UserPromptSubmit` hook (a blocking hook blocks it), always runs as its own turn (never merged into a running turn or into a combined queued prompt), and `@file` typed in a plan revision is no longer expanded (the model reads the file itself).
- **`!` commands obey admin denials.** A shell command typed with `!` is now refused when a `Bash` deny rule (user,
  project or managed), a managed lock-down, a deny rule on a file it reads or writes, or a denying `UserPromptSubmit` or
  `PreToolUse` hook from a settings file applies to it. It still never asks for approval, so a command that Fuigo cannot
  read well enough to match against a deny rule (for example `bash -c "$VAR"` or `eval`) still runs: for the model such
  a command would raise a prompt, and a `!` line never prompts. The refusal names the rule (tool and pattern) or the
  hook, not yet which settings file the rule came from. `PostToolUse` hooks now run after it. Only a prompt the user
  typed can start a `!` command; a scheduled or other automated prompt that carries one is handled as ordinary text, and
  a scheduled run is accepted only if the prompt carries nothing but its display fields.

## Named sessions (off by default)

Sessions of Fuigo on one machine, under one user account, can list each other (`/peers list`, or the model's `list_agents` tool) and send each other messages (the model's `send_message` tool). The feature is off by default; the user guide has a chapter on it ("Named Sessions and Peer Messaging").

**Turning it on.** Set `[features] peer_messaging = true` in your own `config.toml`, in a `FUIGO_CONFIG` overlay, or set `FUIGO_PEER_MESSAGING=1`. An administrator's managed configuration can turn it on, and a requirements pin can force it on or off and overrides every other source. A configuration file inside a repository you open cannot turn it on, and neither can a server-delivered campaign (a remote campaign, a local `[[campaigns]]` entry or `FUIGO_CAMPAIGNS_OVERRIDE`). On a managed machine the administrator's setting decides. `/peers status` shows whether the inbox is ready or the reason it is unavailable.

**Holds.** `/peers held` lists messages held for you, `/peers release <id>` delivers one and `/peers refuse <id>` refuses it. A release does not approve any tool call. A message carries the kinds of actions its sender was denied in the last 30 minutes; the receiving session holds such a message, and after a release it refuses a matching action. A session that nobody is watching refuses what would need a person. The sender can ask to be told when the other session is idle (`notify_when_idle`).

A session in the same permission mode as the sender accepts the message and acts on it even when no window is attached; a session in a different mode holds it. A message from another session is data: it can never approve a permission prompt or change settings, rules or instruction files.

Once a session has read a message from another session, edits and shell commands that write its instruction files, settings, hooks, rules, skills, git configuration or stored session files are refused in every permission mode, until you type `/peers clear-influence`. A shell command that Fuigo cannot analyse is refused in that state too. Git commands that rewrite the working tree (`checkout`, `switch`, `restore`, `reset`, `merge`, `pull`, `rebase`, `stash`, `apply`, `am`, `cherry-pick`, `revert`), package managers, build tools, interpreters, scripts and MCP tools are not refused: Fuigo instead rechecks those files after each tool call, and if one has changed it holds all further messages from other sessions and tells you which file changed.

## For host applications (ACP)

- **Peer messaging.** With `features.peer_messaging` on, the capability `fuigo/capabilities.peerMessaging` lists the methods `_fuigo/peer/configure`, `_fuigo/peer/list`, `_fuigo/peer/list_held` and `_fuigo/peer/release`, and the events `peer_held`, `peer_released`, `peer_refused`, `peer_expired`, `peer_reheld` and `peer_warning` arrive as `fuigo/session_notification` updates. A session takes part only after the host calls `_fuigo/peer/configure` with an operator kind (`attended`, `may_return` or `unattended`). Errors use code `-32011`. With the feature off the methods answer as unknown methods and the capability is absent. A host cannot author a message. A headless run (`fuigo -p --peer`) opts the session in as unattended.
- **Session park (`hold`).** A host can park an idle session with `_fuigo/session/park` and resume it with a prompt or `_fuigo/session/unpark`. While parked, the session starts no turn of its own, sends no frames for that session except replies to the host's own requests, and holds notifications until it is un-parked. The capability is advertised under `fuigo/capabilities.sessionPark` with `modes: ["hold"]`. Commands that were already running when the session was parked keep running. A prompt the host sends un-parks the session; a scheduled task that comes due does not, and is reported with the next prompt. The `stop` mode is not available in this release.

## Install

- Reinstalling the same version with npm now replaces the installed binary when it differs from the one in the package. On Windows a binary that is in use is kept until the next start.

## Known limits

The known limits listed in the 1.0.24 release notes stand unless an entry above says otherwise.

Named sessions:

- Peer messaging protects against mistakes and against a model being talked into something. It does not protect against another program running as you: any program under your user account can talk to the inbox as if it were a Fuigo session.
- Sessions of different Fuigo versions on one machine may not see each other. Leftovers of an older version are not cleaned up automatically.
- If your Fuigo home is a symbolic link, or other users can write to it, only the inbox is unavailable, with the reason shown in `/peers status`. Everything else works.
- Git commands that rewrite the working tree are not blocked for a peer-influenced turn. A change to a protected file made that way is detected afterwards and the session is put on hold.
- Peer messaging works on Windows through a private named pipe. A session started from a network logon (for example SSH or a remote PowerShell session) cannot use it. The Fuigo home must be owned by you, with no write or delete access for anyone except you, SYSTEM and Administrators; its `peers` folder is created for your account only and must stay that way. It has had less testing than on Linux.
- While a remote client (a relay) is attached to a leader, peer messaging is unavailable for every session of that leader, and a message that was already approved goes back to held.
- Local clients of the same user attached to one process are not separated: any of them can list, release or refuse held messages for that process's sessions. A host's statement that a person is present is taken at its word.
- Headless `--peer` acts on a message from a session in the same permission mode with nobody watching.
- Notices can be lost if the session stops listening or during a long remote attach. A held message itself is not lost. Held messages are kept in memory, so a restart drops them.
- "Notify when idle" tells the sender when the other session's turn ended. A notice counts toward the receiving session's limit of peer-started turns.
- A denial is carried for the same action re-sent; a reworded action is not matched.
- In testing, a model occasionally ended a peer-started turn with no reply instead of refusing; nothing was run.
- Session park is hold only (see above).
