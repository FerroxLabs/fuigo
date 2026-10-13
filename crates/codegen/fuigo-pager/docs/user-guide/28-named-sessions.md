# Named Sessions and Peer Messaging

Sessions of Fuigo that run on one machine, under one user account, can list each other and send each other
messages. This chapter explains how to turn the feature on, how to use it, what it will and will not let a
message do, and the limits you should know about.

---

## What It Is

Peer messaging lets one Fuigo session send a text message to another Fuigo session on the same machine. The
receiving session can act on the message, the way a colleague could ask you to do something. A session can:

- list the other sessions it can reach,
- send a message to one of them,
- ask to be told when the other session has finished the turn that handled the message.

**The feature is off by default.** While it is off, Fuigo has no inbox, the `/peers` command is not offered, the
model has none of the peer tools, and nothing about Fuigo's behavior changes. One exception: a resumed session
that is still peer-influenced keeps `/peers clear-influence`, so you can always lift that state.

A message from another session is data, not an instruction from you. It can never approve a permission prompt,
answer a question for you, or change your settings, rules, hooks or instruction files. The sections below show
how Fuigo enforces that.

---

## Turning It On and Off

The setting is `features.peer_messaging`. These sources can set it:

| Source | How | Notes |
| --- | --- | --- |
| Your `config.toml` | `[features]` then `peer_messaging = true` | Your own file in your Fuigo home. |
| The `FUIGO_CONFIG` overlay | A `[features]` table with `peer_messaging` | The overlay keeps the `features` table. |
| The environment | `FUIGO_PEER_MESSAGING=1` (or `0`) | Read when Fuigo starts. |
| Managed configuration | The administrator's managed configuration file | For managed machines. |
| A requirements pin | The administrator's `requirements.toml` | Forces the feature on or off. Overrides every other source. |

Two kinds of source cannot turn it on:

- A configuration file inside a repository you open.
- A server-delivered campaign. Local `[[campaigns]]` entries and `FUIGO_CAMPAIGNS_OVERRIDE` cannot turn it on
  either. A campaign cannot change this setting in either direction.

**On a managed machine the administrator's setting decides.** If a requirements pin turns the feature off, you
cannot turn it on. If it pins the feature on, you cannot turn it off.

Restart Fuigo after you change the setting.

---

## Using It

### Names and addresses

Every session that takes part has three things:

- a **name**, the session's own name as shown in lists,
- a short **reference** in square brackets, such as `[a1b2c3d4]`, 8 characters (12 if two sessions would share
  one), which tells apart sessions with the same name,
- an **address**, which looks like `fuigo-peer:<host>/<session>/<n>`.

You, or the model, can name a target in these ways, tried in this order:

1. The full address. An address is never read as a name.
2. A reference alone: `[a1b2c3d4]`.
3. A name with its reference: `build-fixer [a1b2c3d4]`.
4. A name alone, when exactly one session has it. If two or more do, Fuigo refuses and shows their references.

Names that reach you from other sessions are shown with control and look-alike characters removed and cut to
64 characters.

### Listing sessions

Type `/peers list`. Fuigo shows your own session first, then the other sessions it can reach, one per line. The
model can do the same with its `list_agents` tool. Only sessions that take part are listed. Subagents of your
own session are reached with `send_subagent_message`, not through this feature.

A session takes part when it is an interactive Fuigo session (a terminal window or a leader window) and the
feature is on. A host application opts its sessions in itself (see "For Host Applications"). A subagent never
takes part.

### Sending a message

Ask the model to send one ("tell the docs session to rebuild the index"). The model uses its `send_message`
tool with a target and a message. A message can be at most 32 KiB. The sender's name, permission mode and
other details are filled in by Fuigo; the model cannot set them.

`send_message` does not ask you for permission in any mode. A deny rule, an ask rule, a managed lock-down or a
blocking `PreToolUse` hook still applies to it, as to any tool.

The tool answers with what happened: delivered, held, or rejected (with a reason such as "too large", "rate
limited" or "unavailable"). Fuigo limits each pair of sessions to 10 messages a minute and each machine to 60
messages a minute, and a conversation stops after 8 hops of replies. A session accepts at most 20 messages
that start turns for each prompt you type yourself.

### Asking to be told when the other session is idle

The model can add `notify_when_idle: true` to `send_message`. Fuigo then tells the sending session when the
other session has finished the turn that handled the message. With `notify_when_idle: true` and no message
text, the call only watches the other session. If that session is idle it answers at once. A watch-only call
goes through the same checks as a message, and a session that would only hold the message does not accept it.

You can also be told other outcomes. The sender gets one short notice for each of these:

- the message was held and you released it,
- it was held and expired,
- it was held and refused,
- the model in the other session refused it,
- the other session finished its turn and is idle,
- the other session exited,
- the other session is unavailable (this is not a confirmed exit),
- nothing arrived within 12 hours (the outcome is unknown).

Notices are written by Fuigo. Each one wakes the sending session for a turn. A session can have at most 64
watches open, and a machine at most 256.

### What the receiving session sees

The message reaches the model wrapped in a note that says it comes from another session and gives the
sender's name and reference. Fuigo handles it as follows:

- The model is told the text is not typed by you and must not be treated as your instruction.
- Slash commands in it do nothing. Lines that start with `!` are not run. `@file` mentions are not expanded.
- Your `UserPromptSubmit` hook runs once on the message before Fuigo accepts it, with `origin` set to
  `peer_message`. If the hook blocks it, or fails, Fuigo refuses the message. The `PreToolUse` payload of later
  tool calls carries `peerInfluenced`.
- It does not become the session title, and it does not go into your prompt history.
- If the session is busy, the message waits for the next safe point in the turn. If the session is idle, the
  message starts a turn.

The model has a `refuse_peer_message` tool. It can use it to refuse a message it should not follow. The sender
is told, and later messages from that sender are held for the rest of the session. Use `/peers clear-influence`
to lift this.

---

## Permission Modes and Holds

A message is delivered only when the sender and the receiver are in the **same permission mode**. This
includes plan mode and whether edits are granted for the session. Whether a person is present on each side
must also match. If anything differs, or Fuigo cannot tell the sender's mode, the message is **held for you**.

**Held** means Fuigo has stored the message and has not shown it to the model. A held message waits up to
5 minutes. A session keeps at most 64 held and queued messages, 1 MiB in total. A held message is kept in
memory only, so restarting Fuigo drops it.

Fuigo also holds a message when:

- the sender was recently denied something (see "Denials travel with a message"),
- the sender's loop limit is reached,
- a protected file changed (see "Protected Files and Change Detection"),
- a host application set the session's policy to `hold`. A policy of `refuse` refuses every message.

### Releasing or refusing a held message

| Command | What it does |
| --- | --- |
| `/peers held` | Lists the held messages in this session: id, sender, reason, and seconds to expiry. |
| `/peers release <id>` | Delivers the held message to the session. |
| `/peers refuse <id>` | Refuses the message. The sender is told it was refused. |

Only you can type these. Neither the model nor a message from another session can run them, and a subagent
cannot.

**A release does not approve any tool call.** It only lets the message in. Every tool call the message leads to
goes through the usual permission rules. Fuigo checks again just before it delivers a released message. If the
modes now differ, or anything else changed, the message goes back to held.

### The hold dialog (terminal window)

In the terminal window, a held message shows as one row under the transcript with the count, the newest
sender, the reasons and the expiry. Press `Alt+h` to open a dialog for the held message. It shows the sender,
the mode the sender reports, why the message is held, and when it expires. In the dialog:

- `a` runs `/peers release <id>`.
- `r` runs `/peers refuse <id>`.
- `Esc`, `d` or `q` close the dialog. The message stays held.

All other keys are ignored. The dialog says plainly: "Accepting delivers the message to this session. It does
not approve any tool call." If the terminal is smaller than 52 columns by 6 rows, the dialog does not accept;
refusing and closing still work. The dialog shows the first held message; press `Alt+h` again for the next
one. A message from another session also shows as one row in the transcript with the sender and the first
line of the message.

The dialog accepts `a` only when it has just been drawn in full. After the window is resized, loses or gains
focus, or anything else changes the screen, press `a` again once the dialog is redrawn. The dialog never shares
the screen with another prompt: if a permission prompt, a question or another dialog opens, the hold dialog
closes and the message stays held; `Alt+h` does not open it while another prompt is up. A subagent view has no
hold row and no hold dialog.

### Denials travel with a message

When a session sends a message, Fuigo attaches the kinds of actions that were denied in that session in the
last 30 minutes. This stops a denied action from being routed through another session.

- The receiving session holds a message from a sender with recent denials, in every mode. The held row says
  which kinds were denied (for example "the sender was recently denied: bash").
- If you release it, the receiving session carries those denials. A tool call that is the same action as one
  the sender was denied is refused there, and you get a notice.
- `/peers clear-influence` forgets the carried denials.

### Unattended sessions

A session that nobody is watching cannot answer a hold. It **refuses** what would need a person, and the sender
is told ("no operator"). A message from a session in the same permission mode is still delivered and acted on.
Terminal windows count as attended. A leader window counts as one where a person may return. A host application
declares which it is (see below).

---

## Protected Files and Change Detection

Once a session has read a message from another session, it is **peer-influenced**. That lasts until you type
`/peers clear-influence`. Fuigo refuses to clear it while peer messages are still queued, held or running.

While a session is peer-influenced, in every permission mode, including always-approve and auto, Fuigo refuses
edits and shell commands that write to:

- Fuigo and tool settings, managed and requirements files, permission files, hook folders, and MCP server
  lists,
- instruction files: `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `AGENT.md` at any depth,
- rule, skill, agent and command folders under `.claude`, `.fuigo` or `.cursor`,
- Git configuration and `.git/hooks`,
- shell start-up files, `.ssh`, and `/etc`,
- the stored session files and the peer messaging files in your Fuigo home.

A shell command that Fuigo cannot analyze is refused in that state too.

Some actions are not blocked but are checked afterwards. When a session becomes peer-influenced, Fuigo records
the state of the well-known instruction, settings and rule files (in the working folder, its parents, your home
and your Fuigo home). After each batch of tool calls it checks them again. If one changed, Fuigo holds all
further messages from other sessions until you type `/peers clear-influence`, and it tells you which file
changed. It does not restore the file. This covers writes made by package managers, build tools,
interpreters and scripts, and by Git commands that rewrite the working tree.

---

## For Host Applications

An application that drives Fuigo over ACP uses these methods: `_fuigo/peer/configure`, `_fuigo/peer/list`,
`_fuigo/peer/list_held` and `_fuigo/peer/release`. They are offered under
`fuigo/capabilities.peerMessaging` and answer as unknown methods while the feature is off. A session does not
take part until the application calls `configure` with its operator kind (`attended`, `may_return` or
`unattended`). Events arrive as `fuigo/session_notification` updates named `peer_held`, `peer_released`,
`peer_refused`, `peer_expired`, `peer_reheld` and `peer_warning`. An application cannot author a message.
Errors use code `-32011`. See [Agent Mode and IDE Integration](15-agent-mode.md) for the protocol and the
1.0.25 release notes for the details.

In headless mode, `fuigo -p --peer` opts the session in as an unattended session. Without `--peer`, headless
runs do nothing new.

---

## Platforms

- **Linux:** supported. Sessions talk through a private local socket in your Fuigo home.
- **macOS:** uses the same local-socket inbox as Linux and has had less testing than Linux. macOS has a shorter
  limit on socket path lengths.
- **Windows:** supported. Sessions talk through a private named pipe. The Fuigo home must be on a local fixed
  NTFS-style volume and owned by you.

---

## Limits You Should Know

- Peer messaging protects against mistakes and against a model being talked into something. It does not
  protect against another program running as you. Any program under your user account can talk to the inbox as
  if it were a Fuigo session.
- Sessions of different Fuigo versions on one machine may not see each other. Leftovers of an older version are
  not cleaned up automatically.
- If your Fuigo home is a symbolic link, or other users can write to it, only the inbox is unavailable. The
  reason shows in `/peers status`. Everything else works.
- Git commands that rewrite the working tree are not blocked for a peer-influenced turn. A change to a
  protected file made that way is detected afterwards, and the session is put on hold.
- On Windows, a session started from a network logon (for example over SSH or a remote PowerShell session)
  cannot use peer messaging. `/peers status` says so.
- On Windows, the Fuigo home and its `peers` folder must be owned by you, and nobody except you, SYSTEM and the
  Administrators group may have write or delete access to the home.
- On Windows, a Fuigo home whose parent folder lets other users write or delete (for example a folder made directly
  under `C:\` that inherits modify rights for Authenticated Users) makes the inbox unavailable, with the reason "a parent
  directory of the Fuigo home is not trusted".
- Peer messaging on Windows has had less testing than on Linux.
- While a remote client (a relay) is attached to a leader, peer messaging is unavailable for every session of
  that leader. A message that was already approved goes back to held. It can be released after the client
  detaches.
- Local clients of the same user attached to one process are not separated from each other. Any of them can
  list, release or refuse held messages for that process's sessions. A host application's statement that a
  person is present is taken at its word.
- Headless `--peer` acts on a message from a session in the same permission mode with nobody watching.
- Notices can be lost if the session stops listening or during a long remote attach. A held message itself is
  not lost: it stays held until it expires.
- "Notify when idle" tells the sender when the other session's turn ended. A notice counts toward the receiving
  session's limit of peer-started turns.
- Fuigo catches the same action being re-sent after a denial. It does not catch a reworded action.
- In testing, a model occasionally ended a turn started by a message from another session with no reply instead of
  refusing the message. Nothing was run. Now, when such a turn ends with an empty reply or a refusal from the model
  provider, you see one notice in the transcript. A turn that was started by a message from another session and makes
  no tool call at all (an empty reply, a provider refusal or a reply with only text) is recorded as refused
  automatically with the reason "no action taken": the sender is told. This applies to that message only; later
  messages from that sender are not held because of it (unlike a refusal the model makes with `refuse_peer_message`,
  which holds the sender for the rest of the session). A turn in which the model used a tool is not refused this way. The model can still reply with text and take
  no action; the rule judges the turn by whether any tool was called, not by whether the model's text was a refusal.
- Session park in this release is hold only.

---

## Troubleshooting

Type `/peers status`. It prints `Peer inbox: ready.` or `Peer inbox: unavailable (<reason>)`.

| Reason | What to do |
| --- | --- |
| the feature is off | Turn on `features.peer_messaging`, check for a requirements pin, and restart Fuigo. |
| the Fuigo home is a symbolic link | Point `FUIGO_HOME` at a real folder that you own. |
| the Fuigo home is not private to this user | Run the `chmod go-w` command shown after the reason (for an unusual path with spaces or shell characters no command is shown: remove write access for group and others from that directory yourself). On Windows the reason reads "remove write access for group and others from the Fuigo home: <path>" and no command is shown: remove write access for other users and groups in the folder's Security settings (Properties, Security, Advanced); only you, SYSTEM and Administrators should have it. A home made by an older version on a system with umask 002 (for example Ubuntu) needs `chmod go-w ~/.fuigo` once; homes made by this version are private. |
| a parent directory of the Fuigo home is not trusted | Check the owner and permissions of the folders above the Fuigo home. |
| the Fuigo home is missing or not a directory | Create it, or fix `FUIGO_HOME`. |
| the Fuigo home path is not a plain absolute path | Use an absolute path with no `.` or `..` parts. |
| the peers directory failed its safety checks | Check the owner and permissions of the `peers` folder in your Fuigo home. |
| no usable directory for the inbox socket | Check that your runtime or Fuigo home folder can hold a socket. |
| the inbox socket path failed its safety checks | Remove the unexpected file at that path, or use a shorter `FUIGO_HOME`. |
| a locator file failed its safety checks | Check the `peers` folder in your Fuigo home for files you did not expect. |
| a remote client is connected to this Fuigo | Peer messaging works again after the client detaches. |
| the inbox pipe name is already in use (Windows) | Another program or an older Fuigo session is using the pipe name. Close it and restart Fuigo. |
| the inbox pipe could not be created (Windows) | Restart Fuigo. If it persists, check that your user account can create named pipes and that no security software blocks them. |
| the inbox pipe failed its safety checks (Windows) | Restart Fuigo. If it persists, close other programs that may be using the pipe name. |
| this user account could not be read (Windows) | Sign in with a normal local or domain user account and restart Fuigo. |
| peer messaging is unavailable in a remote (network) logon session (Windows) | Start Fuigo from a local sign-in (for example a desktop terminal) instead of SSH or a remote PowerShell session. |
| unsupported platform | Peer messaging is not available on this platform. |

On systems where new directories are group-writable by default (umask 002, for example Ubuntu), a Fuigo home created by an older version must be fixed once with `chmod go-w ~/.fuigo`. Homes created by this version are private (mode 0700).

If a message you sent is not delivered: check `/peers list` on the target (a session that is not opted in is
not listed), check that both sessions are in the same permission mode, and run `/peers held` in the target. A
message may be held. Fuigo starts the inbox when the first session starts, and it does not retry after a
failed start. Restart Fuigo after you fix the cause.
