# VS Code Extension

The Fuigo extension puts the Fuigo agent in a chat panel inside VS Code and the editors built on it: Cursor,
Windsurf, VSCodium and others that install extensions from Open VSX. It runs your installed `fuigo` binary as
`fuigo agent stdio` and talks to it over the Agent Client Protocol ([Agent Mode](15-agent-mode.md)). It opens no
network port, and the agent behaves exactly as it does in the terminal: same permission modes, same rules, same
sessions.

---

## Install

1. Install the Fuigo CLI and sign in once ([Getting Started](01-getting-started.md)):

   ```bash
   npm install -g fuigo
   fuigo login        # or set FUIGO_API_KEY
   ```

2. Install the extension `ferroxlabs.fuigo`. To sideload a `.vsix` file, run **Extensions: Install from VSIX...** from
   the Command Palette, or:

   ```bash
   code --install-extension fuigo-0.1.0.vsix      # VS Code
   cursor --install-extension fuigo-0.1.0.vsix    # Cursor
   ```

3. Open the **Fuigo** view in the activity bar, or run **Fuigo: Open Chat**.

The extension needs VS Code 1.94 or later (Cursor and Windsurf are newer than that). It finds `fuigo` on your `PATH`,
then in the npm global install. If it is somewhere else, set `fuigo.path` in your **user** settings (see
[Settings](#settings)).

The extension runs only in a trusted workspace. In Restricted Mode it stays off, because the agent reads and edits
files and runs commands. Trust the folder (**Manage Workspace Trust**) to use it.

---

## Using the chat panel

- Type a message and press **Enter** (**Shift+Enter** for a new line). Replies stream in as Markdown, with a card for
  each tool call (click it to see the output) and the agent's plan.
- **Stop** cancels the current turn. **New** starts a fresh session and cancels a turn that is still running.
- The **Mode** picker switches between the agent's modes (Default, Plan, and the others it offers).
- **Session resume.** When the window reloads or the agent restarts, the panel resumes the last session of this
  workspace and replays its history. Click **New** to start over.
- **Fuigo: Open in Terminal** runs the full terminal UI in an integrated terminal, for anything the panel does not
  show.

## Reviewing edits

What needs your approval is decided by the agent's permission mode, exactly as in the terminal
([Permissions and Safety](22-permissions-and-safety.md)). The extension adds no prompts of its own and never
answers a prompt more loosely than you would.

- **Default mode.** Each edit opens as a VS Code diff of the whole file. **Accept** (editor title bar, CodeLens or
  the **Edits** view) writes it into the editor buffer and saves it; **Reject** fails that one edit and the turn goes
  on. If the agent edits the same file twice in a turn, the second diff opens after you decide on the first.
- **Auto and always-approve modes.** Edits are applied straight to the buffer, so they stay undoable. Changed files
  are listed in the **Edits** view, where you can still reject a hunk, a file or everything.
- File reads go through VS Code too, so the agent sees your unsaved changes.

Other permission requests (commands, web fetches, MCP tools) appear as a Quick Pick with the agent's own options
(allow once, always allow, reject). **Show diff** is offered when the request comes with one. In Plan mode the agent
asks you to approve the plan before it starts building: approve, keep planning with feedback, or open the plan.

## Editor context

- **Add Selection to Fuigo** (editor context menu, or the Command Palette) attaches the selected lines to your next
  message as `@path#L5-10`. The chip above the input box shows what is attached; **×** removes it.
- The agent can call four read-only IDE tools on its own: the current selection, the open editors, the diagnostics
  (errors and warnings) and the workspace folders. The extension serves them itself, so it answers their permission
  prompt with "allow once" without asking you.

The IDE tools are registered under a server name with a random suffix, for example `ide-1a2b3c4d`, that changes each
time the window starts. Only those exact tools are answered without a prompt. A different MCP server, for example one
called `ide` in a project's `.mcp.json`, always gets the normal prompt.

---

## Settings

| Setting | Default | What it does |
|---|---|---|
| `fuigo.path` | empty | Path to the `fuigo` binary. Empty: look on `PATH`, then in the npm global install. |

`fuigo.path` is read from user settings (and remote-machine settings) only. A value in a workspace's
`.vscode/settings.json` is ignored, so a repository you clone cannot choose the program the extension runs.

Everything else (model, permission mode, rules, MCP servers, hooks) is the CLI's configuration
([Configuration](05-configuration.md)); the extension reads none of it.

## Privacy and data

- `fuigo` runs as a child process in your first workspace folder, with your user account and environment. Model
  calls, credentials and telemetry follow the CLI's settings.
- Agent text is shown in a webview with a strict Content Security Policy: raw HTML is shown as text, images and other
  remote resources are never loaded, and only `http(s)` and `mailto` links are kept. Links open through VS Code's
  usual external-link confirmation.
- The extension stores one value: the id of the last session in this workspace.

## Organizations with an MCP allowlist

A managed MCP policy that admits servers by name blocks the IDE tools, because their server name changes each time
the window starts. The chat, edits and prompts are unaffected; only the four IDE tools are missing.

---

## Troubleshooting

| Symptom | What to do |
|---|---|
| "the fuigo binary was not found" | Install the CLI (`npm install -g fuigo`) or set `fuigo.path` in user settings. The notification has **Copy install command** and **Set fuigo.path**. |
| "the binary set in fuigo.path does not exist" | Point `fuigo.path` at an executable file: on Windows the `.exe`, or the `fuigo.cmd` shim from npm. |
| `fuigo.path` in `.vscode/settings.json` has no effect | Expected: the setting is user-only. Move it to user settings. |
| The Fuigo view is missing | The workspace is in Restricted Mode. Trust the folder. |
| Nothing happens, or the agent stops | Open **View > Output > Fuigo** for the agent's log, then send a message to restart it. Run `fuigo` in a terminal once to check that sign-in works. |
| An edit did not open a diff | Only Default mode asks. In auto or always-approve mode edits are applied directly: use the **Edits** view or undo. |
| Old history appears after a reload | That is session resume. Click **New** for a fresh session. |

## See also

- [Agent Mode and IDE Integration](15-agent-mode.md): the ACP protocol the extension uses, and other editors.
- [Permissions and Safety](22-permissions-and-safety.md): permission modes and rules.
- [Session Management](17-sessions.md): resuming and rewinding sessions.
