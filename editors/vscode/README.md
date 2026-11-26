# Fuigo for VS Code

Use the [Fuigo](https://github.com/FerroxLabs/fuigo) coding agent from a chat panel in VS Code and in editors built
on it (Cursor, Windsurf, VSCodium and others that install from Open VSX). The extension runs your installed `fuigo`
binary (`fuigo agent stdio`) and talks to it over the Agent Client Protocol (ACP). It opens no network port.

## Setup

1. Install the Fuigo CLI and sign in once:
   ```bash
   npm install -g fuigo
   fuigo login        # or set FUIGO_API_KEY
   ```
2. Install this extension, then open the Fuigo view in the activity bar (or run **Fuigo: Open Chat**).
3. If `fuigo` is not on your `PATH` or in the npm global install, set **`fuigo.path`** to the binary in your user
   settings.

The extension runs only in trusted workspaces (Restricted Mode keeps it off), because the agent reads and edits files
and runs commands.

## Features

- **Chat panel.** Replies stream in as Markdown, with tool calls, the plan and the mode picker (Default, Plan, Ask, ...).
  **New** starts a fresh session; **Stop** cancels the current turn.
- **Session resume.** When the window reloads or the agent restarts, the panel resumes the last session of this
  workspace (`session/load`) and replays its history. **New** starts over.
- **Native edit review.** In Default mode each agent edit opens as a VS Code diff. **Accept** writes it into the
  editor buffer (unsaved changes are kept and seen by the agent); **Reject** fails that one edit and the turn goes on.
  Pending edits are listed in the **Edits** view.
- **Native prompts.** Permission requests use a Quick Pick. Plan mode asks you to approve the plan before building.
- **Editor context.** **Add Selection to Fuigo** (editor context menu) attaches the selection to your next message.
  The agent can also call read-only IDE tools: the current selection, open editors, diagnostics and workspace folders.
- **Terminal fallback.** **Fuigo: Open in Terminal** runs the full terminal UI in an integrated terminal.

## Permissions and data

- The extension starts `fuigo` as a child process in your workspace folder, with your user account and environment.
  The agent's model calls, credentials and telemetry settings are the CLI's; see the Fuigo docs.
- File reads and writes requested by the agent go through VS Code, so they see unsaved buffers and stay undoable.
  The agent's permission mode decides what needs your approval, exactly as in the terminal UI. The extension adds no
  extra prompts and never widens a permission.
- The IDE tools (selection, open editors, diagnostics, workspace folders) are read-only and served by the extension
  itself, so it answers their permission prompt with "allow once" without asking. Only the exact tools of the server
  this window registered qualify: its name carries a random suffix (`ide-1a2b3c4d`), so another MCP server, for example
  one named `ide` in a project's `.mcp.json`, can never borrow that answer.
- `fuigo.path` is read from user settings only. A value in a workspace's `.vscode/settings.json` is ignored, so a
  cloned repository cannot choose the program the extension runs.
- Agent text is rendered as Markdown inside a webview with a strict Content Security Policy: raw HTML is shown as text,
  images and other remote resources are never loaded, and only `http(s)` and `mailto` links are kept.
- The extension stores one value: the id of the last session in this workspace.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `fuigo.path` | empty | Path to the `fuigo` binary. Empty: look on `PATH`, then in the npm global install. User settings only. |

## Troubleshooting

- **"the fuigo binary was not found"**: install the CLI (`npm install -g fuigo`) or set `fuigo.path`. Use
  **Copy install command** or **Set fuigo.path** on the notification.
- **"the binary set in fuigo.path does not exist"**: point `fuigo.path` at an executable file (on Windows the
  `.exe`, or the `fuigo.cmd` shim from npm).
- **Nothing happens / the agent stops**: open **View > Output > Fuigo** for the agent's log. Send a message to restart
  it. Run `fuigo` in a terminal once to check that sign-in works.
- **An edit diff did not appear**: edits only ask in Default mode. In always-approve mode they are applied directly; use
  the **Edits** view or undo to revert.
- **Old history appears after a reload**: that is session resume. Click **New** for a fresh session.

## License

Apache-2.0. See [LICENSE](LICENSE).
