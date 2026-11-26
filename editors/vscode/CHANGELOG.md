# Changelog

## 0.1.0

First release.

- Security: IDE tools are auto-allowed (once) only for this window's own server, `fuigo.path` is a user-only
  setting, and the extension is off in untrusted workspaces.

- Chat panel driving `fuigo agent stdio` over ACP, with Markdown replies, tool calls, plan and mode picker.
- Session resume with `session/load` when the agent supports it.
- Native diff review for agent edits (Accept / Reject), with an Edits view.
- Native permission and plan-approval prompts.
- Read-only IDE tools for the agent (selection, open editors, diagnostics, workspace folders) and
  **Add Selection to Fuigo**.
- **Open in Terminal** fallback and a binary-not-found notice with the install command.
