# Fuigo 1.0.27 release notes

This release follows 1.0.26. On Windows, an HTTP MCP server can now read its bearer token from a file, with the same owner-only rule as on macOS and Linux.

## MCP servers

- `bearer_token_file` now works on Windows. The token is read from a file on every request, as on macOS and Linux, for a server defined in your own `config.toml`. The file must be a regular file of at most 16 KiB, not a symbolic link or other reparse point. It must be owned by you (or by Administrators when Fuigo runs elevated), and only you, SYSTEM and Administrators may have access to it, including permissions it inherits from its folder. A refused file means that server is skipped with a warning that names the file and, when other users have access, how to fix it; Fuigo keeps running. The user guide chapter on MCP servers has the details and an `icacls` command.

## Known limits

- On Windows, network locations (`\\server\share` and mapped network drives) are not accepted for a `bearer_token_file`; device and pipe paths are not accepted either.
- On Windows, a `bearer_token_file` with more than one hard link is refused.
