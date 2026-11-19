# Contract C: config provenance and trust

This document states how Fuigo treats configuration it finds in a project, and when it may run what
that configuration names.

## C.1 Three things that are not the same thing

1. **Discovery**: Fuigo notices a file exists (`CLAUDE.md`, `.claude/settings.json`, `~/.claude.json`,
   a plugin manifest, an MCP server entry).
2. **Compatibility**: Fuigo understands the file's format and can read values from it.
3. **Permission to execute**: Fuigo is allowed to run what the file names: a hook, an MCP server
   command, a plugin.

Discovery and compatibility are cheap and safe. Execution is not. A change may never widen (3) as a
side effect of improving (1) or (2).

## C.2 What is gated

Every surface that can turn repo-controlled declarations into running processes is gated by folder
trust, on both sides:

- **Detection**: the presence of the source raises the folder-trust prompt. This includes project
  `.claude/settings.json` and the home-level `~/.claude.json` `projects.<cwd>.mcpServers` entry.
- **Consumption**: when the workspace is untrusted, repo-local (project-scoped) MCP servers are
  dropped from the merged server list before anything starts.

A coverage guard test enumerates the trust-triggering sources so a new source cannot be added without
being gated or explicitly excluded with a reason.

Claims in this area ("this read is ungated", "this event is never sent") are established by tracing the
call path, never by failing to find a string.

## C.3 Ordering

Gating the discovery paths lands before anything makes plugin hooks fire. Making hooks run turns
repo-controlled declarations into processes, so it may not precede the gates on every path that finds
those declarations.

## C.4 New gates default on

A gate that ships off is not a gate. Every gate under this contract is on by default. An upgrading user
who relied on inherited `CLAUDE.md`, MCP servers or hooks will find them gated; the same change owns
the migration message (one clear line naming what was gated and the single action that restores it)
and the release notes say so. Silent loss of working configuration is not acceptable.

## C.5 Trust semantics are fixed (Contract E)

`--trust` grants the process working directory and persists to `~/.fuigo/trusted_folders.toml`; the
`fuigo/folder_trust/request` ACP round-trip lets a GUI client answer on the user's behalf. Embedders
depend on both (E.5). Nothing under this contract changes either.

## C.6 Acceptance

Discovery, compatibility and execution are separately observable; the home-level read is gated; hooks
cannot fire before their discovery paths are gated; every new gate defaults on and carries a migration
message; and the Contract E trust surface is unchanged.
