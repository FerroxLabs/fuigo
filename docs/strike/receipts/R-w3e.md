# R-w3e: `fuigo inspect` plugin enabled state

## Before
`crates/codegen/fuigo-shell/src/inspect/mod.rs` `list_plugins` (was line 1045) set `enabled: p.trusted`. It ignored
`[plugins].disabled` and the enabled list. User and project plugins unlisted in config are default-disabled by the
loader, yet inspect showed them enabled when trusted.

## After
`list_plugins(discovered, registry)` sets `enabled` from `PluginRegistry::active_plugins()` (matched on plugin id and
root). That is the loader's own verdict: `PluginRegistry::from_discovered`
(`crates/codegen/fuigo-agent/src/plugins/registry.rs:112`) computes `enabled = !is_disabled(dp, disabled) &&
explicitly_enabled`, and `active_plugins` (registry.rs ~263) keeps `enabled && trusted`. Inspect already built this
registry (mod.rs ~457) for skills/agents/MCP, so the list and the loading cannot drift.

## Display only
Yes. The loader (`from_discovered`) already honoured `disabled` and gated MCP ownership on `enabled && trusted`; mcp-doctor
(`mcp_doctor.rs` `discover_servers`) uses the same registry. No loading, trust or permission code changed.
The `untrusted(...)` display filter on names/paths is untouched.

## Tests (`--lib w3e`)
| test | at red 57296193 |
|---|---|
| inspect::tests::inspect_shows_a_trusted_disabled_plugin_as_disabled_w3e | FAILED (assertion) |
| inspect::tests::inspect_malformed_plugins_section_does_not_enable_plugins_w3e | FAILED (assertion: disabled plugin shown enabled; also asserts the existing `[plugins] enabled must be a list of strings, found string` warning) |
| mcp_doctor::tests::doctor_skips_a_disabled_plugin_w3e | passed (missing coverage) |
| mcp_doctor::tests::doctor_malformed_plugins_section_does_not_enable_plugins_w3e | passed (missing coverage) |

mcp-doctor has no user-facing message for a malformed `[plugins]` today (only `tracing::warn`), so none is asserted.

## Release note
`fuigo inspect` now shows a disabled plugin as disabled.

## Unverified
Windows/macOS not run. Plugins matched by name collision losers are not in the registry and now show disabled (they are not loaded).
