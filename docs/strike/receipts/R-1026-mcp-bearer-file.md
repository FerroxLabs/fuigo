# R-1026 MCP `bearer_token_file` (packet 26-6c)

Base `dd2978d5`, branch `strike/b26-6c`. Fuigo's rules override the upstream behaviour wherever they differ.

## Upstream files read (read-only, `~/upstream-grok-build` at `2bdd1d6`)
`xai-grok-config/src/mcp_bearer_token_file.rs` and `_tests.rs` (path type, `_meta` transport), `mcp_server_config.rs` and
`_tests.rs` (field, `KNOWN_MCP_SERVER_FIELDS`, conversion to the ACP entry), `xai-grok-mcp/src/bearer_token_file.rs` and `_tests.rs`
(per-request read, 16 KiB cap, 5 s timeout, stalled-read slot), `mcp_http_client.rs` (the wrapper that supplies the token), and the
spawn code in `servers.rs`. No upstream code was copied; the design (field travels as ACP `_meta`, wrapper reads per request, stalled-read
slot) was re-implemented. Nothing that contacts xAI, telemetry or branding was taken.

## Rules and where they are enforced
Paths are under `crates/codegen/`.

1. **User config only.**
   - Field: `fuigo-config-types/src/mcp.rs` (`McpServerTransportConfig::StreamableHttp.bearer_token_file`).
   - Marked sources (project `.fuigo/config.toml`, project `.mcp.json`, plugin manifests, managed JSON, client upserts): the existing
     `untrusted_source` mark makes `McpServerConfig::checked_bearer_token_file` ignore the setting with a note and the server still starts.
   - TOML layers merged into the effective config (managed, system, requirements, campaign): rule = THE WHOLE SERVER ENTRY MUST COME FROM
     YOUR OWN CONFIG. `fuigo-shell/src/util/config/mcp.rs` `enforce_bearer_file_provenance` (called from `parse_mcp_servers_with_problems`)
     compares the RAW merged TOML table `mcp_servers.<name>` with the RAW user-layer table `mcp_servers.<name>` (`ConfigLayers::load().user`)
     for exact structural equality, before any setup/template rewriting or conversion (`$VAR` expansion has already run on both sides when each layer file is loaded; the token path is left literal). Every key counts (`url`, `setup`,
     `url_template`, `command`, `args`, `env`, `headers`, `oauth`, `enabled`, and any field added later). Any difference drops
     `bearer_token_file` for that server with the note "another configuration layer changed this server; the token file is not used"
     (`McpServerConfig::drop_bearer_token_file_changed`); the server still starts, without the token. The final-origin check after setup
     rewriting is NOT a separate assertion: with an identical entry, the rewriting (setup variables from the same entry plus the user's own
     saved preferences) yields the user's own URL, so whole-entry equality is the rule. Test with an unknown extra key:
     `an_unknown_extra_key_in_a_higher_layer_drops_the_token_file`. Real override vectors are requirements layers and campaign patches; the
     managed layer sits BELOW the user layer.
   - Campaigns (local `[[campaigns]]`, remote, `FUIGO_CAMPAIGNS_OVERRIDE`), `fuigo-config/src/campaigns.rs` `apply_active_campaign_patches`
     with `config_override.rs` `strip_campaign_mcp_servers`: a patch cannot modify ANY key of an MCP server that exists before campaigns
     apply (its whole `mcp_servers.<name>` sub-table is dropped; the user gets a note naming the campaign and server). A campaign may
     still ADD a brand-new server with the fields it could set before (`url`, `headers`, `command`, ...: a new server has no user token),
     but `bearer_token_file` / `bearer_token_env_var` are stripped from every server (`CAMPAIGN_STRIP_PATHS`). `features.peer_messaging` stays stripped.
     The `FUIGO_CONFIG` overlay cannot carry `mcp_servers` (not in its allow-list).
   - Every JSON source (`.mcp.json`, `~/.claude.json`, Cursor, imports): dropped in `mcp_config_from_json_value`.
   - Definitions handed in by an ACP client or an agent definition: dropped in `fuigo-shell/src/session/managed_mcp.rs`
     `refuse_saved_key_in_server` via `fuigo-mcp/src/bearer_token_file.rs` `strip_from_server`.
   - Tests: `fuigo-shell/src/util/config/mcp_bearer_file_tests.rs` (user ok; managed/other layer, different value, project TOML, project
     `.mcp.json` and generic JSON, plugin, client-supplied each ignored with a note and the server still starts).
2. **Owner-only file.** `fuigo-mcp/src/bearer_token_file.rs` `read_checked_bytes`: `O_NOFOLLOW | O_NONBLOCK` open, then `fstat` on the open
   descriptor: regular file, `st_uid == geteuid()`, `mode & 0o077 == 0`, `len <= 16 KiB`, bounded read (`take(16 KiB + 1)`). The content must be
   visible ASCII after dropping one trailing `\n` or `\r\n` (no control character, whitespace or non-ASCII inside; not empty). Token of
   fewer than 16 characters: refused, fixed reason "token too short" (the sent-credential scrubber ignores anything under 8). Path parse
   (`BearerTokenPath::parse`): absolute or `~/` only; `$VAR`, `~user`, `~` and relative paths are refused; no expansion. The user-layer
   `$VAR` expansion (`fuigo-config/src/loader.rs` `expand_env_vars_in_toml_at`) now skips `mcp_servers.<name>.bearer_token_file`, so the
   string reaches the parser literally (test `a_dollar_in_the_path_is_not_expanded_in_the_user_layer`). A failure skips that
   server with a one-line warning naming the server and reason (spawn: `bearer_token_file_for_server` in `servers.rs`; config:
   `checked_bearer_token_file`). Tests: `bearer_token_file_tests.rs` (symlink, group/other bits, 16 KiB limit and exact limit, directory, FIFO
   returns at once, wrong owner (runs when the test user is root), control characters, whitespace, non-ASCII, empty, missing, path rules).
   **Windows:** `BearerTokenPath::parse` returns `UnsupportedPlatform` and the server is skipped with "bearer_token_file is not supported on
   Windows in this release" (fail closed; the ACL check was not attempted).
3. **Never logged or shown.** The token exists only as a local `String` in `BearerTokenFile::read`, handed to rmcp for the request; it is
   not stored in any struct. Config types hold the PATH only (`McpServerTransportConfig` already has a hand-written redacting `Debug`; the
   new field prints the path). `BearerTokenFile` has a hand-written `Debug` (path only). Error enum texts are fixed strings with no path and no
   content. `read` records the token with the sent-credential scrubber (`fuigo_telemetry::sent_credentials::record`) so an echo from a server is
   replaced at the log, display and telemetry sinks. The secret-debug guard (`fuigo-auth/tests/secret_debug_guard.rs`) is satisfied without an
   `ALLOWED` entry: no type with a derived `Debug` holds the field (the `HttpConfig` that carries the `BearerTokenFile` derives only `Clone`). Tests:
   `nothing_logged_at_any_level_holds_the_token` (capture subscriber at all levels, success and refusal), `debug_shows_the_path_never_the_token_...`,
   `no_error_text_holds_the_token_or_the_path`, `refusals_skip_only_that_server_and_never_echo_...`. `/mcp` and doctor never print the field.
4. **Where it may be sent.** `check_url_may_carry_token` (https, or plain http to a loopback IP literal: 127.0.0.0/8, ::1; the NAME `localhost` is refused for a token, since a hosts file or resolver can point it elsewhere; the HTTP MCP policy has no localhost rule of its own) at spawn; the token goes only through the
   `Authorization` bearer of that server's HTTP client (`McpHttpClient::resolve_auth_token`), whose redirect policy (`http_policy::redirect_policy`)
   refuses any cross-origin redirect; `bearer_token_file` plus an inline `Authorization` header (spawn) or `bearer_token_env_var` / header (config) is
   an error for that server. Tests: `the_token_file_is_sent_as_a_bearer_to_the_configured_server`, `a_cross_origin_redirect_never_receives_the_token`
   (a second loopback origin receives nothing), `refusals_skip_only_that_server_...` (plain http off-machine, both forms, relative and env paths),
   `both_forms_or_a_bad_path_skip_that_server_only`.
5. **Re-read per request.** `McpHttpClient::{get_stream, post_message, delete_session}` call `resolve_auth_token` for every request (for
   `get_stream` after any reconnect backoff). The same checks run each time. A file that vanishes or fails a check fails that request with the
   generic reason and logs a warning with the reason; nothing is cached or reused (a stricter choice than "last good token"). OAuth discovery is
   skipped for such a server (config supplies the credential). Tests: `rotation_is_picked_up_on_the_next_request_and_a_bad_file_sends_nothing`,
   `every_read_checks_again_so_rotation_applies_and_a_bad_file_fails_the_request`, `a_stalled_read_times_out_and_later_reads_fail_fast`.

6. **Client upserts.** `mcp/upsert` drops `bearer_token_file` (with the note) in `untrusted_upsert`
   (`fuigo-shell/src/extensions/mcp.rs`) before the definition is persisted, so `config.toml` never holds a client-chosen path.
   Test `an_upserted_bearer_token_file_is_not_persisted`. (An upsert already replaces the whole entry, so editing a server through
   `/mcps` also removes a `bearer_token_file` the user had written by hand; re-add it in `config.toml`.)
7. **Proxies.** reqwest applies `HTTP_PROXY`/`ALL_PROXY` to `http://127.0.0.1` unless `NO_PROXY` excludes it, so a token-file server on
   a loopback URL builds its client with `no_proxy()` (`fuigo-mcp/src/servers.rs`, next to the `local_agent_endpoint` case). Non-loopback
   servers must be https, where a proxy sees only a TLS tunnel. Not unit-tested (reaching the builder's proxy setting needs a process
   environment change); verified by reading the builder.

## Differs from upstream
Honoured only in the user's own `config.toml`; owner-only file checks (upstream only caps size and timeout); loopback or https only; one
credential per server; no setup-template rendering of the path; the field travels under `_meta["fuigo/mcp/bearerTokenFile"]`; Windows refused;
token registered with the scrubber; errors carry no path.

## Stated limits
- Only the final path component is `O_NOFOLLOW`; a symlinked directory earlier in the path is followed (the file's own owner and mode are still checked).
- Ownership is the effective uid; ACLs and extended attributes on Linux are not examined.
- Scrubbing: the token is registered with the sent-credential scrubber, which covers logs, display and telemetry sinks. Successful MCP tool RESULTS fed to the model, and ACP `data` fields other than `message`, are not scrubbed (no existing hook for tool results; not redesigned here), so an MCP server given a token can return it in its results. Stated in the user guide.
- A campaign cannot change an existing MCP server at all (including `enabled`); it can add new servers, without token settings.
- The provenance check compares the user layer file as loaded now; an edit of `config.toml` is the user's own change and is honoured.
- A read that stalls beyond 5 s fails the request; the blocking thread stays until the OS returns (one per server).
- No Windows support in this release.
