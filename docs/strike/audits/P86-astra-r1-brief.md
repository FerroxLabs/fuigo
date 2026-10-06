# P86 Astra round 1 brief

Independent security audit, read-only. Repository: this worktree. Diff range: `84569ea8..HEAD` (branch `strike/p86`;
`git diff 84569ea8 HEAD`). Do not run cargo.

Context (defect CB-1, MEDIUM): `crates/codegen/fuigo-tools/src/util/shell_env_policy.rs` held a hand-kept list of 12
credential env var names removed from every child process (bash tool / `!` commands, hooks, stdio MCP servers, LSP
servers, login-shell capture, persistent-shell state scrub). It missed `FLUX_API_KEY` (FluxRouter, the lead provider),
`ANTHROPIC_AUTH_TOKEN`, and any user-configured `env_key`, so a prompt-injected model could run `env` and read them.
Two tests were vacuous (one set the key on the command, which `env_clear` wipes; one was covered by a second list).

Claims of this change:
1. `fuigo_tools::util::shell_env_policy::provider_key_env_vars` is the single registry of provider key variables;
   `fuigo-shell/src/agent/key_discovery.rs` `PROVIDERS[*].env_vars` now reference it; a test fails if a provider
   names a variable the denylist does not cover.
2. A process-wide, grow-only registry (`register_credential_env_names`) receives every `[model.*]` /
   `[model_providers.*]` `env_key` and `env_http_headers` variable at config parse (`Config::new_from_toml_cfg`), and
   every name `EnvKeys::resolve_value` reads (remote catalogue env_keys). Core names (PATH, HOME, USER, ...) and names
   with `=`/NUL are never registered.
3. `is_provider_credential` consults both; all spawn paths already route through it (`create_env_from_vars`,
   `ShellEnvironmentPolicy::allows`, `parse_login_env_capture`, LSP `create_env`, the persistent-shell scrub).
4. The persistent-shell scrub splices registered names into a shell `case` pattern ONLY if they are shell identifiers.
5. Explicit per-server / per-hook `env`, LSP `env`, and `[shell_environment_policy] set` still deliver a key.
6. New tests plant credentials in the PARENT process environment (fresh test process), spawn through each production
   path, check child + grandchild, prove the parent env arrives (benign var) and explicit env is honoured; the planted
   names are literal so an emptied denylist cannot empty the tests.
7. `.github/workflows/release.yml` `security` job now also runs the `credential_redirects` integration tests
   (fuigo-extra-ca, fuigo-sampler), fuigo-mcp `http_policy::`, and the P86 tests, without running full suites.

Find defects: a credential-carrying variable that still reaches a child through any spawn path in scope; a way user
config can make the registry strip something essential or inject shell syntax; a race (registration after a child is
spawned from the same config); lock poisoning / performance problems on the spawn path; tests that would pass with
the fix reverted (vacuous) or that are flaky; a release.yml command that matches no test or misses one; doc
inaccuracies in `crates/codegen/fuigo-pager/docs/user-guide/18-sandbox.md`. Also say whether any FIRST-PARTY hook,
MCP server, plugin or nested `fuigo` invocation in this repository depends on `FLUX_API_KEY`, `ANTHROPIC_AUTH_TOKEN`
or a configured `env_key` being inherited.

For each finding: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, a concrete scenario, whether a test catches it.
End with one verdict line: LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.
