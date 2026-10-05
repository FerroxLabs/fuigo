Independent pre-gate audit of packet P113 (Fuigo strike), read-only. Repository: this worktree, branch strike/p113.
Diff range: d1b6ba580eb587594d52b5a2550c1bd82a8bcd60..e1171e61 (`git diff d1b6ba58..e1171e61`). Commit ed9af340 adds the
regression tests (they fail at d1b6ba58), e1171e61 the fixes. Do not build or run anything.

The findings being fixed (Phase 7 credential-egress audits):
- CIE-01 HIGH: a stdio MCP server's non-JSON stdout line holding a credential Fuigo sent (e.g. the saved key handed via
  an explicit ${FUIGO_API_KEY} reference, which P70a records) was written raw by `record_decode_error`
  (fuigo-mcp/src/servers.rs) through `EventWriter` (fuigo-session-events/src/log.rs) into events.jsonl and then packed
  by the feedback archive (fuigo-shell/src/upload/feedback_archive.rs).
- CIE-02 HIGH + E1 HIGH: Fuigo's own secret variables (FUIGO_AGENT_SECRET, FUIGO_AUTH, FUIGO_DEPLOYMENT_KEY,
  FUIGO_EXTRA_AUTH_KEY, OTLP header variables, ...) were inherited by stdio MCP / LSP / hook / bash children
  (P86 denylist in fuigo-tools/src/util/shell_env_policy.rs).
- E2 MEDIUM: MCP `bearer_token_env_var` / OAuth client-secret variable names were not added to the child denylist.
- CIE-03 MEDIUM: the relay's HTTP CONNECT proxy path (fuigo-shell/src/agent/proxy.rs) logged and put into errors the
  proxy address including user:password@, and a URL without a port produced an error quoting the whole URL.

Claims of the fix:
1. Every events.jsonl line (EventWriter::emit and append_event_checked) passes P70b's sent-credential scrub
   (fuigo-secrets sent_credentials: string scrub of every JSON string, then a byte-level pass); the decode-error
   sample cap no longer cuts through a recorded credential; the feedback archive scrubs every packed file line by line.
2. A new fuigo-tools list FUIGO_INTERNAL_CREDENTIAL_ENV_VARS is part of the never-inherit denylist (is_provider_credential,
   credential_env_names); explicit env entries (server `env`, hook `env`, policy `set`) still pass. A fuigo-shell test
   pins FIRST_PARTY_CREDENTIAL_ENV_VARS and FUIGO_AGENT_SECRET against the denylist.
3. MCP credential variable names are registered at TOML parse (parse_mcp_servers_with_problems), in the hot-reload
   pre-pass (deny_credentials_named_in), in to_acp_mcp_server / oauth_config, and at resolution.
4. parse_proxy_url strips userinfo (up to the last '@'); no proxy error quotes the URL.

Find defects in the diff: wrong or incomplete fixes, other paths where the same leak remains (other EventWriter or
session-file writers of child/server/provider text, other env-inheritance routes, other places a proxy URL with
userinfo is logged or put in an error), regressions (functional breakage, behaviour changes for users, tests that
would break), tests that do not exercise the production path or would pass with the fix reverted, and process-global
state hazards in tests. For each: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, a concrete scenario, and whether a
test catches it. End with exactly one verdict line: LAND, LAND-WITH-FOLLOWUPS or DO-NOT-LAND.
