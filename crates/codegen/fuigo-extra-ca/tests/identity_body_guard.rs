//! P54 guard: identity carried in request BODIES only appears in reviewed places.
//!
//! P43's `identity_header_guard` pins every identity-class HEADER writer. P54 applied the same
//! disclosure rule to identity in bodies (OTLP resource attributes, Mixpanel, the session
//! registry, the session backend, review-comment records) and classified every site in the R063
//! receipt. This test scans the source of `crates/` and `prod/` and counts, per file, every way a
//! new body could pick up an identity value:
//!
//! * a call of the persisted machine id, `agent_id()` / `agent_id_async()`;
//! * a quoted body key that names who is calling (`"agentId"`, `"device_id"`, `"user.id"`,
//!   `"distinct_id"`, `"principal"`, `"author_email"`, …);
//! * a field declaration or struct-literal field with such a name, at any visibility
//!   (`device_id: …` — `rename_all` turns it into a wire key no literal shows);
//! * a Mixpanel profile write, `.engage(`.
//!
//! P77 added the OS host name (`"hostname"` / `hostname:`) to both lists: it had never been pinned, which is how the
//! relay-sync `initialize` response kept sending it to any configured relay. R082 classifies every site.
//!
//! P81 (R086): the ACP `initialize` response's `_meta.agentId` (the persisted machine id) was classified by R063 row 12
//! as "the local ACP client over stdio". That was incomplete: `agent/app.rs` forwards every agent line to the relay in
//! headless-relay and leader mode. The relay socket writer (`agent/relay.rs` `relay_outbound_frame`) now sends a relay
//! that is not FluxRouter-operated the relay-origin pseudonym instead, and withholds who is signed in (the account
//! fields of the `authenticate`, `fuigo/auth/info`, `fuigo/auth/check_subscription` and `fuigo/auth/logout`
//! responses, and the owner ids of the cloud-environment responses) from it. R086 classifies every identity value that crosses that bridge.
//!
//! The per-file counts are pinned in [`EXPECTED`]. A new site anywhere changes a count and fails
//! here, which forces it to be classified against the P54 rule (FluxRouter-operated: keep;
//! configured by the user for exactly this data: keep and record; anything else: withhold or
//! pseudonymise with `IdentityDisclosure::body_identity` / `body_key_for`) and the pin to be
//! updated in the same change. On failure the test prints the actual table, ready to paste after
//! review. The pin is a baseline: files outside the R063 site table (deserialisers, local state,
//! tests, sampler header plumbing already gated by P30/P43) are counted so that a NEW use in them
//! is caught too.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Quoted body keys that name the caller. Exact case: these are wire keys.
const BODY_KEYS: [&str; 23] = [
    "email",
    "agentId",
    "agent_id",
    "deviceId",
    "device_id",
    "userId",
    "user_id",
    "teamId",
    "team_id",
    "deployment_id",
    "organization_id",
    "distinct_id",
    "principal",
    "author_email",
    "authorEmail",
    "user_email",
    "user.id",
    "team.id",
    "organization.id",
    "deployment.id",
    "api_key.id",
    "user.email",
    // P77 (R082): the OS host name is a stable machine identifier too.
    "hostname",
];

/// Field names whose `pub <name>:` declaration puts an identity value in a serialised body.
const FIELD_NAMES: [&str; 11] = [
    "email",
    "user_email",
    "agent_id",
    "device_id",
    "user_id",
    "team_id",
    "organization_id",
    "deployment_id",
    "principal",
    "author_email",
    "hostname",
];

/// Reviewed per-file counts (path relative to the repo root). Every file not listed must count 0.
const EXPECTED: &[(&str, usize)] = &[
    // Pinned at P54 (R063). The sites the receipt classifies (OTLP resource, Mixpanel, session
    // registry, session backend upsert, review comments, feedback author, external OTEL, ACP
    // initialize, LOC sink, share/session_admin/worktree callers of the upsert) are in R063's
    // table; the rest is the baseline (deserialisers, local logs and state, tests, sampler
    // header plumbing gated by P30/P43), and R063's proposals name the ones that may still reach
    // a body outside P54's ownership.
    ("crates/codegen/fuigo-agent/src/plugins/manifest.rs", 2),
    ("crates/codegen/fuigo-auth/src/auth_provider.rs", 9), // P70a (R087): +4 are the quoted field names `"user_id"`, `"team_id"`, `"deployment_id"`, `"organization_id"` in `CredentialSnapshot`'s hand-written redacting `Debug` (it prints what the derive it replaced printed); +1 is a unit-test fixture literal `user_id: Some("p70-user")`. No body site
    ("crates/codegen/fuigo-config/src/managed_cache.rs", 3),
    ("crates/codegen/fuigo-config/src/managed_cache/claim_tests.rs", 4),
    ("crates/codegen/fuigo-config/src/managed_cache/tests.rs", 47),
    ("crates/codegen/fuigo-config/src/signed_policy/claim_tests.rs", 1),
    ("crates/codegen/fuigo-config/src/signed_policy/tests.rs", 19),
    ("crates/codegen/fuigo-fast-worktree/src/bin/nfs_create_latency_bench.rs", 1),
    ("crates/codegen/fuigo-fast-worktree/src/git/safety_tests/git_dir.rs", 2),
    ("crates/codegen/fuigo-hunk-tracker/src/actor/tests.rs", 2),
    ("crates/codegen/fuigo-hunk-tracker/src/loc/mod.rs", 7),
    ("crates/codegen/fuigo-hunk-tracker/src/loc/tests.rs", 2),
    ("crates/codegen/fuigo-mcp/src/elicitation.rs", 4),
    ("crates/codegen/fuigo-mcp/src/servers_tests.rs", 14),
    ("crates/codegen/fuigo-mixpanel/src/lib.rs", 1),
    ("crates/codegen/fuigo-pager-minimal/src/panel.rs", 1), // P77: `hostname: None` in a session-row fixture; local UI
    ("crates/codegen/fuigo-pager-pty-harness/src/flows.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/background.rs", 3),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/mcp.rs", 5),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/mod.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/permissions.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/routing.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/session_notification.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/tests/goals.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/tests/interactions.rs", 7),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/tests/mod.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/tests/queue_and_adoption.rs", 8),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/tests/settings.rs", 3),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/tests/turn_completion.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/acp_handler/workflow_ingest.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/actions.rs", 133),
    ("crates/codegen/fuigo-pager/src/app/agent_view/cta.rs", 3),
    ("crates/codegen/fuigo-pager/src/app/agent_view/dock_input_tests.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/agent_view/key_owner_tests.rs", 5),
    ("crates/codegen/fuigo-pager/src/app/agent_view/paste.rs", 3),
    ("crates/codegen/fuigo-pager/src/app/agent_view/shell_completion.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/agent_view/workflows_overlay.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/app_view.rs", 4), // P77: +1 `hostname` field of the session-picker row; local UI
    ("crates/codegen/fuigo-pager/src/app/app_view_tests.rs", 8), // P77: +3 `hostname: None` fixtures
    ("crates/codegen/fuigo-pager/src/app/dispatch/auth.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/dispatch/billing.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/dispatch/cta.rs", 6),
    ("crates/codegen/fuigo-pager/src/app/dispatch/dashboard.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/dispatch/interject.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/dispatch/notes.rs", 10),
    ("crates/codegen/fuigo-pager/src/app/dispatch/prompt.rs", 7),
    ("crates/codegen/fuigo-pager/src/app/dispatch/queue.rs", 4),
    ("crates/codegen/fuigo-pager/src/app/dispatch/rewind.rs", 9),
    ("crates/codegen/fuigo-pager/src/app/dispatch/router.rs", 18),
    ("crates/codegen/fuigo-pager/src/app/dispatch/session/fork.rs", 5),
    ("crates/codegen/fuigo-pager/src/app/dispatch/session/lifecycle.rs", 5),
    ("crates/codegen/fuigo-pager/src/app/dispatch/session/load.rs", 4),
    ("crates/codegen/fuigo-pager/src/app/dispatch/session/modal.rs", 2),
    ("crates/codegen/fuigo-pager/src/app/dispatch/settings/setters.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/dispatch/settings/ui.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/dispatch/status.rs", 13),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/auth.rs", 6),
    // P119 (+4): test fixtures for typed verdicts building `TaskResult::PromptResponse`; no request body. Keep.
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/billing.rs", 21),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/cta_e2e.rs", 57),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/dashboard.rs", 3),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/mod.rs", 3), // P77: +1 `hostname: None` fixture
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/notes.rs", 14), // P152: +2 `agent_id:` are the pager's local tab id in `TaskResult::FeedbackComplete` test literals (an in-process action, never a request body).
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/prompt.rs", 49), // P152: +2 `agent_id:` are the pager's local tab id in test action literals (in-process, never a request body).
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/queue_release.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/rewind.rs", 21),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/router.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/session/fork.rs", 14),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/session/lifecycle.rs", 25), // P66 (97efd30a) deleted the dead local-workspace tests; pager-local fixtures, no body site (re-pinned by P54-K, R080 §11)
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/session/load.rs", 48),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/session/modal.rs", 6),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/settings.rs", 4),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/status.rs", 27),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/task_result.rs", 35),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/transcript.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/dispatch/tests/turn.rs", 7),
    ("crates/codegen/fuigo-pager/src/app/dispatch/transcript.rs", 9),
    ("crates/codegen/fuigo-pager/src/app/effects/helpers.rs", 4), // P77: +1 reads `hostname` from a session-list entry (inbound); local UI
    ("crates/codegen/fuigo-pager/src/app/effects/tests.rs", 3), // P77: +1 fixture
    ("crates/codegen/fuigo-pager/src/app/event_loop.rs", 8), // P66 (97efd30a) deleted the dead local-workspace feature; pager-local, no body site (re-pinned by P54-K, R080 §11)
    ("crates/codegen/fuigo-pager/src/app/external_editor.rs", 10),
    ("crates/codegen/fuigo-pager/src/app/foreign_sessions.rs", 2), // P77: `hostname: None` rows; local UI
    ("crates/codegen/fuigo-pager/src/app/modals.rs", 1), // P77: `hostname: None` row; local UI
    ("crates/codegen/fuigo-pager/src/app/queue_edit.rs", 1),
    ("crates/codegen/fuigo-pager/src/app/session_load_barrier.rs", 3),
    ("crates/codegen/fuigo-pager/src/app/status_line_policy.rs", 4),
    ("crates/codegen/fuigo-pager/src/app/turn_completion.rs", 1),
    ("crates/codegen/fuigo-pager/src/plugin_cmd.rs", 1),
    ("crates/codegen/fuigo-pager/src/views/dashboard/state.rs", 1),
    ("crates/codegen/fuigo-pager/src/views/elicitation_view/tests.rs", 5),
    ("crates/codegen/fuigo-pager/src/views/modal.rs", 1),
    ("crates/codegen/fuigo-pager/src/views/session_picker.rs", 1), // P77: `hostname: None` fixture
    ("crates/codegen/fuigo-pager/src/views/tasks_pane.rs", 2),
    ("crates/codegen/fuigo-pager/src/views/welcome/mod.rs", 1), // P77: `hostname: None` fixture
    ("crates/codegen/fuigo-pager/src/views/workflows.rs", 9),
    ("crates/codegen/fuigo-pager/tests/pty_e2e/subscription_watch_and_gate_verify_pty.rs", 2),
    ("crates/codegen/fuigo-plugin-marketplace/src/git.rs", 1),
    ("crates/codegen/fuigo-plugin-marketplace/src/index.rs", 1),
    ("crates/codegen/fuigo-ratatui-inline/benches/bench.rs", 2),
    ("crates/codegen/fuigo-sampler/src/actor/state.rs", 2),
    ("crates/codegen/fuigo-sampler/src/client.rs", 34),
    ("crates/codegen/fuigo-sampler/src/config.rs", 6), // P70a (R087): +2 are the quoted field names `"deployment_id"`, `"user_id"` in `SamplerConfig`'s hand-written redacting `Debug`. No body site
    ("crates/codegen/fuigo-sampler/tests/test_actor.rs", 2),
    ("crates/codegen/fuigo-sampling-types/src/messages.rs", 1),
    ("crates/codegen/fuigo-sandbox/src/network_policy.rs", 1), // P77: `hostname` of a network-policy rule (a destination host, not this machine)
    ("crates/codegen/fuigo-shell/src/agent/auth_method.rs", 2),
    ("crates/codegen/fuigo-shell/src/agent/chat_modes.rs", 1),
    ("crates/codegen/fuigo-shell/src/agent/config.rs", 4),
    ("crates/codegen/fuigo-shell/src/agent/feedback_client.rs", 6),
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/acp_agent.rs", 9), // P77: +1 ACP `initialize` `_meta.hostname` (stdio to the local client: keep; over a bridged relay it is withheld by `relay_outbound_frame` in agent/relay.rs); +1 `RegisterRequest.hostname` (gated by `register_body_for`, P54). P81 (R086): the same response's `_meta.agentId` (`agent_id()`, R063 row 12) is NOT stdio-only: over a bridged relay it is replaced by the relay-origin pseudonym in `relay_outbound_frame`; stdio / IPC: kept
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/agent_ops.rs", 4),
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/mod.rs", 17), // P81 (R086): 2 of these are `email:` / `team_id:` of `auth::AuthMeta` in `auth_response_with_meta` (the `authenticate` response's `_meta`, and `fuigo/auth/check_subscription`): the local ACP client keeps them; over a bridged relay that is not FluxRouter-operated they are withheld by `relay_outbound_frame` (agent/relay.rs)
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/settings_manager.rs", 2),
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/tests.rs", 14),
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/tests/p83_teardown_tests.rs", 2), // P83 (d042e473) teardown test: `email:` + `team_id:` fields of a local `FuigoAuth` fixture; test-only, no body site (R092)
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/tests/p81_relay_bridge_tests.rs", 17), // P81 tests: the real agent's `initialize`, `fuigo/auth/info` and auth metadata through the relay writer (4 `"agentId"`, 3 `"hostname"`, 3 `"email"`, 2 `"team_id"`, 1 `"teamId"`, 1 `agent_id()` call; 3 fields of a session fixture: `email:`, `team_id:`, `organization_id:`)
    ("crates/codegen/fuigo-shell/src/agent/relay.rs", 158), // The relay socket writer's filter (`relay_outbound_frame`) and its tests. Production (10): 2 `"hostname"` (P77: withheld from `result._meta` of ACP initialize and from the `fuigo/session/list` rows), 2 `"agentId"` (P81: the machine id in `result._meta` becomes the relay-origin pseudonym), 2 `"email"`, 1 `"team_id"`, 2 `"teamId"`, 1 `"userId"` (P81: the key lists of the account fields withheld from the auth responses and of the owner ids withheld from the cloud-environment responses). Tests (148): 48 `"hostname"`, 42 `"agentId"`, 21 `"email"`, 15 `"userId"`, 10 `"teamId"`, 5 `"team_id"`, 1 `agent_id()` call, 6 fixture fields (2 `user_id:`, 2 `team_id:`, `hostname:`, `email:`). All of it applies only to a relay that is not FluxRouter-operated
    ("crates/codegen/fuigo-shell/src/agent/session_registry_client.rs", 22), // P77: +9 `hostname` of the registry register body (omitted at a non-FluxRouter registry by `register_body_for`, P54), the list entry (inbound) and tests
    ("crates/codegen/fuigo-shell/src/agent/subagent/handle_request.rs", 3),
    ("crates/codegen/fuigo-shell/src/agent/subagent/mod.rs", 2),
    ("crates/codegen/fuigo-shell/src/agent/subscription_check.rs", 7),
    ("crates/codegen/fuigo-shell/src/auth/config.rs", 3),
    ("crates/codegen/fuigo-shell/src/auth/credential_provider.rs", 9),
    ("crates/codegen/fuigo-shell/src/auth/device_code.rs", 1),
    ("crates/codegen/fuigo-shell/src/auth/external_auth.rs", 5),
    ("crates/codegen/fuigo-shell/src/auth/flow.rs", 10),
    ("crates/codegen/fuigo-shell/src/auth/manager.rs", 1),
    ("crates/codegen/fuigo-shell/src/auth/manager_tests.rs", 44),
    ("crates/codegen/fuigo-shell/src/auth/meta.rs", 4),
    ("crates/codegen/fuigo-shell/src/auth/model.rs", 23),
    ("crates/codegen/fuigo-shell/src/auth/oidc/login.rs", 1),
    ("crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs", 18),
    ("crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs", 4),
    ("crates/codegen/fuigo-shell/src/auth/oidc/test_helpers.rs", 2),
    ("crates/codegen/fuigo-shell/src/auth/p47_service_wire_tests.rs", 1), // P47: FuigoAuth test fixture
    ("crates/codegen/fuigo-shell/src/auth/recovery.rs", 4),
    ("crates/codegen/fuigo-shell/src/auth/refresh/auth_backend_contract_tests.rs", 3),
    ("crates/codegen/fuigo-shell/src/auth/refresh/oidc_refresher.rs", 1),
    ("crates/codegen/fuigo-shell/src/auth/refresh/oidc_refresher_tests.rs", 37),
    ("crates/codegen/fuigo-shell/src/config/reloader.rs", 1),
    ("crates/codegen/fuigo-shell/src/extensions/auth.rs", 7), // P81 (R086): the `fuigo/auth/info` response (`email:`, `team_id:`, `organization_id:` of `AuthInfoResponse`, declared and filled) and the `"email"` of `fuigo/auth/logout`: the local ACP client keeps them; over a bridged relay that is not FluxRouter-operated they are withheld by `relay_outbound_frame` (agent/relay.rs)
    ("crates/codegen/fuigo-shell/src/extensions/bundle.rs", 8),
    ("crates/codegen/fuigo-shell/src/extensions/feedback.rs", 9),
    ("crates/codegen/fuigo-shell/src/extensions/notification.rs", 1),
    ("crates/codegen/fuigo-shell/src/extensions/session_admin.rs", 1),
    ("crates/codegen/fuigo-shell/src/extensions/share.rs", 1),
    ("crates/codegen/fuigo-shell/src/extensions/worktree.rs", 1),
    ("crates/codegen/fuigo-shell/src/leader/server.rs", 5), // P77: the hub registration `metadata.hostname` (key, removal, parameter), gated by `hub_registration_identity`
    ("crates/codegen/fuigo-shell/src/leader/server_tests.rs", 6), // P77 (R082): the mock hub's hello ACK fixture names "user_id" (inbound, test only); the rest are `hostname` assertions of the P77 tests
    ("crates/codegen/fuigo-shell/src/managed_config/response.rs", 2),
    ("crates/codegen/fuigo-shell/src/managed_config/store.rs", 4),
    ("crates/codegen/fuigo-shell/src/managed_config/supervisor.rs", 4),
    ("crates/codegen/fuigo-shell/src/managed_config/tests.rs", 15), // P147: +2 are `deployment_id: None` / `team_id: None` in a test `ManagedConfigResponse` (a FluxRouter response being parsed, not a body Fuigo sends).
    ("crates/codegen/fuigo-shell/src/relay/sync.rs", 14), // P77: the relay-sync `initialize` `_meta.hostname`, gated by `relay_initialize_meta` (parameter, key, removal), and its tests (`hostname` and "agentId" fixtures); 1 is the pre-P77 session-scoped "agentId"
    ("crates/codegen/fuigo-shell/src/remote/client.rs", 6),
    ("crates/codegen/fuigo-shell/src/remote/client_tests.rs", 17),
    ("crates/codegen/fuigo-shell/src/remote/mod.rs", 2),
    ("crates/codegen/fuigo-shell/src/remote/model_source/oai.rs", 2),
    ("crates/codegen/fuigo-shell/src/remote/skills_client.rs", 49), // P70a (R087): +2 are the quoted field names `"user_id"`, `"email"` in `SkillsAuthCandidate`'s hand-written redacting `Debug`. No body site
    ("crates/codegen/fuigo-shell/src/remote/sync.rs", 3),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/laziness.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/memory_dream.rs", 2),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/recap.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/sampler_turn.rs", 3),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/side_call.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/turn.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/workflow.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/acp_session_tests/auth_error_no_retry_tests.rs", 4),
    ("crates/codegen/fuigo-shell/src/session/acp_session_tests/cancel_running_task_tests.rs", 8),
    ("crates/codegen/fuigo-shell/src/session/feedback_manager.rs", 2),
    ("crates/codegen/fuigo-shell/src/session/fork.rs", 2),
    ("crates/codegen/fuigo-shell/src/session/goal_classifier/evidence.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/goal_evaluator.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/helpers/session_compact.rs", 3),
    ("crates/codegen/fuigo-shell/src/session/helpers/session_compact_reasoning_compaction_regression_tests.rs", 2),
    ("crates/codegen/fuigo-shell/src/session/mcp_elicitation.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/merge.rs", 6), // P77: `hostname` of merged session rows (from the registry list). Serialised into the `fuigo/session/list` response: local over stdio/IPC; over a bridged relay withheld by `relay_outbound_frame`
    ("crates/codegen/fuigo-shell/src/session/persistence_feedback_tests.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/slash_commands.rs", 15),
    ("crates/codegen/fuigo-shell/src/session/slash_commands_tests.rs", 19),
    ("crates/codegen/fuigo-shell/src/session/tool_index_tests.rs", 2),
    ("crates/codegen/fuigo-shell/src/session/unified_list/cursor.rs", 1), // P77: fixture
    ("crates/codegen/fuigo-shell/src/session/unified_list/facets.rs", 5), // P77: fixtures
    ("crates/codegen/fuigo-shell/src/session/unified_list/mod.rs", 3), // P77: fixtures of the `fuigo/session/list` response (see session/merge.rs)
    ("crates/codegen/fuigo-shell/src/session/unified_list/row.rs", 1), // P77: `hostname: None` row (see session/merge.rs)
    ("crates/codegen/fuigo-shell/src/session/workflow/host_service.rs", 4),
    ("crates/codegen/fuigo-shell/src/session/workflow/notify.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/workflow/tracker.rs", 6),
    ("crates/codegen/fuigo-shell/src/session/worktree.rs", 3),
    ("crates/codegen/fuigo-shell/src/test_support/lsp_runtime.rs", 2),
    ("crates/codegen/fuigo-shell/src/tools/config.rs", 2),
    ("crates/codegen/fuigo-shell/src/upload/feedback_archive.rs", 7),
    ("crates/codegen/fuigo-shell/src/upload/gcs.rs", 1),
    ("crates/codegen/fuigo-shell/src/util/user_identity.rs", 19),
    ("crates/codegen/fuigo-shell/tests/common/mod.rs", 4),
    ("crates/codegen/fuigo-shell/tests/external_auth_expired_credential.rs", 2),
    ("crates/codegen/fuigo-shell/tests/murage_conformance_acp.rs", 5), // P70a (R087): +2 are `"user_id": ""` and `"email": null` in the `auth.json` fixture a test writes to its sandbox (`seed_auth_json`); a local file, no body site
    ("crates/codegen/fuigo-shell/tests/subagent_sweep_support/mod.rs", 1),
    ("crates/codegen/fuigo-shell/tests/test_startup_prefetch_repair_skip.rs", 2),
    ("crates/codegen/fuigo-telemetry/src/client.rs", 40),
    ("crates/codegen/fuigo-telemetry/src/events/mod.rs", 6),
    ("crates/codegen/fuigo-telemetry/src/external/emit.rs", 4),
    ("crates/codegen/fuigo-telemetry/src/external/mod.rs", 8),
    ("crates/codegen/fuigo-telemetry/src/external/schema.rs", 8),
    ("crates/codegen/fuigo-telemetry/src/external/tests.rs", 16),
    ("crates/codegen/fuigo-telemetry/src/id.rs", 7),
    ("crates/codegen/fuigo-telemetry/src/otel_layer/mod.rs", 63),
    ("crates/codegen/fuigo-telemetry/src/otel_layer/redact.rs", 4),
    ("crates/codegen/fuigo-telemetry/tests/agent_id_prewarm.rs", 2),
    ("crates/codegen/fuigo-telemetry/tests/external_otlp_gates_on.rs", 9),
    ("crates/codegen/fuigo-telemetry/tests/machine_id_off_boot_path.rs", 2),
    ("crates/codegen/fuigo-telemetry/tests/manual_auth_emit.rs", 5),
    ("crates/codegen/fuigo-test-support/src/mock_server.rs", 3),
    ("crates/codegen/fuigo-test-support/src/sandbox.rs", 1),
    ("crates/codegen/fuigo-tools/src/mcp_elicitation/schema.rs", 1),
    ("crates/codegen/fuigo-tools/src/mcp_elicitation/schema_tests.rs", 5),
    ("crates/codegen/fuigo-tools/src/mcp_elicitation/types.rs", 4),
    ("crates/codegen/fuigo-tools/src/mcp_elicitation/validate_tests.rs", 7),
    ("crates/codegen/fuigo-workflow/src/engine.rs", 1),
    ("crates/codegen/fuigo-workflow/src/host.rs", 1),
    ("crates/codegen/fuigo-workflow/src/validate.rs", 1),
    ("crates/codegen/fuigo-workspace-types/src/rpc/git.rs", 1),
    ("crates/codegen/fuigo-workspace-types/src/types/config.rs", 2), // P70a (R087): +1 is the quoted field name `"agent_id"` in `AgentSessionConfig`'s hand-written redacting `Debug`. No body site
    ("crates/codegen/fuigo-workspace-types/src/types/session.rs", 1),
    ("crates/codegen/fuigo-workspace-types/tests/wire_round_trip.rs", 2),
    ("crates/codegen/fuigo-workspace/src/bin/workspace_server_probe.rs", 1),
    ("crates/codegen/fuigo-workspace/src/config.rs", 3),
    ("crates/codegen/fuigo-workspace/src/handle_tests.rs", 1),
    ("crates/codegen/fuigo-workspace/src/hub_auth/mod.rs", 19), // P70a (R087): +1 is the quoted field name `"user_id"` in `AuthEntry`'s hand-written redacting `Debug`, +1 is `"user_id": "p70-user"` in a unit-test JSON fixture; no body site | P47 (d429c380) deleted a loopback test whose auth.json fixture quoted "user_id"; local file read, no body site (re-pinned by P54-K, R080 §11)
    ("crates/codegen/fuigo-workspace/src/hub_auth/proactive_tests.rs", 2),
    ("crates/codegen/fuigo-workspace/src/permission/auto_mode/mod.rs", 1), // P77: the `hostname` shell command in an allowlist; not a body
    ("crates/codegen/fuigo-workspace/src/permission/manager/mod.rs", 3), // P77: the `hostname` shell command in allowlists and a test; not a body
    ("crates/codegen/fuigo-workspace/src/publish.rs", 1),
    ("crates/codegen/fuigo-workspace/src/session/git_gate_tests.rs", 1),
    ("crates/codegen/fuigo-workspace/src/session/git_restore_code_tests.rs", 2),
    ("crates/codegen/fuigo-workspace/src/session/git_tests.rs", 3),
    ("crates/codegen/fuigo-workspace/src/upload/environment.rs", 12), // 7 `user_id` tokens (R063). P71v2 (R073): +1, a test's key list asserting "user_id" is null for a third-party proxy. P77: +3 `hostname` (`$HOSTNAME`) of the workspace environment upload (field, parameter, a test key) and, s20 restack, +1 `"hostname"` in that same P71v2 key list. The record is gated since P71v2: `for_method` nulls `hostname`, `server_id`, `user_id`, `principal_id` for a storage proxy that is not FluxRouter-operated (R082 s20 addendum)
    ("crates/common/fuigo-computer-hub-core/src/local.rs", 1),
    ("crates/common/fuigo-computer-hub-core/src/registry.rs", 1),
    ("crates/common/fuigo-computer-hub-core/src/remote.rs", 2),
    ("crates/common/fuigo-computer-hub-core/src/transport.rs", 1),
    ("crates/common/fuigo-computer-hub-core/tests/compound_resolver.rs", 1),
    ("crates/common/fuigo-computer-hub-core/tests/inner_dispatch.rs", 1),
    ("crates/common/fuigo-computer-hub-core/tests/local_transport.rs", 1),
    ("crates/common/fuigo-computer-hub-core/tests/tool_registry.rs", 2),
    ("crates/common/fuigo-computer-hub-sdk/src/auth.rs", 1),
    ("crates/common/fuigo-computer-hub-sdk/src/connection.rs", 3),
    ("crates/common/fuigo-computer-hub-sdk/src/connection_borrow.rs", 1),
    ("crates/common/fuigo-computer-hub-sdk/src/connection_tests.rs", 10), // P47: +1 mock hub reply in a test
    ("crates/common/fuigo-computer-hub-sdk/src/harness.rs", 1),
    ("crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs", 4),
    ("crates/common/fuigo-computer-hub-sdk/src/pool.rs", 1),
    ("crates/common/fuigo-message-delivery-core/src/envelope.rs", 3),
    ("crates/common/fuigo-test-utils/src/git.rs", 1),
    ("crates/common/fuigo-tool-protocol/src/bot_relay.rs", 47),
    ("crates/common/fuigo-tool-protocol/src/frames.rs", 13), // P77: `ServerIdentityMetadata.hostname` (type, lenient reader, tests); the only producer is the leader hub registration
    ("crates/common/fuigo-tool-protocol/src/handshake.rs", 1),
    ("crates/common/fuigo-tool-protocol/src/registration.rs", 2),
    ("crates/common/fuigo-tool-protocol/tests/bot_relay_conformance.rs", 3),
    ("crates/common/fuigo-tool-protocol/tests/serde_roundtrip.rs", 7),
    ("crates/common/fuigo-tool-types/src/ext.rs", 4),
    ("prod/mc/cli-chat-proxy-types/src/deployment_config_types.rs", 7),
    ("prod/mc/cli-chat-proxy-types/src/feedback_types.rs", 3),
    ("prod/mc/cli-chat-proxy-types/src/metadata_types.rs", 14),
    ("prod/mc/cli-chat-proxy-types/src/sandbox_types.rs", 2), // `user_id` / `team_id` of `SandboxEnvironment` (the backend's record of who owns a cloud environment). P81 (R086): the agent returns it in the `fuigo/cloud/env/list`, `create` and `update` responses; the local ACP client keeps the ids, over a bridged relay that is not FluxRouter-operated they are withheld by `relay_outbound_frame` (agent/relay.rs)
    ("prod/mc/cli-chat-proxy-types/src/session_types.rs", 3), // P77: +2 `hostname` of the registry request/entry types (server side)
];

/// Occurrences of `word` in `line` on identifier boundaries, optionally requiring `next` right after.
fn word_count(line: &str, word: &str, next: Option<char>) -> usize {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(word)
        .filter(|(at, _)| {
            let before = line[..*at].chars().next_back();
            let after = line[at + word.len()..].chars().next();
            !before.is_some_and(is_ident)
                && !after.is_some_and(is_ident)
                && next.is_none_or(|n| after == Some(n))
        })
        .count()
}

/// The body-identity token count of one source text.
fn count_tokens(src: &str) -> usize {
    let mut n = 0;
    for line in src.lines() {
        let trimmed = line.trim_start();
        // A definition is not a use.
        let defines = trimmed.contains("fn agent_id(") || trimmed.contains("fn agent_id_async(");
        if !defines {
            n += word_count(line, "agent_id", Some('('));
            n += word_count(line, "agent_id_async", Some('('));
        }
        n += BODY_KEYS
            .iter()
            .map(|key| line.matches(&format!("\"{key}\"")).count())
            .sum::<usize>();
        // A field declaration (any visibility) or a struct-literal field: `[pub[(…)] ]name: …`.
        let field = trimmed
            .strip_prefix("pub(crate) ")
            .or_else(|| trimmed.strip_prefix("pub(super) "))
            .or_else(|| trimmed.strip_prefix("pub "))
            .unwrap_or(trimmed);
        n += FIELD_NAMES
            .iter()
            .filter(|name| field.starts_with(&format!("{name}:")))
            .count();
        n += line.matches(".engage(").count();
    }
    n
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `(relative path, count)` for every scanned file with a non-zero count, plus the file total.
fn scan() -> (BTreeMap<String, usize>, usize) {
    let root = repo_root();
    let mut files = Vec::new();
    for top in ["crates", "prod"] {
        rust_files(&root.join(top), &mut files);
    }
    let this_file = Path::new(file!()).file_name().unwrap().to_owned();
    let mut counts = BTreeMap::new();
    let mut total = 0;
    for path in &files {
        if path.file_name() == Some(this_file.as_os_str())
            && path.parent().is_some_and(|p| p.ends_with("fuigo-extra-ca/tests"))
        {
            continue;
        }
        let Some(rel) = path
            .strip_prefix(&root)
            .ok()
            .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        else {
            continue;
        };
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        total += 1;
        let n = count_tokens(&src);
        if n > 0 {
            counts.insert(rel, n);
        }
    }
    (counts, total)
}

/// Positive control: the scanner sees every spelling a new body site could use.
#[test]
fn scanner_counts_every_spelling_of_body_identity() {
    let src = r#"
        pub fn agent_id() -> String { todo!() }
        let a = agent_id();
        let b = fuigo_telemetry::id::agent_id_async().await;
        let body = json!({ "agentId": a, "user.id": u, "principal": p });
        pub device_id: Option<String>,
        pub(crate) author_email: Option<String>,
        user_id: String,
        email: String,
        pub user_email: Option<String>,
        let e = json!({ "email": auth.email });
        mixpanel.engage(&id, props);
        let not_one = "agent_instance_id"; let x = my_agent_id(); let y = self.agent_id;
        pub device_identifier: String,
        let meta = json!({ "hostname": host });
        hostname: Some(host),
        let not_a_field = hostname_of(x); let z = self.hostname;
    "#;
    // agent_id() (1) + agent_id_async( (1) + three keys (3) + five fields, public or private,
    // e-mail included (5) + "email" (1) + engage (1); the definition, `agent_instance_id`,
    // `my_agent_id()`, a field read and a longer field name are not tokens. P77: the `"hostname"` key (1)
    // and a `hostname:` field (1); a call and a field read are not.
    assert_eq!(count_tokens(src), 14);
    assert_eq!(count_tokens("let ok = \"session_id\";"), 0);
}

/// Positive control on the real tree: the walk reaches the workspace and finds the known sites.
#[test]
fn body_scan_reaches_the_known_sites() {
    let (counts, files) = scan();
    assert!(files > 1000, "only {files} .rs files scanned: the walk is not reaching the tree");
    for known in [
        "crates/codegen/fuigo-telemetry/src/client.rs",
        "crates/codegen/fuigo-shell/src/agent/session_registry_client.rs",
        "crates/codegen/fuigo-shell/src/remote/client.rs",
    ] {
        assert!(counts.get(known).is_some_and(|n| *n > 0), "{known} not found by the scan");
    }
}

/// The guard. A change here means a new or removed body-identity site: classify it against the
/// P54 rule, then update [`EXPECTED`] from the printed table.
#[test]
fn body_identity_sites_are_exactly_the_reviewed_ones() {
    let (actual, _) = scan();
    let expected: BTreeMap<String, usize> =
        EXPECTED.iter().map(|(path, n)| ((*path).to_string(), *n)).collect();
    if actual != expected {
        let mut table = String::new();
        for (path, n) in &actual {
            table.push_str(&format!("    (\"{path}\", {n}),\n"));
        }
        let mut diff = String::new();
        for (path, n) in &actual {
            if expected.get(path) != Some(n) {
                diff.push_str(&format!("  {path}: expected {:?}, found {n}\n", expected.get(path)));
            }
        }
        for (path, n) in &expected {
            if !actual.contains_key(path) {
                diff.push_str(&format!("  {path}: expected {n}, found 0\n"));
            }
        }
        panic!(
            "body-identity sites changed (P54 guard). Classify each against the P54 rule:\n{diff}\nActual table:\n{table}"
        );
    }
}
