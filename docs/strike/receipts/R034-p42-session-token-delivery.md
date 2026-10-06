# R034 — P42: session-token delivery has one predicate (SECURITY)

**Packet:** P42 (`strike/p42`). **Parent (rebased, 2026-10-01):** `45bd14ee6a0b2fecc57b844aa758a831c69051d2`
(integration HEAD after P22/P23/P25, P45 and P17-F1). **Gated tip:** `cc3c32a7591b0893deab07a937486a7a8e42556a`.
The receipt commit follows it and touches only this file.
**Host:** `hetzner-dsm` (96 cores), lanes `/root/fuigo-builds/p42dev/` (focused runs, mutants) and
`/root/fuigo-builds/p42rp/` (gate, `rp.sh`). `CARGO_BUILD_JOBS=16 RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg
CARGO_TERM_COLOR=never`, builds under `nice -n 10`, tests through `slot-run.sh`. Toolchain digest
(`rustc -vV | sha256sum`): `b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69` (1.94.0, pinned in-tree).
**Not landed.** The coordinator lands.

Sections 3 and 4a are unchanged from the first gate. The history of the first gate (parent `5e5893df`, tip
`7aa22199`, gate NOT met: 26 fixture tests routed the session token to http loopback) is superseded by the
reworks below and by the gate in §8; it is kept in git history (`9b97c770`).

## 1. Read first

- **Gate (§8): met at `cc3c32a7`.** Headers = derived for all four packages at both revisions; tip ⊆ parent
  after isolating four `session::workflow::manager` load-timing names (3/3 pass at tip and parent); clippy: 0 new warnings.
- **Astra (§7): round 7 `LAND`** on `45bd14ee..aeb90071` and **round 8 `LAND`** on the gate-fix commit
  `aeb90071..cc3c32a7`, zero findings at any severity in both.
- **Mutants (§6): 29 of 29 killed** (M1–M26 with M5b, M16b; new M22–M26 and M23b cover the round-6 fix).
- **Round-6 fix (agreed design).** A 401 on a request whose session token was withheld (destination refused
  by `session_may_reach`) is terminal under error type `auth_destination_refused`. The shell composes the
  whole message in `fuigo_shell::extensions::notification::auth_destination_refused_message`: the
  `[endpoints]` remedy first, then one plain sentence ("The endpoint rejected a request that carried no
  credential."), then the `Model:` diagnostics, then `Endpoint:`. Arm 6 of `handle_sampling_failure`
  (`sampler_turn.rs`) calls it, drops the sampler's `Unauthorized (401) …` text, and sends **no
  `http_status`**. The text carries no `(401)`, `Unauthorized (` or `status NNN`.
  Effect in the pager (pager source unchanged): `extract_error_detail` cuts at `Model:`, so the remedy and
  sentence (195 characters, under `sanitize_user_error`'s 200 cap) are the banner; `handle_prompt_response`'s
  401 fallback never sets `reauth_prompted`, so nothing is stashed for a post-login resubmit.
  Follow-up done (`2f871772`, §10): the pager now has `WireErrorType::AuthDestinationRefused`, headline
  "Session token not sent", the remedy as its detail, and no retry or sign-in advice.
- **Round-6 LOW.** `p42_subscription_selected_by_endpoint_is_not_a_withheld_session` writes a real
  `config.toml` (own `FUIGO_HOME`, own process) with one wire slug on two entries: a ChatGPT-subscription
  entry and a credential-less loopback entry. The memo is `NotByok` with provider `None`, so only
  `selected_for_endpoint` excludes the subscription endpoint; the same slug at loopback is a withheld session
  (positive control). Mutant M25 removes that check and is caught.
- **Rebase onto `45bd14ee`** was clean (no textual conflict; P22/P23/P25 touched `auth/subscription/{flow,
  inference,mod,storage,tests}.rs`, which P42 does not edit). `session_withheld_401`'s
  `selected_for_endpoint(model_id, base_url)` call is unchanged and still matches P22–P25's signature.
  Astra round 7 confirmed by `range-diff` that all 18 earlier P42 patches are unchanged.
- **Behaviour note: the idle `/models-v2` refresh cannot fire without a compiled-in prod proxy.**
  `session_setup.rs` requires `is_cli_chat_proxy_url(base_url)` (the compiled prod cli-chat-proxy, or
  loopback) **and** `session_may_reach(base_url)` (a configured non-loopback https origin). Loopback fails the
  second; so only a base URL that is the compiled prod proxy *and* configured in `[endpoints]` passes. The
  prod proxy arm is empty in this tree, so in this build the refresh never runs. That is intended (it is a
  session-token request) but it is a functional loss for builds that relied on a loopback proxy.
- **Auxiliary service clients still send the session token unchecked** (§4b). They are packet **P47**, not P42.
- **Behaviour change (intended):** session users on now-refused URLs get a terminal `auth_destination_refused`
  error with the `[endpoints]` remedy. The exact URL set is in §3.

## 2. Commits (on `45bd14ee`)

| commit | content |
|---|---|
| `86e8f868` | The fix: one predicate, `auth::session_delivery::{session_may_reach, withhold_session_bearer}`, the value-based session-bearer registry, all inference paths, wire-level tests |
| `ff8243e0` | Audit round 1: summary client, image/voice arm, registry records only session-mode credentials and never evicts, catalogue test |
| `73dd4615` | Audit round 2: memory-embeddings seed; held static `ApiKey` is not a session token |
| `35d4d76f` | Compile fix: helper above `spawn_session_actor`'s attribute |
| `5133a946` | Audit round 3: aux fallback and `/tokenize-text` keep a held static key |
| `a56983d9` | Clippy: `?` in `withhold_session_bearer` |
| `9b97c770` | First receipt (gate not met) |
| `1daf1c9c` | Retire P30's known-defect notes (policy doc, shell-base comment) |
| `b22d4fc3` | Rework: terminal withheld-session 401; fixtures and wire tests onto the configured https origin |
| `a5f725ba` | Rework: spawn-level memory-embeddings test (kills M16) |
| `bdc2a2f2` … `bc279c5f` | Rework: `SessionFront` (TLS front for the configured origin) runtime, pooling and re-route fixes; retry-budget wire tests on a real clock |
| `f9cdd4a1` | Audit round 5: refused-destination 401 is not re-authable; subscription 401s are not withheld sessions |
| `aeb90071` | Audit round 6: refused destination composes its own message (remedy first, no status); config-backed subscription test |
| `cc3c32a7` | Gate fixes: refused-destination error data through typed helpers (error-data guard); park-keyed landing in the charged-exhaustion test; clippy field init |

## 3. Behaviour change — exact URL set now refused the session token (401)

The single predicate is `AuthBackend::may_receive_session` → `is_fuigo_api_bearer_url`. The session token
may go only to an **`https` origin (scheme, host, port) equal to a configured `[endpoints]` value**
(`fuigo_api_base_url`, `models_base_url`, `cli_chat_proxy_base_url`), **never loopback**. The compiled
prod cli-chat-proxy arm is empty in this tree.

So the session token is now refused at:
1. **Every `http://` URL**, including `http://<configured host>`.
2. **Every `https` URL whose origin is not configured.** This includes a configured host on another port
   (`https://<configured host>:8443`) and any third-party host.
3. **Every loopback URL** (`localhost`, `127.0.0.0/8`, `::1`), over `http` or `https`, **even when
   configured** as an `[endpoints]` value.

Of those URLs, these previously received the session token:
- **Any URL at all** for a `NotByok` model, on the live turn and in subagents. This includes models absent
  from the local catalogue, which are classed `NotByok`, and arbitrary third-party https hosts.
- On `Unknown`-BYOK turns, in the subagent resolver and through kill-switch substitution, any URL the broad
  `is_fuigo_api_url` admits: a configured host on any scheme or port, plus every loopback URL.
- A buffered session token (from an earlier turn, a model override or the kill switch), at whatever the
  destination became.
- The aux-model fallback, the idle `/models-v2` refresh, the model-catalogue session fallback, and
  `/tokenize-text`, when their URL was `http`, loopback or unconfigured.
- Image, video and voice requests to a configured **https loopback** `fuigo_api_base_url`.

**Unaffected:** `FUIGO_API_KEY`, per-model BYOK keys, auth-provider tokens, deployment keys, and a static
`AuthMode::ApiKey` credential held by the AuthManager. Each keeps its own rules. A configured
`http://localhost` gateway still receives `FUIGO_API_KEY`, but not the session token.

## 4. Every path that can attach the session token — verdict

### 4a. Inference-class destinations (model `base_url`, `[endpoints]` API origins, URLs derived from them)

| # | path | before P42 | P42 verdict | test / mutant |
|---|---|---|---|---|
| 1 | live-turn gate `SessionTokenAuthGate::new` (resolver, seed, preflight heal, 401-recovery eligibility) | broad `is_fuigo_api_url` | **fixed**: `session_may_reach` | cleartext / other-port / loopback wire tests; M1 |
| 2 | `session_token_auth_gate` `NotByok` | `true` for any destination | **fixed**: bounded by the destination, like `Unknown` | NotByok wire test, subagent override test, truth table; M2 |
| 3 | `reconstruct_full_config` buffered `creds.api_key` | sent whenever the gate was inactive | **fixed**: `withhold_session_bearer` at send time | buffered + hard-expired buffered wire tests; M3, M8 |
| 4 | subagent `session_bearer_resolver` (inherit live, fallback, model override) | broad matcher, `NotByok` unconditional | **fixed** | subagent resolver and override wire tests; M4, M2 |
| 5 | subagent inherited seed key (live arm, spawn-context fallback arm) | kept | **fixed**: `withhold_session_bearer` | subagent buffered wire test (both arms); M5, M5b |
| 6 | static `resolve_credentials` session arm (all callers) | strict | **unchanged, correct** | existing P17-R tests |
| 7 | kill switch `enforce_disable_api_key_auth` substitution (agent_ops, `try_resolve_model_credentials`, aux/web-search) | broad matcher | **fixed**: refusal stays broad, substitution uses `session_may_reach` | kill-switch wire test (4 URLs); M6 |
| 8 | aux-model fallback synthetic entry (`api_key: Some(bearer)`) | no check | **fixed** for session credentials; a held static key is kept | aux wire test, static-key test; M7, M18 |
| 9 | `stamp_session_local_sampler_fields` resolver | strict | **unchanged, correct** | — |
| 10 | summary/title client `build_summary_client` (fallback clones primary) | no check | **fixed** (audit R1 H1) | summary wire test; M12 |
| 11 | image-describe, auto classifier, recap/prompt-suggest, `prepare_chat_completion` | go through `reconstruct_full_config` | covered by #3 | — |
| 12 | subagent persistence client (`handle_request.rs` `Client::new`) | built from #4/#5 configs | covered | — |
| 13 | embeddings live provider `embedding_session_credentials` | strict | **unchanged, correct** | — |
| 14 | embeddings static seed `embed_api_key` (startup reindex, backend fallback) | no check | **fixed** (audit R2 H1) | unit test; M16, M16b |
| 15 | idle `/models-v2` refresh (`session_setup.rs`) | `is_cli_chat_proxy_url` only (admits loopback) | **fixed** | wire test; M9 |
| 16 | model catalogue `oai.rs` (custom-endpoint session fallback, Session arm) | no check | **fixed** for session credentials | wire test with refusal assertion and positive control, static-key test; M10 |
| 17 | `/tokenize-text` (`context_snapshot.rs`) | session to `fuigo_api_base_url`, unchecked | **fixed**; a held static key keeps precedence | unit test, static-key test; M11, M19 |
| 18 | tools: image gen/edit, video gen/poll, voice (`auxiliary_credential_for`) | origin match admits https loopback | **fixed**: session only where `session_may_reach(recipient)` | unit test, static-key test; M13, M17 |
| 19 | tools: web search (`auxiliary_credential_for` WebSearch arm) | live key → strict `resolve_credentials` | **unchanged, correct** | — |
| 20 | `fuigo-voice` STT / pager voice | strict `is_fuigo_api_bearer_url` plus #18 | correct | — |
| 21 | `[model_providers]` fail-closed guard | strict | **unchanged, correct** | — |

**Recognising a buffered session token.** A buffered token is recognised **by value**:
`AuthManager::is_session_bearer` checks a per-process, randomly keyed SipHash digest set. Every write of
`inner` adds to it (construction, `with_inner_write`, disk reload), and so does every `owned_inner` read.
Only session-mode credentials are recorded (`AuthMode::ApiKey` is excluded), and the set never evicts.

I judged the `Credentials::auth_type` label unusable. Several writers store a session token without
relabelling it (the preflight heal, model switch). Others label a `FUIGO_API_KEY` as `SessionToken`
(`subagent_auth_type`). Stripping by label would either leak or strip a legitimate key.

With `auth_manager = None` the check fails open. No production session-token path without a manager was
found, and audit rounds 2–4 agree.

**Hard-expired stripping is preserved.** On a permitted destination the resolver path is unchanged: the
seed is `current_wire_valid` and the resolver strips. The wire test
`p42_wire_hard_expired_token_is_still_stripped_at_the_configured_origin` passes at both parent and tip.
On a refused destination every session token is withheld, expired or not.

### 4b. Not inference-class: auxiliary service clients that still send the session token unchecked (packet P47)

These send the session token with no destination predicate (only `is_fuigo_authority` or nothing). They are
**P47's**, not P42's; P42 changed none of them. Paths are under `crates/codegen/`; line numbers were taken at
`64dc2c74` and **re-verified at `aeb90071`** (none of these files changed in the rebase or the round-6 fix):

| file:line | what |
|---|---|
| `fuigo-shell/src/managed_config/supervisor.rs:105` | managed deployment config fetch |
| `fuigo-shell/src/agent/subscription_check.rs:46` | `/user` subscription check |
| `fuigo-shell/src/auth/manager/enrichment.rs:63` | auth enrichment |
| `fuigo-shell/src/extensions/billing.rs:203`, `:295` | billing, auto-topup |
| `fuigo-shell/src/extensions/consent.rs:32` | consent |
| `fuigo-shell/src/extensions/privacy.rs:29` | privacy |
| `fuigo-shell/src/remote/client.rs:49`, `:85`, `:319` | remote settings / bundles; `BackendClient` |
| `fuigo-shell/src/remote/agent.rs:62` | sandbox |
| `fuigo-shell/src/remote/skills_client.rs:428` | skills |
| `fuigo-shell/src/remote/workspaces_client.rs:127` | workspaces |
| `fuigo-shell/src/remote/conversations_client.rs:145` | conversations |
| `fuigo-shell/src/remote/chat_models_client.rs:141` | chat-models modes |
| `fuigo-shell/src/agent/session_registry_client.rs:140` | session registry |
| `fuigo-shell/src/agent/feedback_client.rs:302` | feedback |
| `fuigo-shell/src/auth/credential_provider.rs:155` | trace upload / conversation storage (`build_storage_client_for_proxy`) |
| `fuigo-shell/src/agent/relay.rs:367` | WebSocket relay |
| `fuigo-shell/src/leader/server.rs:204`, `:230` | leader-mode auth provider |
| `fuigo-workspace/src/session/tool_config.rs:393` | hub tool config (leader's static image/video/web-search `api_key`) |
| `fuigo-workspace/src/upload/mod.rs:137` | hub upload |
| `fuigo-workspace/src/hub_auth/mod.rs:565` | hub auth |

Their destinations are service URLs from `[endpoints]` service fields, env chains or compiled constants.
**Proposal (P47):** name the Ferrox-service class and give each client a destination check appropriate to it.

## 5. Tests and focused runs (this round)

New or extended in the round-6 fix (`aeb90071`):
- shell `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy` (extended via
  `p42_assert_refused_destination_wire`: no `http_status`; message starts with the remedy; sentence before
  `\n\n  Model:`; `Endpoint:` line; none of `(401)`, `Unauthorized (`, `status 401`, `Unauthorized`);
- shell `p42_subscription_selected_by_endpoint_is_not_a_withheld_session` (round-6 LOW, §1);
- pager `app::error_display::tests::auth_destination_refused_banner_keeps_the_endpoints_remedy` (banner keeps
  remedy + sentence, drops `Model:`, URL and 401 copy; control: the round-6 message shape loses the remedy);
- pager `app::effects::tests::format_acp_error_refused_destination_keeps_the_remedy` (ACP-error path);
- pager `app::dispatch::tests::prompt::prompt_response_refused_destination_is_not_stashed_for_reauth`
  (PromptResponse first and RetryState first: nothing stashed, no `ReAuthRequired`, banner carries the remedy;
  positive control: a real 401 in the same harness is stashed).

Gate fixes (`cc3c32a7`): arm 6 returns both error shapes through typed helpers (the error-data guard flagged
`.data(data)`); `parked_turn_authenticated_rejection_dispatches_and_exhausts_charged` lands its token after
two observed re-auth parks (it raced a real-clock timer under load); clippy `field_reassign_with_default`.

Focused runs (lane `p42dev`, `dev.sh` = `cargo test --no-run` then `slot-run.sh p42dev nice -n 10 timeout 3000 cargo test …`):

| run | rev | command (after `cargo test --locked`) | result |
|---|---|---|---|
| `f1-shell-lib` | `aeb90071` | `-p fuigo-shell --lib -- p42_ the_registry_knows session_token_auth_gate_truth_table` | 27 passed, exit 0 |
| `f1-shell-it` | `aeb90071` | `-p fuigo-shell --test external_auth_expired_credential` | 1 passed, exit 0 |
| `f1-pager` | `aeb90071` | `-p fuigo-pager --lib -- auth_destination_refused refused_destination is_reauthable_failure prompt_response_formatted_401` | 5 passed, exit 0 |
| `f2-lib` | `cc3c32a7` | lib filter above + `every_acp_error_data_in_shell_source parked_turn_authenticated_rejection enrichment_task_preserves_interleaved_token_rotation` | 30 passed, exit 0 |
| `f2-parked-{1,2,3}` | `cc3c32a7` | `--lib -- --exact …parked_turn_authenticated_rejection_dispatches_and_exhausts_charged` | 1 passed ×3, exit 0 |
| `f2-it`, `f2-pager` | `cc3c32a7` | as `f1` | 1 passed; 5 passed; exit 0 |

## 6. Mutants (Hetzner, one clean worktree + one `CARGO_TARGET_DIR` per mutant, 6 in parallel)

Runner `p42dev/mut.sh <M>`: `git worktree add --detach` of the tip, apply with `p42-mutants.py <M>` (the
definitions file, copied to `Fuigo/p42-mutants.py`), then three runs, each built first:
`cargo test --locked -p fuigo-shell --lib -- p42_ the_registry_knows session_token_auth_gate_truth_table`,
`cargo test --locked -p fuigo-shell --test external_auth_expired_credential`, and, for the notification-path
mutants M1–M5b and M21–M26, `cargo test --locked -p fuigo-pager --lib -- auth_destination_refused refused_destination
is_reauthable_failure prompt_response_formatted_401`. Target and worktree deleted after each. M1–M26 ran at
`aeb90071`; M23b (the data site rewritten by `cc3c32a7`) at `cc3c32a7`. Every mutant compiled (build exit 0).
Results: `Fuigo/p42-mutants-results.txt`; per-mutant logs `hetzner-dsm:/root/fuigo-builds/p42dev/mutlogs/`.

**29 of 29 killed.** M14/M15 are now exercised (the filter includes `the_registry_knows`), and M16 is now killed
by the spawn-level memory test.

| mutant | change | result (failing tests) |
|---|---|---|
| M1 | live gate back to `is_fuigo_api_url` | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`, `p42_wire_buffered_token_is_rechecked_after_the_destination_changes`, `p42_wire_cleartext_url_never_receives_the_session_token`, `p42_wire_notbyok_model_absent_from_the_catalogue_never_receives_the_session_token` (+2 more); log `ce061d709ab11a39…` |
| M2 | `NotByok => true` | **killed** (lib exit 101): `p42_wire_subagent_model_override_notbyok_follows_the_one_predicate`, `session_token_auth_gate_truth_table`, `p42_wire_notbyok_model_absent_from_the_catalogue_never_receives_the_session_token`; log `bd60c076a29415fb…` |
| M3 | drop the `reconstruct_full_config` buffered re-check | **killed** (lib exit 101): `p42_wire_buffered_hard_expired_token_is_withheld_from_a_refused_destination`, `p42_wire_buffered_token_is_rechecked_after_the_destination_changes`; log `70c4f347deff1355…` |
| M4 | subagent resolver back to the broad matcher | **killed** (lib exit 101): `p42_wire_subagent_inherited_buffered_token_is_rechecked`, `p42_wire_subagent_inherited_resolver_follows_the_one_predicate`, `p42_wire_subagent_model_override_notbyok_follows_the_one_predicate`; log `751c9803f08ad2e8…` |
| M5 | drop the subagent live seed re-check | **killed** (lib exit 101): `p42_wire_subagent_inherited_buffered_token_is_rechecked`; log `095d1094d81351d5…` |
| M5b | drop the subagent fallback seed re-check | **killed** (lib exit 101): `p42_wire_subagent_inherited_buffered_token_is_rechecked`; log `8a6affd409da6fbf…` |
| M6 | kill-switch substitution unconditional | **killed** (lib exit 101): `p42_spawn_memory_reindex_sends_non_session_key_to_embeddings`, `p42_spawn_memory_reindex_withholds_session_token_from_refused_embeddings`, `p42_wire_kill_switch_substitutes_the_session_only_where_it_may_go`; log `c1c5cc474754932a…` |
| M7 | aux fallback session filter removed | **killed** (lib exit 101): `p42_wire_summary_client_fallback_rechecks_the_buffered_token`, `p42_wire_aux_fallback_bearer_respects_the_destination`; log `baee30cdb735d46c…` |
| M8 | `is_session_bearer` always false | **killed** (lib exit 101): `p42_wire_summary_client_fallback_rechecks_the_buffered_token`, `p42_wire_subagent_inherited_buffered_token_is_rechecked`, `the_registry_knows_session_bearers_by_value_and_never_static_keys`, `p42_spawn_memory_reindex_sends_non_session_key_to_embeddings` (+5 more); log `1f2b5f32108a3edd…` |
| M9 | `/models-v2` predicate removed | **killed** (lib exit 101): `p42_wire_models_v2_refresh_does_not_send_the_session_to_loopback`; log `c41764b5a6c65f52…` |
| M10 | catalogue session filter removed | **killed** (lib exit 101): `p42_wire_model_catalogue_fetch_does_not_fall_back_to_the_session_at_loopback`; log `08f72b44d39f2b06…` |
| M11 | tokenize predicate always true | **killed** (lib exit 101): `p42_tokenize_key_follows_the_one_predicate`; log `563de1d98fd39e13…` |
| M12 | summary-client re-check removed | **killed** (lib exit 101): `p42_wire_summary_client_fallback_rechecks_the_buffered_token`; log `b29bfd9aac120b9e…` |
| M13 | media/voice arm `session_allowed = true` | **killed** (lib exit 101): `p42_auxiliary_credential_arm_refuses_the_session_at_configured_https_loopback`; log `3abec9061c4dbb95…` |
| M14 | registry records `ApiKey` mode | **killed** (lib exit 101): `the_registry_knows_session_bearers_by_value_and_never_static_keys`; log `e0d05a35f29427cc…` |
| M15 | registry evicts at 4096 | **killed** (lib exit 101): `the_registry_knows_session_bearers_by_value_and_never_static_keys`; log `2d196632685fc672…` |
| M16 | spawn call site uses the raw key | **killed** (lib exit 101): `p42_spawn_memory_reindex_withholds_session_token_from_refused_embeddings`; log `733c2085aa82ca47…` |
| M16b | memory-embed helper returns the raw key | **killed** (lib exit 101): `p42_spawn_memory_reindex_withholds_session_token_from_refused_embeddings`, `p42_memory_embed_key_is_rechecked_against_the_destination`; log `94ca347329c0dbaa…` |
| M17 | media arm ignores a held `ApiKey` key | **killed** (lib exit 101): `p42_static_manager_api_key_is_not_treated_as_a_session_token`; log `7344320642335544…` |
| M18 | aux fallback ignores held-key classification | **killed** (lib exit 101): `p42_static_manager_api_key_is_not_treated_as_a_session_token`; log `2c0a65234772105a…` |
| M19 | tokenize ignores held-key classification | **killed** (lib exit 101): `p42_static_manager_api_key_is_not_treated_as_a_session_token`; log `ec567e5e188fb3dc…` |
| M20 | `session_withheld_401` ignores the memo provider | **killed** (lib exit 101): `p42_subscription_401_is_not_classified_as_a_withheld_session`; log `a19fa91ab44a217b…` |
| M21 | `is_reauthable_failure` stops excluding `auth_destination_refused` | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`; log `796e3c1b244ac16d…` |
| M22 | **new** builder puts the diagnostics before the remedy | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`; pager exit 101: `prompt_response_refused_destination_is_not_stashed_for_reauth`, `format_acp_error_refused_destination_keeps_the_remedy`, `auth_destination_refused_banner_keeps_the_endpoints_remedy`; log `f3581e09a987d74d…` |
| M23 | **new** refused destination sends `http_status` (at `aeb90071`: `wire_status = error.status_code`) | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`; log `5e4b2819ff540468…` |
| M23b | **new** refused destination sends `http_status` (at `cc3c32a7`: `"http_status"` in the typed data) | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`; log `d8bee98f00c93734…` |
| M24 | **new** arm 6 keeps the sampler `Unauthorized (401)` text ahead of the builder | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`; log `2086c3e7e9d44c56…` |
| M25 | **new** `selected_for_endpoint` exclusion removed (round-6 LOW) | **killed** (lib exit 101): `p42_subscription_selected_by_endpoint_is_not_a_withheld_session`; log `3264fd838bafe363…` |
| M26 | **new** the plain sentence carries `Unauthorized (401)` | **killed** (lib exit 101): `p42_withheld_session_401_is_terminal_with_the_endpoints_remedy`; pager exit 101: `format_acp_error_refused_destination_keeps_the_remedy`, `auth_destination_refused_banner_keeps_the_endpoints_remedy`; log `215f072b0f51ad2f…` |

## 7. Pre-gate audit (Astra, `gpt-6-astra`, read-only)

Outputs: `Fuigo/p42-audit-astra{,-2,…,-8}.txt` on the Mac.

| round | on | verdict | findings → action |
|---|---|---|---|
| 1 | `5e5893df..afb1eaf1` | DO-NOT-LAND | H1 summary fallback, H2 media arm at https loopback, M3/M4 registry, M5 test vacuity → fixed |
| 2 | `e5a981b4` | DO-NOT-LAND | H1 embeddings seed, M2 held `ApiKey` over-restricted → fixed |
| 3 | `afe39c13` | DO-NOT-LAND | BLOCKER compile (attribute placement), M2 aux fallback, L3 tokenizer → fixed |
| 4 | `7aa22199` | LAND | none |
| 5 | `ac7bfe92..54a6d490` (rework) | DO-NOT-LAND | 2 MEDIUM: refused-destination notification raised the login banner; a native-subscription 401 could be classed as withheld → fixed in `f9cdd4a1` |
| 6 | `ac7bfe92..64dc2c74` | DO-NOT-LAND | 2 MEDIUM (pager dropped the remedy; prompt stashed for post-login resubmit), 1 LOW (subscription test bypassed `selected_for_endpoint`) → fixed in `aeb90071` |
| 7 | `45bd14ee..aeb90071` | **LAND** | none at any severity; rebase preserved all 18 patches (`range-diff`) |
| 8 | `aeb90071..cc3c32a7` | **LAND** | none at any severity |

Final verdict quoted (round 8): "Round 8: no BLOCKER, HIGH, MEDIUM, or LOW findings in `aeb90071..cc3c32a7`. … LAND".
Round 7: "No remaining BLOCKER/HIGH/MEDIUM/LOW findings identified. … LAND".

## 8. The gate (contract A.2.1)

`/root/fuigo-builds/rp.sh p42rp2 45bd14ee6a0b2fecc57b844aa758a831c69051d2 strike/p42 /root/fuigo-builds/p42b.bundle
fuigo-shell-base fuigo-sampler fuigo-shell fuigo-pager` (per package `slot-run.sh … nice -n 10 timeout 3600 cargo test
--locked --no-fail-fast -p <pkg>`; then `cargo clippy --locked --all-targets` for the four). Summary
`hetzner-dsm:/root/fuigo-builds/p42rp2.out`; logs `p42rp2-{parent,tip}-<pkg>.log`.

| rev | pkg | exit | derived | headers / unfinished | failing | log sha256 |
|---|---|---|---|---|---|---|
| parent `45bd14ee` | fuigo-shell-base | 0 | 4 | 4 / 0 | 0 | `e21f3ec6832d8fa6dfd19651bf59191b669d59d196a3f218b25efd1b21f37008` |
| parent | fuigo-sampler | 0 | 12 | 12 / 0 | 0 | `7016f40dc923757ba82542e20e7c2a4dc82b612d5b157ce5aa9e173d80b87e49` |
| parent | fuigo-shell | 0 | 38 | 38 / 0 | 0 | `8e7c316b517ba7b972cb6e89b67e9b73fef3525c6bb06d3287f3cd7649a79b91` |
| parent | fuigo-pager | 101 | 21 | 21 / 0 | 18 (`paste_key_tests` ×16, `scrollback_paste_focus_forward_tests` ×1, `paste_key_cap…`) | `344ad9b88ae0215be2668ce808fe8b2b9127d80461c249c96c7ad9db76bd17e1` |
| tip `cc3c32a7` | fuigo-shell-base | 0 | 4 | 4 / 0 | 0 | `bd6fabed1fb2bdc7bbe0af573335d38158ffb035697cf8697c661062049b9ffe` |
| tip | fuigo-sampler | 0 | 12 | 12 / 0 | 0 | `7ac92401ff806c42558e1bb9be81902c9ed555b6106c712db9730d02e5d96b1c` |
| tip | fuigo-shell | 101 | 38 | 38 / 0 | 4 (`session::workflow::manager::tests::*`, see isolation) | `7906e06e2f72e18b1cef20b3d463abf6984ae6c6687077ea9592f3e4e2d33384` |
| tip | fuigo-pager | 101 | 21 | 21 / 0 | 18, identical to parent | `88c56ba4c82d3e1f5f617ec5cffb4c2b8d48fad4594cb6f360653db57ff0a1fa` |

All runs admissible (headers = derived, unfinished 0, no 124/signal). **Clippy:** exit 0 at both; warnsets 29 / 29,
**new: none**, gone: 0.

**Tip-only names (fuigo-shell)**, all four `session::workflow::manager::tests` failing with "expected spawn, timed
out" (`manager.rs:1226`) while 6 mutant builds shared the host; P42 does not touch the workflow manager (and
`rp.sh` carries a `P29SKIP` for the same module). Isolation `iso.sh p42iso fuigo-shell "--lib" "<4 names>" cc3c32a7 45bd14ee`:

| name (`session::workflow::manager::tests::…`) | tip `cc3c32a7` ×3 | parent `45bd14ee` ×3 |
|---|---|---|
| `cancel_drops_queued_spawns_before_coordinator` | pass, pass, pass | pass, pass, pass |
| `control_run_refuses_to_pause_an_engine_paused_run` | pass, pass, pass | pass, pass, pass |
| `control_run_refuses_to_stop_a_budget_limited_run_so_resume_still_needs_a_raised_cap` | pass, pass, pass | pass, pass, pass |
| `parallel_panel_respects_concurrency_cap` | pass, pass, pass | pass, pass, pass |

Summaries (sha256): `p42rp2.out` `1c3a6a2c5aeddaec8eec363adde7416ef841d45dd3a2ad494e19655c11349222`, `p42iso.out`
`151d241768965df27f426ecf427883bba09dd3561e22187064ce1dfe59210c5a`, superseded `p42rp.out`
`8693fea8f1ac1b9ce2e66d37071d32c0cca720775081bacefb3796bf41fb6a25`. Gate window 2026-10-01T11:35:54Z–12:58:03Z; isolation
13:01:36Z–14:12:40Z.

Log: `hetzner-dsm:/root/fuigo-builds/p42iso.out` (per-run logs `p42iso-<sha>-<name>-<n>.log`), all 24 runs exit 0.

**Result: tip ⊆ parent holds** for all four packages once the four load-timing names are isolated (they pass
3/3 `--exact` at both revisions; none is P42 code). fuigo-pager tip set = parent set (18 pre-existing paste tests).

Superseded gate at `aeb90071` (`p42rp`): tip-only `error_data_guard_tests::every_acp_error_data_…` (real: fixed in
`cc3c32a7`), `auth_retry_budget_tests::parked_turn_authenticated_rejection_…` (real race in a P42 test: fixed in
`cc3c32a7`), `auth::manager::tests::enrichment_task_preserves_interleaved_token_rotation` and pager
`mermaid_worker::tests::mermaid_view_{disk_hit…,miss…}` (load timing; all pass in the `cc3c32a7` gate), and one
new clippy warning (fixed in `cc3c32a7`). Log shas in `p42rp.out`.

## 9. Unverified

- No wire test runs a real image/voice request; the media/voice arm (#18) is proven by unit tests and mutants
  M13/M17.
- No wire test of `refresh_token_if_expired`'s heal path at a refused destination (same `SessionTokenAuthGate`
  as M1/M2).
- `withhold_session_bearer` fails open when `auth_manager` is `None`; no production caller carrying a session
  token without a manager was found, not proven exhaustively.
- The §4b list is from source inspection (line numbers re-verified), not exhaustive; it is P47's to close.

## 10. Follow-up after the gate: pager copy for `auth_destination_refused` (`2f871772`)

Asked by the coordinator under the no-deferments rule. **Only `fuigo-pager` changes**, in
`app/error_display.rs` (plus test assertions in `app/effects/tests.rs`).
- `WireErrorType::AuthDestinationRefused`: `WireErrorType::parse` maps
  `AUTH_DESTINATION_REFUSED_ERROR_TYPE` to it. `classify` gives the headline "Session token not sent", **no
  action**, and `AUTH_DESTINATION_REFUSED_REMEDY` as the fallback `why`. No status is sniffed from the text
  (only `Api`/`Other` do that).
- Tests: `auth_destination_refused_banner_keeps_the_endpoints_remedy` now asserts the wire type and the
  absence of "Try sending again", "Try again", "send again", "/login" and "Wait a minute". It also checks that
  an empty message still renders the remedy with no retry advice.
  `format_acp_error_refused_destination_keeps_the_remedy` asserts no "Try sending again".
- Focused run (lane `p42dev`, tip `2f871772`):
  - `cargo test --locked -p fuigo-pager --lib -- auth_destination_refused refused_destination
    is_reauthable_failure prompt_response_formatted_401 error_display`: **31 passed, exit 0**. Log
    `f3-pager.out`, sha256 `3c3a93d87339407f7a320cff5395032e43b3bc1393ae8546344681fba86cd43e`.
  - `cargo test --locked -p fuigo-shell --lib -- p42_ the_registry_knows session_token_auth_gate_truth_table
    every_acp_error_data_in_shell_source`: **28 passed, exit 0**. Log `f3-shell-lib.out`, sha256
    `fb9f4c6e06a92aca01f37711846588478496bb189913f1199e7e1b62ac1c694b`.
- Clippy: `cargo clippy --locked --all-targets -p fuigo-pager -p fuigo-shell` exits 0. None of its warnings is
  in a file this commit touches, so there are **0 new**. Log `f3-clippy.out`, sha256
  `6a55ca698adb8d7d4fdc386d342774eab59cce8db0a1c2361b4a6d52ea94d0ba`.
- Mutants (`mut3.sh`, on tip `2f871772`, each with its own worktree and target):

| mutant | change | result |
|---|---|---|
| M27 | `parse` arm removed (the type falls back to `Other`) | **killed** (pager exit 101): `auth_destination_refused_banner_keeps_the_endpoints_remedy`, `format_acp_error_refused_destination_keeps_the_remedy` |
| M28 | the type gets the action "Try sending again." | **killed** (pager exit 101): same two tests |

  The mutant total is now **31 of 31 killed**.
- Astra round 9 (`2f871772`, short check, saved to `Fuigo/p42-audit-astra-9.txt`): "No actionable findings in
  `2f871772`. … LAND".
- The full stacked re-proof is the coordinator's (rebase onto the integration queue). The gate in §8 is at
  `cc3c32a7`, and this commit is on top of it.
