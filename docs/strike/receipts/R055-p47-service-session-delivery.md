# R055 — P47: service-endpoint session delivery has one predicate (SECURITY)

**Packet:** P47 (`strike/p47`). **Parent:** `90c5a4af22cfc87ff98cd57c9ee56c5b5bab466f` (landed integration HEAD:
P42 plus P43/PF2/P46). **Gated tip:** `c1dc667d1326c457e32dd85416aef6fada9c0772`; the receipt commit follows it
and touches only this file (`docs/strike/audits/p47-astra.txt` landed in `6d363a47`).
**Host:** `hetzner-dsm`; lanes `p47dev` (focused runs), `p47mut/<M>` (one worktree + one `CARGO_TARGET_DIR` per
mutant), `p47rp`/`p47rp2` (gate, `rp.sh`). `CARGO_BUILD_JOBS=16 RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg
CARGO_TERM_COLOR=never`, builds under `nice -n 10`, every test through `slot-run.sh`. Toolchain digest
(`rustc -vV | sha256sum`): `b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69` (1.94.0).
**Not landed.** The coordinator lands. Pre-squash history (14 WIP commits on P42's `2c24358e`):
`strike/p47-pre-rebase` = `94669aed`.

## 0. Read first

- **Gate (§6): met at `c1dc667d`.** `Running`/`Doc-tests` headers = derived for all nine packages at both revisions,
  0 unfinished, no 124/signal. Tip ⊆ parent for eight packages outright; `fuigo-workspace` has 9 tip-only names
  (permission-manager, trust-path), all 54 isolation runs pass (3/3 `--exact` at tip and parent). Clippy: 0 new
  warnings (37/37).
- **Astra (§5): round 7 `LAND`** on the rebased branch (`90c5a4af..58cc9c3b`), round 5 `LAND` on the pre-rebase
  branch; rounds 1–4 and 6 were DO-NOT-LAND and every finding is fixed (§5).
- **Mutants (§4): 38 of 38 killed.**
- **Behaviour change (intended).** A session user whose auxiliary service URL is `http://`, loopback, carries
  userinfo, or (for a derived URL such as a `--hub-url`) is off the configured origin now gets a typed refusal and
  no request. A `ws://` loopback local-dev hub/relay no longer receives the session token.
- **P65 / R059 HIGH (startup `/v1/settings` fetch sends the session token to http/loopback): covered by P47, not
  open.** Every settings fetch (`agent_ops.rs:1514`, `:1936`, `agent/models/fetch.rs:70`, the startup prefetch)
  goes through `remote::fetch_settings_blocking` → `fetch_settings_blocking_with_attempts`, whose first act is
  `service_session_gate` (`fuigo-shell/src/remote/client.rs:697`): refused → `SettingsFetch::DestinationRefused`,
  no request, no 401 recovery. Hostile test: `auth::p47_service_wire_tests::p47_wire_remote_settings` (http
  loopback, cleartext FluxRouter, https loopback, userinfo on FluxRouter: nothing recorded, refusal text asserted;
  positive control: the configured https origin receives the bearer). Mutants M17 (gate removed) and M34 (refusal
  reported as `Rejected`) are killed by it. P65's repro ran on an integration HEAD without P47.


## 1. What P47 does

- **One predicate.** `fuigo_extra_ca::service_trust::session_may_reach_service(url, configured_service_base,
  configured_api_origin)` (`crates/codegen/fuigo-extra-ca/src/service_trust.rs:161`). It admits the session token
  only when the URL parses with no userinfo, its scheme is `https`/`wss`, its host is not this machine (localhost,
  `*.localhost`, 127/8, ::1, IPv4-mapped loopback, 0.0.0.0, ::), and its origin is FluxRouter-operated (compiled
  host, https, default port), a configured API origin (P42's `session_may_reach`), or the client's own configured
  service base. No exception for loopback or cleartext. `fuigo-shell` reaches it through
  `auth::session_delivery::session_may_reach_service` (`fuigo-shell/src/auth/session_delivery.rs:80`).
- **One provider rule.** `fuigo_auth::AuthCredentialProvider::bearer_may_reach(url, bearer)` is a required trait
  method decided on the exact value being stamped (`fuigo-auth/src/auth_provider.rs:67`). `AuthRetryMiddleware`
  checks the destination *as written* (URL userinfo survives reqwest's `Basic` conversion as a marker) before the
  first stamp and every post-refresh stamp, and on refusal sends nothing (`fuigo-auth/src/retry_middleware.rs:87`,
  `:141`, `:166`). Exempt: the configured deployment key and the held static `AuthMode::ApiKey` credential, by value.
- **Failure behaviour.** A refused destination gets no request (with or without the token). The client returns a
  typed refusal whose text names `scheme://host[:port]` and the remedy (never path, query or token); every refusal
  is in the unified log with site, origin, reason and message. Storage retries, the upload queue, settings recovery,
  the relay loop and the hub SDK reconnect loop all treat it as terminal. Policy:
  `docs/destination-trust-policy.md` "Service-endpoint session delivery: one predicate (P47)".

## 2. §4b re-verification and every gated site (file:line at the tip)

R034 §4b listed 22 sites. Re-verified with `grep -rn 'Bearer\|bearer_auth\|AUTHORIZATION\|"Authorization"\|snapshot().token'`
over `fuigo-shell`, `fuigo-workspace`, `fuigo-tools`, `fuigo-file-utils`, `fuigo-telemetry` (positive control: the
same grep finds `extensions/billing.rs`'s two sends). Added beyond §4b: the OTLP exporter, the `fuigo-file-utils`
static `user_token` fallbacks, the shell trace-upload static token, the `fuigo trace` command upload, and the hub
SDK reconnect. Upstream delta `2c24358e..90c5a4af` re-grepped after the rebase: its only new send
(`remote/model_source/oai.rs:146`, P43 move) is P42's inference class, already gated by `session_may_reach`.

| site (crates/codegen/…) | configured service base | gate |
|---|---|---|
| `fuigo-shell/src/managed_config/supervisor.rs:370` team fetch | resolved `managed_config_url` | `service_session_gate` → `ManagedConfigError::SessionDestinationRefused` |
| `fuigo-shell/src/agent/subscription_check.rs:91` | `proxy_url` | `service_session_gate` |
| `fuigo-shell/src/auth/manager/enrichment.rs:63` | `proxy_url` | `service_session_gate` |
| `fuigo-shell/src/extensions/billing.rs:201`, `:300` | `proxy_url` | `service_session_gate` |
| `fuigo-shell/src/extensions/consent.rs:44`, `privacy.rs:45` | `proxy_url` | middleware provider |
| `fuigo-shell/src/remote/client.rs:697` settings, `:83` bundle, `:186` archive, `:405` `BackendClient` | proxy / `FUIGO_CODE_BACKEND_URL` | gate / middleware; `SettingsFetch::DestinationRefused` |
| `fuigo-shell/src/remote/agent.rs:64` sandbox | proxy | `service_session_gate` |
| `fuigo-shell/src/remote/skills_client.rs:435`, `workspaces_client.rs:127`, `conversations_client.rs:150`, `chat_models_client.rs:140` | env-chain base | gate → `…::SessionDestinationRefused` |
| `fuigo-shell/src/agent/session_registry_client.rs:178`, `feedback_client.rs:405`/`:420` | base URL | middleware (live), checked static provider |
| `fuigo-shell/src/auth/credential_provider.rs:204`/`:232` `build_storage_client_for_proxy`, `upload/gcs.rs:119` | proxy base | middleware / checked static |
| `fuigo-shell/src/agent/config.rs:519` `resolve_upload_method` static token; `upload/gcs.rs:49` `ClassifiedProxyUpload` (`fuigo trace`) | trace-upload URL | token dropped / kind-classified provider |
| `fuigo-shell/src/auth/credential_provider.rs:422` OTLP provider; `fuigo-telemetry/src/otel_layer/mod.rs:267` exporter | none (FluxRouter + API origins) | batch not exported |
| `fuigo-shell/src/agent/relay.rs:250`, `:367` | `FuigoComConfig.fuigo_ws_url` | loop stops; request not built |
| `fuigo-shell/src/leader/server.rs:283` `HubDestinationGuard` (`:1196` first connect); `crates/common/fuigo-computer-hub-sdk/src/connection.rs:660`, `:1894`, `auth.rs:224` | `[hub].url` | checked before every socket; `ClientError::DestinationRefused` terminal |
| `fuigo-workspace/src/hub_auth/mod.rs:353` | operator hub URL | startup error, auth.json not read |
| `fuigo-workspace/src/upload/mod.rs:177`, `session/tool_config.rs:377` | `FUIGO_CLI_CHAT_PROXY_BASE_URL` | middleware / tools disabled |
| `fuigo-file-utils/src/storage_client.rs:395`/`:500`, `gcs.rs:41` static fallbacks; `storage_client.rs` retry branches, `:1806` multipart aggregation; `queue.rs:2021` | proxy base | checked static; refusal typed and terminal |

Not service class (unchanged, recorded): `auth/api_key_probe.rs:154` (probes a user-entered API key);
`fuigo-memory` embeddings (`embedding.rs`, P42 inference class, `BearerDestination::Unrestricted` with the caller's
decision noted); `session_setup.rs:414` models-v2 (P42 inference class, provider with no service base).

## 3. Tests

Wire tests (fresh process each, P42 `SessionWire`/`SessionFront`; hostile first — http loopback, cleartext
FluxRouter, https loopback, userinfo on FluxRouter — assert NOTHING recorded and the refusal text; then the positive
control at `https://api.fluxrouter.ai`): `fuigo-shell/src/auth/p47_service_wire_tests.rs` (subscription, enrichment,
settings, bundle legacy + archive, `BackendClient`, sandbox, skills/workspaces/conversations/chat-models, session
registry, feedback live + static, storage live + static + trace provider, billing/auto-topup/consent/privacy, OTLP
provider, value-based rule interleaving, upload classification, `fuigo trace` classified upload);
`managed_config/supervisor.rs` `p47_wire_tests`; relay (`agent/app.rs` `p47_relay_never_connects…` proves the loop
exits by itself; `agent/relay.rs` gate test); leader (`leader/server_tests.rs` hostile start + per-connect guard);
hub SDK (`connection_tests.rs` `p47_destination_refused_on_initial_connect…`, `…on_reconnect…`); workspace
(`hub_auth`, `upload`, `handle_tests` wiring); file-utils (`gcs`, `storage_client` multipart, `queue`
end-to-end); telemetry; fuigo-auth middleware (`p47_*`, incl. userinfo marker into the retry check).
Fixtures that sent a session token to a cleartext loopback mock run in a fresh process behind the TLS front
(`test_support::session_wire::fronted_child`; `tests/common/front.rs` for integration tests); P43 identity hostile
tests reach their mock as the non-FluxRouter https origin `service.example.test`. Non-session fixtures use an
explicit `BearerDestination::Unrestricted` static key.

`fuigo-auth`'s middleware tests need `--features middleware` (rp.sh runs the package without it):
`cargo test --locked -p fuigo-auth --features middleware` parent `90c5a4af` 8 passed, exit 0, log sha256
`0bc6c28ad0f0c1ae80bad79db5b9b8234dbe3b262bb09fd1fc88b56bb3b1d644`; tip `c1dc667d` 12 passed, exit 0,
`5b5a7f999e59ea1d82f241349e9ba3219fd782f80ac51e9ab3a7c43f1bbd86ce`.

## 4. Mutants (Hetzner; clean worktree + own `CARGO_TARGET_DIR` per mutant, deleted after)

Runner `p47dev/mut.sh` applies `Fuigo/p47-mutants.py <M>` to a worktree of `58cc9c3b` (the gated tip `c1dc667d`
differs only by the lint commits `6d363a47` and `c1dc667d`: the `BearerRule` type alias, a duplicate `allow`, fmt), builds,
then runs `cargo test --locked -p <pkg> [--features middleware] -- p47` for the mutated package(s). Every mutant
compiled. Results: `Fuigo/p47-mutants-results.txt`; logs `hetzner-dsm:/root/fuigo-builds/p47dev/mutlogs/`.
**38 of 38 killed.** (`fuigo-extra-ca`'s own unit tests are not `p47`-named, so M1–M4 show extra-ca exit 0; the
shell wire tests kill them.)

| mutant | change | result | log |
|---|---|---|---|
| M1 | predicate: scheme check removed | killed (fuigo-extra-ca:0 fuigo-shell:101): `p47_resolve_upload_method_drops_the_session_token_for_a_refused_trace_url` (+13 more) | `2d75a1bf5209b7a8…` |
| M2 | predicate: loopback check removed | killed (fuigo-extra-ca:0 fuigo-shell:101): `p47_relay_never_connects_to_a_cleartext_or_loopback_relay` (+12 more) | `97a183bc2ec13d11…` |
| M3 | FluxRouter arm ignores port | killed (fuigo-extra-ca:0 fuigo-shell:101): `p47_wire_agent_extensions` (+11 more) | `3c2f926dabecee3d…` |
| M4 | predicate admits everything (NotTrusted → Ok) | killed (fuigo-extra-ca:0 fuigo-shell:101): `p47_otel_provider_rule` (+13 more) | `b86dbd1228b1dc3c…` |
| M5 | middleware: first-stamp check removed | killed (fuigo-auth:101 fuigo-shell:101): `p47_classified_trace_upload_keeps_the_credential_kind` (+8 more) | `8998a88726e51c12…` |
| M6 | middleware: post-refresh stamp check removed | killed (fuigo-auth:101 fuigo-shell:0): `p47_the_retry_stamp_is_checked_too` (+1 more) | `b3864069c19c6e7a…` |
| M7 | ShellAuthCredentialProvider rule → Ok | killed (fuigo-shell:101): `p47_provider_rule_is_decided_on_the_stamped_value` (+6 more) | `075b9635daeea3c4…` |
| M8 | OTLP provider rule → Ok | killed (fuigo-shell:101): `p47_otel_provider_rule` (+1 more) | `c06867e895e4a296…` |
| M9 | exporter ignores the provider rule | killed (fuigo-telemetry:101): `p47_bearer_refused_for_follows_the_provider_rule` | `49405f6504d43286…` |
| M10 | static trace-upload token gate always passes | killed (fuigo-shell:101): `p47_resolve_upload_method_drops_the_session_token_for_a_refused_trace_url` (+1 more) | `c0195e0cfcc327f6…` |
| M11 | feedback static provider Unrestricted | killed (fuigo-shell:101): `p47_wire_feedback_client` | `1db1804938f7da0f…` |
| M12 | storage static provider Unrestricted | killed (fuigo-shell:101): `p47_wire_storage_proxy` | `7c6b32cfee470b86…` |
| M13 | managed-config gate result ignored | killed (fuigo-shell:101): `p47_wire_managed_config_team_fetch` | `2dc410d1225a45fb…` |
| M14 | subscription gate bypassed | killed (fuigo-shell:101): `p47_wire_subscription_check` | `56c779c472eabb2d…` |
| M15 | enrichment gate bypassed | killed (fuigo-shell:101): `p47_wire_auth_enrichment` | `318b1b7ebe03bdde…` |
| M16 | billing gate removed | killed (fuigo-shell:101): `p47_wire_agent_extensions` | `8566d94f5b11a29c…` |
| M17 | remote-settings gate bypassed | killed (fuigo-shell:101): `p47_wire_remote_settings` | `784ab56e3fcb0f20…` |
| M18 | bundle-fetch gate removed | killed (fuigo-shell:101): `p47_wire_bundle_fetch` | `e7d9158912515074…` |
| M19 | sandbox gate ignored | killed (fuigo-shell:101): `p47_wire_sandbox_client` | `f2a83779575cecc0…` |
| M20 | skills gate ignored | killed (fuigo-shell:101): `p47_wire_env_configured_rest_clients` | `2e7eceb213d4dd29…` |
| M21 | workspaces gate ignored | killed (fuigo-shell:101): `p47_wire_env_configured_rest_clients` | `7e55132c0a5d234e…` |
| M22 | conversations gate ignored | killed (fuigo-shell:101): `p47_wire_env_configured_rest_clients` | `03b592ecebb071e7…` |
| M23 | chat-models gate ignored | killed (fuigo-shell:101): `p47_wire_env_configured_rest_clients` | `46db46696ba4d541…` |
| M24 | relay gates removed | killed (fuigo-shell:101): `p47_relay_never_connects_to_a_cleartext_or_loopback_relay` (+1 more) | `20cd271883efb70a…` |
| M25 | hub guard always admits | killed (fuigo-shell:101): `p47_hub_destination_guard_decides_each_connect_by_value` (+1 more) | `9e1907234aa74b20…` |
| M26 | standalone hub_auth gate ignored | killed (fuigo-workspace:101): `p47_provider_refuses_a_cleartext_or_loopback_hub` | `ef831e1c59ee60fd…` |
| M27 | workspace upload provider → Ok | killed (fuigo-workspace:101): `p47_upload_bearer_follows_the_service_trust_class` | `de40547e4b3a82d7…` |
| M28 | workspace tool keys gate bypassed | killed (fuigo-workspace:101): `p47_auxiliary_service_wiring_withholds_the_session_from_a_cleartext_or_loopback_base` | `829865b7042e04ac…` |
| M29 | shared service_session_url_gate → Ok | killed (fuigo-shell:101): `p47_relay_never_connects_to_a_cleartext_or_loopback_relay` (+20 more) | `f50322734ec1f17f…` |
| M30 | service_session_gate exempts everything | killed (fuigo-shell:101): `p47_relay_never_connects_to_a_cleartext_or_loopback_relay` (+9 more) | `6f06d7d47c540d47…` |
| M31 | file-utils static user_token Unrestricted | killed (fuigo-file-utils:101): `p47_static_session_upload_never_reaches_a_loopback_proxy` (+2 more) | `d2790bc48adf7e3b…` |
| M32 | queue: refusal not terminal | killed (fuigo-file-utils:101): `p47_session_upload_refusal_is_terminal_in_the_queue` (+1 more) | `7a825789623052c0…` |
| M33 | storage upload retries ignore refusal | killed (fuigo-file-utils:101): `p47_static_session_upload_never_reaches_a_loopback_proxy` (+1 more) | `98f78c2fb61499fe…` |
| M34 | settings refusal reported as Rejected (401 path) | killed (fuigo-shell:101): `p47_wire_remote_settings` | `b480cc2f02157dda…` |
| M35 | held-static-key exemption by mode, not value | killed (fuigo-shell:101): `p47_provider_rule_is_decided_on_the_stamped_value` | `d04c081ac84b1485…` |
| M36 | upload classification ignores credential kind | killed (fuigo-shell:101): `p47_upload_method_checks_only_session_credentials` | `3d5047608b626873…` |
| M37 | hub SDK reconnect check removed | killed (fuigo-computer-hub-sdk:101): `p47_destination_refused_on_reconnect_opens_no_socket_and_stops` | `7a652b060470bc1f…` |
| M38 | hub SDK initial check bypassed | killed (fuigo-computer-hub-sdk:101): `p47_destination_refused_on_initial_connect_opens_no_socket` (+1 more) | `4eb527886d5f75b2…` |

## 5. Astra (`gpt-6-astra`, read-only, `< /dev/null`)

Transcripts: `Fuigo/p47-audit-astra-{1..7}.txt`; verdict sections: `docs/strike/audits/p47-astra.txt`.

| round | on | verdict | findings → action |
|---|---|---|---|
| 1 | `2c24358e..15279388` | DO-NOT-LAND | H1 static storage tokens unchecked; H2 rule re-read the manager (race); H3 upload refusals retried/untyped; M4 settings refusal as 401; M5 API-key exemption; M6 vacuous tests → value-based `bearer_may_reach(url, bearer)`, checked static fallbacks, terminal typed refusals, `SettingsFetch::DestinationRefused`, `resolve_upload_method_for_auth`, synced tests |
| 2 | `..146064ec` | DO-NOT-LAND | 5 MEDIUM: middleware missed userinfo; API-key kind lost on `fuigo trace`/hub; multipart lost the type; vacuous redirect test; raw OTLP endpoint logged → userinfo marker, `ClassifiedProxyUpload`, typed aggregation, deployment-key redirect fixture, sanitized refusal |
| 3 | `..` R2 fixes | DO-NOT-LAND | MEDIUM retry lost the marker; MEDIUM hub empty-bearer reconnect; LOW rationale → destination captured before stamping; hub fixes |
| 4 | `..` R3 fixes | DO-NOT-LAND | MEDIUM hub dropped the API-key exemption; MEDIUM `cfg(unix)` misplaced → `AuthProvider::destination_permits` in the hub SDK (asked before every socket, terminal `DestinationRefused`), `HubDestinationGuard` by value |
| 5 | `2c24358e..a0927139` | **LAND** | none at any severity |
| 6 | rebased `47d386f6` | DO-NOT-LAND | 2 HIGH stale callers (compile), 3 MEDIUM P43 fixtures vs the gate → fixed in `456b6eb5`/`3834c71c` |
| 7 | `90c5a4af..58cc9c3b` | **LAND** | none |

Final verdict quoted (round 7): "I found no uncovered send, lost P43 gate, weakened security assertion or new
regression. … **LAND**". Round 5: "**No BLOCKER, HIGH, MEDIUM or LOW findings remain.** … LAND".

## 6. The gate (contract A.2.1)

`/root/fuigo-builds/rp.sh p47rp2 90c5a4af22cfc87ff98cd57c9ee56c5b5bab466f strike/p47 /root/fuigo-builds/p47.bundle
fuigo-extra-ca fuigo-auth fuigo-file-utils fuigo-memory fuigo-telemetry fuigo-computer-hub-sdk fuigo-workspace
fuigo-shell fuigo-pager` (per package `slot-run.sh … nice -n 10 timeout 3600 cargo test --locked --no-fail-fast -p
<pkg>`, then `cargo clippy --locked --all-targets` for all nine). Summary `hetzner-dsm:/root/fuigo-builds/p47rp2.out`
(sha256 `4890d7e16d925d97e49206f344bcbb83add3a8c648857df89931ac338b15c5a9`); window 2026-10-01T23:44:58Z–2026-10-02T02:00:08Z.

| rev | pkg | exit | derived | headers / unfinished | failing | log sha256 |
|---|---|---|---|---|---|---|
| parent | fuigo-extra-ca | 0 | 14 | 14 / 0 | 0 | `84533ebd0dabc20c4861ecb234f628111864ea77e275dc3ab66e323b6217c216` |
| parent | fuigo-auth | 0 | 2 | 2 / 0 | 0 | `eb1014ab3ecb52f3292eea726ad7032f523817e1efaf045fab4f52f8705d8353` |
| parent | fuigo-file-utils | 0 | 2 | 2 / 0 | 0 | `d0a12ed39c771e4f56b53d141fa13ef113842648f2aa13357b29e53405a42b56` |
| parent | fuigo-memory | 101 | 2 | 2 / 0 | 1 (`dream_lock::tests::marker_failure_keeps_retry_open`) | `37755d16ded59ec2ee5036dcf75fddfa99d58392b8a47c6bcbee29c7e3260751` |
| parent | fuigo-telemetry | 0 | 15 | 15 / 0 | 0 | `88545b34fae06f6e3c08d66d0a6a9b69989c5945b47185ba186ad515c4168655` |
| parent | fuigo-computer-hub-sdk | 0 | 2 | 2 / 0 | 0 | `d6dbbc80ae42e9feb4acac6b858e699a6527e36876827a5c73970355642a01ed` |
| parent | fuigo-workspace | 101 | 5 | 5 / 0 | 8 | `41497e564d10033ad904e0cb6f71c6885a2a4e0b722e10327231f7995fb799e8` |
| parent | fuigo-shell | 0 | 40 | 40 / 0 | 0 | `000027dfa5df9f0017989bbdcce360b52f5cfa0afced8c7fbc70c46f139cd4c5` |
| parent | fuigo-pager | 0 | 21 | 21 / 0 | 0 | `f64e94c993fdc6a4b1a2d161a3cfcbfc1734eee8860c49580e175ad20cf0eb93` |
| tip | fuigo-extra-ca | 0 | 14 | 14 / 0 | 0 | `a10c1aba8402c25620a4c29fcd7624e769d277640e32d9ead0f13ae9c3322855` |
| tip | fuigo-auth | 0 | 2 | 2 / 0 | 0 | `c38ec9a2e33087c5b2c5f9e495f75297cfc3b3f6964b815e619125248653cb62` |
| tip | fuigo-file-utils | 0 | 2 | 2 / 0 | 0 | `b3b0a77171e6c774f6f94638ae598be4a10b543d50cd30b29193198cb3777a4b` |
| tip | fuigo-memory | 0 | 2 | 2 / 0 | 0 | `66241a94a472bb39fc36d54bf2489d40e6d4c6cfe9d00dbe6a43d4a3b26186d2` |
| tip | fuigo-telemetry | 0 | 15 | 15 / 0 | 0 | `a6ab25ecfccaf8e8afce18e2b14388394fb27a3ebdd6918482e5a4115a8cd72b` |
| tip | fuigo-computer-hub-sdk | 0 | 2 | 2 / 0 | 0 | `8c1a53322b3db7c9f46113c7488190f4a9332f564f82044a24e807fdb15cdeee` |
| tip | fuigo-workspace | 101 | 5 | 5 / 0 | 13 | `24ec9269e399e2dcecfb2fb8239b590b91cd87bbfc4bfa842708c698f407eb52` |
| tip | fuigo-shell | 0 | 40 | 40 / 0 | 0 | `4f70df5c8fbee84e0897e1243dea2723309f56c263d606d9a7ea70382e890a05` |
| tip | fuigo-pager | 0 | 21 | 21 / 0 | 0 | `89d07f02cc4544b7d45ba519a658c1f5427241ff2723dd0b61c5e1e3891231e2` |

All runs admissible. **Clippy:** exit 0 at both; warnsets 37 / 37; **new: none**, gone: 0. (The first gate,
`p47rp` at `58cc9c3b`, found two new clippy warnings — a complex type in `fuigo-auth`, a duplicate `allow` in the
integration-test front — fixed in `c1dc667d`; its shell tip-only `leader::server::tests::shutdown_waits_for_in_flight_cpu_profile_stop`
passed in this gate.)

**fuigo-workspace tip-only names (9)**, isolated with `iso.sh p47iso fuigo-workspace "--lib" "<9 names>" c1dc667d
90c5a4af` (summary `p47iso.out` sha256 `de3d120fa8ca7564ee13940f8b3e7217bd2f76594d58edb2721c505df64099af`,
2026-10-02T02:00:25Z–02:59:21Z): all 54 runs exit 0.

| name | tip ×3 | parent ×3 |
|---|---|---|
| `permission::manager::tests::auto_session_approve_all_bash_skips_classifier` | pass ×3 | pass ×3 |
| `permission::manager::tests::auto_session_mcp_server_grant_skips_classifier` | pass ×3 | pass ×3 |
| `permission::manager::tests::auto_session_mcp_tool_grant_skips_classifier` | pass ×3 | pass ×3 |
| `permission::manager::tests::auto_session_web_fetch_domain_grant_skips_classifier` | pass ×3 | pass ×3 |
| `permission::manager::tests::bash_ask_floor_satisfied_by_grant_when_remember_on` | pass ×3 | pass ×3 |
| `permission::manager::tests::concurrent_session_grant_suppresses_prompt` | pass ×3 | pass ×3 |
| `permission::manager::tests::hook_ask::ask_prompts_through_a_saved_grant` | pass ×3 | pass ×3 |
| `permission::manager::tests::reject_always_mcp_persists_and_survives_reload` | pass ×3 | pass ×3 |
| `trust::tests::default_path_sources_from_user_fuigo_home` | pass ×3 | pass ×3 |

These are the host-load permission/HOME-path names that fail in alternating sets at both revisions (the parent's
own run failed 8, four of them parent-only); P47 does not touch `permission/` or `trust`. **Result: tip ⊆ parent
holds for all nine packages after isolation.**

## 7. Unverified / proposals

- No runtime test drives a real OTLP export, a real leader workspace exposure end to end, or a real hub
  reconnect from the leader; those are proven by provider/guard tests, the SDK socket tests and mutants.
- Windows: the integration-test `common` module layout was checked by inspection only.
- The hub SDK change (`destination_permits`, `ClientError::DestinationRefused`) is in `crates/common`; it is gated
  here as `fuigo-computer-hub-sdk`.
- **Proposal:** `fuigo-auth`'s `middleware` feature is not on in a plain `-p fuigo-auth` run, so the gate's
  `fuigo-auth` row never runs the middleware tests; `rp.sh` (or the crate's dev-dependencies) should enable it.
- **Proposal (P43/P47 boundary):** a static API key on the skills client and on workspace bearers is held to the
  session rule because those paths carry no credential kind (documented in the policy).


## Addendum (2026-10-02): rebased onto the s12 stack `ae592509` (P62 → P55 → P44 → P65)

The pre-rebase tip is kept as `strike/p47-pre-s12` = `48ea4ced` (on `90c5a4af`). The P47 code is squashed into one
commit, `9f185d3a`, and this receipt follows it. The full gate above applies to `c1dc667d` on `90c5a4af`. The
coordinator re-proves the stacked tip; this addendum records focused runs only.

**Conflict resolutions (both sides kept):**
- `fuigo-shell/tests/common/mod.rs`: P65 already fronts the seeded mock with its own `tests/common/session_front.rs`.
  P65's version is kept, and P47's duplicate `tests/common/front.rs` is dropped.
- `fuigo-workspace/src/hub_auth/mod.rs`: P55 fixed the IPv6 arm of the loopback local-dev plain-bearer path
  (`is_loopback_hub`). P47 removes that path: it refuses `ws` and loopback hubs before auth.json is read. So
  `is_loopback_hub` and its test are removed, and `ws://[::1]` and `wss://[::1]` are added to
  `p47_provider_refuses_a_cleartext_or_loopback_hub`. P56/P64's auth.json lock and unsaved-persist tests are kept.
- `fuigo-shell/src/leader/server_tests.rs`: P55's `hub_url_allows_insecure_ws` IPv6 test and P47's hub tests are
  both kept.
- `fuigo-shell/src/auth/manager_tests.rs`: upstream's event-driven `enrichment_aborts_when_disk_user_changes_mid_flight`
  is kept, and P47 only fronts its `/user` stub. The in-test `rerun_in_own_process` is dropped where `fronted_child`
  already runs the test alone.
- Upstream delta `90c5a4af..ae592509`, re-grepped for bearer sends: none new.

**P65 / R059 HIGH (startup `/v1/settings` sends the session token to http/loopback):** closed by P47. See §0. The gate
in `remote/client.rs` `fetch_settings_blocking_with_attempts` is present at the new tip, and so is the wire test
`p47_wire_remote_settings`.

**Focused runs** (lane `p47dev`, one target dir, deleted after; `dev.sh` = `cargo test --locked --no-run`, then
`slot-run.sh … cargo test --locked`), all at `0e208bd4`:

| run | command (after `cargo test --locked`) | result | log sha256 |
|---|---|---|---|
| s12-shell | `--no-fail-fast -p fuigo-shell --lib` (includes every `p47_` wire test and every fronted fixture) | 7428 passed, 0 failed, exit 0 | `f0b087cfa378d02db50369c5ec3271b2e72b8c8945fbb80b94fd2b56176bd38f` |
| s12-shellit | `-p fuigo-shell --features test-support --test test_startup_prefetch_{fallback,shared,policy,overlap,repair_skip} --test external_auth_expired_credential` | 16 passed, exit 0 | `fa9efc844435345234ae3eb916be2de6ffe77dc5e99867d08823a000c95442b6` |
| s12-ws | `-p fuigo-workspace --lib -- hub_auth upload p47 auxiliary_service_wiring` | 82 passed, exit 0 | `23943caba44f19b72ff001c014735c9e0fee6935d10cfd21748a9a484d2c8ff7` |
| s12-small | `-p fuigo-extra-ca -p fuigo-file-utils -p fuigo-telemetry -p fuigo-computer-hub-sdk -p fuigo-memory` | 1114 passed, exit 0 | `6f05797ddddafcf05c157e7c7cb52e286220734faa4fa23a3b0a11dc2ec4d23e` |
| s12-auth | `-p fuigo-auth --features middleware` | 12 passed, exit 0 | `b9736326a478ab043b843df8dcce9fba73bcaf56c17ea70679cfe8d918bbf887` |

(The first s12-shellit attempt failed to build because P65 made those targets require `test-support`. It was rerun
with the feature.)

**Astra round 8 (integration, `gpt-6-astra`, read-only): LAND.** Findings: BLOCKER 0, HIGH 0, MEDIUM 0, LOW 0.
Transcript: `Fuigo/p47-audit-astra-8.txt` (sha256 `df0a358664514920289a83f7fcd832b765580c9da049d4db175a8475e0de1182`); the verdict section is appended to
`docs/strike/audits/p47-astra.txt`. Quoted: "62 files retain identical added/deleted patch lines. The four differing
files match the documented resolutions. All 36 `p47_` function names survive; no gate or mutant-sensitive assertion
was lost. … **LAND**".

## Addendum 2 (2026-10-02): the s12 workspace drain regression, fixed in `5db96cbb`

**What the coordinator's re-proof found.** In `fuigo-workspace`, `handle::tests::drain_wedged_producer_does_not_starve_queue_flush`
and `handle::tests::two_phase_drain_waits_for_producer_then_drains_queue` failed 3/3 at `abe960e2` and passed 3/3 at
`ae592509` (`hetzner:/root/fuigo-builds/iso-s12c.out`).

**Cause (a product mistake in P47, not a test problem).** The tests' upload source (`handle_tests.rs`
`UnreachableSource`) is a proxy config with no credential: `user_token: ""`.
1. `StaticFuigoAuth::bearer_destination` treated `Some("")` as a session token, because it only exempted `None`.
2. The auth middleware therefore refused the `http://127.0.0.1:1` proxy.
3. `queue.rs` `upload_disposition` classifies a refusal as terminal, so the queue dropped the item at once instead of
   failing on transport and backing off for an hour.
4. The drain then saw an empty queue: `unfinished` was 1 where the test expects 2, and 0 where it expects 1.

Before the s12 stack these tests evidently did not reach the static fallback this way. The stack's queue changes
exposed the path.

**Fix** (`fuigo-file-utils/src/storage_client.rs` `StaticFuigoAuth::bearer_destination`). An absent or **empty**
`user_token` is no credential, so the static provider gets `BearerDestination::Unrestricted`. That is the pre-P47
behaviour for this case. A non-empty user token is still checked.
- Changing the drain tests would only hide the misclassification.
- Astra round 9 checked that an empty static bearer cannot carry a session credential: `apply` adds only the
  selected bearer and a constant marker header. It also checked that a live provider, when supplied, replaces the
  static fallback entirely.

New test: `storage_client::download_blob_tests::p47_empty_static_user_token_is_not_a_session_token`. It asserts that an
empty or absent token is `Unrestricted`, that a non-empty token is refused at the same loopback proxy (control), and
that an empty-token request yields no typed refusal end to end.

**Mutant M39** (`self.user_token.as_deref().is_none_or(str::is_empty)` changed back to `self.user_token.is_none()`):
**killed**. `fuigo-file-utils` exit 101 on `p47_empty_static_user_token_is_not_a_session_token`; log sha256
`7a6aaa2a3cc3f0b7e92771f48f9919558159871e18cebc08f9109a32cf25a962`. The two drain tests are the original failure
under exactly this code. They are not `p47`-named, so the mutant filter did not run them. Mutants now total
**39 of 39 killed**.

**Runs at `5db96cbb`** (lane `p47dev`, one target at a time, all deleted):

| run | result | evidence |
|---|---|---|
| the two drain tests, `cargo test --locked -p fuigo-workspace --lib -- --exact <name>`, 3× each | 6/6 pass | `p47dev/fix-iso.out` sha256 `134014b456ab70d85030f7f7163c9b5f34f4d323cf19feb0a1f123e5b2ce2a10` |
| `--no-fail-fast -p fuigo-workspace --lib` | 1999 passed, 4 failed | `p47dev/fix-ws.log` sha256 `660f8c95f8480b8730187d955b9726b951cc648558790f2286beed62d560b68d` |
| `--no-fail-fast -p fuigo-file-utils` | 226 passed, 0 failed | `p47dev/fix-fu.log` sha256 `4842f88f131f00cda65a135925f4df58e797061d8bd30669e76c9ef422d44c2a` |

The four failures in the workspace lib run were isolated with `iso.sh p47iso2 fuigo-workspace "--lib" "<4 names>"
5db96cbb ae592509`. All 24 runs exit 0 (3/3 `--exact` at tip and at parent): `p47iso2.out` sha256
`d1745cc0e1965d696c565b598bf12cc08ad35038dcba3fe3b75dea34d10c5bb8`. The four names are
`handle::tests::bind_mcp_discovery_is_concurrent_and_bounded`,
`session::git::tests::get_worktree_info_tilde_collapses_home_prefix`,
`hub_auth::proactive::tests::failed_refresh_retries_faster_than_min_interval_then_exhausts` and
`hub_auth::proactive::tests::rate_limit_429_zero_retry_after_uses_backoff`. They are host-load timing and HOME-path
names that also failed at the parent in the earlier gates, and none is P47 code.

**Astra round 9 (on `5db96cbb`): LAND.** Findings: BLOCKER 0, HIGH 0, MEDIUM 0, LOW 0. Transcript
`Fuigo/p47-audit-astra-9.txt` (sha256 `290c81b385ef523f39f1acf71d5fe139bed20e708fd4680281a4c34ed8b3c856`). Quoted: "Diagnosis is correct. … This is the right layer. The mistake is
classifying an empty static value as a session credential. … The new test is non-vacuous. … **LAND**".

## Addendum 3: rebase onto strike/p69-s15 (`0d89295d`), 2026-10-02

P47 now sits at the end of the queued stack: integration `ac2ba777` (P05a and P05b landed), then P05d, P05c, P08,
P57, P53, P54, P61, P67 and P69. The pre-rebase tip is kept as `strike/p47-pre-s15` (`5475ba77`). P47 is two commits
on `0d89295d`: the code and this receipt.

**The one textual conflict** was `fuigo-telemetry/src/otel_layer/mod.rs`. P54 moved the per-export work into
`RefreshableSpanExporter::export_inputs()`, which returns `ExportInputs` (P43 headers, tenant resource attributes and
span-identity withholding). P47's refusal lived in the old inline closure. It is now merged into `export_inputs`:
- `refused` comes from `bearer_refused_for` on the same snapshot token that `export_inputs` resolves.
- A refusal blanks the token, so no bearer is built into the headers, and `export()` returns
  `InternalFailure(reason)` before any request is made.
- Without a refusal, P54's withholding applies as before.
- The refresh-retry path still re-checks the refreshed token.
- P54's test provider `IdentityCredentials` now applies the production service rule. P54's export test asserts a
  refusal for each non-FluxRouter endpoint and none for FluxRouter.

**Semantic fallout, found by the focused runs and fixed in the P47 commit:**

| Finding | Fix |
|---|---|
| P54's `remote::client::tests::session_upsert_sends_no_machine_id_to_a_non_fluxrouter_backend` sent an OIDC session upsert to a plain-http loopback mock. P47 correctly refuses that (`SessionDestinationRefused`). | The test moves behind `fronted_child` / `front_service`, like the other loopback session tests. The pseudonym assertion uses the fronted base, so every P54 assertion still runs. |
| P54's body-identity guard (`fuigo-extra-ca/tests/identity_body_guard.rs`) counted new sites: P47's hub mock reply (`connection_tests.rs` 9→10) and a FuigoAuth fixture (`p47_service_wire_tests.rs`, new, 1). The base itself also fails the guard at `0d89295d`: P08 `1fe6498c` added a seeded `auth.json` fixture to `murage_conformance_acp.rs` (1→3) without re-pinning. | The three counts are re-pinned with their classifications. P47's new `paywall_check_error` refusal record in `subscription_check.rs` drops `user_id`. Astra 10b noted that the unified log can be uploaded for auth diagnostics, so the pin stays at 7. |
| `remote::client::tests::settings_fetch_maps_status_to_outcome` failed once under load (401 read as `Retry`). It passed in the other full runs and 5 of 5 isolated runs at `9b318d9d`. Cause: P47 had fronted this test, and the test started one mock per case. The shared startup blocking client pools its connection to the front, so a route switch could drop a pooled connection, and with one attempt that becomes `Retry`. | One mock now serves every case and only its reply is swapped, so the front's route never changes. |

**Base delta reviewed for new credential sends:**
- P08's runtime API key (`auth_method.rs`, `acp_agent.rs`, `extensions/auth.rs`) is an API key, not a session. A
  persisted key is stored as `AuthMode::ApiKey`. The sampler uses its own static-key headers.
- The P54/P57 session-registry and backend changes still send through the P47-gated `send_authed`.
- P05c's telemetry→crash-handler dependency adds no credential transport.

Astra round 10 reviewed all eleven `AuthCredentialProvider` implementations and agreed.

**Runs** (lane `p47dev` on Hetzner, one target dir at a time, each deleted after its run):

| run (rev) | result | log sha256 |
|---|---|---|
| `-p fuigo-shell --lib` (`a1f11e3c`) | 7462 passed, 1 failed (the P54 upsert test above) | `e4ec83d3b1245fcdcffe6052b2dfd77014aff563b75e4eda0471d4b12749a684` |
| shell startup-prefetch + external-auth integration tests, `--features test-support` (`a1f11e3c`) | 16 passed, 0 failed | `3ce2f201a38a7ddc79ea2dc0f542c4f0634d774efff8abd6ffd9c74bb9f4bf57` |
| `-p fuigo-workspace --lib -- hub_auth upload p47 auxiliary_service_wiring` plus the two drain tests (`a1f11e3c`) | 84 passed, 0 failed (`drain_wedged_producer_does_not_starve_queue_flush` ok, `two_phase_drain_waits_for_producer_then_drains_queue` ok) | `005e47d4e21f43aa594a6b52d1e07f57e3d391edfdda804a435d214bc18a2aaf` |
| `-p fuigo-extra-ca -p fuigo-file-utils -p fuigo-telemetry -p fuigo-computer-hub-sdk -p fuigo-memory` (`a1f11e3c`); includes P54's otel and identity tests | 1123 passed, 1 failed (the body guard above) | `ab7dee47360e7c914a6093c3feb372fdf37d3f1b10573b749e9cea2661fce524` |
| `-p fuigo-auth --features middleware` (`a1f11e3c`) | 12 passed, 0 failed | `a9cf964625fcecf32baab9c61a55c4a3bdfd4909cb900e4594148e4be86bd367` |
| `-p fuigo-shell --lib` (`726143f2`) | 1 failed: the settings flake above | `5fb0177ad1f8cb764bb331da53200daf817c636a30964ab3f3cfcb88a7f17d69` |
| `-p fuigo-extra-ca -p fuigo-telemetry` (`726143f2`) | pass | `b16eab9833eefc93644fce7412f9ad04faf4055d6f4c23f24fa6333039314f9e` |
| `-p fuigo-shell --lib` (`9b318d9d`) | 7463 passed, 0 failed | `1cc9a7ad2764262c783d2f1144a627f71c42f9b30f94eb828452831743f8649d` |
| settings test `--exact`, 5 runs (`9b318d9d`) | 5/5 pass | `efdc6a34670e6f7f1e000301c86bf2be81ee591e71543683e13491b87020d21d` |
| `-p fuigo-extra-ca --test identity_body_guard` (`9b318d9d`) | 3 passed, 0 failed | `e14a21f23fbfc0bc4d6e5035acf879158d2202377d1444c7da0d32a157193c45` |
| `-p fuigo-shell --lib -- remote::` (code `09438a8f`, the final code) | 126 passed, 0 failed | `4410f39047759174c7f05da594d9d7fc5dbeb2f6efb4dd945c965255dd7252b6` |
| settings test `--exact`, 10 runs at host load ~130 (code `09438a8f`) | 10/10 pass | `df13c215a4d04146cca2c5b38fe84c1af70737d6b68110ad5de243c9a444743e` |

The full gate was not run here; the coordinator re-proves it with `rpb.sh`.

**Astra round 10 (the integration audit at `a1f11e3c`): LAND.** BLOCKER 0, HIGH 0, MEDIUM 0, LOW 0. Transcript
`Fuigo/p47-audit-astra-10.txt` (sha256 `ce013318368fb31d7ef9026effa58b3c7bf0e3187b5665a502000d75d42c90ec`).
Quoted: "OTLP resolution is correct. … No integration defect found. … **LAND**"

**Astra round 10b (the test-only delta `a1f11e3c..726143f2`): LAND.** BLOCKER 0, HIGH 0, MEDIUM 0, LOW 1. The LOW
was an inaccurate count in a guard-table comment. It is resolved because P47's log record no longer carries
`user_id`. Transcript `Fuigo/p47-audit-astra-10b.txt` (sha256
`82cc418548381663c6eb58c672d94881e1d61b98791585d3fd759184592ecb25`). Quoted: "The test migration is correct. … The
four re-pins are justified … **LAND**"

**Astra round 10c (the final delta `726143f2..09438a8f`: the log record without `user_id` and the single-mock settings
test): LAND.** BLOCKER 0, HIGH 0, MEDIUM 0, LOW 0. Transcript `Fuigo/p47-audit-astra-10c.txt` (sha256 `90d8060b379851518a72a694a036884d9fcca6d19c99b79460cb81dc297ea565`). Quoted:
"Diagnosis is plausible. … The fix preserves all six cases. … The refusal record removes the intended identity. …
**LAND**"
