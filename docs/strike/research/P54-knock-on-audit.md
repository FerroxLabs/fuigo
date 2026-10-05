# P54 knock-on audit (P54-K) — does identity-in-bodies break anything real?

**Question (Sean, 2026-10-02):** P54's behaviour change is accepted, "but check and verify to make sure that won't cause
any knock-on problems."
**Scope:** P54 as landed at integration `a6903998` (receipt `R063-p54.md`; policy `docs/destination-trust-policy.md`
§"Identity in request bodies"). Header rule precedent: P43 (`R039-p43.md` §9–10).
**Method:** two independent hunts — the lead (Fable) and Astra (`gpt-6-astra`, read-only, started first from the same
facts and no hypotheses: `docs/strike/audits/P54K-astra-hunt.txt`) — then a cross-audit of each other's lists, code
reading with file:line, and real tests on Hetzner for every claim a test can carry. Evidence for the tests and the gate is
in receipt `docs/strike/receipts/R080-p54k.md`.

## 0. Answer in one paragraph

For the **default install nothing P54 touches is reachable**: every body-identity site sits behind an auxiliary base
that ships empty (`CLI_CHAT_PROXY_BASE_URL_DEFAULT = ""`, `fuigo-env` `PRODUCTION_ENDPOINTS` all empty,
`FUIGO_CODE_BACKEND_URL` has no compiled default) or behind a Mixpanel token no public build bakes
(`fuigo-telemetry/src/config.rs:137` `internal_defaults()` → `None/false`). Inference goes to `https://api.fluxrouter.ai`,
which is FluxRouter-operated, so billing and attribution there are untouched (P54 never gated the sampler). Murage sees
no difference: its ACP driver injects `FUIGO_HOME`, `FUIGO_API_KEY`, `FUIGO_API_BASE_URL` only and reads
`_meta.modelId`, not `agentId`. The knock-ons that are real are all confined to **operator-configured** deployments
(their own cli-chat-proxy / session backend / storage proxy / internal OTLP collector / Mixpanel project): a one-time
re-key of every machine and user at upgrade, no `hostname` in their registry's register request (so their session
picker's "Host" line shows only what that registry fills in itself), no account/tenant attributes in their OTLP traces. Nothing client-side compares a raw id against what the server now holds, so no local session, fork,
worktree resume, share link or index is orphaned. Four small things were worth fixing on `strike/p54k` (§3): an empty
account id became one shared, valid-looking Mixpanel user; review comments omitted the machine key while the LOC
records of the same session carried a pseudonym to the same proxy; dropped LOC lines were silent; and the pseudonym
recipe was unpublished, so an operator holding raw ids could not migrate their own rows. The remaining decisions for
Sean are in §5, each with a recommendation.

## 1. Facts the verdicts rest on

| fact | where |
|---|---|
| Auxiliary bases are empty by default; `has_proxy()` gates the registry, storage proxy, feedback, `/deployment/config` and the internal OTLP firehose | `fuigo-shell/src/agent/config.rs:55-59,307-316`; `fuigo-env/src/lib.rs:21-37` |
| The session registry additionally needs `remote_settings.session_registry_enabled` (fetched from the proxy) or a local override, and Fuigo auth | `agent/mvp_agent/agent_ops.rs:606-626` |
| `FUIGO_CODE_BACKEND_URL` has no compiled default; unset means share/writeback/fork-sync/remote-delete are off with a `NotConfigured` error | `fuigo-shell/src/remote/client.rs:9-16,389-393`; test `backend_client_without_backend_url_fails_closed_with_a_true_message` |
| Mixpanel is on only with a build-time token (`FUIGO_TELEMETRY_BUILD_MIXPANEL_TOKEN`) or a configured one; `internal_defaults()` is `(None, None, None, false)` | `fuigo-telemetry/src/config.rs:137-165,251-255`; README `fuigo-shell/README.md:1381` |
| Default inference host `https://api.fluxrouter.ai/v1` is FluxRouter-operated | `config.rs:64`; `fluxrouter.rs:111` |
| `agent_id()` = `FUIGO_AGENT_ID` env, else `$FUIGO_HOME/agent_id` (0600, atomic), else a machine-derived UUIDv5 (macOS hardware ids; Linux `/etc/machine-id` + `$HOSTNAME`; random v4 fallback) persisted there | `fuigo-telemetry/src/id.rs:52-85` |
| `destination_pseudonym` = UUIDv8 from `SHA-256("fuigo.p54.body-identity-pseudonym.v1" ‖ 0 ‖ origin ‖ 0 ‖ value)`; origin = `Url::origin().ascii_serialization()` (scheme, lowercased host, non-default port) | `fuigo-extra-ca/src/fluxrouter.rs:249-286` |
| Shared HTTP clients refuse cross-origin redirects, so a permitted body cannot be redirected to another host | `fuigo-extra-ca/src/redirect.rs`, `lib.rs:63-65` |
| Neither backend `SessionInfo` nor registry `SessionRecord` returns a machine id; no client code compares `agent_id`/`device_id` with a server value | `remote/client.rs:254-270`; `session_registry_client.rs:115-137`; repo-wide grep of `agent_id ==` / `device_id ==` (only pager-local `AgentId(n)` and subagent ids) |
| One-shot feedback archives are only ever `UploadMethod::Proxy`; `Direct`/`S3` are refused before the archive is built | `agent_ops.rs:3567-3603` |
| Review comments go to `build_gcs_config` (Direct GCS / S3 / Proxy) | `agent_ops.rs:3481-3513`; `extensions/feedback.rs:383-520` |

## 2. Candidate table (lead's hunt), with verdicts

Verdicts: **CONFIRMED** (traced and reproduced in a test or by construction), **PLAUSIBLE** (a server or vendor
component Fuigo does not ship decides), **REFUTED** (checked; cannot happen).

| # | candidate | verdict | evidence | consequence / action |
|---|---|---|---|---|
| 1a | Upgrade continuity, **default install**: anything orphaned or duplicated | **REFUTED** | §1 rows 1–5; new test `p54_default_install_has_no_body_identity_destination` (`remote/client_tests.rs`) pins the proxy, storage-proxy, internal-OTLP and backend resolvers at "no host" and the Mixpanel mechanism (on only with a build-time token). That no public build bakes a token is a release-pipeline fact (README) the test cannot see | none |
| 1b | Upgrade continuity, **operator session backend** (`FUIGO_CODE_BACKEND_URL`, non-FluxRouter): sessions upserted before the upgrade carry the raw `agentId`, after it the origin pseudonym | **PLAUSIBLE** (server-side) | `remote/client.rs:284-299`; every write path (sync, share, fork, worktree resume) goes through `upsert_session` | A backend that groups or authorises by `agentId` sees each machine once more as a new one; a backend that enforces owner immutability on a PUT could refuse (share waits on that upsert: `client.rs:450`; writeback only warns: `sync.rs:119-129`). Fuigo ships no such backend. **Mitigation shipped:** the pseudonym recipe is published and pinned (§3.4) so the operator can rewrite their rows raw→pseudonym offline. Release note §6 |
| 1c | Upgrade continuity, **operator registry** (cli-chat-proxy): `deviceId` pseudonymised, `hostname` omitted | **PLAUSIBLE** (grouping) / **CONFIRMED** (request), UI conditional | `session_registry_client.rs:175-191`; `acp_agent.rs:1729-1797`; the picker's "Host" row reads `entry.hostname` (`fuigo-pager/src/views/session_picker.rs:772`) and the wire type returns it (`SessionRecord.hostname`) | Old replicas under the raw device id, new ones under the pseudonym (update/finalize carry only the session id). The register request carries no `hostname`; the picker shows whatever the registry returns, so its "Host" line disappears for those replicas unless the server fills it in itself. Accepted behaviour (R063 decision 3); decision for Sean in §5.2 |
| 1d | Client-side: local session index, fork, worktree resume, share links keyed by the raw id | **REFUTED** | fork copies locally then registers in a spawned task (`session/fork.rs:96-125`); worktree resume resolves the local session then forks (`session/worktree.rs:143`); share URLs use `permission_id` (`client.rs:35-40`); index keyed by `session_id` (`fuigo-session-search/src/fts.rs:204`); no raw-id comparisons (§1) | none |
| 1e | Pseudonym stability across restarts / machines / reinstalls | **CONFIRMED** stable iff (`agent_id`, origin) stable | §1 rows 6–7 | Restart: stable (cached file). Reinstall keeping `$FUIGO_HOME`: stable. Fresh home: macOS re-derives the same hardware hash; Linux depends on `/etc/machine-id` + `$HOSTNAME` (pre-existing). Two machines: two keys, as before. **New:** a change to the configured URL's *origin* re-keys (§2 row 2b). Pinned both ways by `destination_pseudonym_keys_on_the_normalized_origin_only` |
| 1f | Same user, two machines, one account | **REFUTED** as a regression | Mixpanel keys on the account id → one pseudonym on both machines; backend/registry keyed on the machine id → two, as before | none |
| 2a | FluxRouter misclassified as third party: ports, case, trailing dot, userinfo, path | **REFUTED** | `fluxrouter.rs:54-60,111-114` and tests `fluxrouter_api_urls_match_on_every_surface_and_spelling`, `identity_gate_is_the_fluxrouter_predicate_restricted_to_https` | `https://api.fluxrouter.ai[:any][./path]` in any case is permitted |
| 2b | Origin spellings that re-key a non-FluxRouter pseudonym | **CONFIRMED** (by design) | `fluxrouter.rs:259-265`; new test pins: same key for default port, host case, userinfo, path/query/fragment; different key for `http`↔`https`, non-default port, IP literal, host alias, trailing dot; two services on two origins get two keys | Document (done in the `destination_pseudonym` doc comment and §6). Not changed: re-keying the domain tag now would itself re-key, and no release has shipped P54 yet, so the contract is pinned rather than altered |
| 2c | Self-hosted / managed Ferrox / staging FluxRouter hosts (`staging.api.fluxrouter.ai`, custom `[endpoints]`) lose identity | **CONFIRMED** (by design, P30/P43 fail-closed) | `fluxrouter.rs:104-110,340-361` | Visible, not silent: `apply_identity_headers` warns (P43). A managed deployment off `api.fluxrouter.ai` gets pseudonymous keys and no tenant attributes in OTLP; P43 §9.4's per-origin opt-in remains the only route if Ferrox ever needs it |
| 2d | Leak direction: lookalikes, userinfo, IDN, redirects | **REFUTED** | lookalike/userinfo tests in `fluxrouter.rs:340-361`; `Url` IDNA-normalises before the compare; same-origin redirect policy (`redirect.rs`) | none |
| 3 | Murage / ACP embedders depend on a raw id P54 now withholds | **REFUTED** | ACP `initialize` `_meta.agentId` unchanged (`acp_agent.rs:493-515`, stdio); Murage's driver (`murage-0163-chromebatch2/server/drivers/acp/fuigo.ts`) sets `FUIGO_HOME`/`FUIGO_API_KEY`/`FUIGO_API_BASE_URL` and reads `_meta.modelId`; its own `deviceId` is a push-relay id, unrelated; `tests/murage_conformance_acp.rs:158` only requires `agent_id` to exist in the sandbox home (hermeticity), still true; Contract E (`strike-contracts/docs/strike/contracts/E-downstream-embedder-compatibility.md`) promises credentials, argv, protocol and model state, none of the changed bodies | none |
| 4a | Billing / usage attribution on FluxRouter | **REFUTED** | sampler headers and FluxRouter-only body fields untouched by P54 (`fuigo-sampler/src/client.rs`); OTLP to FluxRouter keeps resource and span identity on the first attempt and the refresh retry (`otel_layer/mod.rs:307-345`, test `export_inputs_withhold_identity_…` asserts the FluxRouter side); auxiliary 401 retries re-send the already-decided body (`fuigo-auth/src/retry_middleware.rs`) | none |
| 4b | Something that WAS first-party is now pseudonymised | **REFUTED** | `body_key_for` returns the value for every FluxRouter-operated URL (`fluxrouter.rs:240-246`, tests). Every site whose raw id changed (Mixpanel, operator registry/backend, LOC archives to an operator proxy) is a destination that is never FluxRouter-operated; nothing FluxRouter-bound changed | none |
| 4c | Operator OTLP collector (`FUIGO_INTERNAL_OTLP_TRACES_ENDPOINT`, or the legacy `OTEL_EXPORTER_OTLP_*` internal override) loses `user.id`/`team.id`/… | **CONFIRMED** (accepted) | `otel_layer/mod.rs:207-290`; `agent/config.rs:345-367` | Dashboards joining on those keys stop matching new spans. This is R063 decision 3, accepted. Release note §6. The external OTEL path (double opt-in) keeps identity and is the supported route for a user's own collector |
| 5a | Mixpanel: once-at-upgrade split | **CONFIRMED** for configured projects; **REFUTED** for public builds (off) | `fuigo-telemetry/src/client.rs:63-124`; `config.rs:137-165` | Every `distinct_id` changes once: the old profile stays with the raw id (never updated again), a new profile appears under the pseudonym; MAU/retention cohorts double-count across the upgrade window; `$insert_id` dedupe unaffected; track and engage share the pseudonym so new profiles and events join |
| 5b | Alias / identify bridge without sending the raw id | **REFUTED** (impossible) | Mixpanel's `$identify`, `$create_alias` and `$merge` all take both ids in the request body, which would put the raw account id on Mixpanel's wire — exactly what P54 forbids | Recommendation §5.3: accept the split; annotate the dashboard date; no client-side bridge |
| 5c | Empty account id → one shared, valid-looking Mixpanel user | **CONFIRMED** (fixed, §3.1) | external auth starts with `user_id: ""` (`auth/external_auth.rs:14-37`) and `is_fuigo_auth()` is true for a Fuigo issuer, so `init` passed `Some("")` (`agent/init.rs:274-276`); `mixpanel_distinct_id("")` is a constant UUID at that origin | Pre-P54 the empty string went as `distinct_id` too, but P54 turned it into a credible UUID that Mixpanel aggregates as one user. Now: empty counts as missing → machine-id pseudonym |
| 6a | Support correlation, FluxRouter proxy | **REFUTED** | headers (`x-userid`, `x-email`, P43) and bodies unchanged for FluxRouter | none |
| 6b | Support correlation, operator proxy | **CONFIRMED** (accepted, narrowed) | `x-userid` already withheld since P43; `hunk_records.jsonl` human `authorId` → `null`, machine ids → pseudonym (`upload/feedback_archive.rs:46-100`); review comments **omitted** `agentId` (`extensions/feedback.rs:383-404` at a6903998) | Correlation at that operator is by `sessionId`/`commentId` plus one stable machine pseudonym per origin. **Changed (§3.2):** review comments now carry the same pseudonym as the LOC records, so post-upgrade create ↔ tombstone ↔ hunks join and a consumer that requires the field keeps working. A pre-upgrade create keyed `(raw agentId, commentId)` still does not match a post-upgrade tombstone until the operator migrates (recipe §3.4) — PLAUSIBLE pending migration. Residual: `feedback.jsonl` `author_email` still rides archives raw (R063 decision 2, proposal P-2) |
| 7a | Pseudonym derivation failure | **REFUTED** | infallible: SHA-256 over bytes; unparseable URL hashed verbatim (`fluxrouter.rs:261-265`, test) | none |
| 7b | Empty `archive_destination` (Direct/S3) would pseudonymise the user's own bucket | **REFUTED** (dead branch) | `one_shot_feedback_gcs_config` returns `None` for non-Proxy (`agent_ops.rs:3598-3603`); the empty string fails closed anyway | none |
| 7c | Missing / empty user id | **CONFIRMED** for Mixpanel (§5c, fixed); **REFUTED** elsewhere | OTLP drops empty values (`otel_layer/mod.rs:240-252`); LOC `user_id: Option` (`agent_ops.rs:4305`); product events (`events_url`, user-configured) unchanged | — |
| 7d | Logged-out / API-key-only users | **REFUTED** | `is_fuigo_auth()` is false for `ApiKey` (`auth/model.rs:137-143`) → telemetry gets no user id → machine-id pseudonym; registry/backend need Fuigo auth and are skipped otherwise | none |
| 7e | Offline | **REFUTED** | derivation needs no network; nothing is sent | none |
| 7f | Unparseable LOC lines silently dropped from an upload | **CONFIRMED** (fixed, §3.3) | `feedback_archive.rs:60-63` | now counted and `warn`ed; local file untouched |
| 7g | A backend validating UUID *version* rejects the v8 pseudonym | **PLAUSIBLE** (external), **REFUTED** for the shipped types | registry type takes `Option<String>` (`prod/mc/cli-chat-proxy-types/src/session_types.rs:27-30`) | note in §6 |

## 3. Fixes on `strike/p54k` (tip in R080)

1. **Mixpanel: an empty account id is not a key** (`fuigo-telemetry/src/client.rs`, `mixpanel_key_source`). Applied
   to both `/track` and `/engage`; the product-events path (user-configured) is untouched. Test
   `an_empty_account_id_is_not_a_mixpanel_key` ("", "  ", "\t" → the machine-id pseudonym, never the empty-string
   pseudonym). Mutant: filter removed → fails.
2. **Review comments carry the proxy-origin pseudonym, not nothing** (`fuigo-shell/src/extensions/feedback.rs`
   `stamp_review_agent_id`, Proxy branch → `body_key_for`). Where the session's archive is uploaded the proxy already
   holds that key; in a deployment-key configuration (comments uploaded, one-shot archives refused:
   `agent_ops.rs:3580`) it is a new pseudonymous, origin-scoped machine key — inside the P54 policy, at the
   operator's own proxy, and the trade Sean decides in §5.1. Test `review_comment_records_carry_the_machine_id_only_to_permitted_storage`
   now pins `comment.agentId == withhold_loc_identity(url, …).agentId` for three non-FluxRouter URLs and still pins the
   raw id for FluxRouter, Direct and S3. Mutants: branch omits → fails; branch sends raw → fails.
   Policy doc row updated.
3. **Dropped LOC lines are counted and warned** (`fuigo-shell/src/upload/feedback_archive.rs`). Behaviour unchanged
   (fails closed); observability only.
4. **Published, pinned pseudonym recipe** (`fuigo-extra-ca/src/fluxrouter.rs`): the doc comment carries a 6-line
   Python reproduction and `destination_pseudonym_matches_its_published_recipe` pins three vectors computed
   independently with `hashlib` (e.g. `https://backend.example` × `5d1f0c2a-…89ab` → `c3ad749c-6794-8fb7-a4f2-03664010e911`).
   An operator holding raw ids can migrate rows; nobody without them can invert it. Mutant: domain tag changed → fails.
5. **Origin-normalisation contract pinned** (`destination_pseudonym_keys_on_the_normalized_origin_only`).
6. **Default-install pin** (`p54_default_install_has_no_body_identity_destination`): if the proxy base, the storage
   proxy, the internal OTLP endpoint or the session backend ever gains a compiled default host, this test fails and the
   default-install verdict must be redone. For Mixpanel it pins the mechanism only (enabled ⇔ a build-time token); a
   release that bakes a token would pass it, so "public builds bake no token" rests on the release pipeline and the
   README, not on this test.

## 4. Astra's independent list and the cross-audit

Astra's hunt (`docs/strike/audits/P54K-astra-hunt.txt`) ran before it saw any lead hypothesis. Its overall verdict:
*"no confirmed P54 blocker for default Fuigo or Murage, but 'no knock-on problems' is unsupported — configured
deployments have confirmed attribution losses and unresolved backend continuity risks."*

| Astra # | finding (Astra's severity / verdict) | lead's cross-audit |
|---|---|---|
| 1 | HIGH / PLAUSIBLE — operator backend ownership or routing can break at upgrade | Agree it is plausible; severity **MEDIUM** here: no such backend ships, the base has no default, and the recipe fix (§3.4) gives the operator a migration. = row 1b |
| 2 | MEDIUM / PLAUSIBLE — registry device continuity and "Host" in the picker | Agree. = row 1c. Decision §5.2 |
| 3 | MEDIUM / CONFIRMED — Mixpanel raw-id continuity stops; no alias is sent | Agree. = rows 5a/5b. Astra's note that Mixpanel is off in source defaults matches §1 |
| 4 | MEDIUM / CONFIRMED — non-FluxRouter internal OTLP collectors lose tenant attribution, incl. legacy `OTEL_EXPORTER_OTLP_*` override | Agree. = row 4c (accepted R063 decision 3) |
| 5 | MEDIUM / CONFIRMED — origin changes re-key; two services on two origins get two keys; trailing dot kept for non-FluxRouter hosts | Agree; verified `url` crate normalisation independently and pinned both directions (§3.5). = rows 1e/2b |
| 6 | MEDIUM / CONFIRMED — feedback loses raw joins; human `authorId` null | Agree; accepted scope of P54. = row 6b |
| 7 | MEDIUM / PLAUSIBLE — a review-comment consumer requiring `agentId`, or matching tombstones on `(agentId, commentId)`, breaks; the CLI reports `recorded: true` regardless | Agree. Field presence **repaired** (§3.2): the record carries the origin pseudonym. Historical pairs (pre-upgrade create, post-upgrade tombstone) stay PLAUSIBLE pending the operator's migration |
| 8 | LOW / PLAUSIBLE — UUID-version validators | Agree; shipped types accept any string. = row 7g |
| 9 | LOW / CONFIRMED — malformed LOC lines vanish silently | Agree; **fixed** (§3.3) |
| 10 | INFO / CONFIRMED — stability follows the underlying id; `FUIGO_AGENT_ID` override | Agree. = row 1e |
| 11 | INFO / CONFIRMED — empty account id not treated as missing (pre-existing) | Agree it predates P54; disagree it is only INFO: P54 made the empty key a credible UUID. **Fixed** (§3.1) |
| 12 | INFO / REFUTED — local sessions, index, forks, worktree resume | Agree. = row 1d |
| 13 | INFO / REFUTED — default FluxRouter traffic or ordinary host spelling becomes pseudonymous | Agree. = rows 2a/2c |
| 14 | INFO / REFUTED — Murage ACP / Contract E | Agree; the lead additionally checked the Murage driver source. = row 3 |
| 15 | INFO / REFUTED — inference billing, retry accounting, local usage | Agree. = row 4a |

Lead findings Astra did not raise: the dead `Direct`/`S3` archive branch (7b, refuted), the `is_fuigo_auth()` gate for
API-key users (7d, refuted), and the explicit impossibility of a Mixpanel bridge (5b). Astra findings the lead had not
listed before reading it: the `recorded: true` masking of an asynchronous server-side rejection (7), and that the
tombstone pairs with the create record (7) — both folded into fix §3.2.

Astra's diff audit of the fixes (rounds and final verdict) is in `docs/strike/audits/P54K-astra.txt` and quoted in R080.

## 5. Decisions for Sean (each with a verified recommendation)

1. **Review comments: pseudonym instead of omission at a non-FluxRouter proxy** (§3.2, already applied).
   *Recommendation: keep.* Verified: whenever a feedback archive is uploaded the same origin already receives the
   identical key (`withhold_loc_identity`; the test pins equality), and the policy P54 landed allows "a per-origin
   pseudonym". The one configuration where it is genuinely new is a deployment key (comments go, archives do not):
   there the operator's own proxy gains a one-way, origin-scoped machine key — the same class of key it gets from the
   session registry's `deviceId`. Reverting is one line (`body_key_for` → `body_identity`).
   *Interaction with P71v2 (accepted, not yet landed):* P71v2 refuses ALL file content to a non-FluxRouter storage
   proxy inside `gcs::upload_bytes`, which review comments also use (`feedback.rs:467,522`). Once it lands, no
   non-FluxRouter proxy receives a review record, so this branch is dormant in production and the decision has no live
   configuration left; it stays correct and pinned as a unit (R080 §9).
2. **`hostname` omitted from the register request at a non-FluxRouter registry → the picker's "Host" line for those
   replicas shows only what that registry fills in itself (nothing, unless the server derives one).**
   *Recommendation: accept (unchanged).* Verified: the host name is a stable machine identifier that often carries the
   user's name; the pseudonymous `deviceId` still separates machines; the picker still shows CWD, source, model and
   times. Widening it by configuration would breach the P30 rule that configuration never widens identity.
3. **Mixpanel split for operators who configure a token.** *Recommendation: accept; no alias; add one line to the
   release notes (§6).* Verified: every Mixpanel merge API carries both ids in its body; a client-side bridge would send
   the raw account id to Mixpanel. Public builds are unaffected (no baked token).
4. **Operator backends keyed on the raw `agentId`/`deviceId`.** *Recommendation: accept with the published recipe
   (§3.4) and the release note (§6).* Verified: the recipe is deterministic and reproduces the Rust output on three
   pinned vectors, so an operator can rewrite their rows offline before rolling the client out.
5. **Residual (not a P54 knock-on, carried from R063):** `feedback.jsonl` `author_email`, `unified_log` `user_id` and
   workspace environment uploads still carry raw identity to a non-FluxRouter proxy. *Handed to P71v2* (`wt-p71v2`,
   Sean-accepted): its destination rule sends no archive, trace, diagnostic, share or heap bytes to such a proxy at all,
   which covers R063 proposals 1 and 2 without a filter; the workspace environment record keeps the field rule there.

## 6. Release-note wording (operators only; nothing for a default install)

> **Identity in auxiliary-service request bodies (1.0.21).** Fuigo now sends account, team, organisation and
> deployment identifiers, e-mail addresses, the host name and the persisted machine id in request bodies only to
> FluxRouter-operated services (`https://api.fluxrouter.ai`) and to destinations you configured for that data
> (external OTEL, product events, `[feedback.user]`). Every other destination receives the field omitted or, where
> the service needs a stable key, a per-origin pseudonym (a one-way, UUID-shaped key that is the same for one
> machine or account at one origin and different at every other origin).
>
> If you run your **own cli-chat-proxy session registry, session backend (`FUIGO_CODE_BACKEND_URL`), storage proxy,
> internal OTLP collector or Mixpanel project**, expect, once, at upgrade: each machine and account appears under a
> new key (`deviceId`, `agentId`, Mixpanel `distinct_id`); registry entries no longer carry `hostname`; internal
> OTLP spans no longer carry `user.id`, `team.id`, `organization.id`, `deployment.id`, `api_key.id`. The key is
> deterministic: `destination_pseudonym` in `fuigo-extra-ca` documents the recipe, so a service that already holds
> the raw ids can compute the new keys and migrate its rows. Changing the configured URL's origin (scheme, host,
> non-default port) re-keys again; paths do not. Mixpanel cannot be bridged without sending the raw id, so the split
> is permanent there. Default installs, FluxRouter billing and attribution, Murage and other ACP embedders, local
> sessions, forks, worktree resume and share links are unaffected.
