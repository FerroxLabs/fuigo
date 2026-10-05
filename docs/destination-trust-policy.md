# Destination trust policy: two classes, never merged (P30)

Fuigo decides two different things about a request's destination. Each decision has its own trust
class, its own code and its own name. Before P30 both were called "first-party", which is how the
proposal arose to make one consult the other. That proposal was rejected. The word "first-party" is
no longer used for destinations.

P47 adds a third class for session delivery to auxiliary Ferrox services: the **service-endpoint** class
("Service-endpoint session delivery: one predicate (P47)" below). It builds on the two classes below and
merges neither. It admits FluxRouter-operated origins and configured API origins for credential delivery
only, plus each client's own configured service base. It never decides identity disclosure.

| | **FluxRouter-operated** | **User-configured API origin** |
|---|---|---|
| Decides | **Identity disclosure.** May the `x-fuigo-*` identity headers go to this destination? | **Credential delivery.** May the session bearer or `FUIGO_API_KEY` be attached? Does the API-key kill switch refuse a key here? |
| Source of truth | Compiled: `fuigo_extra_ca::fluxrouter::FLUXROUTER_API_HOST` plus `https` | Configuration: `[endpoints]` → `fuigo_shell_base::util::TrustedApiOrigins` |
| Code | `fuigo_extra_ca::fluxrouter::is_fluxrouter_operated_url`, `IdentityDisclosure` | DELIVERY: `is_fuigo_api_bearer_url` (session bearer: configured origin, `https`, never loopback; reached in `fuigo-shell` through `AuthBackend::may_receive_session`), `is_configured_api_origin` (`FUIGO_API_KEY`: configured origin, `https`, or `http` on a configured loopback origin). REFUSAL: `is_fuigo_api_url` (host-only, scheme- and port-agnostic, admits every loopback URL; it should never decide delivery, but today it does in three places: see "Known defect") |
| Can the user widen it? | **No.** | **Yes.** That is its purpose. |
| Fails closed to | Identity withheld (logged by `fuigo_sampler::client::apply_identity_headers`; `warn` when there was an identity to withhold) | No credential attached (logged by `session_may_be_sent_to` / `env_api_key_may_be_sent_to`) |

## Why they must stay separate

- **Configured trust must not decide identity.** A user may configure `https://api.openai.com/v1`, or a
  loopback gateway, as an API origin. Sending that destination the credential the user chose to send
  it is correct. Sending it the Ferrox account id, the tenant UUID and a persisted machine id is not.
  Those values are the same at every provider the user configures, so any provider that receives
  them can link the user's traffic across providers. Closing that leak is why P15 exists.
- **The compiled host must not decide credentials.** Credential delivery has to follow the endpoint the
  user configured. If it does not, a self-hosted gateway receives no credential and every request
  goes out unauthenticated. P17-R fixed that defect. The reverse also holds: an installation that did
  not configure FluxRouter must not send FluxRouter its credential just because the host is the
  compiled one.

## Enforcement

- **By type.** The identity gate in `fuigo-sampler` (`FuigoRequestHeaders::identity`,
  `SamplingClient::identity_disclosure`, `apply_identity_headers`) takes an `IdentityDisclosure`, not a
  `bool`. Only `IdentityDisclosure::for_destination(url)` can grant one, and it asks only
  `is_fluxrouter_operated_url`. The type has no public field and no `From<bool>`. Two `compile_fail`
  doctests in `fluxrouter.rs` pin that. A configured-trust answer is a `bool` and cannot be passed
  where an identity decision is required. `IdentityDisclosure::WITHHELD` is public because
  withholding is always safe.
- **By name.** `is_first_party_url` is renamed `is_fluxrouter_operated_url`, so the old name no longer
  compiles. In `fuigo-shell`, `endpoint_is_first_party` is renamed `endpoint_is_configured_api_origin`.
  The comments, docs and test messages that used "first-party" for a configured destination now say
  "configured API origin".
- **By test.** `fuigo-shell-base` `util::tests::credential_delivery_and_identity_disclosure_are_decided_independently`
  pins the policy in both directions. `fuigo-extra-ca`
  `identity_disclosure_is_granted_by_the_compiled_host_check_alone` and
  `a_user_configured_gateway_is_not_granted_identity_disclosure` pin the type.

## The configured-gateway case: bearer yes, identity no

A user on their own configured remote HTTPS gateway receives the session bearer and no `x-fuigo-*`
identity headers. **This is correct, and it is the policy.** (The *intended* session policy is that
the bearer never goes to loopback or cleartext, even when configured; a configured `http://localhost`
gateway receives `FUIGO_API_KEY` but not the session bearer. The static credential path enforces
that, and since P42 every other session-delivery path does too: see "Session-token delivery: one
predicate (P42)".)

1. The user chose the destination, so the user chose to send it a credential. Fuigo did not choose the
   destination, so Fuigo does not volunteer a cross-provider identifier to it. The two decisions have
   different owners, and each class follows its owner.
2. The gateway does not need the identity headers to work. It authenticates with the bearer, and the
   correlation headers (`conv-id`, `req-id`, `session-id`, `turn-idx`, `transient-retry`,
   `model-override`) still reach every destination (P15-R). What the gateway loses is FluxRouter's
   proxy-side version gating and telemetry, which only FluxRouter performs.
3. The cost can be seen and undone. When the config carried an identity to withhold, the sampler logs
   a `warn` that names the remedy. The opposite failure would disclose identity silently, and could
   not be undone.

There is no opt-in for sending identity to a configured gateway, and P30 does not add one. If a
managed deployment ever needs it, add it as an explicit per-origin setting that is separate from
`[endpoints]`, so that configuring an endpoint can never imply disclosure. That would be a contract
change with its own packet. No current consumer is known.

## Call sites, by class

| Call site | Decides | Class | Verdict |
|---|---|---|---|
| `fuigo-sampler` `SamplingClient::new` → `IdentityDisclosure::for_destination` → `apply_identity_headers` and `FuigoRequestHeaders::apply` | `x-fuigo-{user,deployment,agent}-id`, `-client-version`, `-client-identifier` on inference | FluxRouter-operated | correct |
| `fuigo-sampler` cache-bypass body field; `fuigo-tools` `web_search/client.rs:178` | FluxRouter-only request fields Fuigo adds by itself | FluxRouter host (`is_fluxrouter_url`, scheme-agnostic: only "will the host understand it" matters) | correct |
| `fuigo-shell` `auth/backend/fuigo.rs` `may_receive_session`, `credential_provider`, `fuigo-voice`, `fuigo-pager` voice | session bearer | configured (`is_fuigo_api_bearer_url`) | correct |
| `fuigo-shell` `agent/config.rs` `env_api_key_may_be_sent_to` | `FUIGO_API_KEY` | configured (`is_configured_api_origin`) | correct |
| `fuigo-shell` `SessionTokenAuthGate::new` (`sampler_turn.rs`), `session_bearer_resolver` (`agent/subagent/mod.rs`) | session token on the live turn / subagent under an `Unknown` BYOK status | delivery, `session_delivery::session_may_reach` (P42; was the broad matcher) | correct since P42 |
| `fuigo-shell` `enforce_disable_api_key_auth` | kill switch: refuse the API key (correct, broad); substitute the session (delivery) | refusal `is_fuigo_api_url`; substitution `session_may_reach` (P42) | correct since P42 |
| `fuigo-shell` `auth/credential_provider.rs` `embedding_session_credentials` | session credential on embeddings | configured, delivery (`is_fuigo_api_bearer_url`) | correct |
| `fuigo-shell` `agent/config.rs` `response_include_extensions` | `no_inline_citations` Responses include | configured (`is_trusted_fuigo_https_url`) | unchanged and **recorded, not certified**: sent when the effective model entry says `supports_backend_search`. That flag is model metadata (from a catalogue, possibly inherited, or a `[model.*]` override) and is not bound to the current destination: an override can change `base_url` and keep the flag. Nothing verifies that the destination accepts the field. It carries no identity and no credential, so neither class strictly governs it. |
| `fuigo-shell` `agent/config.rs` `inject_url_derived_headers` → `x-fuigo-client-mode` | two-valued behaviour flag | neither (ungated) | correct, explained in place (P15-R) |

## Session-token delivery: one predicate (P42)

P30 recorded that session-token delivery was not decided by one predicate (the `Unknown`-BYOK gate,
the subagent resolver and the kill-switch substitution used the broad `is_fuigo_api_url`; `NotByok`
delivered without a destination check; a buffered token survived a withheld resolver). P42 fixed it:

- Every path that can attach the session token to an inference-class request (model `base_url`, the
  `[endpoints]` API origins and URLs derived from them) decides with
  `fuigo-shell` `auth::session_delivery::session_may_reach`, which is `AuthBackend::may_receive_session`
  (`is_fuigo_api_bearer_url`: configured origin, `https`, never loopback). `NotByok` and `Unknown` decide
  only whether the token is wanted.
- A buffered token is re-checked against the current destination at send time
  (`withhold_session_bearer`); a session token is recognised by value (`AuthManager::is_session_bearer`).
  A static `AuthMode::ApiKey` credential, `FUIGO_API_KEY` and BYOK keys keep their own rules.
- A 401 caused by withholding the session is terminal and names the `[endpoints]` remedy.
- Behaviour change: a session user on an `http://`, other-port, unconfigured or loopback URL gets 401.

The per-path list, tests and mutants are in `docs/strike/receipts/R034-p42-session-token-delivery.md`.
Auxiliary Ferrox-service clients (billing, consent, remote settings, skills, feedback, trace upload,
relay, workspace hub/leader) are a separate class: see the next section (P47).

## Service-endpoint session delivery: one predicate (P47)

The auxiliary service clients sent the session token with no destination check. P47 names their class and
gives it one predicate: `fuigo_extra_ca::service_trust::session_may_reach_service(url, configured_service_base,
configured_api_origin)`. In `fuigo-shell` it is reached through `auth::session_delivery::session_may_reach_service`,
which passes P42's `session_may_reach` as the configured-API-origin answer.

**The rule.** The session token may go to a service URL only when all of these hold:

1. The URL parses and carries no userinfo. reqwest strips userinfo into a `Basic` header before the auth middleware
   runs, so the middleware records the destination as written, with a userinfo marker, before its first stamp. It
   checks that recorded destination for every stamp, including the stamp after a refresh.
2. The scheme is `https`, or `wss` for the two WebSocket services (relay, Computer Hub).
3. The host is not this machine: `localhost`, `*.localhost`, `127.0.0.0/8`, `::1`, IPv4-mapped loopback,
   `0.0.0.0`, `::`.
4. The origin is one of:
   - **FluxRouter-operated:** the compiled `FLUXROUTER_API_HOST` over `https` on its default port.
   - **A configured API origin:** P42's `[endpoints]` trust set, the same origins that may receive the session
     for inference.
   - **The client's configured service base:** the base the client resolved from operator configuration
     (an `[endpoints]` service key, `[hub].url`, or a named service environment variable). Scheme, normalized
     host and effective port must all match.

There is **no exception** for loopback or cleartext. A configured `http://` or loopback service base does
not admit itself, because rules 2 and 3 are checked before rule 4. The configured service base must come from
configuration. It must never come from a caller, a server response or a URL the client is about to follow. A
URL from such a source is admitted only on a configured origin. For example, a `--hub-url` that is not on
`[hub].url`'s origin is refused.

Like the API class, this class can be widened by whoever can write the configuration. It cannot be widened by
a caller or by a server. Unlike the API class, it can never be widened to plain `http` or to loopback.

**Who is not affected.** A deployment key, a static `AuthMode::ApiKey` credential, `FUIGO_API_KEY` and BYOK keys
keep their own rules. Only a session credential is checked, and the check runs on the **exact value** about to be
attached. `AuthCredentialProvider::bearer_may_reach(url, bearer)` exempts `bearer` only if it equals the configured
deployment key, or equals the static `AuthMode::ApiKey` credential the `AuthManager` holds. It never re-reads which
mode the manager is in, so a credential switch between the snapshot and the check cannot exempt one value and
send another. Some values are treated as session tokens regardless of mode:
- a raw token with no `AuthManager` to classify it, such as a `user_token` in a static storage, feedback or
  trace-upload client;
- the workspace's hub, upload and tool bearers (`fuigo-workspace`). These come through a hub `AuthProvider`, which
  carries no credential kind. It is usually the OIDC session, either from `auth.json` or from the leader, but a
  leader may hand over a static API key. The conservative session rule is applied to all of them;
- the bearer of the relay (built only for a session) and the skills client (primary and `auth.json` alternates);
The leader's hub exposure classifies its credential by value before EVERY socket the hub SDK opens, on the
initial connect and on each reconnect. It does this through `fuigo_computer_hub_sdk::AuthProvider::destination_permits`,
implemented by `HubDestinationGuard`. A static API key keeps its own rules. A session token goes only to an
admitted hub. A refusal opens no socket: the SDK fails the connect, or stops its reconnect loop, with
`ClientError::DestinationRefused`.

The `fuigo trace` upload carries its credential's kind through `upload::gcs::ClassifiedProxyUpload`, so a static API
key keeps its own rules there, and its retry loop stops on a refusal.

These are deliberate. A static API key on those paths needs the same https, non-loopback service URL that a session
token needs.

**Failure behaviour.** A refused destination gets **no request at all**: not the request with the token, and
not the request without it. Sending it unauthenticated would still put the body (feedback text, traces,
conversation data) and the identity headers (`x-userid`, `x-email`) on an untrusted wire. It would also come
back as a 401 that every client reports as "run `fuigo login`", which is the wrong remedy. The client returns
an error whose text is `RefusedServiceDestination`'s `Display`. That text names the refused origin
(`scheme://host[:port]`, never a path, query or token), says the request was not made, and gives the remedy:
point the service's endpoint setting at an https origin that is not this machine. Every refusal is also written
to the unified log as `auth: service request not sent: …`, with the site, origin, reason and full message. This
holds for the clients whose return value carries no error, too: enrichment, the subscription check, and the
workspace tool keys. Per client:

| Client | Configured service base | On refusal |
|---|---|---|
| Managed config, team session (`managed_config/supervisor.rs`) | resolved `managed_config_url` | `ManagedConfigError::SessionDestinationRefused`, not retryable; the deployment-key path is unchanged |
| `/user` subscription check (`agent/subscription_check.rs`) | `proxy_url` | check returns `None`; logs `paywall_check_error` `kind=destination_refused` |
| `/user` enrichment (`auth/manager/enrichment.rs`) | `proxy_url` | enrichment skipped; logs `reason=destination_refused` |
| Billing, auto top-up (`extensions/billing.rs`) | `proxy_url` | ACP error carrying the refusal text |
| Consent, privacy (`extensions/consent.rs`, `privacy.rs`; auth middleware) | `proxy_url` | ACP error carrying the refusal text |
| Remote settings (`remote/client.rs` `fetch_settings_blocking`) | `cli_chat_proxy_base_url` | `SettingsFetch::DestinationRefused(text)`. It is terminal, but it is not a 401: no auth recovery runs and nothing is re-fetched. The OTEL gate treats it as "no remote policy" |
| Subagent bundle, archive (`remote/client.rs`) | `cli_chat_proxy_base_url` | `BackendError::SessionDestinationRefused` |
| Session-history backend (`remote/client.rs` `BackendClient`; middleware) | `FUIGO_CODE_BACKEND_URL` | `BackendError::SessionDestinationRefused` |
| Sandbox (`remote/agent.rs`) | `cli_chat_proxy_base_url` | error carrying the refusal text |
| Skills, workspaces, conversations, chat modes (`remote/*_client.rs`) | their env-chain base | `…Error::SessionDestinationRefused` (not retryable). The skills client treats every key it may try (primary and `auth.json` alternates) as a session token |
| Session registry, feedback (`agent/session_registry_client.rs`, `feedback_client.rs`; middleware, live and static) | their base URL (`proxy_url` / `feedback_base_url`) | error carrying the refusal text |
| Proxy storage / trace upload (`auth/credential_provider.rs` `build_storage_client_for_proxy`, `upload/gcs.rs`; the `fuigo-file-utils` static `user_token` fallbacks `StorageClient::new` and `gcs` `build_proxy_client_with_fallback`) | the proxy base | error carrying the typed refusal. The storage client's network retries stop on it, and the upload queue classifies it as terminal: no retry, no park. `Config::resolve_upload_method` also drops a session token for a refused trace-upload URL before any upload method is built |
| OTLP exporter (`fuigo-telemetry` `otel_layer`, `OtelAuthCredentialProvider`) | none: FluxRouter and configured API origins only | batch not exported; `warn` (a malformed endpoint is never echoed). An `OTEL_*` or internal-endpoint repoint gets no session token; a deployment key still goes |
| Relay (`agent/relay.rs`) | `FuigoComConfig.fuigo_ws_url` | relay stops at once, with a terminal line `Fuigo relay disabled: …`; no reconnect loop |
| Leader workspace exposure (`leader/server.rs` `handle_workspace_start`, `HubDestinationGuard`; `LeaderAuthProvider` feeds the hub; `fuigo-computer-hub-sdk` asks the guard before every socket) | `[hub].url`, else the compiled hub default | first connect: control error carrying the refusal text, before anything connects. Reconnect: no socket, and the connection stops terminally (`ClientError::DestinationRefused`). A static API key, matched by value, keeps its own rules |
| Standalone workspace server hub auth (`fuigo-workspace` `hub_auth::provider`) | the operator's hub URL | startup error; auth.json is not read. The old plain-bearer path for a `ws://` loopback hub is removed |
| Workspace uploads (`fuigo-workspace` `upload` `HubAuthCredentialProvider`; middleware) | `FUIGO_CLI_CHAT_PROXY_BASE_URL` | upload error carrying the refusal text |
| Workspace image/video/web-search tool keys (`fuigo-workspace` `session/tool_config.rs`) | `FUIGO_CLI_CHAT_PROXY_BASE_URL` | the three tools stay disabled; `warn` with the remedy |

**Enforcement.** `fuigo_auth::AuthCredentialProvider::bearer_may_reach(url)` is a **required** trait method, so
every provider states its rule. `AuthRetryMiddleware` consults it before every stamp, including the stamp after a
refresh. On a refusal the middleware returns `BearerDestinationRefused` and sends nothing.
`StaticAuthCredentialProvider` takes an explicit `BearerDestination` (`Unrestricted` for a non-session key,
`Checked(rule)` otherwise). Clients that set `Authorization` themselves call
`session_delivery::service_session_gate` (for a resolved credential) or `service_session_url_gate` (for a raw
token) before they build the request. Tests, mutants and the per-site list with file:line references are in
`docs/strike/receipts/R055-p47-service-session-delivery.md`.

**Behaviour change (intended).** A session user whose auxiliary service URL is `http://`, loopback, on another
port, or on an origin that is not configured now gets a clear refusal instead of a request. This includes a
local-development `ws://localhost` hub or relay, and a self-signed loopback proxy.

## Out of scope: other meanings of "first-party"

In `fuigo-shell`, "first-party" also describes a **credential** (Fuigo's own key or session, as opposed
to BYOK). Examples are `FIRST_PARTY_CREDENTIAL_ENV_VARS`, `first_party_env_*` and
`scrub_first_party_credentials`. It also describes a **product surface** (the first-party TUI and
skills). Neither use classifies a destination, so P30 leaves them unchanged.

## Identity outside the inference sampler (P43: closed)

P30 recorded this as a known boundary. P43 closes it: every place Fuigo itself writes an
identity-class header now decides with `IdentityDisclosure` for the request's own destination.

- **The identity class** is `fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES`: the five P15 names
  the sampler gates (`x-fuigo-user-id`, `-deployment-id`, `-agent-id`, `-client-version`,
  `-client-identifier`) plus `x-userid` (Ferrox account id), `x-email` (account e-mail) and
  `x-teamid` (team id). Correlation headers and `x-fuigo-client-mode` stay outside it (P15-R).
- **Helpers.** `IdentityDisclosure::header_map(pairs)` (empty when withheld; only identity names
  accepted), `withhold_from_header_map` (for a map built before the destination is final),
  `allows_header` (string-keyed tool and OTLP maps), and `for_websocket_destination` (`wss` to the
  compiled host is the TLS equivalent of `https`; `ws` is refused). `fuigo-shell`'s auxiliary
  clients share `remote::account_identity_headers`.
- **Not stripped:** headers a user or operator configured for a destination (`[model.*]
  extra_headers`, OTLP header settings, MCP server headers). Those are the user's own choice.
- **Consequence, intended:** an operator-configured cli-chat-proxy, session backend, skills,
  workspaces, conversations, sandbox, relay, OAuth issuer, OTLP collector, storage or voice host
  that is not `https://api.fluxrouter.ai` now receives the bearer and no `x-userid`, `x-email`,
  `x-teamid`, machine id or client labels. Fuigo ships every one of those bases empty, so a default
  install sends identity only to FluxRouter. A server that keyed behaviour on those headers (for
  example the imagine/video ZDR scoping on `x-fuigo-client-identifier`) must be FluxRouter-operated
  to get them.

The full site enumeration, with file and line, is in the P43 receipt (`docs/strike/receipts/R039-p43.md`).

### Identity in request bodies (P54)

P54 applies the same rule to identity carried in a request BODY. Shared helpers in
`fuigo_extra_ca::fluxrouter`: `IdentityDisclosure::body_identity(value)` (the value only when
permitted; the caller omits the field otherwise) and `IdentityDisclosure::body_key_for(url, value)`
(the value for a FluxRouter-operated `url`; otherwise `destination_pseudonym(url, value)`, a
UUID-shaped one-way key stable at that origin and unrelated at every other origin, used only where
the receiving feature needs a stable key).

| Body | Destination | Decision |
|---|---|---|
| Internal OTLP resource `user.id`, `team.id`, `organization.id`, `deployment.id`, `api_key.id`, and span/event/link attributes such as `user_id` | internal traces endpoint | FluxRouter-operated only (same decision as the headers on that request); omitted elsewhere, on the first attempt and the refresh retry |
| Mixpanel `distinct_id`, `agent_id`, `team_id`, `deployment_id`, `principal`, `user_id` (track and engage) | `api.mixpanel.com`, a third-party vendor | identity keys removed; `distinct_id` is the Mixpanel-origin pseudonym |
| Session registry `deviceId`, `hostname` | registry (cli-chat-proxy) | FluxRouter: kept; otherwise `deviceId` is the pseudonym and `hostname` is omitted |
| Session backend upsert `agentId` (sync, share, fork, worktree resume) | `FUIGO_CODE_BACKEND_URL` | FluxRouter: kept; otherwise pseudonym |
| Review-comment `agentId` | trace storage | own bucket (Direct GCS, S3): kept; storage proxy: FluxRouter unchanged, else the proxy-origin pseudonym (P54-K: the same key `hunk_records.jsonl` carries to that proxy, so create, tombstone and LOC records of one session stay joinable there) |
| `hunk_records.jsonl` (`agentId`, `authorId`) inside a feedback trace archive | storage proxy | decided when the archive is built, for every record: FluxRouter unchanged; otherwise machine id pseudonymised, account id removed. The local file keeps the real ids |
| External OTEL identity attributes | the customer's own collector (double opt-in) | kept: configured by the user for exactly this data |
| Product events (`events_url`) | only ever user/operator-configured | kept |
| Feedback `author_name`/`author_email` | feedback service | kept: only resolved when `[feedback.user]` is configured in a trusted tier |
| ACP `initialize` `agentId` | the local ACP client over stdio or IPC | kept: not a network destination |
| The same response, and every other agent response, when the relay is bridged to the agent (`agent/app.rs`: headless-relay mode, and leader mode, where the relay also sees the responses to local IPC clients) | the configured relay (`FUIGO_WS_URL`) | decided by the relay socket writer (`agent/relay.rs` `relay_outbound_frame`) on the URL the socket is opened to. FluxRouter-operated (`wss` to the API host): every frame unchanged. Any other relay: `_meta.agentId` (the machine id) is the relay-origin pseudonym (`IdentityDisclosure::body_key_for_websocket`, P81); `_meta.hostname` and the session rows' `hostname` are omitted (P77); who is signed in is omitted from the `authenticate`, `fuigo/auth/info`, `fuigo/auth/check_subscription` and `fuigo/auth/logout` responses (e-mail, names, profile image, team / organisation / principal ids and names) and the owner ids from the cloud-environment responses (P81). Not withheld: `agentInstanceId` (per process), relay sync's session-scoped `agentId`, session and subagent ids, roles, tier, gate, retention flags (P15-R: correlation, not identity) |

The guard `fuigo-extra-ca/tests/identity_body_guard.rs` pins every body-identity token per file.
The full table, with file and line, is in `docs/strike/receipts/R063-p54.md`; the relay bridge is in
`docs/strike/receipts/R082-p77.md` (host name) and `docs/strike/receipts/R086-p81.md` (machine id, account).
`fuigo agent serve` is an inbound server, not a destination Fuigo dials: its authenticated peer receives what the local
client receives (R086 has the proposal).

### Credentials over the relay bridge (P82)

A bridged relay (above) can send the agent requests and receives every line the agent writes. A credential is handed
over that bridge only to a FluxRouter-operated relay, decided on the URL the relay socket is opened to by the same
rule (`IdentityDisclosure::for_websocket_destination`). The handshake's session bearer is not this rule's business:
it is delivered by the service-endpoint class above (P47), which admits the configured relay.

| What | Any other relay |
|---|---|
| A request for `fuigo/auth/getBearerToken` or `fuigo/getApiKey` (`agent/relay_credentials.rs` `CREDENTIAL_METHODS`) | answered on the relay socket with a JSON-RPC error (`-32600`, kind `invalid_request`); the agent never receives it, so the credential is never produced for it. A notification for one is dropped |
| Every other message from the relay | handed to the agent as the serialisation of the value the gate decided on (one line, no duplicate keys, no escapes); a message that is not a JSON object is not handed over |
| The answers to a LOCAL client's `getBearerToken` / `getApiKey` (leader mode copies them to the relay) | `result.result.token` / `result.result.key` omitted |
| Cloud-environment responses | the `value` of every `secrets[]` and `environmentVariables[]` entry (the name stays), and the environment's `setupScript` / `maintenanceScript`, omitted |
| The MCP catalog (`fuigo/mcp/list`, `fuigo/mcp/servers_updated`) and `fuigo/mcp/auth_trigger` | of every server: the `value` of every `env[]` entry (the name stays), `command`, `args`, `url` (all expanded, so a `${TOKEN}` arrives as the token, and a relay that may write a server's configuration could read any variable back), `setup` and `setupValues` (a setup variable's `map` holds literal values); `auth_trigger`'s `setup` |
| The agent's own `terminal/create` requests (in leader mode a local client's are copied to the relay) | `params.env` omitted (the session's environment from settings and a trusted `.envrc`): a relay that runs the terminal runs it without them |
| The hooks (`fuigo/hooks/list`, the `hooks_changed` session notification) | of every hook: `command` and `url` omitted (a literal token in either would arrive as it is) |

The response side is read strictly: a frame whose credential fields cannot be decided (not a JSON object, or a
duplicate key on the path to them) is not sent. A FluxRouter-operated relay and the local stdio / IPC clients are
unchanged. **Not covered** (R089 lists them as proposals): credentials embedded in other content (a git remote URL with
userinfo, a marketplace source URL, prompt history, tool input and output), and a relay that uses the agent's own
tools (files, terminal) or its configuration methods to read a credential: the bridge lets a relay drive the agent
(R089 §1: `_fuigo/fs/read_file` reads `auth.json` unconfined by default). Sean's decision (2026-10-03): such a
relay is bridged only with the user's opt-in, and an opted-in relay is trusted to drive the agent (P93, next section). Full enumeration:
`docs/strike/receipts/R089-p82.md`.

### Relays not operated by FluxRouter (P93)

The agent is bridged to a relay (headless-relay mode, and leader mode) only when the relay is FluxRouter-operated
(`IdentityDisclosure::for_websocket_destination`, the rule above) or the user opted in to that relay's origin
(`scheme://host[:port]`, `wss` read as `https`): `trusted_origins = ["https://relay.example"]` under `[relay]` in the
user config file `$FUIGO_HOME/config.toml`, read from that file alone, or `FUIGO_TRUSTED_RELAY_ORIGINS`. A project's
`.fuigo/config.toml`, the `FUIGO_CONFIG` overlay, managed and remote settings, campaigns and `requirements.toml` cannot
opt in, and neither can a relay that is not yet bridged: without the opt-in no socket is opened, so not a byte (not even
`initialize`) is sent to it, and the refusal says what to set and where (`agent/relay_opt_in.rs`). Another origin needs
its own opt-in, which only the user, or something the user already trusts with the agent, can write: an opted-in relay
can write the user config file like any other file (below), so it can opt in further origins. No relay URL configured
(the default install) is not a refusal: there is nothing to bridge, as before. A running leader that refused decides
again, re-reading the config file, each time a headless client registers.
**An opted-in relay is trusted to drive the agent exactly like the local client**, as an MCP server you add is trusted
to run: it can read any file the agent can (`_fuigo/fs/read_file`, including `auth.json`), run terminals, add or change
MCP servers, plugins, skills and configuration, and read configuration back (with environment variables expanded).
P82's filters above protect only against PASSIVE leaks to such a relay (credentials in what the agent sends it unasked);
they are not a boundary against a relay that asks. Opt in only to relays you control. Accordingly R089's open finding
(`_fuigo/skills/add` then `_fuigo/skills/config` returns `${VAR}` expanded) and its class stay open by design for
opted-in relays (accepted, Sean's decision of 2026-10-03; `docs/strike/receipts/R100-p93.md`). Relay sync (TUI session
sharing, `[relay] enabled`) is not a bridge, but it sends the relay the whole session transcript, so (P125) it is gated
by the same opt-in: a session is synced only to a FluxRouter-operated relay or one whose origin is in
`[relay] trusted_origins` (or `FUIGO_TRUSTED_RELAY_ORIGINS`). A refusal is shown in the TUI (which relay, why, how to
trust it), for the leader's refused bridge as well as for a refused sync.
