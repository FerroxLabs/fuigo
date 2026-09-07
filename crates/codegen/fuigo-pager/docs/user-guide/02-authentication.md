# Authentication

Fuigo supports several authentication methods, including interactive browser login, enterprise single sign-on (SSO), and headless CI/CD runners.

---

## ChatGPT and Grok subscriptions

Subscription login is explicit and separate from Fuigo's existing API-key and
first-party authentication. It never imports Codex, Grok CLI, or Wayland sessions.

```bash
fuigo login --provider chatgpt
fuigo login --provider xai
fuigo login --provider chatgpt --status
fuigo login --provider xai --status
fuigo models --provider chatgpt
fuigo models --provider xai
```

ChatGPT opens a browser and listens on `localhost:1455`. xAI uses a random local
callback port. On Unix, if xAI displays a code instead of redirecting, paste it
into Fuigo's terminal prompt; input is hidden. Login times out after ten minutes
and Ctrl-C cancels waiting. Subscription device-code login is not implemented.
Windows currently supports the browser callback path only.

A subscription must grant the requested model access. Model listing shows IDs
returned by the authenticated backend; it does not promise access to every model.
A denial never switches to a paid API key or Flux Router.

To select subscription inference, add named auth providers and models to your
trusted user config (`~/.fuigo/config.toml`, or `$FUIGO_HOME/config.toml`):

```toml
[auth_provider.chatgpt-subscription]
subscription = "chatgpt"
# Optional: bind to an account ID shown by login --status.
# account = "your-account-id"

[auth_provider.grok-subscription]
subscription = "xai"

[model.chatgpt-subscription]
model = "REPLACE_WITH_CHATGPT_MODEL_ID_FROM_LIST"
base_url = "https://chatgpt.com/backend-api/codex"
auth_provider = "chatgpt-subscription"

[model.grok-subscription]
model = "REPLACE_WITH_XAI_MODEL_ID_FROM_LIST"
base_url = "https://api.x.ai/v1"
auth_provider = "grok-subscription"
```

Replace the model placeholders, then select `-m chatgpt-subscription` or
`-m grok-subscription`, or select that configured model in the TUI/ACP client.
Keep each subscription's wire model/endpoint mapping unambiguous. Do not combine
subscription auth with `api_key`, `env_key`, or a command helper. Flux Router keeps
its existing API-key configuration.

When switching models, Fuigo retains conversation messages and tool results.
Model-private reasoning is included only for history from the same emitting model;
foreign encrypted reasoning is omitted from the outgoing request, not deleted from
saved history.

Fuigo stores subscription credentials under `$FUIGO_HOME/subscriptions` (default
`~/.fuigo/subscriptions`) with owner-only file permissions. These are plaintext
credentials protected by OS permissions. Refreshes are serialized between Fuigo
processes and persisted atomically. A failed or interrupted refresh can require a
new login; Fuigo will not reuse a potentially consumed refresh token.

```bash
fuigo logout --provider chatgpt
fuigo logout --provider xai
# Remove one account without removing sibling accounts:
fuigo logout --provider chatgpt --account ACCOUNT_ID
```

Logout removes only the named provider/account from Fuigo. It does not sign out
other applications or revoke their sessions. Logging into another account keeps
sibling records and selects the new account; configure `account` to pin a model.

Protocol constants and flow behavior reuse Ferrox Labs' Wayland Core and Wayland
implementations (Apache-2.0). Public OAuth client compatibility and subscription
entitlements must be confirmed with the actual account; this is not a vendor
endorsement or a guarantee of a stable third-party subscription API.

---

## Browser Login (Default)

On first launch, Fuigo opens your browser to authenticate with grok.com:

```bash
fuigo
```

Fuigo stores credentials in `~/.fuigo/auth.json` and reuses them across sessions. Fuigo refreshes access tokens automatically in the background. When a token can't be refreshed, Fuigo prompts you to sign in again. Credentials without a server-provided expiry fall back to a 30-day lifetime.

### Credential storage

Tokens in `~/.fuigo/auth.json` (and MCP OAuth tokens in `~/.fuigo/mcp_credentials.json`) are written with owner-only permissions (`0600` on Unix). Anyone with filesystem access to those paths can use the credentials, so:

- Prefer full-disk encryption (FileVault, BitLocker, LUKS, or equivalent).
- Do not copy `auth.json` or `mcp_credentials.json` into shared directories, tickets, or chat.
- On multi-user hosts, keep `$HOME` / `$FUIGO_HOME` private to your account.

### Re-authenticate

To switch accounts or resolve an authentication problem, run:

```bash
fuigo login
```

Running `fuigo login` starts the sign-in flow again, replacing your cached session. By default, it opens your browser and signs in through Ferrox Labs OAuth at `auth.x.ai`. Pass a flag to select a different flow:

| Flag | Description |
|------|-------------|
| `--oauth` | Sign in through Ferrox Labs OAuth at `auth.x.ai`. This is the default, so the flag is optional. |
| `--device-auth` (alias `--device-code`) | Sign in with the device-code flow for headless or remote environments. |

To sign out of the existing first-party session, run `fuigo logout` without `--provider`.

---

## API Key

For CI/CD, automation, or environments without browser access, use an API key from [console.x.ai](https://console.x.ai):

```bash
export FUIGO_API_KEY="fuigo-..."
fuigo
```

Fuigo uses the API key as a fallback when no session token is active. If you have already signed in interactively, the stored session token takes precedence. To fall back to the API key, run `fuigo logout` or delete `~/.fuigo/auth.json`.

---

## OIDC (Customer SSO)

Authenticate developers through your own Identity Provider (IdP) -- such as Okta, Azure AD, or Auth0 -- instead of grok.com.

### 1. Register a public client in your IdP

- Grant type: Authorization Code with PKCE (Proof Key for Code Exchange)
- Redirect URI: `http://127.0.0.1/callback` -- a loopback address. Fuigo binds a random port at sign-in time, and most IdPs treat the loopback redirect as port-agnostic per [RFC 8252](https://tools.ietf.org/html/rfc8252).
- No client secret. PKCE replaces it.

### 2. Configure the CLI

Via config file:

```toml
# ~/.fuigo/config.toml
[fuigo_com_config.oidc]
issuer = "https://acme.okta.com"
client_id = "0oa1b2c3d4e5f6g7h8i9"
```

Or via environment variables:

```bash
export FUIGO_OIDC_ISSUER="https://acme.okta.com"
export FUIGO_OIDC_CLIENT_ID="0oa1b2c3d4e5f6g7h8i9"
```

You can also override the API endpoint to point at your own proxy:

```bash
export FUIGO_CLI_CHAT_PROXY_BASE_URL="https://fuigo-proxy.acme.com/v1"
```

### 3. Run `fuigo`

The CLI discovers endpoints via `{issuer}/.well-known/openid-configuration`, opens the IdP login page, and stores tokens in `~/.fuigo/auth.json`. Tokens auto-refresh silently via the stored `refresh_token`.

### Optional fields

| Field | Default | Notes |
|-------|---------|-------|
| `scopes` | `["openid", "profile", "email", "offline_access", "api:access"]` | `offline_access` enables silent token refresh |
| `audience` | None | Required by some IdPs (e.g., Auth0) |

---

## External Auth Provider

When browser-based login isn't possible -- for example, on sandboxed VMs, CI runners, or air-gapped networks -- delegate authentication to an external binary or script.

### How It Works

```
+--------------+     sh -c     +------------------------+
|     Fuigo     |-------------->|  your auth binary      |
|              |               |                        |
|  reads       |<-- stdout ----|  prints token          |
|  auth.json   |               |                        |
|              |   (stderr)    |  prints status/URLs    |--> surfaced to user
+--------------+               +------------------------+
```

1. Fuigo runs your command via `sh -c "<command>"`
2. Your binary runs whatever auth flow it needs (SSO, device code, certificate exchange)
3. **stderr** carries human-readable output, such as login URLs and status messages. Fuigo reads stderr and surfaces it to the user; in the TUI, it turns the first `https://` URL into a clickable sign-in link.
4. **stdout** is captured by Fuigo and saved as the access token
5. Exit 0 = success; exit non-zero = Fuigo falls back to interactive login

### The stdout / stderr Contract

| Stream | What to print | Who sees it |
|--------|---------------|-------------|
| **stdout** | The token -- nothing else | Fuigo (parsed and stored in auth.json) |
| **stderr** | Login URLs, status messages, errors | The user (Fuigo reads stderr and shows the sign-in URL as a clickable link in the TUI) |

**Do not print anything to stdout except the token.** No progress messages, no debug output. Fuigo reads stdout, trims surrounding whitespace, and parses the result as a token.

### stdout Token Format

**Bare string** -- just the raw token:

```
eyJhbGciOiJSUzI1NiIs...
```

**JSON** -- with optional refresh token, expiry, and issuer:

```json
{"access_token": "eyJhbGciOi...", "refresh_token": "ref-tok", "expires_in": 3600, "issuer": "https://idp.example.com"}
```

Use JSON if your tokens expire and you want Fuigo to automatically re-run the binary before expiry.

JSON fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `access_token` | yes | Bearer token Fuigo sends to the Ferrox Labs API |
| `refresh_token` | no | Stored for reference. Fuigo refreshes by re-running your binary, not with an OAuth refresh grant |
| `expires_in` | no | Token lifetime in seconds; enables proactive refresh before expiry |
| `issuer` | no | Identifies the token's issuer |

### Configuration

Via config file:

```toml
# ~/.fuigo/config.toml
[auth]
auth_provider_command = "/usr/local/bin/my-auth-provider"
auth_provider_label = "Acme Corp"   # optional -- customizes the TUI login button
auth_token_ttl = 3600               # optional -- token lifetime in seconds
```

Or via environment variables:

```bash
export FUIGO_AUTH_PROVIDER_COMMAND="/usr/local/bin/my-auth-provider"
export FUIGO_AUTH_PROVIDER_LABEL="Acme Corp"
export FUIGO_AUTH_TOKEN_TTL=3600
```

### Token Refresh

Fuigo runs your binary on two different contracts, and `FUIGO_AUTH_EXPIRED` is how
it tells them apart. Each run fully replaces the stored credential, so emit the
same JSON fields (such as `issuer`) on every invocation, including refreshes.

- **`FUIGO_AUTH_EXPIRED=1` — a headless refresh.** Fuigo is re-minting over a
  credential it already holds: a near-expiry rotation, or a token the server
  rejected. Nobody is watching. stdin is closed, your stderr is swallowed, and
  the binary is given a few seconds before it is killed. Mint silently or exit
  non-zero — never block.
- **Unset — a sign-in.** `fuigo login`, the sign-in screen, or the escalation
  Fuigo performs when a headless run couldn't mint. A user is waiting, your
  stderr reaches them, and you have 300 seconds — enough for a browser round
  trip or a device code.

```bash
#!/bin/sh
if [ "$FUIGO_AUTH_EXPIRED" = "1" ]; then
    # Headless: silent refresh only. Declining is the fast, correct answer
    # when your SSO session has lapsed and only the user can renew it.
    echo "Refreshing token..." >&2
    TOKEN=$(my-company-auth --refresh --silent) || exit 1
else
    echo "Authenticating via Acme Corp SSO..." >&2
    TOKEN=$(my-company-auth --login --interactive)
fi

if [ -z "$TOKEN" ]; then
    echo "Authentication failed" >&2
    exit 1
fi

echo "{\"access_token\": \"$TOKEN\", \"expires_in\": 3600}"
```

When the headless run can't produce a token, Fuigo stops treating the stored
credential as usable and starts the sign-in flow instead — the same one you get
on a machine that has never signed in, with your binary's stderr shown, so a
device-code URL or a browser prompt reaches you. Exiting promptly on
`FUIGO_AUTH_EXPIRED=1` is what makes that handover fast; a binary that blocks
instead makes you wait out the refresh timeout on every start. Mid-session, the
turn fails with a re-auth prompt and `/login` re-runs the binary interactively.

One case stays ambiguous, and only in **leader mode** (`--leader`, or
`[cli] use_leader = true`; off by default): with no credential at all, the
leader makes one extra attempt in the background just after startup, and that
run has the variable unset, like a sign-in. A binary that mints without help
(service account, keytab, mounted token) succeeds there and the session heals
itself. One that must prompt just sits, up to the 300s sign-in ceiling —
nothing waits on it, the sign-in screen is already up, and that run's stderr
goes to `~/.fuigo/leader.log` rather than to you.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FUIGO_AUTH_PROVIDER_COMMAND` | Path to your auth binary |
| `FUIGO_AUTH_PROVIDER_LABEL` | Display name on the TUI login screen (e.g., "Acme Corp") |
| `FUIGO_AUTH_TOKEN_TTL` | Token lifetime in seconds (for bare-string tokens without `expires_in`) |
| `FUIGO_AUTH_EXPIRED` | Set to `1` on a headless refresh: don't prompt, and don't hand back a cached token. Unset on a sign-in, where a user is attached |
| `FUIGO_AUTH_EARLY_INVALIDATION_SECS` | Seconds before expiry to proactively refresh (default: 300) |

---

## Device Code Flow

For headless environments (SSH sessions, Docker containers, remote VMs) where no browser is available locally:

```bash
fuigo login --device-auth    # or: fuigo login --device-code
```

This prints a URL and code to the terminal. Open the URL on any device, enter the code, and complete authentication. Fuigo polls until the login is confirmed.

You can also implement the device-code flow through an [External Auth Provider](#external-auth-provider) for full control.

---

## Automatic Credential Refresh

Fuigo automatically refreshes expired credentials:

- **Before expiry:** If your auth provider returned `expires_in` (JSON output) or you set `auth_token_ttl`, Fuigo re-runs the auth binary ~5 minutes before expiry.
- **On auth error:** If the server returns 401 Unauthorized, Fuigo refreshes the credentials and retries the request.
- **OIDC:** If a `refresh_token` is available, Fuigo silently refreshes via your IdP without re-opening the browser.

Tune the refresh buffer:

```bash
# Refresh 5 minutes before expiry (default)
export FUIGO_AUTH_EARLY_INVALIDATION_SECS=300

# Disable the proactive buffer: refresh at expiry or on a 401 (set to 0)
export FUIGO_AUTH_EARLY_INVALIDATION_SECS=0
```

---

## Hot Reload

Fuigo picks up changes to `~/.fuigo/auth.json` automatically. If you update credentials externally (for example, with a script that writes new tokens), Fuigo uses the new credentials on the next API call without a restart.

---

## Auth Precedence

Fuigo resolves credentials for each request in this order, highest to lowest:

1. **Per-model `api_key` or `env_key`** -- set under `[model.<name>]` in `config.toml`. Wins whenever present.
2. **Active session token** -- obtained through browser, OIDC/OAuth2, or external-provider login and stored in `~/.fuigo/auth.json`.
3. **`FUIGO_API_KEY`** -- fallback when no session token is active.

When more than one login flow is configured, Fuigo populates the session token from the first available source, highest to lowest:

1. **External auth provider** (`auth_provider_command`)
2. **Enterprise OIDC** -- when OIDC is configured, through `[fuigo_com_config.oidc]` in `config.toml` or the `FUIGO_OIDC_ISSUER` and `FUIGO_OIDC_CLIENT_ID` environment variables
3. **Ferrox Labs OAuth2 browser login** -- the default

During a session, the active method handles all mid-session refreshes.

---

## Related settings

Coding-data sharing — **Coding data, retention, and training** in Settings,
which `/privacy` opens — does not change these config knobs:

| Setting | How to set it |
|---------|---------------|
| `[features] telemetry` | `config.toml` or `FUIGO_TELEMETRY_ENABLED` |
| `[telemetry] trace_upload` | `config.toml` or `FUIGO_TELEMETRY_TRACE_UPLOAD` |
| External OpenTelemetry | `FUIGO_EXTERNAL_OTEL` / `[telemetry] otel_*`. See [Monitoring Usage](24-monitoring-usage.md). |

On team accounts, only a team admin can change coding-data sharing.
Team admins can also enable or disable Zero Data Retention (ZDR) for their team.
See [How to enable ZDR](https://docs.x.ai/developers/faq/security#how-to-enable-zdr).
When ZDR is on, coding-data sharing cannot be changed at all — the settings
row shows `ZDR` in place of the value.

See [Monitoring Usage](24-monitoring-usage.md#related-settings) and [Configuration](05-configuration.md#telemetry).

---

## Troubleshooting

### Debug logging

Set `RUST_LOG` to control the verbosity of the file log and headless stderr output. (The TUI's on-screen tracing pane uses a fixed filter and ignores `RUST_LOG`.) In the TUI, file logging defaults to `DEBUG`; in headless mode (`-p`), `RUST_LOG` defaults to `off` so only the answer is printed — set `RUST_LOG=error` (or broader) to see logs on stderr.

In the TUI, set `FUIGO_LOG_FILE` to an absolute path to write logs to that file:

```bash
FUIGO_LOG_FILE=/tmp/fuigo.log RUST_LOG=debug fuigo
tail -f /tmp/fuigo.log
```

`FUIGO_LOG_FILE` is treated as a literal file path. A relative value such as `1` writes a file named `1` in the current directory.

In headless mode, logs go to stderr. Redirect them to a file:

```bash
RUST_LOG=debug fuigo -p "hello" 2> /tmp/fuigo.log
```

### Common log messages

| Log message | What it means |
|-------------|---------------|
| `auth: running external auth provider (headless refresh)` / `(interactive login)` | Fuigo is running your binary, and on which contract |
| `auth: external auth provider returned fresh token` | Fuigo parsed and stored the token |
| `auth: external auth provider failed` | Binary exited non-zero or stdout was empty |
| `auth: external auth provider timed out (likely needs interactive auth), killing` | Binary did not exit before the timeout and was killed |
| `auth: failed to start external auth provider` | Command could not be spawned (binary not found) |

### Common fixes

- **"Authentication failed"** -- Run `fuigo logout` to clear cached credentials, then `fuigo login` to sign in again.
- **Token expires too quickly** -- Set `auth_token_ttl` or return `expires_in` in your auth provider's JSON output.
- **OIDC redirect fails** -- Ensure your IdP allows loopback redirect URIs (`http://127.0.0.1/callback`).
- **External auth provider not found** -- Check that the `auth_provider_command` path is correct and the binary is executable.
