# P99 Astra round 1 (gpt-6-astra, read-only) on fe16738c..c05a3bad

Final report, verbatim. Full transcript: Hetzner /root/fuigo-builds/p99/astra/astra-r1.txt, sha256 c407e505f6a0675f9d40f9e5d450b8b87ad534e97768ff547d834655c511c923.

Audited `fe16738c..c05a3bad` at `c05a3bad587e00b2521b6ffb868bc133ab9b15b2`, including the locked dependency source. Read-only: no builds, tests, or file changes.

**P99 correctly adds the shell’s endpoint binding and the narrow Google exception.** I found six issues below. The HIGH finding predates this range and is in the explicitly requested MCP audit surface.

1. **HIGH — MCP OAuth still sends credentials to an unbound discovery endpoint.**  
   Locations: [oauth.rs:330](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-mcp/src/oauth.rs:330), [oauth.rs:479](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-mcp/src/oauth.rs:479), [http_policy.rs:83](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-mcp/src/http_policy.rs:83).

   A compromised discovery response can retain the expected `issuer` while changing `token_endpoint` to `https://collector.example/token`—or non-loopback HTTP. Fuigo installs that metadata; rmcp 3.2.0 constructs its token client directly from it. Code exchange sends the code, PKCE verifier, and any configured BYO client secret; refresh sends the stored refresh token. The adapter checks HTTP/HTTPS and the vendor denylist, without binding the destination to the issuer. Callback `iss` validation does not prevent this scenario.

   **Test coverage:** P99 tests do not cover MCP. Existing MCP tests cover blocked vendor hosts, redirects, and callback issuer validation, not this first-hop substitution. **Pre-existing; unchanged by P99.**

2. **MEDIUM — Cross-origin redirect refusals are retried and can produce a re-login instruction.**  
   Locations: [protocol.rs:476](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:476), [refresh.rs:235](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:235), [oidc_refresher.rs:289](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/refresh/oidc_refresher.rs:289).

   An admitted `/token` endpoint returning a cross-origin 307/308 is correctly prevented from forwarding credentials. However, the redirect policy produces a reqwest transport error, not `TokenEndpointRefused` or `DispatchError::Denied`. It therefore receives up to three POST attempts and becomes `Failed { network_unreachable: false }`. Five such refresh failures escalate to `PermanentFailure::Other`, whose message tells the user to sign in again.

   Credentials remain stored for `Other`; this is **not** the credential-clearing branch. Nevertheless, the refusal reason is lost and policy denial consumes the escalation budget.

   **Test coverage:** The new redirect test permits multiple source POSTs and checks only that the collector receives nothing and the result is not success. It misses retries, escalation, and error presentation. **Pre-existing behavior; the new test leaves it uncovered.**

3. **MEDIUM — URL-bearing diagnostics remain unsanitized.**  
   Locations: [protocol.rs:318](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:318), [protocol.rs:519](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:519), [refresh.rs:241](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:241).

   Discovery can supply `https://user:secret@issuer.example/token`; debug logging records that complete URL before the new check refuses it. For admitted endpoints containing sensitive query parameters, transport/redirect errors retain the URL and are written into unified logs without `without_url()`. Login can also propagate those URL-bearing errors.

   The new **direct refusal message itself is sanitized**. The surrounding diagnostics are not.

   **Test coverage:** The new assertions inspect the refusal message, not tracing output or transport-error logs. **Pre-existing; unchanged by P99.**

4. **MEDIUM — Amazon Cognito users lose shell login and refresh support.**  
   Locations: [login.rs:385](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/login.rs:385), [protocol.rs:577](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:577).

   Cognito user pools publish discovery under `cognito-idp.<region>.amazonaws.com/<pool>`, while token endpoints use the pool’s hosted or custom domain. Both configurations are refused. Existing shell sessions stop refreshing and become unusable when their access tokens expire. AWS documents this domain separation. [AWS user-pool domain documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html).

   **Test coverage:** Generic foreign-origin tests enforce this rejection, but there is no Cognito-specific compatibility test. **Introduced for the shell; intentional and accurately disclosed in the guide.** The hub already had this restriction at the base. This is a product compatibility consequence, not a reason to silently broaden the exception.

5. **LOW — The local-HTTP gate is broader than literal `FUIGO_LOCAL_AUTH=1`, and its test misses that distinction.**  
   Locations: [config.rs:160](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/config.rs:160), [config.rs:238](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/config.rs:238), [protocol.rs:1443](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:1443).

   `use_local_auth()` accepts every nonempty value except `"0"`, including `"false"`, `"no"`, and `"2"`. P99 consequently permits local HTTP under those values too. The exemption remains confined to the exact local issuer and same-origin loopback endpoint; **I found no non-loopback escape**.

   **Test coverage:** The new test neither establishes an enabled environment nor tests the accepted issuer. With the variable unset, an implementation reduced to `use_local_auth()` would pass its negative cases. Unit tests also always take the `cfg!(test)` HTTP exemption, leaving release-mode gating unverified.

   The SDK comment saying this argument is “never true in a shipped build” is now inaccurate ([oidc_provider.rs:83](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs:83)); the guide’s unconditional HTTPS statement omits the shell’s local-development exception.

6. **LOW — The login test does not actually observe whether the browser opens.**  
   Location: [login.rs:663](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/login.rs:663).

   Moving the check after `webbrowser::open()` but before waiting for the callback would still satisfy its timeout, typed-error, empty-collector, and absent-auth-file assertions. The current production ordering is correct; the test does not protect the full behavior named in its title.

   **Test coverage:** This regression would escape the new test. An observable browser-launch boundary or equivalent ordering assertion is needed.

The seven claims resolve as follows:

| Claim | Source-review result |
|---|---|
| 1. Shell credential send sites | Confirmed for the shell’s own OIDC implementation: both send sites check immediately before constructing the POST. MCP is the separate gap above. |
| 2. Local HTTP restriction | Origin and loopback confinement confirmed; literal `=1` claim is inaccurate. |
| 3. Redirect containment | Confirmed: every shell redirect is compared with the first request’s origin, including scheme, port, and userinfo restrictions. |
| 4. Credential preservation | Confirmed for direct `TokenEndpointRefused`, including disk retry and manager handling. Redirect refusals have the separate classification problem above. |
| 5. Google exception | Confirmed: one compiled, directed HTTPS/default-port pair. No configurable expansion, suffix/subdomain matching, reversed direction, or trailing-dot admission. Parsed-host normalization does not authorize a distinct IDN origin. Google documents this endpoint pair. [Google OIDC reference](https://developers.google.com/identity/openid-connect/reference). |
| 6. Production-path tests | Confirmed, with the coverage limitations above. The redirect fixture proves the original endpoint received the refresh token. No test results are claimed from this audit. |
| 7. Guide accuracy | Main rule, Google exception, Cognito restriction, and stored-token behavior are accurate; the local-development qualification is missing. |

Cached discovery documents still pass through the send-time checks. Device authentication constructs its endpoint from the configured issuer; subscriptions use fixed recipient-bound endpoints; external authentication delegates to the configured executable. None provides another discovery-named send path in the shell OIDC implementation.

The landing recommendation applies to this bounded change: its credential-routing protection is sound by inspection. The pre-existing MCP HIGH finding needs an owned security follow-up.

LAND-WITH-FOLLOWUPS
