# P99 Astra round 2 (gpt-6-astra, read-only) on fe16738c..352ccaae

Final report, verbatim. Full transcript: Hetzner /root/fuigo-builds/p99/astra/astra-r2.txt, sha256 5255e894ae4820f4bf5a63d1ff2c76d9f454814171231d5ea0ad6d12f9696b70.

Audited `fe16738c..352ccaae`, including the round-1 delta, at `352ccaaeb152c9bb2a5b65a32ed6008e122e68e3`. Read-only: no builds, tests, or file changes.

**No BLOCKER/HIGH defect found in P99’s credential-destination binding.** Three follow-ups remain:

1. **MEDIUM — URL-bearing diagnostics remain exposed.**  
   Locations: [protocol.rs:320](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:320), [protocol.rs:453](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:453), [refresh.rs:239](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:239).

   Discovery naming `https://user:secret@issuer.example/token` still writes that URL through `discover_once` before refusal. An admitted endpoint containing a sensitive query parameter is also logged after validation; ordinary transport errors retain its URL and reach unified logs.

   Moving the two send-site debug statements fixes their refused-URL exposure, but does not eliminate the surrounding leakage. The new refusal messages themselves are sanitized.

   **Coverage:** Existing assertions inspect returned messages, not captured tracing/unified logs. They miss these cases. **Pre-existing; residual round-1 finding, accurately disclosed in the round-2 brief.**

2. **LOW — Redirect classification preserves credentials but loses the specific reason and overstates non-forwarding.**  
   Locations: [protocol.rs:358](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:358), [redirect.rs:18](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-extra-ca/src/redirect.rs:18).

   A same-origin `/token → /token` 307/308 loop follows redirects until the hop limit. By inspection, that permits eleven POSTs on the admitted origin before returning `fuigo redirect limit exceeded`. `refused_redirect` discards this reason and reports “the credential was not forwarded.”

   Credentials remain confined to the admitted origin; suppressing another retry is appropriate. The defect is the missing loop diagnosis and inaccurate assurance after same-origin forwarding. Preserve a sanitized distinction between cross-origin refusal and hop-limit exhaustion, and qualify the assurance as “not forwarded outside the admitted origin.”

   The comments at [protocol.rs:40](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:40) and [oidc_refresher.rs:244](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/refresh/oidc_refresher.rs:244) also incorrectly describe every refusal as occurring before any request.

   **Coverage:** The updated redirect test covers immediate cross-origin 307/308 responses, not same-origin loops or followed hops preceding refusal. **Introduced by the round-1 correction.**

3. **LOW — The guide still states an unconditional HTTPS guarantee.**  
   Location: [02-authentication.md:190](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md:190).

   Changing “issuer must” to “Configure the issuer” leaves the preceding claim that credentials go **only** to HTTPS endpoints. With `FUIGO_LOCAL_AUTH` enabled and issuer `http://localhost:22255`, the shipped shell deliberately permits same-origin HTTP. The guide still omits this exception and its distinction from hub behavior.

   **Coverage:** The new pure-function tests demonstrate the exception but cannot catch contradictory prose. **Residual round-1 documentation finding.**

The remaining security claims hold by source inspection:

- Both shell credential-send paths use the checked URL; cached discovery does not bypass validation.
- The Google exception remains one directed HTTPS/default-port origin pair. I found no suffix, subdomain, userinfo, reversed-pair, or local-development widening.
- Ordinary connection/TLS/timeout failures are not converted into redirect refusals merely because a redirect preceded them. This matches the locked [reqwest redirect implementation](https://raw.githubusercontent.com/seanmonstar/reqwest/v0.12.24/src/redirect.rs).
- Refusals preserve stored credentials, retain a transient outcome, and bypass escalation accounting. Retry suppression applies within `refresh_tokens`; the existing outer 401-recovery loop can initiate another refresh attempt.
- The production browser wrapper directly calls the original function. Its test substitution now observes launch ordering; it does not establish native browser-launch success.

The Cognito restriction remains intentional and disclosed. I agree with deferring the unchanged MCP HIGH to its separately owned packet; this audit does not close that risk.

LAND-WITH-FOLLOWUPS
