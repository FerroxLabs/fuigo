# Astra round 2 — final report (verbatim; full transcript: Hetzner /root/fuigo-builds/p87/astra/P87-astra-r2-report.txt, sha256 d11bcc0c3d1a74371d2c7c392d09b78c7e3c8baf6a901c873639e2168fb87c26)

Reviewed `84569ea8..b840ff81` at `b840ff81` on `strike/p87`. No builds, tests, mutations, or file edits performed. **No BLOCKER/HIGH defect found in the reviewed production callers.** The remaining findings concern test reliability, one API-policy mismatch, and the accepted compatibility restriction.

1. **MEDIUM — Guard tests can silently pass without exercising the guard.**  
   [subscription.rs:261](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/subscription.rs:261), also line 223 and [egress.rs:222](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/egress.rs:222).  
   With `FUIGO_ALLOW_UPSTREAM_HOSTS=1` inherited from the previously documented subscription setup, all three guard assertions return successfully without checking anything. The wire tests bypass DNS through explicit routes, so those tests would still pass if the subscription resolver installation were removed. **Existing tests do not catch this in that environment.** Run guard qualification in an isolated process with the override removed, or fail explicitly on that unmet precondition.

2. **MEDIUM — The new SDK redirect regression can pass before reaching the token endpoint.**  
   [oidc_provider.rs:528](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs:528).  
   An unreachable effective HTTP proxy causes discovery to fail. The test then satisfies all assertions: an error occurred, the collector received nothing, and the refresh token stayed unchanged—even if `same_origin_redirects()` were removed. It never asserts that discovery and `/token` were reached. **The test does not catch this false-positive condition.** Count endpoint hits, verify the submitted fixture token, and isolate proxy configuration.

3. **LOW — The negative subscription guard test inherits proxies and can contact the network.**  
   [subscription.rs:240](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/subscription.rs:240).  
   This test deliberately bypasses `execute` and uses `SubscriptionClient::new`, retaining environment proxies. With an HTTP CONNECT proxy, destination DNS occurs remotely; the proxy can receive the request for `api.mixpanel.com` before the expected resolver refusal. This produces an environment-dependent failure and contradicts the fixture’s “before any socket opens” premise. **Its assertion eventually fails, but does not prevent contact.** Use the production constructor with `no_proxy()`, as the admission test already does.

4. **LOW — The builder does not reject userinfo supplied in its input URL.**  
   [subscription.rs:115](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/subscription.rs:115).  
   `request(POST, "https://alice:secret@auth.x.ai/oauth2/token").build()` passes through reqwest, which removes userinfo and creates Basic authorization before `execute` checks the resulting URL. Thus the request is accepted despite the stated userinfo prohibition. The destination remains the permitted host; this is a policy/coverage mismatch, not a demonstrated cross-host disclosure. **Existing tests miss it:** they pass unmodified URLs directly to `Recipient::accepts`. Validate before reqwest normalizes the URL, or narrow the documented guarantee.

5. **MEDIUM — Split-host IdPs remain incompatible, as explicitly accepted in Round 1.**  
   [oidc_provider.rs:85](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs:85).  
   Google’s issuer is `accounts.google.com`, while its token endpoint is `oauth2.googleapis.com`; refresh therefore remains denied. [Google discovery metadata](https://accounts.google.com/.well-known/openid-configuration). **The cross-origin tests correctly enforce this restriction.** Source documentation now acknowledges it, but the [user guide’s automatic-refresh statement](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md:188) still omits the requirement. Retain the product-owner follow-up and document supported issuer topology.

The six claims resolve as follows; “verified” here means source inspection.

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Read-only Round 2 audit completed |
| F1: exact-host guard | ✅ Done | Installed; only production exception-factory caller is `SubscriptionClient`. No widening found through case, trailing dots, IP URLs, or redirects. Recipient validation precedes proxy dispatch. |
| F7: dispatch restriction | ✅ Done | Wrapper exposes neither `send`, `build_split`, nor the raw client. Exported requests carry no client capability. |
| Production wire tests | ✅ Done | Use `build` with routes, test CA, and `no_proxy`. Assertions would detect enabled redirects or removed recipient validation; DNS coverage has finding 1. |
| CB-3 and Round 1 redirect fix | ✅ Done | Default SDK client now restricts redirects to the same origin. Fuigo’s injected client does likewise. Proactive endpoint refusal becomes policy denial and stops the loop. Arbitrary SDK-injected clients remain the caller’s documented responsibility. |
| Test-only boundaries and origin comparison | ✅ Done | Hook module and invocation are both `#[cfg(test)]`; both refresh callers use `cfg!(test)`. Origin comparison uses parsed scheme/host/effective port, including IDNA normalization. [URL semantics](https://docs.rs/url/2.5.8/url/struct.Url.html#method.origin), [Rust test configuration](https://doc.rust-lang.org/reference/conditional-compilation.html#test). |
| CB-5 and subscription documentation | ✅ Done | Dispatch docs accurately describe denylist-only checking. Subscription instructions remove the override requirement and explain its process-wide telemetry implications. |

LAND-WITH-FOLLOWUPS
