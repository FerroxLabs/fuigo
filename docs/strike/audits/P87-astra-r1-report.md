# Astra round 1 — final report (verbatim; full transcript: Hetzner /root/fuigo-builds/p87/astra/P87-astra-r1-report.txt, sha256 a4a7a6a8038818667ef4ed77e036a4a6e14d39073b1b6d934e51e3d545b45049)

CB-3 is incomplete: the standalone SDK can still send a refresh token across origins through redirects. I reviewed `84569ea8..59445331` at the requested HEAD. No files changed; no builds or tests ran. Test sensitivity below is inferred from source.

1. **HIGH — SDK redirects bypass the new token-endpoint check.**  
   [oidc_provider.rs:322](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs:322), with client construction at line 273 and dispatch at line 329.

   Discovery can name an allowed `https://issuer.example/token`, which then returns `307 Location: https://collector.example/collect`—or an HTTP destination. The default SDK client follows the redirect and replays the form containing `refresh_token`. The check runs only before the first request. Removing Authorization on cross-origin redirects does not remove form credentials. This follows the pinned [reqwest redirect implementation](https://raw.githubusercontent.com/seanmonstar/reqwest/v0.12.24/src/redirect.rs).

   **Tests:** Not caught. The new SDK test advertises a foreign endpoint directly; it never exercises an allowed endpoint redirecting elsewhere. This is an existing exposure left open by the claimed fix. Workspace-injected and proactive clients have a same-origin redirect policy and avoid this bypass. The standalone default needs equivalent enforcement.

2. **MEDIUM — Subscription tests can pass with broken production exception wiring.**  
   [subscription.rs:370](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/subscription.rs:370), plus the production-client test at line 222.

   Replace the constructor’s `resolver_allowing_exactly(recipient.host())` with ordinary `egress::resolver()`: real xAI subscriptions become blocked, but the new tests still pass. Every successful wire request uses `resolve_to_addrs`, which [returns the override without invoking the underlying resolver](https://raw.githubusercontent.com/seanmonstar/reqwest/v0.12.24/src/dns/resolve.rs). The separate production-client test checks only denied destinations; its final assertions merely establish that the recipient hosts belong to the denylist.

   **Tests:** This mutation is not caught. The wire tests *would* detect removal of the recipient check or enabling ordinary redirect following. Their coverage does not establish successful production resolver admission. They also append `.no_proxy()`, so “only loopback routes/test root appended” is literally inaccurate.

3. **MEDIUM — The new origin restriction rejects legitimate split-host IdPs.**  
   [oidc_provider.rs:80](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs:80), applied by [proactive.rs:550](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-workspace/src/hub_auth/proactive.rs:550).

   An issuer at `https://login.example` with its legitimate token service at `https://tokens.example/token` now cannot refresh. The proactive loop stops and retains the old token; the SDK returns the stale token after refresh failure. Split-host metadata is real: [Google’s discovery document](https://accounts.google.com/.well-known/openid-configuration) names issuer `accounts.google.com` and token endpoint `oauth2.googleapis.com`.

   **Tests:** They enforce this rejection rather than identify it as a compatibility regression. This is a deliberate consequence of the stated policy, not an origin-comparison bug. It needs an explicit supported-provider restriction and documentation, or a separately approved mechanism for binding trusted token endpoints.

4. **LOW — CB-5 documentation incorrectly lists redirect confinement as sufficient credential binding.**  
   [dispatch.rs:14](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/dispatch.rs:14).

   The new text says a credential-bearing call needs “one of” the listed protections, including the same-origin redirect policy. A caller following that guidance can build the standard client and send a bearer directly to `https://collector.example`; `send_checked` allows it, and no redirect is necessary. Redirect confinement cannot establish that the *initial* destination owns the credential.

   **Tests:** No test catches this documentation error. Require initial credential-recipient binding **and** appropriate redirect handling.

The remaining claims hold at source level:

- **F1/F7:** The exception has one production construction site; the raw client and builder are private. `execute` checks the parsed recipient before proxy/DNS dispatch. I found no subscription bypass through case, trailing dots, IP literals, or redirects.
- **CB-3 comparison/classification:** Default ports and IDNs use parsed URL origins; endpoint userinfo is rejected. Helper refusals become proactive policy denials. Both production call sites pass `cfg!(test)`; no shipping configuration enabling it was found. Rust distinguishes [test-harness configuration](https://doc.rust-lang.org/reference/conditional-compilation.html#test) from ordinary builds.
- **Authentication guide:** The subscription opt-in instruction is removed, and the process-wide lifting of the vendor denylist—including telemetry hosts—is correctly disclosed.

DO-NOT-LAND


