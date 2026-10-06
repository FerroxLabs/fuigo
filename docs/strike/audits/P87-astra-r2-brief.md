Independent security audit of commit range 84569ea8..b840ff81 in this repo (branch strike/p87). Read-only; do not build.

Claims to verify:
1. F1: crates/codegen/fuigo-extra-ca/src/subscription.rs SubscriptionClient now installs the egress guard (egress.rs `resolver_allowing_exactly`) whose only exception is the recipient's own host; every other blocked name is refused. The exception cannot be reached by any other client or path.
2. F7: `SubscriptionClient::request` returns `SubscriptionRequestBuilder`, which cannot dispatch; the only dispatch is `execute` after the exact-recipient check.
3. The new unit tests in subscription.rs (`wire` module) drive the PRODUCTION construction (`SubscriptionClient::build` with only loopback routes/test root appended) and would fail if redirects were enabled or the recipient check removed.
4. CB-3: crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs `check_token_endpoint` and its use in the SDK `do_refresh` and in crates/codegen/fuigo-workspace/src/hub_auth/proactive.rs `do_refresh` ensure the refresh token is sent only to an https token_endpoint on the issuer's origin (loopback http only when cfg!(test)). A refusal in the proactive loop is a policy denial.
5. CB-5: crates/codegen/fuigo-extra-ca/src/dispatch.rs docs state check_url/send_checked are only the vendor denylist.
6. Docs: crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md no longer instructs setting FUIGO_ALLOW_UPSTREAM_HOSTS=1 for subscriptions and states accurately what it unlocks.

Find defects: bypasses of the guard or recipient check, ways the exception widens (case, trailing dot, proxies, IP literals, redirects), tests that would pass against a broken production path, cfg!(test) leaking into shipped builds, origin comparison mistakes (default ports, IDN, userinfo), regressions for real users (e.g. IdPs whose token endpoint is on another host), and inaccurate docs. For each finding: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.

Round 2. Round 1 findings and responses (verify each fix, and look for anything new):
- HIGH SDK default client followed redirects off the token endpoint origin -> fixed in oidc_provider.rs (same_origin_redirects) + test.
- MEDIUM exception wiring untested -> egress.rs cfg(test) thread-local hook + subscription.rs test production_client_guard_admits_its_own_host. Check the hook cannot affect non-test builds and that the test genuinely exercises the production construction.
- MEDIUM split-host IdPs refused -> intended policy per the packet brief; documented; escalated to the product owner (not changed).
- LOW dispatch.rs docs -> reworded.
