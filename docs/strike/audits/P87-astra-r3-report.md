# Astra round 3 — final report (verbatim; full transcript: Hetzner /root/fuigo-builds/p87/astra/P87-astra-r3-report.txt, sha256 b1b41a241e0e1dbea0e0eddb511af458c118c6e8fe3b2a950e151ac9efc48eb2)

Reviewed `84569ea8..34a404c3` on `strike/p87`. **No BLOCKER/HIGH defect or new production bypass found.** Read-only inspection only; no builds, tests, mutations, or edits performed.

1. **MEDIUM — Retained compatibility restriction: split-host IdPs cannot refresh.**  
   [oidc_provider.rs:85](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/common/fuigo-computer-hub-sdk/src/oidc_provider.rs:85).  
   Google publishes issuer `accounts.google.com` and token endpoint `oauth2.googleapis.com`; this check therefore rejects its refresh endpoint. [Google discovery metadata](https://accounts.google.com/.well-known/openid-configuration). Hub authentication eventually loses validity when the stored access token expires. **Tests enforce this restriction:** the helper and both refresh-path tests reject foreign origins. This remains intentional under the supplied brief, and the [user guide now documents it](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md:190). Retain the product-owner follow-up.

2. **LOW — New module documentation incorrectly prohibits every query string.**  
   [subscription.rs:5](/Volumes/Mando/WaylandBots/Fuigo/wt-p87/crates/codegen/fuigo-extra-ca/src/subscription.rs:5).  
   The new description says “no … query,” but `https://chatgpt.com/backend-api/codex/models?client_version=1.0.5` is intentionally accepted; that endpoint requires the narrowly validated `client_version` parameter. Following the blanket description would produce a rejected catalogue request. **The existing `subscription_catalog_allows_only_required_client_version` test pins the correct behavior, but does not catch the inaccurate prose.** Document this exception.

All prior-round corrective responses are present and supported by source inspection:

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Round-3 audit completed against the requested range. |
| F1: guard and exception isolation | ✅ Done | Production constructor installs `resolver_allowing_exactly(recipient.host())`. Its only production caller is `SubscriptionClient`; the raw client remains private. |
| Guard wiring and test preconditions | ✅ Done | Admission hook observes the production resolver. All three relevant tests assert the guard is enabled. Negative and positive construction tests use `no_proxy()`. |
| F7 and userinfo correction | ✅ Done | Wrapper exposes no `send`, `build_split`, raw client, or dispatch conversion. `execute` checks the recipient before dispatch. Input userinfo is remembered before reqwest normalization and rejected by `build()`, with regression coverage. |
| Production wire tests | ✅ Done | Call the production `build`, appending routes, test root, and `no_proxy`. Removing recipient validation breaks the denial assertions; enabling redirects breaks the response/contact assertions. These are source conclusions, not executed mutation results. |
| SDK redirect correction | ✅ Done | Default client uses same-origin redirects. The 307/308 test now requires exactly one `/token` submission containing the fixture refresh token, eliminating the earlier pre-dispatch false positive. |
| CB-3 refresh binding | ✅ Done | Both refresh paths validate before sending the form. Proactive checker refusals become `DispatchError::Denied`; the loop stops while retaining credentials. |
| CB-5 and user-guide corrections | ✅ Done | Dispatch documentation states denylist-only checking. Subscription instructions remove the override requirement and explain its process-wide effect, including telemetry hosts. |
| Remaining follow-ups | ⬜ Pending | Retained split-host policy decision and the LOW module-documentation correction above. |

No widening was found through case normalization, trailing dots, IP-literal substitution, default ports, IDN normalization, or redirects. Subscription recipient validation occurs before proxy dispatch, so remote proxy DNS does not bypass that boundary.

Both refresh call sites pass `cfg!(test)`; the resolver observation hook and invocation are `#[cfg(test)]`. No checked build configuration enabled that flag for ordinary builds. [Rust test configuration](https://doc.rust-lang.org/reference/conditional-compilation.html#test). Arbitrary SDK-injected clients still carry the documented responsibility for redirect safety; Fuigo’s actual injected client satisfies it.

LAND-WITH-FOLLOWUPS


