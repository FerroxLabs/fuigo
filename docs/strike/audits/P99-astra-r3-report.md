# P99 Astra round 3, final (gpt-6-astra, read-only) on fe16738c..4505bfb5

Final report, verbatim. Full transcript: Hetzner /root/fuigo-builds/p99/astra/astra-r3.txt, sha256 b4d5c3a87d6bf05b70987b98b20e5a3c674990971f3583380ac08683a481c7d5.

Audited `fe16738c..4505bfb5` at `4505bfb54275d867260df5d39f70198c17f09bab`, including the round 2 delta and relevant callers. Read-only: no builds, tests, or file changes.

**No BLOCKER/HIGH defect found in P99’s credential-destination binding. Three follow-ups remain.**

1. **MEDIUM — HTTP error bodies can still expose credentials in diagnostics.**  
   Locations: [protocol.rs:494](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:494), [protocol.rs:629](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:629), [refresh.rs:239](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:239).

   An admitted endpoint or its gateway can return a non-2xx response containing a reflected request—for example, `{"error":"invalid_request","error_description":"Rejected refresh_token=SECRET"}`. The entire body becomes the displayed `TokenRefreshHttp` error and is written into unified logs. Code exchange similarly returns the raw body, potentially exposing the code and verifier. Recognized terminal errors also log unsanitized `error_description` at [refresh.rs:214](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:214).

   `without_url()` does not affect these custom errors. Preserve status and recognized OAuth error codes for classification, while excluding raw response text from diagnostics.

   **Coverage:** Existing tests do not assert redaction of reflected secrets in HTTP response bodies. The new connection-refusal test never exercises this path. **Pre-existing; remains outside the round 3 sanitization fix.**

2. **LOW — `redacted_for_log` retains embedded credentials in non-HTTP URLs.**  
   Locations: [protocol.rs:333](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:333), invoked before endpoint validation at [protocol.rs:323](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs:323).

   Discovery can supply `blob:https://user:secret@idp.example/token`. In the locked URL implementation, a blob URL’s path contains the embedded URL; its origin is derived from that embedded URL. Consequently, this formatter produces `https://idp.examplehttps://user:secret@idp.example/token`, retaining the secret and hiding the original scheme. This follows directly from the [url 2.5.8 implementation](https://docs.rs/url/2.5.8/src/url/origin.rs.html).

   The credential POST remains protected: the endpoint is subsequently refused. The defect is incomplete diagnostic sanitization. Render only HTTP/HTTPS URLs this way and use a fixed placeholder for unsupported schemes.

   **Coverage:** The new helper test covers HTTPS and an unparsable string, not valid non-HTTP URLs. **Residual exposure in the new round 3 helper; the previous raw logging also exposed it.**

3. **LOW — One refusal comment still incorrectly says the token was not forwarded.**  
   Location: [refresh.rs:21](/Volumes/Mando/WaylandBots/Fuigo/wt-p99/crates/codegen/fuigo-shell/src/auth/oidc/refresh.rs:21).

   A same-origin 307 loop forwards the token repeatedly before hitting the limit. A same-origin hop followed by a refused cross-origin hop also forwards it within the admitted origin. Both produce `Refused`, contradicting “the token was not forwarded.”

   The user-facing messages are corrected. Apply their “outside the token endpoint’s origin” qualification to this remaining comment.

   **Coverage:** The new loop test exercises the scenario but cannot detect contradictory prose. **Residual round 2 documentation issue.**

The core protection holds by source inspection: both credential POST paths use checked URLs; cached discovery cannot bypass validation; the Google exception remains one directed HTTPS/default-port pair; and the shipped local-HTTP exemption remains confined to the selected local issuer. Refusals bypass retry/escalation accounting and reach the manager’s transient branch without clearing stored credentials.

The redirect-message match agrees with the current policy’s static text. Ordinary transport failures remain transport failures. URL removal preserves reqwest’s error kind and source chain, so it does not change the inputs used by `is_network_unreachable` or the retry gate. [Locked reqwest implementation](https://raw.githubusercontent.com/seanmonstar/reqwest/v0.12.24/src/error.rs).

LAND-WITH-FOLLOWUPS
