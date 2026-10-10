# R-flux-a: FLUX-TRAFFIC part A (key probe)

## Problem
At every ACP `initialize` Fuigo sent `GET {base}/api-key` with the user's bearer key. Flux has no such route (404
`unsupported_endpoint`), and a host app starting one Fuigo per turn repeated it (~20k requests a day). A 404 was
`Unknown` and nothing was remembered.

## Call flow
`acp_agent.rs` initialize -> `should_probe_first_party_env_key` -> `first_party_env_key_allows_advertise(base)` ->
`probe_fuigo_api_key` -> `probe_remembering` (memory, then `probe_detailed` -> `send_checked`). `allows_advertise()` is
true for Usable and Unknown, false for Unusable; it only decides whether `fuigo.api_key` is advertised as an auth
method (plus `set_first_party_env_api_key_ok`). Unknown keeps today's meaning (fail open). Base = `endpoints.fuigo_api_base_url`
(default `https://api.fluxrouter.ai/v1`; `FUIGO_API_BASE_URL` or `[endpoints]`).

## Change (owner update replaces "skip Flux")
- Flux base (host exactly `api.fluxrouter.ai`, const `FLUX_API_HOST`, a test pins it to the host of
  `FUIGO_API_BASE_URL_DEFAULT`; no suffix match): `GET {origin}/key/info` (no `/v1`). 200 with `info.blocked == true` ->
  Unusable; other parseable 200 -> Usable (missing or non-boolean `blocked` = not blocked); 401 -> Unusable; any other
  status, timeout, transport error or unparseable body -> Unknown. Only `blocked` is declared in the parser.
- Other hosts: unchanged `/api-key` probe and classification (no allow-list).
- 404/405 on either route and any host: Unknown, remembered per probed URL for 24 h (key independent).
- Usable/Unusable remembered per (URL, key) for 1 h. Unknown from timeout, transport, 5xx, 429, parse error or a local
  denial is never stored.
- x.ai guard untouched: `send_checked` denies locally; test `an_x_ai_base_is_denied_locally_on_both_routes_and_nothing_is_remembered`.

## Memory file
`<fuigo home>/api-key-probe-state.json`, 0600, via `fuigo_config::fs_atomic::write_atomically` (temp + rename; last writer
wins, no lock). Content: `unsupported:[{h,t}]`, `verdicts:[{h,v,t}]`; `h` = SHA-256 over a tag, the normalised URL
(userinfo, query, fragment dropped) and, for verdicts, the full key; `v` = usable|unusable; `t` = unix seconds. At most
64 per list, oldest dropped. Missing, corrupt, over 64 KiB or future-dated data is ignored and overwritten. No field of
the response and no key or URL is stored or logged (test greps the bytes and the unified log).
Trade-offs: a cached Usable outlives a revocation by up to 1 h. A cached Unusable for the SAME key (topped up,
unblocked) stays up to 1 h; a changed key is a new entry. No natural re-login hook exists for the env key, so nothing clears
an entry early (deleting the file does). While Unusable is cached the key is not advertised, as with a live Unusable.
The 24 h route memory is per URL, so changing the key does not re-probe (the route's absence is key independent).

## Evidence (mock on 127.0.0.1, Hetzner lane fluxa)
- Before (red, 87ad6a6e): 100 initializes against a 404 server sent 100 requests (assertion left 100, right 1); 100 Flux
  initializes sent 100. After: 1 and 1; the hour boundary sends 1 more; a second key sends its own.
- Red: 10 of 31 probe tests fail by assertion/panic at 87ad6a6e. Fix: b973677c + 9f06b46a (borrow fix); 31 pass.
- Final proof table: see report (3 runs, lib, guard, clippy at the final tip).

## Unverified
No run against api.fluxrouter.ai or any real service (by rule); `/key/info` shape is from the Flux side's statement.
