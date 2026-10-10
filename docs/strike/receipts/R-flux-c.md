# R-flux-c: the model-list 401 backoff survives a restart (plus the audit fixes of part B)

Branch `strike/flux-c-persist` on top of A (`d7508baa`) and B (`9a5721f2`). Base integration c98e7546.

## Measured (mock on 127.0.0.1, 401 on /v1/models and /key/info, 404 elsewhere, fake key)
| Run | /v1/api-key | /v1/models | note |
|---|---|---|---|
| Simulated, 56 starts 65 s apart, BEFORE (both memories off) | 56 | 112 | 2 model requests per start |
| Simulated, A+B only (no disk backoff) | 1 | 112 | A remembers the 404; every start still fetches twice |
| Simulated, A+B+C | 1 | 6 | starts 0,1,3,7,15,30 (waits 1,2,4,8,16,30 min), 1 request each |
| Real binary at c98e7546, 6 starts 65 s apart, netns | 6 | 12 | 1 probe + 2 models per start (the operator's burst) |
| Real binary at 418cf72a, same | 1 | 3 | per start: 1+1, 1, 0, 1, 0, 0 |
| Simulated, 56 different rejected keys (flapping), A+B+C | - | 8 | starts 0,1,2 free, then 3,5,9,17,32 on the URL table |

Why two model requests per start: the STARTUP PREFETCH (blocking `prefetch_models_blocking` / `startup_prefetch`) and the
first rung of the catalog ladder (`ModelsManager::fetch_and_apply_inner`) both end in `fetch_models_uncommitted`; only the
second went through part B's gate, and the first did not record its 401 anywhere. Finding fixed.

## Design as built
1. File: `<fuigo home>/api-key-probe-state.json` gains `models_401:[{h,n,t}]` and `models_401_url:[{h,n,t}]`
   (`#[serde(default)]`, no `deny_unknown_fields`, so part-A-only files parse). `h` = SHA-256(tag, normalised models URL,
   env key and/or session token as sent); URL list: SHA-256(tag, URL). 64 entries, 24 h life, 64 KiB cap, future-dated ignored,
   atomic 0600 write. Env key vs OAuth/subscription token: both are hashed when present, so a refresh that returns a NEW
   token is a new entry; the SAME rejected token keeps its entry.
2. Written on each network 401 (n+1, t); cleared (own entry and URL entry) only on a network success. A cache hit is a
   separate outcome (`ModelsFetchOutcome::Cached`) and neither clears nor extends a wait.
3. Read/write point: ONE place, `fetch.rs` `fetch_models_uncommitted` before `source.fetch`, under a process-wide lock so two
   racing paths cannot both send before the first 401 is recorded. Every path ends there (startup prefetch in app.rs/server.rs,
   `startup_prefetch`, ladder, refresh watcher, etag refresh, `on_auth_changed`): all through the gate, yes.
4. Notice: a remembered-401 skip returns `Rejected`, so the manager raises the same `ConfigNotice` path as part B. Item 3:
   when the watch returns to empty the session is told to forget the note (`ForgetConfigNotice`), so a later episode shows it again.
5. Inside the window a new process has no fresh list: it uses the same fall back as after a 401 before (bundled defaults or a
   fresh disk cache). A valid key is unaffected: entries exist only after a 401 for that credential.
6. Clock: wall clock; backwards = future-dated = ignored (fetch); forwards = expired early (fetch).

## Flapping-credential cap (audit finding 2)
| URL-wide consecutive 401s (all credentials) | An unseen credential |
|---|---|
| 0-2 | fetches at once |
| 3, 4, 5, ... | waits 1, 2, 4, 8, 16, 30 min after the last 401 of that URL |
A 200 clears the URL entry and that credential's entry. `ModelsManager::note_successful_sign_in` (called in `acp_agent.rs` when
authenticate completes and when a runtime key is installed) clears every remembered rejection at once; an auth command that
merely returns a string does not. A user who fixes the key after three failed tries waits at most the current URL interval.

## Tests (fuigo-shell lib, `agent::models::tests::persist_401::*`, each in its own process)
two-process climb through the table, 10 s / 61 s, 200 clears, other credential, corrupt/oversized/future/part-A file, file
holds no key/URL, 56-start hour (three configurations), flapping credentials, sign-in clears, cache hit leaves the run alone;
`auth_notice_forward_tests` extended.
Red: the first commit (8cabaad9) was red only because the harness needed `rerun_in_own_process`; I did not capture an
assertion-level red run at 63181798 (finding: BEFORE numbers above come from the c98e7546 binary and the memory-off simulation).

## Proof at 418cf72a (+ clippy/doc fixups after): 3 targeted runs ok (53 tests), whole `fuigo-shell --lib` 8284 ok, `fuigo-extra-ca` ok.

## Unverified
Windows ACL call (`set_windows_owner_only_acl` after the write) not compiled on Windows by me. No real service contacted.
Binary runs were debug builds inside `unshare -n`, one process at a time per run.

## Follow-up D (audit LOW 1-3, NOTE 5), branch strike/flux-d-followup
1. Sign-in from another window / subscription unblock. Done inside `ModelsManager::on_auth_changed` (all callers: the auth
   watcher `app.rs`, both unblock refreshes in `mvp_agent/mod.rs`, `authenticate`). It clears every remembered model-list
   rejection (`note_successful_sign_in`) exactly when: a session is present AND the credential fingerprint (env key plus
   session token, in memory) differs from the one seen at the previous call or at construction. Same credential (unrelated
   rewrite of `auth.json`) and sign-out clear nothing, so a flapping writer cannot bring the fast loop back.
   Tests (`persist_401.rs`): `an_auth_file_change_to_a_new_credential_clears_the_url_wait`,
   `an_auth_file_touch_with_the_same_credential_keeps_the_url_wait`,
   `the_subscription_unblock_refresh_clears_the_wait_only_for_a_new_token`, `signing_out_does_not_clear_the_url_wait`;
   NOTE 5: `mvp_agent::tests::authenticate_with_a_runtime_key_clears_the_model_list_wait` (real `authenticate`, entry gone).
2. Lock: every load-modify-save goes through `RouteMemory::update`, under an advisory flock on `api-key-probe-state.lock`
   (owner-only), non-blocking attempts every 5 ms for at most 200 ms (`lock_is_contended`: kind and raw OS error), explicit
   unlock in a Drop guard (`HeldFlock`). Lock file unopenable or busy past 200 ms: go on without it, as before.
   Test: `concurrent_writers_lose_no_401_count` (2 threads x 100 updates, 1.5 ms pause between load and save).
3. Read-only home: a failed write keeps the per-credential and per-URL run in a process-wide list (`UNSAVED`, only while
   the file cannot be written; dropped by a later good write or a sign-in; at most 128 entries). Within one process the cap
   holds; across processes nothing can be remembered without a writable file. Test:
   `an_unwritable_home_still_holds_the_cap_inside_one_process` (path under a regular file).
Red (assertion level, 05728963 + 0d48ca91): (i) and (iii) `left: 1 right: 0`; item 2 `left: 99 right: 200`; item 3 `the URL wait
holds ...` failed. Fix commits: item 1 (models.rs), items 2+3 together (api_key_route_memory.rs), then 8cbedb24 (final).
Proof at 8cbedb24: my tests x3 (19 ok each), whole `fuigo-shell --lib` 8312 ok, `no_memory_writes_acp` 5 ok, `fuigo-extra-ca` ok,
clippy exit 0 with no warning on my lines. Burst simulation `fifty_six_starts_in_an_hour_before_and_after` (asserts): key probe 56 -> 1,
model list 112 -> 112 (A+B) -> 6 (A+B+C), unchanged. Release notes: one clause added (sign in again, also from another window).
Lock polling is 5 ms (not 20 ms): at 20 ms a writer that re-locks at once starves the other and it gives up after 200 ms.
Unverified: Windows (the lock helper is the repo idiom, not compiled on Windows by me; os error 33 path untested). Tests ran
on a build box, no real service contacted (mocks on 127.0.0.1, closed loopback port for `authenticate`).
