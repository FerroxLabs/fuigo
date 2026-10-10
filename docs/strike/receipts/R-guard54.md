# R-guard54: P54 identity-body guard re-pinned

Rule: `identity_body_guard` (crates/codegen/fuigo-extra-ca/tests) counts, per file, every way a request/serialised body could
pick up caller identity (`agent_id()` calls, quoted identity keys, identity field declarations, `.engage(`). A new site must be
reviewed against the P54 rule (FluxRouter-operated: keep; user-configured for that data: keep and record; else withhold/pseudonymise).

Failure at cd9d3eab: 3 files drifted (exactly these; run1 on Hetzner, `cargo test --locked -p fuigo-extra-ca`).
Nobody saw it earlier because no landing lane ran `fuigo-extra-ca`.

| file | pinned -> actual | commit (packet) | date |
|---|---|---|---|
| pager agent_view/key_owner_tests.rs | 5 -> 6 | 4784cfc4 (U10 minimal elicitation card) | 2026-10-07 |
| pager dispatch/queue.rs | 4 -> 5 | d52be8ca (P193 held side question) | 2026-10-09 |
| pager dispatch/tests/session/load.rs | 48 -> 57 | 8ef61a39 +2, 7b190af9 +6, e661ed68 +1 (all P193) | 2026-10-07..09 |

Review of each new site (integration cd9d3eab):

| site | what it is | verdict |
|---|---|---|
| key_owner_tests.rs:1386 | `"email": "a@b.co"` in an elicitation `accept` content fixture (test) | complies: fake test data, no body sent |
| queue.rs:305 | `agent_id: AgentId` param of `send_held_side_question` (product); `AgentId(pub usize)` is the pager-local tab index, forwarded in-process to `notes::start_side_question`; no machine id, no serialisation | complies |
| load.rs:3550,4184,3829,3870,4004 | `agent_id:` in `TaskResult::SessionLoadFailed` literals (test) | complies: local tab id |
| load.rs:3801,4016 | same, `SessionRestoreFailed` (test) | complies |
| load.rs:3585 | same, `SessionCreated` (test) | complies |
| load.rs:3937 | same, `ForkSessionFailed` (test) | complies |

No violation found. The scanner does not count `agent_id: AgentId` inside one-line fn signatures (load.rs fail_load, loaded_ok, restore_failed).

Updated: the three EXPECTED entries (with receipt comments) in identity_body_guard.rs. No other guard in the crate needed changes (see Proof in the report).

Process: this guard must run in every landing lane (`cargo test --locked -p fuigo-extra-ca`), or drift accumulates unreviewed.
