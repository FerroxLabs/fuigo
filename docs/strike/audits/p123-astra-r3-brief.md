# P123 Astra round 3 brief (last round)

Read-only checkout `/Volumes/Mando/WaylandBots/Fuigo/wt-p123`, branch `strike/p123`. Do NOT run cargo, do not modify anything,
and do NOT open the earlier audit reports in `docs/strike/audits/` (they are huge). Parent `bfb0ffa4`; compare with `v1.0.20`.
Audit `git log bfb0ffa4..HEAD`; the newest commit is the round-2 redesign. Items: see `p123-astra-r1-brief.md`.

## Round 2 findings and what was done
- N1 HIGH (prompt alignment cut completed turns from a healthy fork when indexes drift): the alignment heuristic is REMOVED
  from `copy.rs` entirely.
- H1 (K17 coherence) is now solved with a protocol instead of a heuristic: `storage/snapshot_lock.rs` (`snapshot.lock` in the
  session dir). The persistence actor (`persistence.rs`, arm `PersistenceMsg::Chat`) writes a prompt's transcript echo and its
  chat item while holding that lock, echo first (it flushes the pending echo before appending the chat item). A fork's
  snapshot (`copy.rs` `snapshot_source`) takes the same lock, then the chat and transcript append locks, reads both, releases.
  Lock order: snapshot lock, then one append lock at a time by the actor; chat before transcript for the snapshot.
  Stated limits: a rewind (chat replaced before its marker is queued), content inside a turn (assistant chunks stream before
  the assistant chat item), and a mixed-version writer that does not take the lock.
- N2 MEDIUM (a suspended reader of rewind points made the rewrite fail): the rewrite holds the append lock SHARED (appenders
  take it exclusively, readers shared), 10 s bounded, `WouldBlock` as before only for a stuck appender.
Everything else from round 1 is unchanged (see `p123-astra-r2-brief.md`).

## What I want back
FIXED / NOT FIXED per finding; NEW regressions vs `bfb0ffa4` and `v1.0.20` with severity and a concrete scenario; verdict
(LAND-OK only with zero BLOCKER and zero HIGH). Look hardest at: deadlock or stall between the snapshot lock, the append
locks and the persistence actor (the actor awaits while holding the snapshot lock file handle); `flush_pending` before the
chat item changing write ordering or failure latching; whether echo-before-chat can be violated by the call order in
`turn.rs`; test determinism. End with the verdict table even if you run short of time.
