# R-xs-p2: leader transport extraction (no behaviour change)

Extracted (all in crates/codegen/fuigo-shell/src/leader/):
- Private bind: `peer_check.rs` `bind_private_with(path, bind)` (pub(crate), generic over the listener; unix 0700 temp dir, 0600, rename; non-unix just calls `bind`). `bind_private(path)` is now a one-line wrapper (leader call site unchanged). `peer_check` is now `pub(crate) mod` (mod.rs:58).
- Frames: `protocol.rs` `read_frame_limited`, `write_frame_limited`, `FrameReader::with_limit`; `read_frame`, `write_frame`, `FrameReader::new` delegate with `MAX_MESSAGE_SIZE`. The `MessageTooLarge` text still names the leader cap (error text must not change).
- Same-user check: `peer_check.rs` `verdict_for(side, &UnixStream, key_path)` (unix, pub(crate)), `peer_is_same_user`, `PeerVerdict`, `Side`, test seam `set`/`Inject` widened to pub(crate); doc says: proves the OS user only. `server_accepts`/`client_accepts` unchanged in signature. Windows decision fn `peer_auth::decide` was already pub(crate), untouched.

Call sites: unchanged (server.rs / client.rs still call bind_private, server_accepts, client_accepts, read_frame, write_frame, FrameReader::new).

Proof (Hetzner lane xs2, netns, slot-run): `fuigo-shell --lib leader` 341 pass (incl. 3 new xs2_* tests in peer_check_tests.rs, appended; no existing assertion edited); test_leader_stdio_integration + test_leader_sandbox_confinement pass; fuigo-extra-ca pass; fuigo-auth secret_debug_guard pass (no re-pin needed); clippy: no warning in touched lines (one pre-existing at leader/mod.rs:2573).

Windows-gated items touched (UNRUN, coordinator to `cargo check` on Windows): `bind_private_with` `#[cfg(not(unix))]` variant (new, generic, calls `bind(path)`); `bind_private` now unconditional wrapper (was split by cfg); `verdict_for`/`os_peer_uid` unix-only (signature type LeaderStream -> tokio UnixStream, identical on unix); `server_accepts`/`client_accepts` cfg(not(unix)) bodies unchanged. peer_check.rs keeps `#![cfg_attr(not(unix), allow(unused))]`. Frame code has no cfg.

Not verified: Windows compile; fuigo-pager leader_cluster tests not run.
