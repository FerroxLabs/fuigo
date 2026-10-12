# R-xs-p8c: connection core (sub-packet 8c)

Files: `crates/codegen/fuigo-shell/src/peer_inbox/{conn.rs,conn_tests.rs}` (plus the two-line `mod.rs` and `mod peer_inbox;` in `lib.rs`, to be merged with 8b). Inert: no socket, no caller outside tests.

Functions: `serve_one(stream, our_hello, &impl InboxHost)`, `exchange(stream, our_hello, &expect_host, op)`, trait `InboxHost { list, send, notice }`, typed `ConnError`.
Deadlines: each write 5 s (`WRITE_DEADLINE`), whole exchange 10 s (`EXCHANGE_DEADLINE`), tokio time.
Reused from the leader: `FrameReader::with_limit(MAX_FRAME_BYTES)` (cap checked from the prefix, cancel-safe) and `write_frame_limited`; `ProtocolError` is mapped to `ConnError`, never displayed.
Tests (conn_tests.rs): 13 tests, all pass: happy_path_list_send_notice, oversized_prefix_is_refused_before_any_body, one_byte_per_second_is_dropped_at_ten_seconds, client_one_byte_per_second_server_is_dropped_too, a_peer_that_never_reads_hits_the_write_deadline, wrong_version_gets_unavailable_and_never_reaches_the_host, client_sees_host_mismatch_and_sends_no_op, client_sees_version_mismatch_as_its_own_error, two_pipelined_ops_give_one_reply_and_one_host_call, invalid_ops_never_reach_the_host, mutation_fuzz_never_panics_and_host_sees_only_valid_input, no_error_text_contains_peer_bytes, client_refuses_a_reply_of_the_wrong_kind_and_an_op_that_fails_validate. Full fuigo-shell run: 67 test result lines, 0 failed. Clippy --all-targets: no findings in peer_inbox.
