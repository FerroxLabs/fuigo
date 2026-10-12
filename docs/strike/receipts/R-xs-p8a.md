# R-xs-p8a: wire contracts and locator row rules (packet 8a)

Crate `fuigo-peer` only. Files: `src/wire.rs`, `src/locator_row.rs`, `src/wire_tests.rs`, export lines in `src/lib.rs`. No IO, no new dependency, no caller outside tests.

## Types
- `wire`: `HostId`, `BoundedId`, `ReasonText`, `Hello`, `NoticeKind`, `Op {List, Send, Notice}`, `SessionRow`, `Reply {List, Send, Notice, Unavailable}`, `WireError`, `WIRE_VERSION` = 1, `check_wire_frame`.
- `locator_row`: `HostDir {Home, Runtime}`, `HostRow` (no path field), `parse_rows`, `RowsError`, `socket_path`, `choose_dir`, `DirChoice`, `DirUnavailable`, `TryResult`, `Reap`, `reap_decision`.

## Limits
- Frame 64 KiB (`MAX_FRAME_BYTES`); rows file 64 KiB, 64 rows; list page 64 rows, 4 pages; reason 256 bytes; ids 128 bytes.
- Socket path 103 bytes (macOS 104 minus NUL, smaller than Linux 108); home suffix 44, runtime suffix 50.

## Reap table (`reap_decision(dir, expected, first, second)`)
| tries | Home | Runtime |
|---|---|---|
| Refused, Refused | Reap | Reap |
| NoSuchFile / Refused mix | Reap | Keep |
| Hello(x != expected) twice, same x | Reap | Reap |
| any Timeout, VersionMismatch, Other | Keep | Keep |
| any Hello(expected) | Keep | Keep |
| everything else | Keep | Keep |

pid is not a parameter.

## Tests (`wire_tests`, 11)
every_op_and_reply_round_trips, unknown_op_unknown_field_and_watch_are_rejected, list_page_and_reason_and_rows_are_bounded, hello_version_is_exact, host_id_shape_is_enforced, a_to_address_cannot_change_the_socket_path, directory_choice_by_length, rows_parse_and_match_serde_output, rows_refuse_bad_input, reap_table, mutated_frames_never_panic_and_never_yield_an_invalid_envelope (6000 iterations, fixed seed).

Result: `cargo test --locked --no-fail-fast -p fuigo-peer`: 43 passed, 0 failed (32 before). Clippy `--all-targets`: clean.
