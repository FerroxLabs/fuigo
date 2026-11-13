# Fuigo terminal I/O patch

This is crossterm 0.28.1 from the locally installed crates.io package, retaining
its MIT license and library tests. The published package checksum is
`829d955a0bb380ef178a640b91779e3987da38c9aea133b20614cfed8cdea9c6`.
Examples and their unused development dependencies are omitted.

Two Unix terminal fixes are local to this copy:

- `src/terminal/sys/unix.rs`: keyboard negotiation has one 200 ms deadline for
  both Kitty flags and trailing DA1. Silence falls back to classic input;
  an answered Kitty query still enables the protocol if DA1 never arrives.
  Interrupted polls retry within that same deadline (including the event
  reader's interrupted-as-silence result). After accepting Kitty flags, one
  final zero-timeout poll consumes a DA1 arriving at the deadline; other errors
  terminate the probe.
- `src/event/source/unix/mio.rs`: retain readable state while the descriptor
  has buffered input, checking level readiness before each continued read
  because stdin may be blocking. Returning a parsed event previously lost
  the edge after one 1,024-byte read, stalling large unbracketed pastes.
  EOF returns `Ok(None)` instead of retrying forever; read errors other than
  `WouldBlock` and `Interrupted` propagate to the caller. Interrupted reads
  retain their retry behaviour. Level checks require `POLLIN`, not merely any
  poll event: hangup alone never permits a blocking read. `POLLNVAL` or a
  failed level check preserves readiness and falls back to one read per mio
  notification. On macOS, `FIONREAD` checks queued tty bytes because `poll`
  cannot reliably check `/dev/tty` when stdin is piped.

The readiness regression writes several buffers with one notification and
checks every byte plus a subsequent write. Process tests in
`fuigo-pager-bin/tests/startup_robustness.rs` exercise silent and answering
terminals and a 200 KB unbracketed paste through a real PTY. A Linux process
regression also checks typed keys and an exact 20 KB paste on the controlling
PTY with piped stdin; `macos-tests.yml` runs the library tests on macOS.
On macOS, interactive input with piped stdin is unsupported because kqueue
registration of `/dev/tty` fails with `EINVAL` (a pre-existing limitation).

Keeping the changes inside the event reader preserves its parsing and queued
type-ahead. A detached probe with a caller-side timeout would continue holding
the reader lock and delay subsequent keyboard input. Remove this patch when a
released dependency supplies these guarantees.

The dependency's existing color tests mutate process-wide overrides and need
serial execution. Its library tests remain opt-in (the registry dependency
was not tested by workspace defaults). Run the complete suite with
`cargo test --locked -p crossterm --lib -- --test-threads=1`, also run by
`.github/workflows/dispatch-policy.yml`; the new Fuigo
process regressions are part of ordinary `fuigo-pager-bin` tests.

The kept dev-dependencies support these library tests: `temp-env` for color
overrides, `serial_test` for Windows cursor/terminal tests, and `serde_json`
for color serialization tests when the `serde` feature is enabled.
