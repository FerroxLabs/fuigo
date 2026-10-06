//! Stderr for paths where fd 2 may already be dead: re-exports
//! [`fuigo_tty_utils::best_effort_stderr`].
//!
//! Once stderr's reader is gone (a closed terminal pane, a pipe whose reader exited) or its
//! target is full, every write fails, `eprintln!` panics on that failure, and under
//! `panic = "abort"` the panic is a SIGABRT plus a crash report on the next launch. Every
//! diagnostic in this crate and the composition-root binary goes through
//! `fuigo_tty_utils::cli_eprintln!` / `cli_eprint!` or the line helpers here; the crate denies
//! `clippy::print_stderr` outside tests so a raw `eprintln!` cannot come back. See the module
//! docs there for the policy (text dropped, never a panic, never a changed exit code).

pub use fuigo_tty_utils::best_effort_stderr::*;
