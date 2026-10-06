# fuigo-crash-handler

Crash handler for SIGBUS/SIGSEGV/SIGABRT with best-effort backtrace capture, per-process crash slots, and ASLR-safe symbolication.

## How it works

`install()` opens this process's own slot, `crash_dir/crash-<pid>-<start>.bin` (`<start>` is the OS process start-time token), records the main image's load base, extent and build identity, installs a classifying panic hook, and registers a `sigaction` handler. On crash the handler writes a binary blob (`GCRX` v2) into the pre-opened slot and restores the terminal via pre-computed escape sequences. The handler uses only async-signal-safe operations (atomics, pre-built statics, `write`/`lseek`/`close`, `getpid`, `time`, `pthread_self`). A clean exit deletes the empty slot (`atexit`, Unix); a forked child never writes to or deletes its parent's slot.

On next launch, `check_previous_crashes()` reports only slots whose owner is dead (pid gone, or pid reused by a process with a different start time); live sessions' slots are never touched. Each dead blob is claimed with an atomic rename (reported once even when sessions start together), symbolicated, written to `history/crash-<time>-<pid>.txt` (owner-only; last 10 kept) and `last-crash-report.txt`, then removed. Empty slots of dead owners are swept silently; pre-1.0.21 `last-crash.bin` blobs are reported without symbols.

Symbolication re-bases each in-image instruction pointer (`ip - crashed_base + current_base`) so it works across ASLR, and only when the reader is the same build (version, image size, build id / `LC_UUID` / PE stamp, executable size); otherwise the report lists `fuigo+0x<offset>` for offline `addr2line`/`atos`.

The panic hook records a class code (`Broken pipe`/`os error 32`, `No space left on device`/`os error 28`, or other — the same strings the Sentry filter drops), the panicking thread's name (32 bytes, no path separators) and thread id; never the panic message. A SIGABRT on that thread is reported as a Rust panic; benign classes keep their report but `startup_notice()` stays silent for them.

Nothing is uploaded: this crate has no network code.

## Limitations

### Frame capture is best-effort

Frame capture uses two fully async-signal-safe techniques:
1. The crash instruction pointer is extracted directly from the `ucontext_t` passed by the kernel.
2. Additional frames are captured by walking the frame-pointer chain (RBP on x86_64, x29 on aarch64) with raw pointer reads.

In release builds without `-C force-frame-pointers`, the frame-pointer chain may be incomplete or empty (the compiler omits frame pointers by default for optimization). The crash PC is always captured. In debug/dev builds, frame pointers are retained by default, producing fuller call stacks.

### sigaltstack is per-thread

The alternate signal stack is installed only on the thread that calls `install()`. Tokio worker threads do not inherit it. Stack overflows on worker threads will still trigger the handler (sigaction is process-wide), but without altstack protection the handler itself may fault on the overflowed stack.

## Usage

```rust
use std::path::PathBuf;

let crash_dir = PathBuf::from("/home/user/.myapp/crash");

// Order does not matter: each process has its own slot.
let reports = fuigo_crash_handler::check_previous_crashes(&crash_dir, env!("CARGO_PKG_VERSION"));
if let Some(notice) = fuigo_crash_handler::startup_notice(&reports) {
    eprintln!("{notice}");
}

// install() before any threads or async runtime — sigaltstack is per-thread.
// Creates crash_dir if it does not exist.
fuigo_crash_handler::install(fuigo_crash_handler::CrashHandlerConfig {
    app_version: env!("CARGO_PKG_VERSION").to_string(),
    crash_dir,
});
```
