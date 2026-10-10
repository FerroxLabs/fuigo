//! A tokio-runtime START-UP failure must not report the generic run-failure code.
//!
//! `main` used to exit `1` when the runtime could not be built (EMFILE creating the I/O driver, pre-warm
//! timeout). `1` is also what a failed run exits, so a script could not tell "Fuigo never started"
//! from "the run failed" -- the same ambiguity Contract D.2.1 removes for permission denials. The
//! start-up failure now has its own code, `4`.
//!
//! The failure is provoked for real, not stubbed: the child holds descriptors it inherited under a hard `RLIMIT_NOFILE`,
//! so tokio cannot create its epoll/eventfd pair and `Builder::build` returns `Err(EMFILE)`. Nothing in the binary knows
//! it is under test. (An address-space limit does NOT work: a refused worker `pthread_create` is a tokio `expect` panic,
//! i.e. SIGABRT under `panic = "abort"`, not an `Err`.)
//!
//! P195 (K26): the limit itself can no longer be what provokes it. A limit under the start-up floor (`MIN_OPEN_FILES`) is
//! refused before the runtime is built (`low_nofile_exit.rs` pins that), so this test holds the limit AT the floor and uses up
//! the descriptors with inherited ones instead. The effect on the binary is the same: it has few descriptors left.
//!
//! Which exact number of held descriptors lands the failure at the runtime build rather than at some other early
//! `open()` depends on how many descriptors the binary holds by then, so the test sweeps a small range instead of
//! hard-coding one. The sweep makes two claims: at least one count reaches the runtime-build failure (otherwise the
//! test proves nothing), and EVERY run that reports that failure exits `4`. Runs that die elsewhere are not this
//! test's subject.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

/// Resolve the pager binary like the other integration tests here.
fn pager_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(&p)
            .unwrap_or_else(|e| panic!("failed to absolutize PAGER_BINARY {p}: {e}"));
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("PAGER_BINARY is unset and this build is not `cargo test`")
}

const STARTUP_FAILURE_EXIT_CODE: i32 = 4;

/// The hard descriptor limit of every run: the start-up floor (`MIN_OPEN_FILES` in `main.rs`), the lowest limit `fuigo`
/// starts under.
const NOFILE_LIMIT: u32 = 64;

/// How many inherited descriptors the child holds. With the limit above, stdio plus this many leaves the binary only a few
/// descriptors; above the top of the range the descriptor table is full before `exec` can finish, below the bottom of
/// the range the binary gets past the runtime build.
const HELD_SWEEP: std::ops::RangeInclusive<u32> = 40..=60;

struct Run {
    held: u32,
    code: Option<i32>,
    stderr: String,
}

fn run_with_held_descriptors(held: u32) -> Run {
    // Hermetic: a run that gets past start-up (fewer held descriptors) must have no credentials, endpoints
    // or config to act on, a disposable working directory instead of the checkout, and every network
    // kill switch the other process tests use (telemetry, trace upload, feedback, auto-updater), so a
    // start-up that survives the descriptor limit cannot reach a real endpoint. `env()` is the
    // sandbox's full hermetic baseline.
    let sandbox = fuigo_test_support::TestSandbox::builder().build();
    let mut command = Command::new(pager_binary());
    command
        .args(["--no-auto-update", "-p", "hello"])
        .env_clear()
        .envs(sandbox.env())
        .current_dir(sandbox.workspace())
        // Own process group, so a timeout can kill everything the pager started.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: the closure runs between fork and exec and only makes async-signal-safe libc calls (`setrlimit`, `open`).
    // The descriptors it opens are deliberately NOT close-on-exec: the pager inherits them and they count against its limit.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: libc::rlim_t::from(NOFILE_LIMIT),
                rlim_max: libc::rlim_t::from(NOFILE_LIMIT),
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for _ in 0..held {
                if libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) < 0 {
                    break;
                }
            }
            Ok(())
        });
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "the child is placed in its own process group (process_group(0)) and the whole \
                  group is SIGKILLed on the deadline, so nothing it starts outlives this function"
    )]
    let mut child = command.spawn().expect("spawn fuigo");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let (text_tx, text_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr_pipe, &mut text);
        let _ = text_tx.send(text);
    });
    let pgid = i32::try_from(child.id()).expect("pid fits i32");
    // A run that gets past start-up could try to do real work; never let one hang the suite.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: plain signal to the process group this test created above.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
            break child.wait().expect("reap killed child");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    // Unconditional: the pager may have exited on its own while something it started is still in the group,
    // holding the stderr pipe open. A normal exit and the deadline path both end with the group dead.
    // SAFETY: plain signal to the process group this test created above (ESRCH when it is already empty).
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    Run {
        held,
        code: status.code(),
        // Bounded: the group is dead, so EOF is imminent; never wait on it forever.
        stderr: text_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| String::from("<stderr not drained>")),
    }
}

#[test]
fn a_runtime_startup_failure_exits_four_not_the_generic_one() {
    let runs: Vec<Run> = HELD_SWEEP.map(run_with_held_descriptors).collect();
    let reached: Vec<&Run> = runs
        .iter()
        .filter(|r| r.stderr.contains("failed to start tokio runtime"))
        .collect();

    assert!(
        !reached.is_empty(),
        "no held-descriptor count in {HELD_SWEEP:?} made the runtime build fail, so this test proves \
         nothing; outcomes (held, exit): {:?}",
        runs.iter().map(|r| (r.held, r.code)).collect::<Vec<_>>()
    );
    for run in reached {
        assert_eq!(
            run.code,
            Some(STARTUP_FAILURE_EXIT_CODE),
            "a start-up failure must exit {STARTUP_FAILURE_EXIT_CODE}, not 1 (a failed run) and \
             not a signal; held={}\nstderr:\n{}",
            run.held,
            run.stderr
        );
        assert!(
            run.stderr.contains("never started"),
            "stderr says the run never started: {}",
            run.stderr
        );
    }
}
