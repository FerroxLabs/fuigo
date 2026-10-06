// Test-only crate (dev-dependency): its prints are harness diagnostics, never a shipped stream
// (R077 workspace print deny).
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![allow(
    unused_imports,
    unused_variables,
    unused_mut,
    unreachable_code,
    dead_code
)]
//! Shared test utilities for fuigo-build crates.
//!
//! Provides:
//! - [`MockInferenceServer`]: Mock /v1/chat/completions and /v1/responses with request logging
//! - [`loopback_ip`]: The loopback address paused-clock tests can reach a local server on (see [`loopback`])
//! - [`FuigoStdioClient`]: ACP client that drives `fuigo agent stdio` as a subprocess
//! - [`RawStdioClient`]: raw-wire ACP driver for bytes the typed client can't produce (Foundation `\/` methods, string UUID ids)
//! - [`AgentSpawnSpec`]: both argv halves (`<global> agent <agent flags> stdio`) plus child-env removal, for embedder-argv conformance
//! - [`leader::LeaderStdioClient`]: ACP client that drives `fuigo agent --leader stdio` (unix)
//! - [`TestSandbox`]: Own isolated paths, hermetic child env, optional git setup, diagnostics
//! - [`TestProcess`]: Own detached child lifecycle, process-tree teardown, bounded output tails
//! - [`run_headless`]: Run `fuigo -p` against the mock server and capture output
//! - [`git_workdir`]: Create a git-initialized [`TestSandbox`]
//! - [`EnvGuard`]: RAII env-var override; exclusive process-wide for [`env::PROCESS_ANCHORS`]
//! - [`FuigoHome`]: a private `FUIGO_HOME` (temp dir + exclusive guard) for one test
//! - [`fuigo_binary`]: Resolve the fuigo binary path (FUIGO_BINARY env or cargo_bin)
//! - [`spawn_counting_server`]: Connection-counting HTTP/1.1 server for wire/pooling tests
//! - [`uds_proxy::UdsProxy`]: Frame-aware fault-injection proxy for leader IPC sockets (unix)
//! - [`ResourceSnapshot`]: RSS/threads/fds sampling for soak tests
/// Multiply a harness timeout by `FUIGO_TEST_TIMEOUT_SCALE` (positive integer, default 1).
/// CI lanes on shared runner pools raise it so pool load slows tests instead of failing them (see the Fuigo merge CI workflow).
pub fn scaled(base: std::time::Duration) -> std::time::Duration {
    let scale = std::env::var("FUIGO_TEST_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(1);
    base * scale
}
pub mod acp_client;
pub mod counting_server;
pub mod env;
pub mod headless;
mod inference_override;
#[cfg(unix)]
pub mod leader;
pub mod loopback;
pub mod mock_server;
pub mod process;
pub mod reexec;
pub mod resources;
pub mod sandbox;
pub mod scripted;
pub mod sse;
#[cfg(unix)]
pub mod uds_proxy;
pub use acp_client::{AgentSpawnSpec, FuigoStdioClient, RawReply, RawStdioClient};
pub use counting_server::spawn_counting_server;
pub use env::{EnvGuard, FuigoHome, git_workdir, fuigo_binary, isolate_fuigo_env};
pub use headless::{
    HeadlessResult, assert_headless_success, assert_no_crashes, run_headless,
    run_headless_in_sandbox, run_headless_in_sandbox_borrowed,
    run_headless_in_sandbox_borrowed_with_env, run_headless_in_sandbox_with_env,
    run_headless_with_env, stderr_tail,
};
pub use inference_override::{InferenceEndpoint, InferenceExpectation, InferenceRequestMatcher};
#[cfg(unix)]
pub use leader::LeaderFixture;
pub use loopback::{loopback_ip, refused_loopback_url};
pub use mock_server::{
    MockInferenceServer, MockModelEntry, ScriptedResponse, SseEvent, StorageUpload,
};
#[cfg(unix)]
pub use process::{classify_kill_zero, pid_liveness, process_has_exited_without_reap, sigkill};
pub use process::{
    PidLiveness, TestOutput, TestOutputSnapshot, TestProcess, TestProcessConfig, TestProcessState,
    TestProcessStderr, TestProcessStdout, TestProcessTermination, TestProcessTree, TestStdin,
};
pub use resources::{ResourceGrowth, ResourceSnapshot, RssMeasurement, RssOutcome, RssSampler};
pub use sandbox::{TestSandbox, TestSandboxBuilder};
