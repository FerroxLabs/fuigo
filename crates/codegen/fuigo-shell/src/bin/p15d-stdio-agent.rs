//! Test helper: the real agent loop (`run_stdio_agent`) on stdin/stdout, so a test can start TWO separate processes and talk
//! ACP to each. Built only with the `test-support` feature. It is not part of any shipped build.

use fuigo_shell::agent::config::{Config, TitlePolicy};

fn main() -> anyhow::Result<()> {
    // The main thread of a Windows process has a 1 MiB stack, too small for the agent; run on a thread with a large one.
    std::thread::Builder::new()
        .name("p15d-agent".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(run)?
        .join()
        .map_err(|_| anyhow::anyhow!("agent thread panicked"))?
}

fn run() -> anyhow::Result<()> {
    fuigo_extra_ca::ensure_default_crypto_provider();
    let mut config = Config::default();
    // No title requests: they would add model calls the test does not script.
    config.session.title_policy = Some(TitlePolicy::Local);
    let runtime = tokio::runtime::Builder::new_multi_thread().thread_stack_size(16 * 1024 * 1024).enable_all().build()?;
    runtime.block_on(fuigo_shell::agent::app::run_stdio_agent(&config, None, None))
}
