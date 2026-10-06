//! Shared non-blocking file appender and worker-guard registry for telemetry file-log layers.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

// Park every worker guard for the process lifetime
// Dropping a guard flushes and shuts down that file's writer thread, so accumulate (never overwrite) to let multiple file-log layers coexist
static FILE_LOG_GUARDS: OnceLock<Mutex<Vec<WorkerGuard>>> = OnceLock::new();

/// `tracing_appender::non_blocking` over `writer`, with every record passed through
/// [`fuigo_secrets::sent_credentials::ScrubWriter`] first (P70b: a log file is a log sink, so a credential this
/// process sent upstream and an upstream echoed back is replaced, exact match). Every telemetry file log is built
/// through here. The worker writes each record with one `write_all`, so a record is scrubbed whole.
pub(crate) fn scrubbed_non_blocking<W: std::io::Write + Send + 'static>(
    writer: W,
) -> (NonBlocking, WorkerGuard) {
    tracing_appender::non_blocking(fuigo_secrets::sent_credentials::ScrubWriter::new(writer))
}

/// Opens `path` in append mode and parks the worker guard for the process lifetime so buffered logs aren't lost.
pub(crate) fn non_blocking_file_writer(path: &Path) -> std::io::Result<NonBlocking> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let (non_blocking, guard) = scrubbed_non_blocking(file);
    let guards = FILE_LOG_GUARDS.get_or_init(|| Mutex::new(Vec::new()));
    // Recover from a poisoned mutex so the guard is always parked; dropping it would shut down the writer thread and silently lose buffered logs
    let mut guards = guards
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guards.push(guard);
    Ok(non_blocking)
}

/// Drop all parked worker guards, flushing their non-blocking writers.
/// Call at process exit so short-lived runs (e.g. headless `fuigo -p`) don't lose buffered logs.
pub(crate) fn flush_file_log_guards() {
    if let Some(m) = FILE_LOG_GUARDS.get() {
        // Recover from a poisoned mutex so exit-flush still drains the guards.
        let mut guards = m.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        guards.clear(); // dropping each WorkerGuard flushes and joins its writer thread
    }
}

#[cfg(test)]
mod tests {
    /// P70b guard: every telemetry file log goes through [`super::scrubbed_non_blocking`]. A new
    /// `tracing_appender::non_blocking(` call elsewhere in this crate would be a log sink that skips the
    /// exact-match scrub of credentials sent upstream.
    #[test]
    fn every_file_log_writer_is_built_through_the_scrubbing_helper() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let needle = ["tracing_appender::", "non_blocking("].concat();
        let offenders: Vec<String> = files
            .iter()
            .filter(|p| !p.ends_with("appender.rs"))
            .filter(|p| std::fs::read_to_string(p).is_ok_and(|s| s.contains(&needle)))
            .map(|p| p.display().to_string())
            .collect();
        assert!(
            offenders.is_empty(),
            "unscrubbed file log writers: {offenders:?}"
        );
        assert!(
            files.len() > 10,
            "walked the crate sources: {}",
            files.len()
        );
    }
}
