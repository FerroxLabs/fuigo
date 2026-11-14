//! Deduplicate advisory startup warnings, including across our bwrap re-exec.
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

const HANDOFF: &str = "__FUIGO_SANDBOX_STARTUP_WARNINGS";

fn emitted() -> &'static Mutex<HashSet<String>> {
    static EMITTED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    EMITTED.get_or_init(|| {
        let inherited = std::env::var(HANDOFF)
            .ok()
            .and_then(|value| serde_json::from_str(&value).ok())
            .unwrap_or_default();
        Mutex::new(inherited)
    })
}

/// Consume private warning state inherited across a sandbox re-exec, once at startup.
///
/// # Safety
/// Call from the executable entry point before spawning any threads. Removing an
/// environment variable is unsafe when other threads may access the environment.
pub unsafe fn consume_startup_warnings() {
    static CONSUMED: std::sync::Once = std::sync::Once::new();
    CONSUMED.call_once(|| {
        // Initialize deduplication before removing the inherited diagnostic state.
        // Library callers may still initialize it lazily, without mutating the env.
        let _ = emitted();
        // SAFETY: the caller guarantees single-threaded process startup.
        unsafe { std::env::remove_var(HANDOFF) };
    });
}

/// This controls diagnostics only; it never changes policy or enforcement.
pub(crate) fn first(key: String) -> bool {
    emitted()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(key)
}

#[cfg(target_os = "linux")]
pub(crate) fn handoff(command: &mut std::process::Command) {
    let keys = emitted().lock().unwrap_or_else(|error| error.into_inner());
    if !keys.is_empty()
        && let Ok(value) = serde_json::to_string(&*keys)
    {
        command.env(HANDOFF, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_warning_emission_never_mutates_environment() {
        const CHILD: &str = "FUIGO_WARNING_EMISSION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(first("late-warning".to_owned()));
            assert_eq!(std::env::var(HANDOFF).unwrap(), "[]");
            println!("WARNING_EMISSION_CHECKED");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "startup_warnings::tests::later_warning_emission_never_mutates_environment",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(HANDOFF, "[]")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("WARNING_EMISSION_CHECKED"));
    }

    #[test]
    fn executable_mains_consume_handoff_before_starting_threads() {
        for source in [
            include_str!("../../fuigo-pager-bin/src/main.rs"),
            include_str!("../../fuigo-workspace/src/bin/workspace_server.rs"),
        ] {
            let main = source.split("\nfn main()").nth(1).unwrap();
            let body = main.split_once('{').unwrap().1;
            let first_statement = body
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with("//"))
                .unwrap();
            assert_eq!(
                first_statement,
                "unsafe { fuigo_sandbox::consume_startup_warnings() };"
            );
        }
    }
}
