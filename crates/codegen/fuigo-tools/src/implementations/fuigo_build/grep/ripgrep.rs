use std::path::PathBuf;
use std::sync::OnceLock;
use fuigo_tool_runtime::{ToolError, ToolErrorKind};

#[cfg(bundle_rg)]
const RG_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/bundle-rg/rg-",
    env!("FUIGO_TOOLS_RG_VER"),
    "-",
    env!("FUIGO_TOOLS_RG_TARGET"),
    ".bin.zst"
));

#[cfg(bundle_rg)]
fn resolve_bundled_rg() -> Result<Option<PathBuf>, crate::util::vendor::InstallError> {
    crate::util::vendor::resolve(
        concat!(
            "rg-",
            env!("FUIGO_TOOLS_RG_VER"),
            "-",
            env!("FUIGO_TOOLS_RG_TARGET")
        ),
        RG_BYTES,
        env!("FUIGO_TOOLS_RG_SHA256"),
    )
}

/// Resolve `resolve` once, caching only a SUCCESS in `cell`.
///
/// A failed resolution is returned to the caller but never stored, so the next
/// call retries. (Caching the `Result` in a `OnceLock` made one transient
/// failure permanent for the whole process.) Concurrent first callers may each
/// run `resolve`; the first success wins and everyone returns that value.
fn resolve_cached<F>(cell: &OnceLock<PathBuf>, resolve: F) -> Result<PathBuf, String>
where
    F: FnOnce() -> Result<PathBuf, String>,
{
    if let Some(found) = cell.get() {
        return Ok(found.clone());
    }
    let found = resolve()?;
    Ok(cell.get_or_init(|| found).clone())
}

fn resolve_rg_uncached() -> Result<PathBuf, String> {
    #[cfg(bundle_rg)]
    {
        resolve_bundled_rg()
            .map(|found| found.unwrap_or_else(|| PathBuf::from("rg")))
            .map_err(|e| e.to_string())
    }
    #[cfg(not(bundle_rg))]
    {
        Ok(rg_from_path_or_runfiles())
    }
}

pub fn rg_path() -> Result<PathBuf, ToolError> {
    static RG_EXEC: OnceLock<PathBuf> = OnceLock::new();
    resolve_cached(&RG_EXEC, resolve_rg_uncached)
        .map_err(|msg| ToolError::new(ToolErrorKind::Execution, msg))
}

#[cfg(not(bundle_rg))]
fn rg_from_path_or_runfiles() -> PathBuf {
    if let Ok(p) = std::env::var("RG_BIN_PATH") {
        return PathBuf::from(p);
    }
    if let Ok(rf) = std::env::var("RUNFILES_DIR")
        && let Ok(entries) = std::fs::read_dir(PathBuf::from(rf))
    {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .contains("ripgrep_hermetic")
            {
                for sub in ["amd64/rg", "arm64/rg", "rg"] {
                    let candidate = entry.path().join(sub);
                    if candidate.exists() {
                        return candidate;
                    }
                }
            }
        }
    }
    PathBuf::from("rg")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn failed_resolution_is_retried_and_success_is_cached() {
        let cell = OnceLock::new();
        let calls = Cell::new(0u32);

        let first = resolve_cached(&cell, || {
            calls.set(calls.get() + 1);
            Err("transient".to_string())
        });
        assert_eq!(first, Err("transient".to_string()));
        assert!(cell.get().is_none(), "an Err must not be cached");

        let second = resolve_cached(&cell, || {
            calls.set(calls.get() + 1);
            Ok(PathBuf::from("/x/rg"))
        });
        assert_eq!(second, Ok(PathBuf::from("/x/rg")));
        assert_eq!(calls.get(), 2, "the failure must have been retried");

        let third = resolve_cached(&cell, || {
            calls.set(calls.get() + 1);
            Err("must not run".to_string())
        });
        assert_eq!(third, Ok(PathBuf::from("/x/rg")));
        assert_eq!(calls.get(), 2, "a cached success must not re-resolve");
    }
}
