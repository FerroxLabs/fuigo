//! P19 / receipt R006: a search that could not start must be an error, never an empty result.
//!
//! Its own integration test file, and that is deliberate. `rg_path()` caches its
//! resolution in a process-wide `OnceLock`, so `RG_BIN_PATH` only takes effect for the
//! FIRST caller in a process. Putting this in an inline `mod tests` would make it depend
//! on being scheduled before every other test that greps — exactly the order-dependence
//! this strike keeps finding. One file, one process, no shared mutable state.
//!
//! The defect this pins: both grep implementations used to turn a `cmd.spawn()` failure
//! into `Ok` with empty stdout, zero matches and `exit_code: -1`. The tool call therefore
//! SUCCEEDED, and a model asking whether the codebase contains something was told "no"
//! when the truth was "the search never ran". Observed for real under a full-parallel test
//! run, where `ulimit -n` 1024 against 96 test threads produced EMFILE and 44 tests failed
//! with empty "successful" results.

use fuigo_tools::implementations::opencode::grep::{GrepInput, GrepTool};
use fuigo_tools::types::resources::{Cwd, Resources};

/// `rg_path()` is consulted once per process; set the override before anything else runs.
fn point_rg_at_a_binary_that_does_not_exist(dir: &std::path::Path) {
    let missing = dir.join("definitely-not-ripgrep");
    assert!(!missing.exists(), "the fixture must not exist");
    // SAFETY: single-threaded, first statement of the only test in this process.
    unsafe { std::env::set_var("RG_BIN_PATH", &missing) };
}

#[tokio::test]
async fn a_search_that_cannot_start_is_an_error_not_an_empty_result() {
    let tmp = tempfile::tempdir().unwrap();
    point_rg_at_a_binary_that_does_not_exist(tmp.path());

    std::fs::write(tmp.path().join("a.txt"), "hello world\n").unwrap();

    let mut resources = Resources::new();
    resources.insert(Cwd(tmp.path().to_path_buf()));

    let result = fuigo_tool_runtime::Tool::run(
        &GrepTool,
        fuigo_tools::types::tool_metadata::test_ctx(resources.into_shared()),
        GrepInput {
            pattern: "hello".to_string(),
            path: None,
            include: None,
        },
    )
    .await;

    let err = match result {
        Err(e) => e,
        Ok(output) => panic!(
            "a search that could not start reported SUCCESS: exit_code={}, {} matches, \
             stdout={:?}. That is indistinguishable from 'no matches' and is the whole defect.",
            output.exit_code,
            output.match_count,
            String::from_utf8_lossy(&output.stdout)
        ),
    };

    let message = err.to_string();
    assert!(
        message.contains("did not run"),
        "the error must say the search did not run, so a caller cannot read it as \
         'no results'; got: {message}"
    );
}
