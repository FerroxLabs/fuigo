//! One native child lifecycle using the existing ACP/mock harness, not a perf sweep.
#[allow(dead_code)]
mod acp_harness;
#[path = "perf_harness/mod.rs"]
mod perf_harness;
#[path = "subagent_sweep_support/mod.rs"]
mod support;

fn execution_records(dir: &std::path::Path) -> Vec<serde_json::Value> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            records.extend(execution_records(&entry.path()));
        } else if entry.file_name().to_string_lossy().starts_with("execution-")
            && entry.path().extension().is_some_and(|e| e == "json") {
            records.push(serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap());
        }
    }
    records
}

#[test]
fn native_child_completes_with_durable_parent_grant() {
    // One test/binary; finite local-only fixture budget, set before threads.
    unsafe {
        std::env::set_var("FUIGO_MAX_MODEL_CALLS", "20");
        std::env::set_var("FUIGO_SWEEP_DEADLINE_S", "60");
        std::env::set_var("FUIGO_TURN_SUMMARY", "false");
    }
    let env = support::sweep_env_init();
    let outcome = support::burst_on_fresh_mock(&env, 1, "none");
    assert_eq!(outcome.rows.len(), 1, "one real native child must be observed");
    assert_eq!(outcome.failures, 0, "native child did not finish successfully");
    let home = std::path::PathBuf::from(std::env::var_os("FUIGO_HOME").unwrap());
    let records = execution_records(&home);
    assert!(records.iter().any(|record| record["grants"].as_object().is_some_and(|grants|
        grants.values().any(|grant| grant["calls"].as_u64().is_some_and(|calls| calls > 0)))),
        "child inference must debit a durable parent grant");
}
