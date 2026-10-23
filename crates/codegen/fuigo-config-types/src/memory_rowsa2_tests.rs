//! ROWS-A2 (1.0.32) 51.6: memory is one on/off setting, `[memory] enabled`, that the command-line flag and the
//! environment can override.

use super::*;

fn config(source: &str) -> toml::Value {
    toml::from_str(source).expect("test config parses")
}

#[test]
fn memory_is_on_by_default_and_one_setting_turns_it_off() {
    assert!(
        std::env::var_os("FUIGO_MEMORY").is_none(),
        "this test needs FUIGO_MEMORY unexported"
    );
    assert!(MemoryConfig::resolve_with_override(None, &config(""), None).enabled, "on by default");
    assert!(
        !MemoryConfig::resolve_with_override(None, &config("[memory]\nenabled = false"), None).enabled,
        "[memory] enabled = false turns it off"
    );
    assert!(
        MemoryConfig::resolve_with_override(None, &config("[memory]\nenabled = true"), None).enabled
    );
    // Tuning other memory settings does not switch it off.
    assert!(
        MemoryConfig::resolve_with_override(None, &config("[memory.search]\nmax_results = 3"), None).enabled
    );
}

#[test]
fn the_command_line_beats_the_file_in_both_directions() {
    assert!(
        std::env::var_os("FUIGO_MEMORY").is_none(),
        "this test needs FUIGO_MEMORY unexported"
    );
    let off = config("[memory]\nenabled = false");
    assert!(MemoryConfig::resolve_with_override(Some(true), &off, None).enabled);
    assert!(!MemoryConfig::resolve_with_override(Some(false), &config(""), None).enabled);
}
