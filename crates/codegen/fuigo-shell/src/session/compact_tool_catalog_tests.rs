//! Staleness checks for `compact_tool_descriptions.json`: the compact
//! presentation only swaps a description when the catalog's `original` and
//! `parameters` match the advertised tool byte-for-byte, so a catalog entry
//! that drifts from the tool source silently disables compaction for that
//! tool. These tests pin the two `read_file` entries (the ones carrying the
//! per-call byte cap) to the live tool source; the ACP harness test
//! `openai_codex_harness_acp` checks the advertised read_file definitions
//! (description and `files` parameter) against the catalog end to end.
use fuigo_tools::implementations::codex::CodexReadFileTool;
use fuigo_tools::implementations::fuigo_build::read_file::{MAX_READ_BYTES, ReadFileTool};
use fuigo_tools::types::context::TruncationConfig;
use fuigo_tools::types::template_renderer::TemplateRenderer;
use fuigo_tools::types::tool_metadata::ToolMetadata;
use fuigo_tools::types::tool::ToolKind;
use std::collections::HashMap;

#[derive(serde::Deserialize)]
struct Entry {
    name: String,
    original: String,
    parameters: serde_json::Value,
    compact: String,
}

fn catalog() -> Vec<Entry> {
    serde_json::from_str(include_str!("compact_tool_descriptions.json")).expect("valid catalog")
}

/// The two `read_file` entries: codex (file_path) first, fuigo-build (target_file) second.
fn read_file_entries() -> (Entry, Entry) {
    let mut entries: Vec<Entry> = catalog().into_iter().filter(|e| e.name == "read_file").collect();
    assert_eq!(entries.len(), 2, "one codex and one fuigo-build read_file entry");
    entries.sort_by_key(|e| e.parameters["properties"].get("target_file").is_some());
    let fuigo_build = entries.pop().unwrap();
    let codex = entries.pop().unwrap();
    assert!(codex.parameters["properties"].get("file_path").is_some());
    (codex, fuigo_build)
}

/// Every `N KB` figure in `text`.
fn kb_figures(text: &str) -> Vec<usize> {
    text.match_indices(" KB")
        .filter_map(|(i, _)| text[..i].rsplit(|c: char| !c.is_ascii_digit()).next()?.parse().ok())
        .collect()
}

fn files_param_description(parameters: &serde_json::Value) -> &str {
    parameters["properties"]["files"]["description"].as_str().expect("files param description")
}

#[test]
fn read_file_catalog_entries_state_the_live_per_call_cap() {
    let cap_kb = MAX_READ_BYTES / 1024;
    assert_eq!(cap_kb, 40, "per-call read budget is ~10K tokens (40 KB); update this test with the cap");
    let (codex, fuigo_build) = read_file_entries();
    for entry in [&codex, &fuigo_build] {
        for (label, text) in [
            ("original", entry.original.as_str()),
            ("compact", entry.compact.as_str()),
            ("files param", files_param_description(&entry.parameters)),
        ] {
            let figures = kb_figures(text);
            assert!(
                !figures.is_empty() && figures.iter().all(|kb| *kb == cap_kb),
                "read_file {label} must state the {cap_kb} KB per-call cap and no other KB figure, got {figures:?}: {text}"
            );
        }
        assert!(
            entry.original.contains("several paths in one call") && entry.original.contains("whole files by default"),
            "read_file original must keep the multi-path and whole-file wording: {}",
            entry.original
        );
    }
}

#[test]
fn codex_read_file_catalog_entry_matches_tool_source() {
    let (codex, _) = read_file_entries();
    let live = fuigo_tools::types::template_renderer::strip_template_markers(CodexReadFileTool.description_template());
    assert_eq!(codex.original, live, "codex read_file catalog `original` is stale; regenerate the catalog");
}

#[test]
fn fuigo_build_read_file_catalog_entry_matches_tool_source() {
    let (_, fuigo_build) = read_file_entries();
    // The registry renders `${{ params.read.target_file }}` with the client's
    // parameter names (canonical here) and `{max_lines_read}` from the default
    // truncation config, exactly as the headless dump that fed the catalog.
    let renderer = TemplateRenderer::new(
        HashMap::from([(ToolKind::Read, "read_file".to_string())]),
        HashMap::from([(ToolKind::Read, HashMap::from([("target_file".to_string(), "target_file".to_string())]))]),
    );
    let rendered = renderer.render(ReadFileTool.description_template()).expect("renders");
    let live = TruncationConfig::default().interpolate_description(&rendered, "read_file", 0, 600_000);
    assert_eq!(fuigo_build.original, live, "fuigo-build read_file catalog `original` is stale; regenerate the catalog");
}
