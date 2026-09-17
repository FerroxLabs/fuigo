//! U062: a row-scoped extensions-modal key pressed where the selection has no target must say
//! which row to select instead of resolving to a silent no-op.
//!
//! Every verb family that can land on a header row is covered: the Plugins group header
//! (`Space` / `u` / `x`), the Marketplace source header (`i` / `u` / `d`), the Marketplace plugin
//! row for the source-scoped `x`, and the Hooks / Skills group headers (`Space`).
//!
//! These drive the real key pipeline and re-render between presses, because the live input path
//! reads the renderer-published `entry_*` vectors.

use crate::app::app_view::InputOutcome;
use crate::views::extensions_modal::{
    ExtensionsModalState, ExtensionsTab, ModalMessage, TabDataState,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn render_modal(agent: &mut super::AgentView) {
    let area = ratatui::layout::Rect::new(0, 0, 100, 40);
    let mut buf = ratatui::buffer::Buffer::empty(area);
    let state = agent
        .extensions_modal
        .as_mut()
        .unwrap_or_else(|| panic!("extensions modal must be open"));
    crate::views::extensions_modal::render_extensions_modal(&mut buf, area, state, None, false, 0);
}

/// Pipeline harness: entries are built by the real renderer between keys. Vim mode is pinned off
/// so the picker takes the non-vim path regardless of the developer's on-disk `[ui].vim_mode`.
fn pipeline_agent(modal: ExtensionsModalState) -> super::AgentView {
    crate::appearance::cache::set_vim_mode(false);
    let mut agent = super::test_fixtures::make_agent();
    agent.extensions_modal = Some(modal);
    render_modal(&mut agent);
    agent
}

fn press(agent: &mut super::AgentView, code: KeyCode) -> InputOutcome {
    let outcome = agent.handle_extensions_modal_key(&key(code));
    render_modal(agent);
    outcome
}

fn state_of(agent: &super::AgentView) -> &ExtensionsModalState {
    agent
        .extensions_modal
        .as_ref()
        .unwrap_or_else(|| panic!("extensions modal must stay open"))
}

fn plugin_info(name: &str, enabled: bool) -> fuigo_hooks_plugins_types::PluginInfo {
    fuigo_hooks_plugins_types::PluginInfo {
        name: name.into(),
        id: format!("user/abcd1234/{name}"),
        root: "/tmp/p".into(),
        scope: fuigo_hooks_plugins_types::PluginScope::User,
        trusted: true,
        enabled,
        version: None,
        description: None,
        skill_count: 0,
        skill_names: Vec::new(),
        agent_count: 0,
        agent_names: Vec::new(),
        hook_status: fuigo_hooks_plugins_types::HookStatus::None,
        hook_count: 0,
        mcp_server_count: 0,
        mcp_status: fuigo_hooks_plugins_types::McpStatus::None,
        marketplace_source: None,
        origin: None,
        conflict: None,
    }
}

fn hook_info(name: &str, source_dir: &str) -> fuigo_hooks_plugins_types::HookInfo {
    fuigo_hooks_plugins_types::HookInfo {
        name: name.into(),
        event: fuigo_hooks_plugins_types::HookEvent::PreToolUse,
        handler_type: fuigo_hooks_plugins_types::HookHandlerType::Command,
        matcher: None,
        command: None,
        url: None,
        timeout_ms: 0,
        source_dir: source_dir.into(),
        disabled: false,
        pinned: false,
        removable: false,
    }
}

fn marketplace_plugin(
    name: &str,
    relative_path: &str,
) -> fuigo_hooks_plugins_types::MarketplacePluginEntry {
    fuigo_hooks_plugins_types::MarketplacePluginEntry {
        name: name.into(),
        version: Some("2.0.0".into()),
        description: None,
        category: None,
        author: None,
        tags: Vec::new(),
        keywords: Vec::new(),
        domains: Vec::new(),
        homepage: None,
        relative_path: relative_path.into(),
        skill_count: 0,
        has_hooks: false,
        has_agents: false,
        has_mcp: false,
        install_status: "update_available".into(),
        installed_version: Some("1.0.0".into()),
        components: None,
        remote_url: None,
        remote_ref: None,
        remote_sha: None,
        remote_subdir: None,
    }
}

fn marketplace_source(
    plugins: Vec<fuigo_hooks_plugins_types::MarketplacePluginEntry>,
    error: Option<&str>,
) -> fuigo_hooks_plugins_types::MarketplaceScanResult {
    fuigo_hooks_plugins_types::MarketplaceScanResult {
        source_name: "qa-source".into(),
        source_kind: "git".into(),
        source_url_or_path: "https://example.com/plugins.git".into(),
        plugins,
        error: error.map(Into::into),
    }
}

fn marketplace_modal(
    sources: Vec<fuigo_hooks_plugins_types::MarketplaceScanResult>,
) -> ExtensionsModalState {
    let mut modal = ExtensionsModalState::new(ExtensionsTab::Marketplace);
    modal.marketplace_data =
        TabDataState::Loaded(fuigo_hooks_plugins_types::MarketplaceListResponse { sources });
    modal
}

fn marketplace_modal_agent() -> super::AgentView {
    pipeline_agent(marketplace_modal(vec![marketplace_source(
        vec![
            marketplace_plugin("test-plugin", "plugins/test-plugin"),
            marketplace_plugin("other-plugin", "plugins/other-plugin"),
        ],
        None,
    )]))
}

fn plugins_modal_agent() -> super::AgentView {
    let mut modal = ExtensionsModalState::new(ExtensionsTab::Plugins);
    modal.plugins_data = TabDataState::Loaded(fuigo_hooks_plugins_types::PluginsListResponse {
        plugins: vec![plugin_info("qa-plugin-local", true)],
    });
    pipeline_agent(modal)
}

fn assert_hint(agent: &super::AgentView, expected: &str, label: &str) {
    let state = state_of(agent);
    assert_eq!(
        state.modal_message,
        Some(ModalMessage::Info(expected.to_string())),
        "{label}: expected explicit feedback naming the action"
    );
    assert_eq!(state.pending_action, None, "{label}");
    assert_eq!(
        state.picker_state.query(),
        "",
        "{label}: the action key must not become search input"
    );
}

/// Plugins group header + a row-scoped key: a group spans repos, so the key posts the row hint
/// naming the action instead of guessing a plugin, and never touches the search field.
#[test]
fn plugins_group_header_row_actions_prompt_for_plugin_row() {
    for (key_char, verb) in [(' ', "enable/disable"), ('u', "update"), ('x', "uninstall")] {
        let mut agent = plugins_modal_agent();
        // Selection starts on the group header (first selectable row).
        assert_eq!(
            state_of(&agent).selected_data_index(),
            None,
            "{key_char:?}: selection must start on the group header"
        );
        let outcome = press(&mut agent, KeyCode::Char(key_char));
        assert!(
            matches!(outcome, InputOutcome::Changed),
            "{key_char:?}: no dispatch from a header row, got {outcome:?}"
        );
        assert_hint(&agent, &format!("Select a plugin row to {verb}."), &format!("{key_char:?}"));
    }
}

/// Marketplace source row + a per-plugin key: the key stays bound while the footer hides it, so a
/// press posts the row hint naming the action instead of a silent no-op.
#[test]
fn marketplace_source_row_plugin_actions_prompt_for_plugin_row() {
    for (key_char, verb) in [('i', "install"), ('u', "update"), ('d', "uninstall")] {
        let mut agent = marketplace_modal_agent();
        // Selection starts on the source header row.
        let outcome = press(&mut agent, KeyCode::Char(key_char));
        assert!(
            matches!(outcome, InputOutcome::Changed),
            "{key_char}: no dispatch from a source row"
        );
        assert_hint(&agent, &format!("Select a plugin row to {verb}."), &key_char.to_string());
    }
}

/// Marketplace plugin row + `x`: removal is a source verb, so the row hint says so instead of
/// prompting to remove the parent source out from under the plugin.
#[test]
fn marketplace_plugin_row_remove_source_prompts_for_source_row() {
    let mut agent = marketplace_modal_agent();
    press(&mut agent, KeyCode::Down); // source header -> first plugin row
    assert!(
        state_of(&agent).selected_data_index().is_some(),
        "Down must land on a plugin row"
    );
    let outcome = press(&mut agent, KeyCode::Char('x'));
    assert!(matches!(outcome, InputOutcome::Changed));
    assert_hint(&agent, "Select a source row to remove source.", "x");
}

/// Hooks and Skills group headers advertise Space in the footer too, so they post the same row
/// hint as the Plugins / Marketplace headers instead of a silent no-op.
#[test]
fn hook_and_skill_toggle_on_group_header_posts_row_hint() {
    let mut hooks = ExtensionsModalState::new(ExtensionsTab::Hooks);
    hooks.hooks_data = TabDataState::Loaded(fuigo_hooks_plugins_types::HooksListResponse {
        hooks: vec![hook_info("src/hook-a", "/tmp/hooks")],
        project_trusted: true,
        load_errors: Vec::new(),
    });
    let mut skills = ExtensionsModalState::new(ExtensionsTab::Skills);
    skills.skills_data = TabDataState::Loaded(vec![
        fuigo_tools::implementations::skills::types::SkillInfo {
            name: "my-skill".into(),
            enabled: true,
            ..Default::default()
        },
    ]);

    for (noun, modal) in [("hook", hooks), ("skill", skills)] {
        let mut agent = pipeline_agent(modal);
        assert_eq!(
            state_of(&agent).selected_data_index(),
            None,
            "{noun}: selection must start on the group header"
        );
        let outcome = press(&mut agent, KeyCode::Char(' '));
        assert!(
            matches!(outcome, InputOutcome::Changed),
            "{noun}: header row must not dispatch a toggle, got {outcome:?}"
        );
        assert_hint(&agent, &format!("Select a {noun} row to enable/disable."), noun);
    }
}

/// With no row to point at (nothing installed, a filter hiding everything, no sources, or a source
/// header whose scan failed or found nothing) a row-scoped key stays silent instead of posting a
/// hint that swallows the next keypress.
#[test]
fn row_scoped_keys_stay_silent_when_the_list_has_no_rows() {
    let mut no_plugins = ExtensionsModalState::new(ExtensionsTab::Plugins);
    no_plugins.plugins_data =
        TabDataState::Loaded(fuigo_hooks_plugins_types::PluginsListResponse { plugins: vec![] });
    let mut all_filtered_out = ExtensionsModalState::new(ExtensionsTab::Plugins);
    all_filtered_out.plugins_data =
        TabDataState::Loaded(fuigo_hooks_plugins_types::PluginsListResponse {
            plugins: vec![plugin_info("disabled-plugin", false)],
        });
    all_filtered_out.plugins_filter = crate::views::extensions_modal::StatusFilter::Enabled;

    for (label, modal, key_char) in [
        ("no plugins", no_plugins, 'u'),
        ("all filtered out", all_filtered_out, 'u'),
        ("no sources", marketplace_modal(vec![]), 'i'),
        (
            "errored source header",
            marketplace_modal(vec![marketplace_source(vec![], Some("clone failed"))]),
            'i',
        ),
        (
            "empty source header",
            marketplace_modal(vec![marketplace_source(vec![], None)]),
            'i',
        ),
    ] {
        let mut agent = pipeline_agent(modal);
        let outcome = press(&mut agent, KeyCode::Char(key_char));
        assert!(
            matches!(outcome, InputOutcome::Changed),
            "{label}: got {outcome:?}"
        );
        let state = state_of(&agent);
        assert_eq!(state.modal_message, None, "{label}: no row to point at");
        assert_eq!(state.pending_action, None, "{label}");
        assert_eq!(state.picker_state.query(), "", "{label}");
    }
}
