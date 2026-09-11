//! Opt-in presentation only. Never remove tools, alter schemas or modify registry.
use fuigo_sampling_types::ToolSpec;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Entry {
    name: String,
    original: String,
    parameters: serde_json::Value,
    compact: String,
}

fn catalog() -> &'static [Entry] {
    static CATALOG: OnceLock<Vec<Entry>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("compact_tool_descriptions.json"))
            .expect("checked built-in description catalog")
    })
}

pub(crate) fn native_search_arguments(arguments: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(arguments).ok()
        .is_some_and(|v| v.get("scope").and_then(|v| v.as_str()) == Some("native"))
}

pub(crate) fn fingerprint(tool: &ToolSpec) -> String {
    blake3::hash(&serde_json::to_vec(tool).expect("serializable tool spec")).to_hex().to_string()
}

/// Session-owned presentation hints, not permission state. Reconciled with the
/// currently eligible projection for EVERY request. No cross-session globals.
#[derive(Debug, Clone, Default)]
pub(crate) struct NativePresentation {
    task: String,
    catalog: Vec<ToolSpec>,
    selected: std::collections::BTreeMap<String, String>,
    full: bool,
    enabled: bool,
    restored: bool,
    mode: Option<String>,
    checkpoint: Option<PresentationHints>,
}

/// Bounded, untrusted presentation hints. Never persisted authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationHints {
    mode: String,
    selected: std::collections::BTreeMap<String, String>,
}

const HINTS_FILE: &str = "tool-presentation.json";

pub(crate) async fn persist_hints(dir: &std::path::Path, hints: &PresentationHints) -> std::io::Result<()> {
    crate::session::storage::write_bytes_atomic_async(
        &dir.join(HINTS_FILE), serde_json::to_vec(hints).map_err(std::io::Error::other)?,
    ).await
}

/// The advertised list for an enabled projection: deferred schemas stay hidden unless selected (or `full`),
/// and `search_tool` names what is still hidden. Tool order and every visible schema are preserved.
fn render(
    tools: Vec<ToolSpec>, deferred: &std::collections::BTreeSet<String>, full: bool,
    selected: impl Fn(&ToolSpec) -> bool,
) -> Vec<ToolSpec> {
    let hidden: Vec<_> = tools.iter().filter(|t| deferred.contains(&t.name) && !selected(t)).map(|t| t.name.clone()).collect();
    let mut visible: Vec<_> = tools.into_iter().filter(|t| full || !deferred.contains(&t.name) || selected(t)).collect();
    if let Some(search) = visible.iter_mut().find(|t| t.name == "search_tool") {
        let base = search.description.get_or_insert_with(String::new);
        if !hidden.is_empty() && !full {
            base.push_str(" Native media tools are available via scope=native: ");
            // Names come only from eligible native registry, never descriptions
            // from external servers. Keep the discovery hint bounded.
            base.push_str(&hidden.iter().take(16).cloned().collect::<Vec<_>>().join(", "));
            base.push_str(". Search reveals schemas for the next request; call native tools directly, never through use_tool. Discovery is not approval.");
        }
    }
    visible
}

impl NativePresentation {
    pub(crate) fn load(dir: &std::path::Path) -> Self {
        use std::io::Read;
        let result = (|| -> std::io::Result<PresentationHints> {
            let file = std::fs::File::open(dir.join(HINTS_FILE))?;
            let mut bytes = Vec::new();
            file.take(8193).read_to_end(&mut bytes)?;
            if bytes.len() > 8192 { return Err(std::io::Error::other("presentation hints oversized")); }
            let hints: PresentationHints = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
            if !matches!(hints.mode.as_str(), "full" | "compact" | "adaptive") || hints.selected.len() > 8
                || hints.selected.iter().any(|(name, hash)| name.len() > 256 || hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit())) {
                return Err(std::io::Error::other("invalid presentation hints"));
            }
            Ok(hints)
        })();
        match result {
            Ok(hints) => Self { selected: hints.selected.clone(), mode: Some(hints.mode.clone()), restored: true, checkpoint: Some(hints), ..Default::default() },
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound { tracing::warn!(%error, "Ignoring invalid presentation hints; using configured default"); }
                Self::default()
            }
        }
    }

    pub(crate) fn mode(&self) -> String {
        // Explicit host configuration, including full/unknown, overrides saved hints.
        std::env::var("FUIGO_TOOL_PRESENTATION").ok().or_else(|| self.mode.clone()).unwrap_or_else(|| "full".into())
    }

    pub(crate) fn pending_checkpoint(&self) -> Option<PresentationHints> {
        let mode = self.mode();
        if self.checkpoint.is_none() && !matches!(mode.as_str(), "compact" | "adaptive") { return None; }
        let hints = PresentationHints {
            mode: if matches!(mode.as_str(), "compact" | "adaptive") { mode } else { "full".into() },
            selected: self.selected.iter().take(8).map(|(k,v)| (k.clone(),v.clone())).collect(),
        };
        (self.checkpoint.as_ref() != Some(&hints)).then_some(hints)
    }

    pub(crate) fn checkpoint_saved(&mut self, hints: PresentationHints) { self.checkpoint = Some(hints); }

    pub(crate) fn project(
        &mut self, task: &str, tools: Vec<ToolSpec>,
        deferred: &std::collections::BTreeSet<String>, enabled: bool,
    ) -> Vec<ToolSpec> {
        if self.task != task {
            self.task = task.to_owned();
            if !self.restored { self.selected.clear(); }
            self.restored = false;
            self.full = false;
        }
        self.enabled = enabled;
        self.catalog = tools.iter().filter(|t| deferred.contains(&t.name)).cloned().collect();
        self.selected.retain(|name, hash| self.catalog.iter().any(|t| &t.name == name && fingerprint(t) == *hash));
        if !enabled { return tools; }
        let selected = &self.selected;
        render(tools, deferred, self.full, |t| selected.contains_key(&t.name))
    }

    /// What [`Self::project`] would advertise from the current selection, without touching any state.
    /// Cache-aligned side calls use it only before this session actor has sent a main-turn request.
    pub(crate) fn preview(
        &self, tools: Vec<ToolSpec>,
        deferred: &std::collections::BTreeSet<String>, enabled: bool,
    ) -> Vec<ToolSpec> {
        if !enabled { return tools; }
        render(tools, deferred, self.full, |t| self.selected.get(&t.name).is_some_and(|hash| *hash == fingerprint(t)))
    }

    pub(crate) fn discover(&mut self, query: &str, limit: usize) -> serde_json::Value {
        if !self.enabled {
            return serde_json::json!({"results": [], "available": false, "note": "Native activation unavailable in current execution state"});
        }
        if query.len() > 256 || query.trim().is_empty() || limit == 0 {
            return serde_json::json!({"results": [], "note": "Use a nonempty query of at most256 bytes and positive limit"});
        }
        let query = query.to_lowercase();
        let words: Vec<_> = query.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
        let mut candidates: Vec<_> = self.catalog.iter().filter_map(|tool| {
            let text = format!("{} {}", tool.name, tool.description.as_deref().unwrap_or("")).to_lowercase();
            let score = if tool.name.eq_ignore_ascii_case(query.trim()) { usize::MAX }
                else { words.iter().filter(|word| text.contains(**word)).count() };
            (score > 0).then_some((score, tool))
        }).collect();
        candidates.sort_by(|a,b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
        let mut results = Vec::new();
        for (_,tool) in candidates.into_iter().take(limit.min(3)) {
            let row = serde_json::json!({"tool_name":tool.name,"description":tool.description,"input_schema":tool.parameters});
            let mut proposed = results.clone(); proposed.push(row.clone());
            if serde_json::to_vec(&proposed).unwrap().len() > 15000 {
                // Preserve full schema validity; next request exposes everything
                // rather than truncating the selected tool's argument contract.
                self.full = true;
                return serde_json::json!({"results":results,"note":"Schema result limit reached; full eligible tools will be advertised next request. No tools were executed."});
            }
            self.selected.insert(tool.name.clone(), fingerprint(tool));
            results.push(row);
        }
        if self.selected.len() >= 8 { self.full = true; }
        serde_json::json!({"results":results,"available":true,
            "note":"Selected native schemas will be advertised next request. Call original tool names directly; all ordinary approvals and limits still apply. No tool executed."})
    }
}

pub(crate) fn present(tools: &mut [ToolSpec], compact: bool) {
    if !compact { return; }
    for tool in tools {
        // Match the complete known schema and description, not merely a name.
        // Custom definitions and future schema revisions retain their full docs.
        if let Some(entry) = catalog().iter().find(|entry| {
            entry.name == tool.name && tool.description.as_deref() == Some(entry.original.as_str())
                && entry.parameters == tool.parameters
        }) {
            tool.description = Some(entry.compact.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn presentation_restart_reconciles_hints_and_child_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        let tools = native_tools();
        let hints = PresentationHints { mode: "adaptive".into(), selected: std::collections::BTreeMap::from([
            ("image_gen".into(), fingerprint(&tools[2]))
        ]) };
        persist_hints(dir.path(), &hints).await.unwrap();
        let deferred = std::collections::BTreeSet::from(["image_gen".into()]);
        let mut restored = NativePresentation::load(dir.path());
        assert_eq!(restored.mode.as_deref(), Some("adaptive"));
        assert_eq!(restored.project("resumed", tools.clone(), &deferred, true).len(), 3);
        // Compactions/model requests do not reset the running task's hints.
        for _ in 0..2 { assert_eq!(restored.project("resumed", tools.clone(), &deferred, true).len(), 3); }
        let mut child = NativePresentation::load(dir.path());
        assert_eq!(child.project("child", tools[..2].to_vec(), &deferred, true).len(), 2);
        assert!(child.selected.is_empty(), "restored hints cannot add child-ineligible tools");
        assert_eq!(restored.selected.len(), 1, "child reconciliation is private");
        let mut changed = tools.clone();
        changed[2].parameters["required"] = serde_json::json!(["different"]);
        let mut restarted = NativePresentation::load(dir.path());
        assert_eq!(restarted.project("resumed", changed, &deferred, true).len(), 2);
        assert!(restarted.selected.is_empty());
    }

    #[tokio::test]
    async fn invalid_presentation_hints_never_restore_selection() {
        let dir = tempfile::tempdir().unwrap();
        let hints = PresentationHints { mode: "adaptive".into(), selected: std::collections::BTreeMap::from([
            ("image_gen".into(), "not-a-fingerprint".into())
        ]) };
        persist_hints(dir.path(), &hints).await.unwrap();
        assert!(NativePresentation::load(dir.path()).selected.is_empty());
        std::fs::write(dir.path().join(HINTS_FILE), vec![b'x'; 8193]).unwrap();
        assert!(NativePresentation::load(dir.path()).selected.is_empty());
    }

    fn native_tools() -> Vec<ToolSpec> {
        vec![ToolSpec {name:"search_tool".into(),description:Some("Search MCP".into()),parameters:serde_json::json!({})},
             ToolSpec {name:"read_file".into(),description:Some("Read".into()),parameters:serde_json::json!({})},
             ToolSpec {name:"image_gen".into(),description:Some("Generate image artwork".into()),parameters:serde_json::json!({"type":"object","required":["prompt"]})}]
    }

    #[test]
    fn native_discovery_activates_without_execution_and_preserves_schema() {
        let mut state=NativePresentation::default();
        let all=native_tools();
        let deferred=std::collections::BTreeSet::from(["image_gen".into()]);
        let visible=state.project("task",all.clone(),&deferred,true);
        assert_eq!(visible.len(),2);
        assert!(visible[0].description.as_ref().unwrap().contains("image_gen"));
        let found=state.discover("image_gen",3);
        assert_eq!(found["results"][0]["input_schema"],all[2].parameters);
        let next=state.project("task",all.clone(),&deferred,true);
        assert_eq!(next.len(),3);
        assert_eq!(next[2].parameters,all[2].parameters);
        assert_eq!(state.project("different-task",all,&deferred,true).len(),2);
    }

    #[test]
    fn preview_matches_project_without_mutating_state() {
        let json = |tools: &Vec<ToolSpec>| serde_json::to_string(tools).unwrap();
        let deferred=std::collections::BTreeSet::from(["image_gen".into()]);
        let mut state=NativePresentation::default();
        let hidden=state.preview(native_tools(),&deferred,true);
        assert_eq!(hidden.len(),2);
        assert_eq!(json(&hidden), json(&state.clone().project("task",native_tools(),&deferred,true)));
        state.project("task",native_tools(),&deferred,true);
        state.discover("image_gen",3);
        let before=format!("{state:?}");
        let revealed=state.preview(native_tools(),&deferred,true);
        assert_eq!(format!("{state:?}"),before,"preview must not mutate presentation state");
        assert_eq!(revealed.len(),3);
        assert_eq!(json(&revealed), json(&state.clone().project("task",native_tools(),&deferred,true)));
        let mut changed=native_tools(); changed[2].parameters["required"]=serde_json::json!(["different"]);
        let stale=state.preview(changed.clone(),&deferred,true);
        assert_eq!(stale.len(),2,"a stale selection never reveals a changed schema");
        assert_eq!(json(&stale), json(&state.clone().project("task",changed,&deferred,true)));
        assert_eq!(json(&state.preview(native_tools(),&deferred,false)), json(&native_tools()));
    }

    #[test]
    fn native_discovery_revocation_finalization_and_session_isolation() {
        let mut state=NativePresentation::default();
        let deferred=std::collections::BTreeSet::from(["image_gen".into()]);
        state.project("task",native_tools(),&deferred,true);
        state.discover("image",3);
        let mut changed=native_tools(); changed[2].parameters["required"]=serde_json::json!(["prompt","approval"]);
        assert_eq!(state.project("task",changed,&deferred,true).len(),2,"schema revision invalidates activation");
        state.project("task",native_tools()[..2].to_vec(),&deferred,true);
        assert_eq!(state.discover("image",3)["results"],serde_json::json!([]));
        state.project("task",native_tools(),&deferred,false);
        assert_eq!(state.discover("image",3)["available"],false);
        assert!(NativePresentation::default().selected.is_empty());
    }

    #[test]
    fn native_discovery_bounds_do_not_truncate_schema() {
        let mut state=NativePresentation::default();
        let mut tools=native_tools();
        tools[2].parameters["description"]=serde_json::json!("x".repeat(17000));
        let deferred=std::collections::BTreeSet::from(["image_gen".into()]);
        state.project("task",tools.clone(),&deferred,true);
        let result=state.discover("image",3);
        assert!(result.to_string().len()<16000);
        assert!(state.full);
        assert_eq!(state.project("task",tools.clone(),&deferred,true)[2].parameters,tools[2].parameters);
    }

    fn fixture(entry: &Entry) -> ToolSpec {
        ToolSpec { name: entry.name.clone(), description: Some(entry.original.clone()), parameters: entry.parameters.clone() }
    }

    #[test]
    fn compact_presentation_preserves_every_structural_schema() {
        let mut tools: Vec<_> = catalog().iter().map(fixture).collect();
        let before = tools.clone();
        present(&mut tools, true);
        assert_eq!(tools.len(), before.len());
        for (after, old) in tools.iter().zip(&before) {
            assert_eq!(after.name, old.name);
            assert_eq!(after.parameters, old.parameters);
            assert!(after.description.as_ref().unwrap().len() < old.description.as_ref().unwrap().len());
        }
        let first = serde_json::to_value(&tools).unwrap();
        present(&mut tools, true);
        assert_eq!(serde_json::to_value(tools).unwrap(), first, "idempotent mirrored presentation");
    }

    #[test]
    fn full_mode_and_custom_or_changed_definitions_are_untouched() {
        let entry = &catalog()[0];
        let mut full = vec![fixture(entry)];
        let before = serde_json::to_value(&full).unwrap();
        present(&mut full, false);
        assert_eq!(serde_json::to_value(full).unwrap(), before);
        let mut changed = vec![fixture(entry), fixture(entry), fixture(entry)];
        changed[0].description = Some("custom policy: require extra approval".into());
        changed[1].parameters["additionalProperties"] = serde_json::json!(false);
        changed[2].name = "external__run_terminal_command".into();
        let before = serde_json::to_value(&changed).unwrap();
        present(&mut changed, true);
        assert_eq!(serde_json::to_value(changed).unwrap(), before);
    }

    #[test]
    fn compact_catalog_preserves_critical_usage_constraints() {
        let get = |name| catalog().iter().find(|entry| entry.name == name).unwrap().compact.as_str();
        for text in ["SIGTERM", "SIGKILL", "setsid/nohup", "timeout 0", "40000", "full-log", "do not poll"] {
            assert!(get("run_terminal_command").contains(text), "{text}");
        }
        for text in ["exact", "indentation", "uniquely", "replace_all"] {
            assert!(get("search_replace").contains(text), "{text}");
        }
        for text in ["immutable source/args", "restart is terminal", "higher", "not all branches"] {
            assert!(get("workflow").contains(text), "{text}");
        }
    }
}
