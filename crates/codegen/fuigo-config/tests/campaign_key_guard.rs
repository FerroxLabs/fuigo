//! Classification guard for campaign patches.
//!
//! A campaign patch is first confined to the campaign allowlist (`CAMPAIGN_ALLOW_PATHS`); this test is the second layer
//! behind it. It checks that no key which may set where a credential or the user's content goes, or what the client
//! executes, is left unclassified. This test walks every key of the config schema (the `Deserialize`
//! structs reachable from `Config` and `ConfigModelOverride`, found by scanning the source) and requires every key
//! whose last segment looks like a destination, credential or execution setting to be CLASSIFIED: stripped from
//! campaign patches (`CAMPAIGN_STRIP_KEYS`, `CAMPAIGN_STRIP_PATHS`, the MCP secret fields, or the patch-wide strip
//! lists) or listed in `CAMPAIGN_ALLOWED` below with a reason (those are keys the denylist does not strip and the
//! allowlist drops anyway, apart from the allowed `mcp_servers` fields). A new matching key fails here until its author decides.
//!
//! Same style as `fuigo-extra-ca/tests/identity_body_guard.rs`: a source scan, so a field added anywhere is seen.

use fuigo_config::config_override::{
    CAMPAIGN_ALLOW_PATHS, CAMPAIGN_MCP_SECRET_FIELDS, CAMPAIGN_STRIP_KEYS, CAMPAIGN_STRIP_PATHS, PATCH_STRIP_KEYS,
    PATCH_STRIP_PATHS,
};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Keys that match the pattern and are NOT stripped by the denylist, each with why that is safe. A campaign cannot set
/// most of them: the allowlist (`CAMPAIGN_ALLOW_PATHS`) drops them before the merge, so this is the second layer. Only
/// the `mcp_servers.*` fields below and `model.*.name` / `model.*.context_window` are reachable by a campaign.
const CAMPAIGN_ALLOWED: &[(&str, &str)] = &[
    ("announcements.cta.url", "a link shown in an announcement banner, opened only by the user; nothing is sent to it"),
    ("compaction.memory_flush.soft_threshold_tokens", "a token count, not a credential"),
    ("doom_loop_recovery.window_tokens", "a token count, not a credential"),
    ("features.codebase_indexing", "a feature toggle (`base` is part of `codebase`)"),
    ("mcp_servers.*.command", "a campaign may ADD a server; its command is a literal (never env-expanded) and an existing server is untouchable"),
    ("mcp_servers.*.url", "a campaign may ADD a server; its url is a literal (never env-expanded) and carries no credential field"),
    ("mcp_servers.*.urlTemplate", "alias of `url`: same reasoning"),
    ("mcp_servers.*.url_template", "alias of `url`: same reasoning"),
    ("mcp_servers.*.expose_image_base64", "a display toggle (`base` is part of `base64`)"),
    ("mcp_servers.*.oauth_client_id", "a public OAuth client id; the flow needs the user's interactive consent and sends no stored credential"),
    ("mcp_servers.*.oauth_scopes", "scope names for the interactive OAuth flow; no credential"),
    ("model.*.auth_scheme", "how the user's own key is presented to the user's own host (host and key are stripped)"),
    ("model.*.compaction_at_tokens", "a token count, not a credential"),
    ("model.*.max_completion_tokens", "a token count, not a credential"),
    ("models.max_completion_tokens", "a token count, not a credential"),
    ("prompt_suggestions.max_output_tokens", "a token count, not a credential"),
    ("session.load_envrc", "a toggle that evaluates the workspace `.envrc`; folder trust is the boundary for that code, as for the user's own setting"),
    ("toolset.web_search.auth_scheme", "header scheme only; host, key and headers of this table are stripped"),
    ("toolset.web_search.compaction_at_tokens", "a token count, not a credential"),
    ("toolset.web_search.doom_loop_recovery.window_tokens", "a token count, not a credential"),
    ("toolset.web_search.max_completion_tokens", "a token count, not a credential"),
    ("ui.voice_keybind_enabled", "a keybinding toggle (`key` is part of `keybind`)"),
    ("harness.block_for_upload", "whether exit waits for an upload already enabled elsewhere; enables nothing"),
    ("harness.upload_flush_timeout_secs", "how long exit waits for that upload; enables nothing"),
];

const PATTERNS: &[&str] = &[
    "url", "uri", "endpoint", "host", "base", "proxy", "header", "token", "key", "secret", "password", "credential",
    "auth", "cert", "env", "cmd", "command", "prefix", "exporter", "socket",
    // Where code, instructions or updates are loaded from.
    "registry", "installer", "dir", "paths",
    // What loads or runs, what leaves the machine, and how it is sent.
    "definition", "discover", "sources", "upload", "transport",
];

fn matches_pattern(last: &str) -> bool {
    let l = last.to_ascii_lowercase();
    PATTERNS.iter().any(|p| l.contains(p)) || l.ends_with("_bin") || l.ends_with("_path")
}

// ---- a small scanner for `Deserialize` structs (and enums, when flattened) -------------------------------------

struct Field {
    names: Vec<String>,
    ty: String,
    flatten: bool,
}

struct Def {
    is_enum: bool,
    fields: Vec<Field>,
}

fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let bytes = line.as_bytes();
        let mut cut = line.len();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] == b'/' && bytes[i + 1] == b'/' && (i == 0 || bytes[i - 1] != b':') {
                cut = i;
                break;
            }
            i += 1;
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

fn matching_brace(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    for c in body.chars() {
        match c {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if c == ',' && depth == 0 {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    parts
}

fn words(s: &str) -> Vec<&str> {
    s.split(|c: char| !(c.is_alphanumeric() || c == '_')).filter(|w| !w.is_empty()).collect()
}

fn quoted_after<'a>(attr: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("{key} = \"");
    let mut out = Vec::new();
    let mut rest = attr;
    while let Some(i) = rest.find(&needle) {
        let after = &rest[i + needle.len()..];
        if let Some(end) = after.find('"') {
            out.push(&after[..end]);
            rest = &after[end..];
        } else {
            break;
        }
    }
    out
}

/// Parse `name: Type` fields (with their attributes) out of a struct body or the joined variant bodies of an enum.
fn parse_fields(body: &str) -> Vec<Field> {
    let mut fields = Vec::new();
    for part in split_top_level(body) {
        let mut rest = part.trim();
        let mut attrs = String::new();
        while rest.starts_with("#[") {
            let mut depth = 0usize;
            let mut end = None;
            for (i, c) in rest.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else { break };
            attrs.push_str(&rest[..=end]);
            attrs.push(' ');
            rest = rest[end + 1..].trim_start();
        }
        if let Some(r) = rest.strip_prefix("pub") {
            rest = r.trim_start();
            if rest.starts_with('(')
                && let Some(close) = rest.find(')')
            {
                rest = rest[close + 1..].trim_start();
            }
        }
        // First `:` that is not part of `::`.
        let b = rest.as_bytes();
        let mut colon = None;
        for i in 0..b.len() {
            if b[i] == b':' && (i + 1 >= b.len() || b[i + 1] != b':') && (i == 0 || b[i - 1] != b':') {
                colon = Some(i);
                break;
            }
        }
        let Some(colon) = colon else { continue };
        let name = rest[..colon].trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let ty = rest[colon + 1..].trim().to_owned();
        let attr_words = words(&attrs);
        if attr_words.iter().any(|w| *w == "skip" || *w == "skip_deserializing") {
            continue;
        }
        let renamed = quoted_after(&attrs, "rename");
        let mut names = vec![renamed.first().map_or_else(|| name.to_owned(), |r| (*r).to_owned())];
        names.extend(quoted_after(&attrs, "alias").into_iter().map(str::to_owned));
        fields.push(Field { names, ty, flatten: attr_words.contains(&"flatten") });
    }
    fields
}

fn scan_source(src: &str, defs: &mut HashMap<String, Vec<Def>>) {
    let src = strip_line_comments(src);
    for kw in ["struct", "enum"] {
        let needle = format!("{kw} ");
        let mut from = 0;
        while let Some(rel) = src[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Must read `pub struct` / `pub(crate) struct` at the start of a line.
            let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
            let prefix = src[line_start..at].trim();
            if !(prefix == "pub" || (prefix.starts_with("pub(") && prefix.ends_with(')'))) {
                continue;
            }
            let after = &src[from..];
            let name_len = after.find(|c: char| !(c.is_alphanumeric() || c == '_')).unwrap_or(after.len());
            let name = &after[..name_len];
            if name.is_empty() {
                continue;
            }
            let mut j = from + name_len;
            let bytes = src.as_bytes();
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'<' {
                let mut depth = 0usize;
                while j < bytes.len() {
                    match bytes[j] {
                        b'<' => depth += 1,
                        b'>' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                    j += 1;
                }
            }
            if j >= bytes.len() || bytes[j] != b'{' {
                continue;
            }
            // Attributes sit between the previous item's end and this line.
            let window_start = [src[..line_start].rfind("}\n"), src[..line_start].rfind(";\n")]
                .into_iter()
                .flatten()
                .max()
                .unwrap_or(0);
            if !src[window_start..at].contains("Deserialize") {
                continue;
            }
            let Some(close) = matching_brace(&src, j) else { continue };
            let body = &src[j + 1..close];
            let is_enum = kw == "enum";
            let fields = if is_enum {
                // Only the struct-like variants carry named fields.
                let mut joined = Vec::new();
                let mut k = 0;
                let b = body.as_bytes();
                while k < b.len() {
                    if b[k] == b'{'
                        && let Some(end) = matching_brace(body, k)
                    {
                        joined.push(body[k + 1..end].to_owned());
                        k = end;
                    }
                    k += 1;
                }
                parse_fields(&joined.join(","))
            } else {
                parse_fields(body)
            };
            defs.entry(name.to_owned()).or_default().push(Def { is_enum, fields });
        }
    }
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name == "tests" || name == "target" || name.starts_with('.') {
                continue;
            }
            rust_sources(&path, out);
        } else if name.ends_with(".rs") && !name.contains("test") {
            out.push(path);
        }
    }
}

fn walk(
    defs: &HashMap<String, Vec<Def>>,
    name: &str,
    path: &[String],
    stack: &mut Vec<String>,
    flat_only: bool,
    out: &mut BTreeSet<String>,
) {
    let Some(list) = defs.get(name) else { return };
    for def in list {
        if def.is_enum && !flat_only {
            continue;
        }
        for field in &def.fields {
            let idents: Vec<&str> =
                words(&field.ty).into_iter().filter(|w| defs.contains_key(*w) && !stack.iter().any(|s| s.as_str() == *w)).collect();
            if field.flatten {
                for t in idents {
                    stack.push(t.to_owned());
                    walk(defs, t, path, stack, true, out);
                    stack.pop();
                }
                continue;
            }
            let is_map = field.ty.contains("Map<");
            for n in &field.names {
                let mut p = path.to_vec();
                p.push(n.clone());
                out.insert(p.join("."));
                for t in &idents {
                    let mut child = p.clone();
                    if is_map {
                        child.push("*".to_owned());
                    }
                    stack.push((*t).to_owned());
                    walk(defs, t, &child, stack, false, out);
                    stack.pop();
                }
            }
        }
    }
}

fn schema_keys() -> BTreeSet<String> {
    let codegen = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(&codegen).expect("crates dir").flatten() {
        rust_sources(&krate.path().join("src"), &mut files);
    }
    assert!(files.len() > 200, "source scan found only {} files; the guard cannot see the schema", files.len());
    let mut defs: HashMap<String, Vec<Def>> = HashMap::new();
    for f in files {
        if let Ok(src) = std::fs::read_to_string(&f) {
            scan_source(&src, &mut defs);
        }
    }
    let mut out = BTreeSet::new();
    let mut stack = vec!["Config".to_owned()];
    walk(&defs, "Config", &[], &mut stack, false, &mut out);
    let mut stack = vec!["ConfigModelOverride".to_owned()];
    walk(&defs, "ConfigModelOverride", &["model".to_owned(), "*".to_owned()], &mut stack, false, &mut out);
    out
}

// ---- classification ----------------------------------------------------------------------------------------------

/// `pattern` (dotted, `*` = any one segment) is a prefix of `path`.
fn pattern_covers(pattern: &[&str], path: &[&str]) -> bool {
    pattern.len() <= path.len() && pattern.iter().zip(path).all(|(p, s)| *p == "*" || p == s)
}

fn stripped_by(path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('.').collect();
    for key in CAMPAIGN_STRIP_KEYS.iter().chain(PATCH_STRIP_KEYS) {
        if segs[0] == *key {
            return Some(format!("CAMPAIGN_STRIP_KEYS/PATCH_STRIP_KEYS `{key}`"));
        }
    }
    for dotted in CAMPAIGN_STRIP_PATHS {
        let pat: Vec<&str> = dotted.split('.').collect();
        if pattern_covers(&pat, &segs) {
            return Some(format!("CAMPAIGN_STRIP_PATHS `{dotted}`"));
        }
    }
    for pat in PATCH_STRIP_PATHS {
        if pattern_covers(pat, &segs) {
            return Some(format!("PATCH_STRIP_PATHS `{}`", pat.join(".")));
        }
    }
    for field in CAMPAIGN_MCP_SECRET_FIELDS {
        if pattern_covers(&["mcp_servers", "*", *field], &segs) {
            return Some(format!("CAMPAIGN_MCP_SECRET_FIELDS `{field}`"));
        }
    }
    None
}

fn allowed(path: &str) -> bool {
    CAMPAIGN_ALLOWED.iter().any(|(p, _)| *p == path)
}

#[test]
fn every_destination_credential_or_exec_key_is_classified_for_campaigns() {
    let keys = schema_keys();
    // The scan sees the schema: a few keys we know exist must be in it, or the scanner broke.
    for known in [
        "hub.url",
        "toolset.bash.cmd_prefix",
        "toolset.web_fetch.proxy_endpoint",
        "telemetry.otel_endpoint",
        "model.*.base_url",
        "mcp_servers.*.url",
        "mcp_servers.*.headers",
        "shell_environment_policy",
        "endpoints.fuigo_api_base_url",
    ] {
        assert!(keys.contains(known), "schema scan lost `{known}`: the scanner no longer sees the config structs");
    }

    let mut unclassified = Vec::new();
    let mut both = Vec::new();
    for key in &keys {
        let last = key.rsplit('.').next().unwrap_or(key);
        if !matches_pattern(last) {
            continue;
        }
        match (stripped_by(key).is_some(), allowed(key)) {
            (false, false) => unclassified.push(key.clone()),
            (true, true) => both.push(key.clone()),
            _ => {}
        }
    }
    assert!(
        unclassified.is_empty(),
        "config key(s) {unclassified:?} look like a destination, credential or execution setting and are neither \
         stripped from campaign patches nor allowed. Classify each in `fuigo-config/src/config_override.rs`: add it to \
         CAMPAIGN_STRIP_PATHS (it can send a credential or the user's content somewhere, or run something), or to \
         CAMPAIGN_ALLOWED in this test with a one-line reason (it cannot)."
    );
    assert!(both.is_empty(), "config key(s) {both:?} are both stripped and listed in CAMPAIGN_ALLOWED: keep one");

    // An allowed entry must still exist, so the list cannot rot.
    let stale: Vec<&str> = CAMPAIGN_ALLOWED.iter().map(|(p, _)| *p).filter(|p| !keys.contains(*p)).collect();
    assert!(stale.is_empty(), "CAMPAIGN_ALLOWED lists key(s) {stale:?} that are no longer in the config schema: remove them");
}

/// review R3-4 / R4-4: the name-pattern scan above cannot see a SEMANTIC selector or toggle (`features.telemetry`,
/// `agent.name`, `disabled_mcp_servers`, `marketplace.sources`): its name matches no pattern, yet it turns a destination
/// or an execution path on. This registry names every one explicitly, independent of the scanner, so removing an entry
/// from `CAMPAIGN_STRIP_PATHS` fails here. Do not widen the name patterns instead.
const SECURITY_RELEVANT_STRIP_REGISTRY: &[&str] = &[
    "features.peer_messaging",
    "mcp_servers.*.bearer_token_file",
    "mcp_servers.*.bearer_token_env_var",
    "model.*.notice",
    "model.*.base_url",
    "model.*.api_base_url",
    "model.*.extra_headers",
    "model.*.env_http_headers",
    "model.*.http_headers",
    "model.*.query_params",
    "model.*.model_provider",
    "model.*.auth_provider",
    "model.*.api_key",
    "model.*.env_key",
    "model.*.mtls_cert_dir",
    "models.extra_headers",
    "toolset.web_fetch.allow_local",
    "hub.url",
    "shell_environment_policy",
    "toolset.bash.cmd_prefix",
    "toolset.web_fetch.proxy_endpoint",
    "toolset.web_search.base_url",
    "toolset.web_search.flux_base_url",
    "toolset.web_search.api_key",
    "toolset.web_search.extra_headers",
    "toolset.web_search.env_http_headers",
    "toolset.web_search.mtls_cert_dir",
    "telemetry.events_url",
    "telemetry.events_api_key",
    "telemetry.mixpanel_token",
    "telemetry.otel_endpoint",
    "telemetry.otel_enabled",
    "telemetry.otel_logs_exporter",
    "telemetry.otel_metrics_exporter",
    "telemetry.otel_protocol",
    "telemetry.otel_log_user_prompts",
    "telemetry.otel_log_tool_details",
    "telemetry.otel_certificate",
    "telemetry.otel_client_certificate",
    "telemetry.otel_client_key",
    "feedback.user.command",
    "tools.zdr_video_output_s3",
    "cli.installer",
    "cli.npm_registry",
    "cli.session_registry",
    "paths",
    "plugins.paths",
    "skills.bundled_skill_dirs",
    "skills.paths",
    "skills.server_skill_dirs",
    "agent.definition",
    "plugins.enabled",
    "plugins.disabled",
    "plugins.auto_discover",
    "marketplace.sources",
    "skills.auto_discover",
    "telemetry.trace_upload",
    "telemetry.otel_transport",
    "features.telemetry",
    "features.lsp_tools",
    "agent.name",
    "disabled_mcp_servers",
    "subagents.roles.*.prompt_file",
    "subagents.personas.*.instructions_file",
];

#[test]
fn security_relevant_selectors_and_toggles_are_stripped_from_campaigns() {
    let missing: Vec<&str> = SECURITY_RELEVANT_STRIP_REGISTRY
        .iter()
        .copied()
        .filter(|p| !CAMPAIGN_STRIP_PATHS.contains(p))
        .collect();
    assert!(missing.is_empty(), "registered selector(s) {missing:?} are no longer in CAMPAIGN_STRIP_PATHS");
    // Each registered path really is removed from a patch (a `*` stands for one table key).
    for path in SECURITY_RELEVANT_STRIP_REGISTRY {
        let segments: Vec<String> = path.split('.').map(|s| if s == "*" { "x".to_owned() } else { s.to_owned() }).collect();
        let mut value = toml::Value::Boolean(true);
        for seg in segments.iter().rev() {
            let mut t = toml::Table::new();
            t.insert(seg.clone(), value);
            value = toml::Value::Table(t);
        }
        let mut patch = value.as_table().cloned().unwrap();
        fuigo_config::config_override::strip_campaign_paths(&mut patch);
        assert!(patch.is_empty(), "campaign patch still carries `{path}`: {patch:?}");
    }
}

/// The reviewed campaign allowlist, each path with the reason campaigns need it and why it cannot send data to a
/// campaign-chosen destination, set a credential or widen a permission (`mcp_servers` may add a server, a remote URL
/// or a local program, which is reported to the user and untrusted). `CAMPAIGN_ALLOW_PATHS` must equal this list: a path added there without a
/// reviewed entry here fails, and so does a removal.
const REVIEWED_CAMPAIGN_ALLOW_PATHS: &[(&str, &str)] = &[
    ("models.default", "the soft default-model nudge, dismissed by a `/model` pick; string only"),
    ("models.image_description", "helper-model nudge, resolved as a default, never as the user's choice; string only"),
    ("models.session_summary", "helper-model nudge, resolved as a default, never as the user's choice; string only"),
    ("model.*.name", "display name of a model; string only, route and credential keys stay stripped"),
    ("model.*.context_window", "context size of a model; integer from 1024 to 10,000,000 only"),
    ("mcp_servers", "a campaign may ADD a server: new names only, no secret fields, literal strings, marked untrusted"),
    ("managed_mcps.enabled", "a campaign may only turn managed MCP servers OFF; `false` only"),
];

#[test]
fn campaign_allow_paths_match_the_reviewed_list() {
    let listed: BTreeSet<String> = CAMPAIGN_ALLOW_PATHS.iter().map(|p| p.join(".")).collect();
    let reviewed: BTreeSet<String> = REVIEWED_CAMPAIGN_ALLOW_PATHS.iter().map(|(p, _)| (*p).to_owned()).collect();
    assert_eq!(
        listed, reviewed,
        "CAMPAIGN_ALLOW_PATHS changed: review each added path (it must be a key campaigns use that cannot send data to a \
         campaign-chosen destination, set a credential or widen a permission, with a value constraint where needed) and list it with its reason \
         in REVIEWED_CAMPAIGN_ALLOW_PATHS"
    );
    assert_eq!(REVIEWED_CAMPAIGN_ALLOW_PATHS.len(), reviewed.len(), "duplicate entry in REVIEWED_CAMPAIGN_ALLOW_PATHS");
}
