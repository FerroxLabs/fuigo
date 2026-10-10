//! P169: the layered managed MCP + marketplace policy engine. Ported and adapted from upstream 72a61251
//! `managed_policy/tests.rs` (`layer_resolution_semantics`, `user_layer_cannot_satisfy_admin_managed_only_grant`,
//! `admin_project_pin_ignores_user_layer_grants`, `mcp_verdict_matrix`, `mcp_block_reason_display_and_source_are_pinned`,
//! `managed_only_block_names_an_unsatisfied_lockdown_source`, `marketplace_add_gate_fails_closed`,
//! `managed_config_layers_from_disk_reach_the_policy_engine`). Fuigo binds every source to every server, so upstream's
//! origin (native vs foreign) dimension is gone.

use std::path::{Path, PathBuf};

use fuigo_config::policy_sources::{PolicyLayerTier, PolicySource, policy_sources_at};

use super::super::{AllowedMcpServer, ManagedSettings, McpServerAllowlist};
use crate::permission::types::{RuleAction, ToolFilter};
use super::*;

const SYS_REQ: &str = "/etc/fuigo/requirements.toml";
const SYS_MANAGED: &str = "/etc/fuigo/managed_config.toml";
const USER_REQ: &str = "/home/u/.fuigo/requirements.toml";
const USER_MANAGED: &str = "/home/u/.fuigo/managed_config.toml";
const MDM: &str = "ai.x.grok:requirements_toml_base64";
const CLAUDE: &str = "/etc/claude-code/managed-settings.json";

const ADMIN_TIERS: [(PolicyLayerTier, &str); 3] = [
    (PolicyLayerTier::Mdm, MDM),
    (PolicyLayerTier::SystemRequirements, SYS_REQ),
    (PolicyLayerTier::SystemManaged, SYS_MANAGED),
];
const USER_TIERS: [(PolicyLayerTier, &str); 2] = [
    (PolicyLayerTier::UserRequirements, USER_REQ),
    (PolicyLayerTier::UserManaged, USER_MANAGED),
];

fn hs(name: &str, url: &str) -> agent_client_protocol::McpServer {
    agent_client_protocol::McpServer::Http(
        agent_client_protocol::McpServerHttp::new(name, url.to_string()).headers(vec![]),
    )
}

fn sa(name: &str, command: &str, args: &[&str]) -> agent_client_protocol::McpServer {
    agent_client_protocol::McpServer::Stdio(
        agent_client_protocol::McpServerStdio::new(name, PathBuf::from(command))
            .args(args.iter().map(|a| a.to_string()).collect()),
    )
}

/// Sources from TOML strings (tier order applied by the engine's input contract: sorted like `policy_sources_at`).
fn layered(
    claude: Option<serde_json::Value>,
    layers: &[(PolicyLayerTier, &str, &str)],
) -> ManagedSettings {
    let mut sources: Vec<PolicySource> = layers
        .iter()
        .map(|(tier, path, toml_str)| {
            let value: toml::Value = toml::from_str(toml_str).unwrap();
            PolicySource {
                tier: *tier,
                ownership: tier.ownership(),
                path: PathBuf::from(path),
                policy: Ok(serde_json::to_value(value).unwrap()),
            }
        })
        .collect();
    if let Some(json) = claude {
        sources.push(PolicySource {
            tier: PolicyLayerTier::Vendor,
            ownership: PolicyLayerTier::Vendor.ownership(),
            path: PathBuf::from(CLAUDE),
            policy: Ok(json),
        });
    }
    sources.sort_by_key(|s| s.tier);
    resolve_managed_settings(sources)
}

fn allowed(ms: &ManagedSettings, url: &str) -> bool {
    ms.mcp_allowlist.is_server_allowed(&hs("s", url))
}

/// Strictest wins across a requirements layer and the Claude file: the Claude allow list alone cannot grant what the
/// managed-only pin and the requirements allow list exclude; serverCommand denies; strict marketplaces intersect.
#[test]
fn layer_resolution_semantics() {
    let ms = layered(
        Some(serde_json::json!({
            "allowedMcpServers": [
                { "serverUrl": "https://ok.example.com/*" },
                { "serverUrl": "https://user-extra.example.com/*" }
            ]
        })),
        &[(
            PolicyLayerTier::SystemRequirements,
            SYS_REQ,
            r#"
allow_managed_mcp_servers_only = true
enable_all_project_mcp_servers = false

[[allowed_mcp_servers]]
server_url = "https://ok.example.com/*"

[[denied_mcp_servers]]
server_command = ["npx", "evil-mcp"]

[[strict_known_marketplaces]]
source = "git"
url = "https://github.com/example-corp/approved-plugins.git"

[[strict_known_marketplaces]]
source = "github"
repo = "acme/approved-plugins"
ref = "stable"
"#,
        )],
    );
    assert!(allowed(&ms, "https://ok.example.com/mcp"));
    assert!(
        !allowed(&ms, "https://user-extra.example.com/mcp"),
        "allowed by the Claude source alone, blocked by the requirements list"
    );
    assert!(
        ms.mcp_allowlist
            .is_server_denied(&sa("t", "npx", &["evil-mcp"]))
    );
    assert!(
        !ms.mcp_allowlist
            .is_server_denied(&sa("t", "npx", &["evil-mcp", "--x"])),
        "serverCommand is an exact argv match"
    );
    assert!(ms.mcp_allowlist.managed_only());
    assert_eq!(ms.project_mcp.source(), Some(Path::new(SYS_REQ)));
    assert!(ms.marketplace_allowlist.is_restricted());
    assert!(
        ms.marketplace_allowlist
            .is_url_allowed("https://github.com/example-corp/approved-plugins.git")
    );
    assert!(
        ms.marketplace_allowlist
            .is_url_allowed("https://github.com/acme/approved-plugins.git"),
        "github+repo is canonicalized to its clone URL"
    );
    assert!(
        !ms.marketplace_allowlist
            .is_url_allowed("https://github.com/evil/repo.git")
    );
}

#[test]
fn a_deny_in_any_layer_beats_an_allow_in_another() {
    let ms = layered(
        None,
        &[
            (
                PolicyLayerTier::UserManaged,
                USER_MANAGED,
                "[[allowed_mcp_servers]]\nserver_url = \"https://x.example.com/*\"\n",
            ),
            (
                PolicyLayerTier::UserRequirements,
                USER_REQ,
                "[[denied_mcp_servers]]\nserver_name = \"evil\"\n",
            ),
        ],
    );
    assert!(
        !ms.mcp_allowlist
            .is_server_allowed(&hs("evil", "https://x.example.com/mcp"))
    );
    assert!(
        ms.mcp_allowlist
            .is_server_allowed(&hs("good", "https://x.example.com/mcp"))
    );
}

#[test]
fn every_restricted_source_must_allow() {
    let ms = layered(
        None,
        &[
            (
                PolicyLayerTier::SystemManaged,
                SYS_MANAGED,
                "[[allowed_mcp_servers]]\nserver_url = \"https://a.example.com/*\"\n[[allowed_mcp_servers]]\nserver_url = \"https://b.example.com/*\"\n",
            ),
            (
                PolicyLayerTier::UserManaged,
                USER_MANAGED,
                "[[allowed_mcp_servers]]\nserver_url = \"https://a.example.com/*\"\n",
            ),
        ],
    );
    assert!(allowed(&ms, "https://a.example.com/mcp"));
    assert!(
        !allowed(&ms, "https://b.example.com/mcp"),
        "the user layer narrows further"
    );
}

/// Present-but-empty and malformed lists lock down; an explicit empty deny list is harmless.
#[test]
fn lockdown_shapes_fail_closed() {
    for (label, body, locked) in [
        ("empty allow list", "allowed_mcp_servers = []\n", true),
        (
            "allow list not an array",
            "allowed_mcp_servers = \"https://a/*\"\n",
            true,
        ),
        (
            "deny list not an array",
            "denied_mcp_servers = { server_name = \"x\" }\n",
            true,
        ),
        (
            "unenforceable deny entry",
            "[[denied_mcp_servers]]\nbogus = 1\n",
            true,
        ),
        (
            "unmatchable deny url",
            "[[denied_mcp_servers]]\nserver_url = \"/admin/*\"\n",
            true,
        ),
        ("empty deny list", "denied_mcp_servers = []\n", false),
        (
            "spelled both ways, differently",
            "allowedMcpServers = []\nallowed_mcp_servers = [{ server_name = \"a\" }]\n",
            true,
        ),
    ] {
        let ms = layered(None, &[(PolicyLayerTier::UserManaged, USER_MANAGED, body)]);
        assert_eq!(
            !allowed(&ms, "https://anything.example.com/mcp"),
            locked,
            "{label}"
        );
        if locked {
            assert!(ms.mcp_allowlist.is_lockdown(), "{label}");
            assert!(matches!(
                ms.mcp_allowlist
                    .verdict(&hs("s", "https://anything.example.com/mcp")),
                McpVerdict::Blocked(McpBlockReason::Lockdown { .. })
            ));
        }
    }
}

/// An unusable allow entry grants nothing but does not lock down the usable ones.
#[test]
fn unusable_allow_entry_is_dropped_not_fatal() {
    let ms = layered(
        None,
        &[(
            PolicyLayerTier::UserManaged,
            USER_MANAGED,
            "[[allowed_mcp_servers]]\nbogus = 1\n[[allowed_mcp_servers]]\nserver_url = \"https://ok.example.com/*\"\n",
        )],
    );
    assert!(allowed(&ms, "https://ok.example.com/mcp"));
    assert!(!allowed(&ms, "https://other.example.com/mcp"));
}

/// Fail closed: a policy file that could not be read locks MCP and marketplaces down, attributed to that file.
#[test]
fn an_unreadable_policy_layer_locks_everything_down() {
    let ms = resolve_managed_settings(vec![PolicySource {
        tier: PolicyLayerTier::SystemRequirements,
        ownership: PolicyLayerTier::SystemRequirements.ownership(),
        path: PathBuf::from(SYS_REQ),
        policy: Err("TOML parse error at line 1, column 3".to_string()),
    }]);
    let verdict = ms
        .mcp_allowlist
        .verdict(&hs("s", "https://ok.example.com/mcp"));
    assert_eq!(
        verdict,
        McpVerdict::Blocked(McpBlockReason::Lockdown {
            source: PathBuf::from(SYS_REQ)
        })
    );
    assert!(ms.marketplace_allowlist.is_restricted());
    assert!(
        ms.marketplace_allowlist
            .add_block_reason("https://github.com/a/b.git")
            .is_some()
    );
    assert!(ms.project_mcp.is_disabled());
    assert!(ms.non_managed_hooks.is_disabled());
    // P183 round 9 (Grok r5 H2): and every tool call is denied (no validated copy of the file exists)
    assert!(tool_denied(&ms, ToolFilter::Bash), "Bash must be denied");
    assert!(tool_denied(&ms, ToolFilter::Edit), "Edit must be denied");
}

/// Is a call of `tool` denied outright by a managed rule with no pattern (the deny-every-tool rule, or a remembered
/// `permissions.deny` entry for that tool)?
fn tool_denied(ms: &ManagedSettings, tool: ToolFilter) -> bool {
    ms.permissions.iter().any(|r| {
        r.value.action == RuleAction::Deny
            && r.value.pattern.is_none()
            && (r.value.tool == ToolFilter::Any || r.value.tool == tool)
    })
}

fn broken_claude() -> PolicySource {
    PolicySource {
        tier: PolicyLayerTier::Vendor,
        ownership: PolicyLayerTier::Vendor.ownership(),
        path: PathBuf::from(CLAUDE),
        policy: Err("expected value at line 1 column 1".to_string()),
    }
}

/// P183 round 9 (Grok r5 H2), sequence "absent then broken": a Claude file that is broken with no validated copy denies
/// every tool, and still locks MCP, marketplaces, hooks and project MCP.
#[test]
fn broken_claude_file_without_copy_denies_every_tool_p183r9() {
    let ms = resolve_managed_settings(vec![broken_claude()]);
    assert!(tool_denied(&ms, ToolFilter::Bash));
    assert!(tool_denied(&ms, ToolFilter::Edit));
    assert!(ms.non_managed_hooks.is_disabled());
    assert!(ms.marketplace_allowlist.is_restricted());
}

/// "Valid then broken before the first engine read" / "valid, cached, then broken": the validated copy's `permissions.deny`
/// and `defaultMode` stay in force (no blanket deny, no weaker than the copy), with the same MCP and hooks lock-down.
#[test]
fn broken_claude_file_with_copy_keeps_copy_rules_p183r9() {
    let copy = serde_json::json!({"permissions": {"deny": ["Bash"]}});
    let ms = resolve_managed_settings_with(vec![broken_claude()], |s| {
        (s.tier == PolicyLayerTier::Vendor).then(|| copy.clone())
    });
    assert!(tool_denied(&ms, ToolFilter::Bash), "remembered deny stays");
    assert!(!tool_denied(&ms, ToolFilter::Edit), "the copy, not a blanket deny");
    assert!(ms.non_managed_hooks.is_disabled());
    assert!(ms.project_mcp.is_disabled());
}

/// Admin TOML with a validated copy is enforced by the requirements path, so no blanket deny here; MDM never has one.
#[test]
fn broken_admin_toml_denies_only_without_copy_p183r9() {
    let src = PolicySource {
        tier: PolicyLayerTier::SystemRequirements,
        ownership: PolicyLayerTier::SystemRequirements.ownership(),
        path: PathBuf::from(SYS_REQ),
        policy: Err("x".to_string()),
    };
    let with_copy = resolve_managed_settings_with(vec![src.clone()], |_| Some(serde_json::Value::Null));
    assert!(!tool_denied(&with_copy, ToolFilter::Bash));
    assert!(with_copy.non_managed_hooks.is_disabled());
    assert!(tool_denied(&resolve_managed_settings_with(vec![src], |_| None), ToolFilter::Bash));
}

/// An admin-owned managed-only lockdown accepts only admin-owned grants; a user-owned one accepts any.
#[test]
fn user_layer_cannot_satisfy_admin_managed_only_grant() {
    const LOCKDOWN: &str = "allow_managed_mcp_servers_only = true\n";
    const GRANT: &str = "[[allowed_mcp_servers]]\nserver_url = \"https://ok.example.com/*\"\n";
    const URL: &str = "https://ok.example.com/mcp";
    for (admin, admin_path) in ADMIN_TIERS {
        for (user, user_path) in USER_TIERS {
            let ms = layered(
                None,
                &[(admin, admin_path, LOCKDOWN), (user, user_path, GRANT)],
            );
            assert!(
                !allowed(&ms, URL),
                "a {user:?} grant must not satisfy a {admin:?} lockdown"
            );
            assert_eq!(
                ms.mcp_allowlist.verdict(&hs("s", URL)),
                McpVerdict::Blocked(McpBlockReason::NotGranted {
                    source: PathBuf::from(admin_path)
                }),
                "the block names the unsatisfied lockdown source"
            );
        }
    }
    let ms = layered(
        None,
        &[
            (PolicyLayerTier::Mdm, MDM, LOCKDOWN),
            (PolicyLayerTier::SystemManaged, SYS_MANAGED, GRANT),
        ],
    );
    assert!(
        allowed(&ms, URL),
        "admin entries satisfy an admin lockdown in another admin tier"
    );
    let ms = layered(
        None,
        &[
            (PolicyLayerTier::SystemRequirements, SYS_REQ, GRANT),
            (PolicyLayerTier::UserManaged, USER_MANAGED, LOCKDOWN),
        ],
    );
    assert!(
        allowed(&ms, URL),
        "a user-pinned lockdown accepts an admin grant"
    );
    let ms = layered(
        None,
        &[(
            PolicyLayerTier::UserManaged,
            USER_MANAGED,
            &format!("{LOCKDOWN}{GRANT}"),
        )],
    );
    assert!(
        allowed(&ms, URL),
        "a user-pinned lockdown accepts the same file's grant"
    );
    let ms = layered(
        Some(
            serde_json::json!({ "allowedMcpServers": [ { "serverUrl": "https://ok.example.com/*" } ] }),
        ),
        &[(PolicyLayerTier::SystemManaged, SYS_MANAGED, LOCKDOWN)],
    );
    assert!(
        allowed(&ms, URL),
        "Claude-file entries are admin-owned and satisfy an admin lockdown"
    );
}

/// The project-MCP pin's exception grant is ownership-aware.
#[test]
fn admin_project_pin_ignores_user_layer_grants() {
    const PIN: &str = "enable_all_project_mcp_servers = false\n";
    const GRANT: &str = "[[allowed_mcp_servers]]\nserver_url = \"https://proj.example.com/*\"\n";
    let blocks = |ms: &ManagedSettings| {
        ms.mcp_project_pin_block(&hs("p", "https://proj.example.com/mcp"))
            .is_some()
    };
    for (user, user_path) in USER_TIERS {
        let ms = layered(
            None,
            &[
                (PolicyLayerTier::SystemManaged, SYS_MANAGED, PIN),
                (user, user_path, GRANT),
            ],
        );
        assert!(blocks(&ms), "an admin pin ignores a {user:?} grant");
    }
    let ms = layered(
        None,
        &[
            (PolicyLayerTier::SystemRequirements, SYS_REQ, GRANT),
            (PolicyLayerTier::SystemManaged, SYS_MANAGED, PIN),
        ],
    );
    assert!(
        !blocks(&ms),
        "an admin grant carves the exception out of an admin pin"
    );
    let ms = layered(
        None,
        &[(
            PolicyLayerTier::UserManaged,
            USER_MANAGED,
            &format!("{PIN}{GRANT}"),
        )],
    );
    assert!(!blocks(&ms), "a user pin accepts the same file's grant");
    let ms = layered(
        Some(serde_json::json!({ "enableAllProjectMcpServers": false })),
        &[(
            PolicyLayerTier::UserManaged,
            USER_MANAGED,
            &format!("{PIN}{GRANT}"),
        )],
    );
    assert!(
        blocks(&ms),
        "the Claude file's pin upgrades a user pin: the user grant stops counting"
    );
    assert_eq!(ms.project_mcp.source(), Some(Path::new(CLAUDE)));
    let ms = layered(None, &[(PolicyLayerTier::UserManaged, USER_MANAGED, GRANT)]);
    assert!(!blocks(&ms), "no pin, no block");
}

#[test]
fn mcp_verdict_attribution() {
    let ms = layered(
        None,
        &[
            (
                PolicyLayerTier::SystemManaged,
                SYS_MANAGED,
                "[[denied_mcp_servers]]\nserver_url = \"https://evil.example.com/*\"\n",
            ),
            (
                PolicyLayerTier::UserRequirements,
                USER_REQ,
                "[[allowed_mcp_servers]]\nserver_url = \"https://ok.example.com/*\"\n",
            ),
        ],
    );
    assert_eq!(
        ms.mcp_allowlist
            .verdict(&hs("e", "https://evil.example.com/mcp")),
        McpVerdict::Blocked(McpBlockReason::Deny {
            source: PathBuf::from(SYS_MANAGED)
        })
    );
    assert_eq!(
        ms.mcp_allowlist
            .verdict(&hs("o", "https://other.example.com/mcp")),
        McpVerdict::Blocked(McpBlockReason::NotGranted {
            source: PathBuf::from(USER_REQ)
        })
    );
    assert_eq!(
        ms.mcp_allowlist
            .verdict(&hs("k", "https://ok.example.com/mcp")),
        McpVerdict::Allowed
    );
}

/// Display (doctor, JSON, logs) keeps the full path; the user-facing refusal names the file only.
#[test]
fn mcp_block_reason_display_and_source_are_pinned() {
    let reason = McpBlockReason::Deny {
        source: PathBuf::from(SYS_MANAGED),
    };
    assert_eq!(
        reason.to_string(),
        "matches deniedMcpServers (/etc/fuigo/managed_config.toml)"
    );
    assert_eq!(
        reason.user_facing_reason(),
        "matches deniedMcpServers (managed_config.toml)"
    );
    assert_eq!(
        McpBlockReason::Lockdown {
            source: PathBuf::from(USER_REQ)
        }
        .user_facing_reason(),
        "locked down by policy (requirements.toml)"
    );
    assert_eq!(
        McpBlockReason::NotGranted {
            source: PathBuf::new()
        }
        .user_facing_reason(),
        "not in allowedMcpServers ()"
    );
}

#[test]
fn marketplace_add_gate_fails_closed() {
    let unrestricted = layered(None, &[]);
    assert_eq!(
        unrestricted
            .marketplace_allowlist
            .add_block_reason("/tmp/local"),
        None
    );
    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemManaged,
            SYS_MANAGED,
            "[[strict_known_marketplaces]]\nsource = \"git\"\nurl = \"https://github.com/ok/repo.git\"\n",
        )],
    );
    assert_eq!(
        ms.marketplace_allowlist
            .add_block_reason("https://github.com/ok/repo"),
        None,
        "the .git suffix and case normalize"
    );
    assert_eq!(
        ms.marketplace_allowlist
            .add_block_reason("/tmp/local")
            .as_deref(),
        Some("source not in strictKnownMarketplaces (managed_config.toml)"),
        "a local path never matches a git allowlist; the refusal names the file only"
    );
    let locked = layered(
        None,
        &[(
            PolicyLayerTier::UserManaged,
            USER_MANAGED,
            "strict_known_marketplaces = []\n",
        )],
    );
    assert!(locked.marketplace_allowlist.is_lockdown());
    assert!(
        locked
            .marketplace_allowlist
            .add_block_reason("https://github.com/ok/repo.git")
            .is_some()
    );
    let both = layered(
        None,
        &[
            (
                PolicyLayerTier::SystemManaged,
                SYS_MANAGED,
                "[[strict_known_marketplaces]]\nsource = \"git\"\nurl = \"https://github.com/ok/repo.git\"\n",
            ),
            (
                PolicyLayerTier::UserManaged,
                USER_MANAGED,
                "[[strict_known_marketplaces]]\nsource = \"github\"\nrepo = \"other/repo\"\n",
            ),
        ],
    );
    assert!(
        both.marketplace_allowlist
            .add_block_reason("https://github.com/ok/repo.git")
            .is_some(),
        "strictest wins: every source must allow"
    );
}

/// The Claude file's present-but-empty `allowedMcpServers` is a lockdown (Claude semantics). Before P169 Fuigo read
/// it as unrestricted.
#[test]
fn claude_empty_allow_list_is_a_lockdown() {
    let ms = layered(Some(serde_json::json!({ "allowedMcpServers": [] })), &[]);
    assert!(!allowed(&ms, "https://any.example.com/mcp"));
}

#[test]
fn hooks_pin_reaches_managed_settings() {
    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemRequirements,
            SYS_REQ,
            "allow_managed_hooks_only = true\n",
        )],
    );
    assert_eq!(ms.non_managed_hooks.source(), Some(Path::new(SYS_REQ)));
    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemRequirements,
            SYS_REQ,
            "allow_managed_hooks_only = false\n",
        )],
    );
    assert!(!ms.non_managed_hooks.is_disabled());
}

/// Real files on disk reach the engine through `policy_sources_at` (layer discovery and the TOML → JSON key filter).
#[test]
fn policy_files_from_disk_reach_the_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let sys = tmp.path().join("etc");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&sys).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        sys.join("managed_config.toml"),
        "[[denied_mcp_servers]]\nserver_name = \"evil\"\n[features]\nfoo = true\n",
    )
    .unwrap();
    std::fs::write(
        home.join("managed_config.toml"),
        "[[allowed_mcp_servers]]\nserver_url = \"https://ok.example.com/*\"\n",
    )
    .unwrap();
    let vendor = sys.join("managed-settings.json");
    std::fs::write(
        &vendor,
        r#"{"strictKnownMarketplaces": [{"source": "github", "repo": "a/b"}]}"#,
    )
    .unwrap();
    let ms = resolve_managed_settings(policy_sources_at(
        Some(&sys),
        Some(&home),
        Some(&vendor),
        None,
    ));
    assert!(
        !ms.mcp_allowlist
            .is_server_allowed(&hs("evil", "https://ok.example.com/mcp"))
    );
    assert!(
        ms.mcp_allowlist
            .is_server_allowed(&hs("good", "https://ok.example.com/mcp"))
    );
    assert!(
        !ms.mcp_allowlist
            .is_server_allowed(&hs("good", "https://no.example.com/mcp"))
    );
    assert!(
        ms.marketplace_allowlist
            .is_url_allowed("https://github.com/a/b.git")
    );
    assert_eq!(ms.features.source_path.as_deref(), Some(vendor.as_path()));

    // P169 consistency rule (Grok 4.7 C / P183): a broken user-home file warns and is skipped.
    std::fs::write(home.join("requirements.toml"), "allowed_mcp_servers = [\n").unwrap();
    let ms = resolve_managed_settings(policy_sources_at(
        Some(&sys),
        Some(&home),
        Some(&vendor),
        None,
    ));
    assert!(
        ms.mcp_allowlist
            .is_server_allowed(&hs("good", "https://ok.example.com/mcp")),
        "a broken user-home requirements.toml is skipped, not a lockdown"
    );
    assert!(
        !ms.mcp_allowlist
            .is_server_allowed(&hs("evil", "https://ok.example.com/mcp")),
        "the intact admin layer still binds"
    );
    assert!(!ms.non_managed_hooks.is_disabled() && !ms.project_mcp.is_disabled());

    // An admin-path file that is broken fails closed.
    std::fs::write(sys.join("requirements.toml"), "allowed_mcp_servers = [\n").unwrap();
    let ms = resolve_managed_settings(policy_sources_at(
        Some(&sys),
        Some(&home),
        Some(&vendor),
        None,
    ));
    assert!(
        !ms.mcp_allowlist
            .is_server_allowed(&hs("good", "https://ok.example.com/mcp")),
        "a broken /etc/fuigo requirements.toml fails closed"
    );
}

/// P169 (Grok 4.7 #5): an admin-path policy file a non-root user can write (here: group-writable) is broken admin
/// policy and fails closed, so emptying it cannot wipe the org rules.
#[cfg(unix)]
#[test]
fn a_writable_admin_policy_file_fails_closed_even_when_emptied() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let sys = tmp.path().join("etc");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&sys).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let managed = sys.join("managed_config.toml");
    std::fs::write(&managed, "").unwrap();
    std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o666)).unwrap();
    let ms = resolve_managed_settings(policy_sources_at(Some(&sys), Some(&home), None, None));
    assert!(
        !ms.mcp_allowlist
            .is_server_allowed(&hs("any", "https://ok.example.com/mcp")),
        "a writable admin file must not apply as an empty (permissive) policy"
    );
    assert!(ms.marketplace_allowlist.is_lockdown());
    assert!(ms.non_managed_hooks.is_disabled());
}

/// A per-source allowlist built by hand still behaves (the shell builds these in its tests).
#[test]
fn single_source_policy_from_allowlist() {
    let policy = McpServerPolicy::from(McpServerAllowlist::new(
        vec![AllowedMcpServer::Name { name: "a".into() }],
        vec![],
        None,
    ));
    assert!(policy.is_server_allowed(&hs("a", "https://x/")));
    assert!(!policy.is_server_allowed(&hs("b", "https://x/")));
}

/// P169 (Grok 4.7 #4): an in-process ACP SDK server has only a name. A `serverName` allow entry grants it, a
/// `serverName` deny wins, a URL/command-only allow list does not grant it, a deny-only source lets it through, a
/// lockdown blocks it, and a user-layer name grant cannot satisfy an admin managed-only lock.
#[test]
fn name_only_servers_are_judged_by_server_name_entries() {
    let blocked = |ms: &ManagedSettings, name: &str| {
        !matches!(ms.mcp_allowlist.name_only_verdict(name), McpVerdict::Allowed)
    };
    let ms = layered(None, &[]);
    assert!(!blocked(&ms, "sdk"), "no policy: allowed");

    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemManaged,
            SYS_MANAGED,
            "[[allowed_mcp_servers]]\nserver_name = \"sdk\"\n",
        )],
    );
    assert!(!blocked(&ms, "sdk"));
    assert!(blocked(&ms, "other"), "a name allow list excludes other names");

    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemManaged,
            SYS_MANAGED,
            "[[allowed_mcp_servers]]\nserver_url = \"https://ok.example.com/*\"\n",
        )],
    );
    assert!(blocked(&ms, "sdk"), "a URL-only allow list grants no name-only server");

    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemManaged,
            SYS_MANAGED,
            "[[allowed_mcp_servers]]\nserver_name = \"sdk\"\n[[denied_mcp_servers]]\nserver_name = \"sdk\"\n",
        )],
    );
    assert!(matches!(
        ms.mcp_allowlist.name_only_verdict("sdk"),
        McpVerdict::Blocked(McpBlockReason::Deny { .. })
    ));

    let ms = layered(
        None,
        &[(
            PolicyLayerTier::SystemManaged,
            SYS_MANAGED,
            "[[denied_mcp_servers]]\nserver_url = \"https://evil.example.com/*\"\n",
        )],
    );
    assert!(!blocked(&ms, "sdk"), "a deny-only source lets a name it does not deny through");

    let ms = layered(
        None,
        &[(PolicyLayerTier::SystemManaged, SYS_MANAGED, "allowed_mcp_servers = []\n")],
    );
    assert!(matches!(
        ms.mcp_allowlist.name_only_verdict("sdk"),
        McpVerdict::Blocked(McpBlockReason::Lockdown { .. })
    ));

    let ms = layered(
        None,
        &[
            (
                PolicyLayerTier::SystemManaged,
                SYS_MANAGED,
                "allow_managed_mcp_servers_only = true\n",
            ),
            (
                PolicyLayerTier::UserManaged,
                USER_MANAGED,
                "[[allowed_mcp_servers]]\nserver_name = \"sdk\"\n",
            ),
        ],
    );
    assert!(blocked(&ms, "sdk"), "a user-layer grant cannot satisfy an admin managed-only lock");
}

/// A checkout the way a real install leaves it: under the install dir, with the clone's own `origin` remote.
fn write_origin(path: &Path, url: &str) {
    std::fs::create_dir_all(path.join(".git")).unwrap();
    std::fs::write(
        path.join(".git").join("config"),
        format!("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"),
    )
    .unwrap();
}

fn installed(dir: &Path, key: &str, url: &str, plugin: &str) -> fuigo_agent::plugins::install_registry::InstalledRepo {
    let path = dir.join("installed-plugins").join(key);
    write_origin(&path, url);
    fuigo_agent::plugins::install_registry::InstalledRepo {
        kind: fuigo_agent::plugins::install_registry::InstallKind::Git {
            url: url.to_string(),
            git_ref: None,
            commit: "0".repeat(40),
            subdir: None,
        },
        installed_at: String::new(),
        updated_at: String::new(),
        path,
        plugins: std::collections::HashMap::from([(
            plugin.to_string(),
            fuigo_agent::plugins::install_registry::RepoPlugin {
                subdir: None,
                version: None,
            },
        )]),
        marketplace: None,
    }
}

/// P169 (Grok 4.7 #1): the load restriction lists exactly the installs from allowed sources, by full id; unrestricted
/// marketplaces give no restriction at all.
#[test]
fn plugin_load_restriction_lists_only_allowed_installs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry =
        fuigo_agent::plugins::InstallRegistry::empty(tmp.path().join("installed-plugins"));
    let good = installed(tmp.path(), "good", "https://github.com/a/b.git", "demo");
    let bad = installed(tmp.path(), "bad", "https://github.com/evil/x.git", "evil");
    let good_id = good.plugin_id("demo").unwrap();
    registry.insert("good".into(), good);
    registry.insert("bad".into(), bad);

    let unrestricted = layered(None, &[]);
    assert_eq!(
        unrestricted
            .marketplace_allowlist
            .plugin_load_restriction(&registry),
        None
    );

    let ms = layered(
        Some(serde_json::json!({"strictKnownMarketplaces": [{"source": "github", "repo": "a/b"}]})),
        &[],
    );
    let restriction = ms
        .marketplace_allowlist
        .plugin_load_restriction(&registry)
        .expect("restricted");
    assert_eq!(restriction.allowed_ids, vec![good_id]);
    assert!(restriction.allowed_ids.iter().all(|id| id.starts_with("user/")));

    let lockdown = layered(Some(serde_json::json!({"strictKnownMarketplaces": []})), &[]);
    assert_eq!(
        lockdown
            .marketplace_allowlist
            .plugin_load_restriction(&registry)
            .map(|r| r.allowed_ids),
        Some(Vec::new()),
        "a marketplace lockdown loads no plugin"
    );
}

fn allowed_ab() -> ManagedSettings {
    layered(
        Some(serde_json::json!({"strictKnownMarketplaces": [{"source": "github", "repo": "a/b"}]})),
        &[],
    )
}

fn load_ids(ms: &ManagedSettings, registry: &fuigo_agent::plugins::InstallRegistry) -> Vec<String> {
    ms.marketplace_allowlist
        .plugin_load_restriction(registry)
        .expect("restricted")
        .allowed_ids
}

/// Round 6 (Grok r5 MEDIUM): the install record is user-writable, so its recorded source cannot admit a checkout the
/// user placed outside the install dir (the audit's `/tmp/evil` example).
#[test]
fn plugin_load_restriction_ignores_a_record_pointing_outside_the_install_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry =
        fuigo_agent::plugins::InstallRegistry::empty(tmp.path().join("installed-plugins"));
    let ok = installed(tmp.path(), "ok", "https://github.com/a/b.git", "demo");
    let ok_id = ok.plugin_id("demo").unwrap();
    registry.insert("ok".into(), ok);
    // Forged record: the allowed source string, but the path is the user's own directory.
    let mut forged = installed(tmp.path(), "scratch", "https://github.com/a/b.git", "evil");
    forged.path = tmp.path().join("evil");
    write_origin(&forged.path, "https://github.com/a/b.git");
    registry.insert("forged".into(), forged);
    assert_eq!(load_ids(&allowed_ab(), &registry), vec![ok_id]);
}

/// A symlink inside the install dir that leaves it is outside it.
#[cfg(unix)]
#[test]
fn plugin_load_restriction_ignores_a_symlink_out_of_the_install_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry =
        fuigo_agent::plugins::InstallRegistry::empty(tmp.path().join("installed-plugins"));
    let mut forged = installed(tmp.path(), "scratch", "https://github.com/a/b.git", "evil");
    let outside = tmp.path().join("outside");
    write_origin(&outside, "https://github.com/a/b.git");
    let link = tmp.path().join("installed-plugins").join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    forged.path = link;
    registry.insert("link".into(), forged);
    assert!(load_ids(&allowed_ab(), &registry).is_empty());
}

/// A git install must still be the clone of the recorded URL: the checkout's own `origin` has to agree with the record.
#[test]
fn plugin_load_restriction_requires_the_checkout_origin_to_match_the_record() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry =
        fuigo_agent::plugins::InstallRegistry::empty(tmp.path().join("installed-plugins"));
    let genuine = installed(tmp.path(), "genuine", "https://github.com/a/b.git", "demo");
    let genuine_id = genuine.plugin_id("demo").unwrap();
    registry.insert("genuine".into(), genuine);
    // The record says the allowed URL; the checkout is a clone of somewhere else.
    let swapped = installed(tmp.path(), "swapped", "https://github.com/a/b.git", "swapped");
    write_origin(&swapped.path, "https://github.com/evil/x.git");
    registry.insert("swapped".into(), swapped);
    // The record says the allowed URL; the directory is not a git checkout at all.
    let bare = installed(tmp.path(), "bare", "https://github.com/a/b.git", "bare");
    std::fs::remove_dir_all(bare.path.join(".git")).unwrap();
    registry.insert("bare".into(), bare);
    assert_eq!(load_ids(&allowed_ab(), &registry), vec![genuine_id]);
}

fn restricted_registry(tmp: &Path) -> fuigo_agent::plugins::InstallRegistry {
    fuigo_agent::plugins::InstallRegistry::empty(tmp.join("installed-plugins"))
}

fn provenance(url: &str) -> fuigo_agent::plugins::install_registry::MarketplaceProvenance {
    fuigo_agent::plugins::install_registry::MarketplaceProvenance {
        source_url_or_path: url.to_string(),
        source_display_name: "m".to_string(),
        plugin_subdir: "plugins/pwn".to_string(),
    }
}

/// Round 7 (grok-p169-r6.md MEDIUM 1): a `Local` record inside the install dir whose `marketplace.source_url_or_path`
/// names an allowed URL. No checkout origin was ever compared with that string, so it must not admit the plugin.
#[test]
fn plugin_load_restriction_ignores_a_local_record_with_forged_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry = restricted_registry(tmp.path());
    let mut forged = installed(tmp.path(), "pwn", "https://github.com/a/b.git", "pwn");
    forged.kind = fuigo_agent::plugins::install_registry::InstallKind::Local {
        source_path: tmp.path().join("my-own-dir"),
        subdir: None,
    };
    forged.marketplace = Some(provenance("https://github.com/a/b.git"));
    registry.insert("pwn".into(), forged);
    assert!(load_ids(&allowed_ab(), &registry).is_empty());
}

/// Round 7 (same finding, Git form): the origin equals the record's `url` (any URL the user writes) while the
/// provenance string names the allowed one. The allowlist sees the origin, which is not allowed.
#[test]
fn plugin_load_restriction_judges_the_checkout_origin_not_the_provenance_string() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry = restricted_registry(tmp.path());
    let mut forged = installed(tmp.path(), "pwn", "https://github.com/evil/x.git", "pwn");
    forged.marketplace = Some(provenance("https://github.com/a/b.git"));
    registry.insert("pwn".into(), forged);
    assert!(load_ids(&allowed_ab(), &registry).is_empty());
}

/// Round 7 (LOW, normaliser): the origin check uses the policy's normaliser, so a differently-cased origin of the same
/// repository is the same repository (it was a false reject).
#[test]
fn plugin_origin_check_uses_the_policy_normaliser() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry = restricted_registry(tmp.path());
    let repo = installed(tmp.path(), "ok", "https://github.com/a/b.git", "demo");
    write_origin(&repo.path, "HTTPS://GitHub.com/A/B.git");
    let id = repo.plugin_id("demo").unwrap();
    registry.insert("ok".into(), repo);
    assert_eq!(load_ids(&allowed_ab(), &registry), vec![id]);
}

/// Round 7 (grok-p169-r6.md MEDIUM 2): a plugin `subdir` that is a symlink out of the install dir. The canonical
/// plugin root, not just `repo.path`, must be confined.
#[cfg(unix)]
#[test]
fn plugin_load_restriction_ignores_a_subdir_symlink_out_of_the_install_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry = restricted_registry(tmp.path());
    let mut repo = installed(tmp.path(), "stub", "https://github.com/a/b.git", "evil");
    let outside = tmp.path().join("evil-target");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("plugin.json"), r#"{"name": "evil"}"#).unwrap();
    std::os::unix::fs::symlink(&outside, repo.path.join("escape")).unwrap();
    repo.plugins.get_mut("evil").unwrap().subdir = Some("escape".to_string());
    assert_eq!(repo.plugin_id("evil"), None, "the id of a root outside the install dir is never minted");
    registry.insert("stub".into(), repo);
    assert!(load_ids(&allowed_ab(), &registry).is_empty());
}

/// Round 7 guard: the honest marketplace copy still loads. A `Local` install with provenance is bound to the checkout
/// it was copied from, whose origin names the allowed marketplace source; the allowlist sees that origin.
#[test]
fn plugin_load_restriction_admits_a_marketplace_copy_bound_to_its_source_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let mut registry = restricted_registry(tmp.path());
    let src = tmp.path().join("cache").join("market");
    write_origin(&src, "https://github.com/a/b.git");
    let mut copy = installed(tmp.path(), "copy", "https://github.com/a/b.git", "demo");
    std::fs::remove_dir_all(copy.path.join(".git")).unwrap();
    copy.kind = fuigo_agent::plugins::install_registry::InstallKind::Local {
        source_path: src.join("plugins").join("demo"),
        subdir: None,
    };
    copy.marketplace = Some(provenance("https://github.com/a/b.git"));
    let id = copy.plugin_id("demo").unwrap();
    registry.insert("copy".into(), copy.clone());
    assert_eq!(load_ids(&allowed_ab(), &registry), vec![id]);
    // Same record, but the source checkout's origin is somewhere else: refused.
    write_origin(&src, "https://github.com/evil/x.git");
    assert!(load_ids(&allowed_ab(), &registry).is_empty());
}

/// Round 8 (grok-p169-r7.md LOW): a checkout or subdir that does not canonicalize has no plugin root.
#[test]
fn plugin_root_is_none_when_the_path_does_not_canonicalize() {
    let tmp = tempfile::tempdir().unwrap();
    let mut repo = installed(tmp.path(), "stub", "https://github.com/a/b.git", "demo");
    assert!(repo.plugin_root("demo").is_some(), "guard: an existing checkout has a root");
    repo.plugins.get_mut("demo").unwrap().subdir = Some("missing".to_string());
    assert_eq!(repo.plugin_root("demo"), None, "subdir that does not exist");
    repo.plugins.get_mut("demo").unwrap().subdir = Some("/no/such/absolute/dir".to_string());
    assert_eq!(repo.plugin_root("demo"), None, "absolute subdir replaces the checkout path");
    repo.plugins.get_mut("demo").unwrap().subdir = None;
    repo.path = tmp.path().join("gone");
    assert_eq!(repo.plugin_root("demo"), None, "checkout that does not exist");
}

// ---- P183 round 10 (Grok r6 H): an admin entry replaced by a non-regular object, read through the real source reader ----------

fn mkfifo_at(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
}

/// The audit's sequence at the policy-engine boundary: each replacement object is an `Err` source (never absent or blank), so
/// the engine locks MCP, hooks and project MCP; with a validated copy it enforces the copy (no blanket deny) and without one
/// it denies every tool. A directory whose entry a group/other can write is the same.
#[test]
fn replaced_admin_entry_is_a_broken_source_the_engine_locks_down_p183r10() {
    use std::os::unix::fs::PermissionsExt as _;
    for name in ["requirements.toml", "managed_config.toml"] {
        for kind in ["dev-null", "fifo", "directory", "dangling", "writable-parent"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(name);
            match kind {
                "dev-null" => std::os::unix::fs::symlink("/dev/null", &path).unwrap(),
                "fifo" => mkfifo_at(&path),
                "directory" => std::fs::create_dir(&path).unwrap(),
                "dangling" => std::os::unix::fs::symlink("/nonexistent-p183r10/x", &path).unwrap(),
                _ => {
                    std::fs::write(&path, "allow_managed_hooks_only = false\n").unwrap();
                    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
                }
            }
            let d = dir.path().to_path_buf();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(policy_sources_at(Some(&d), None, None, None));
            });
            let sources = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("{name} {kind}: reading blocked"));
            assert!(
                sources.iter().any(|s| s.path == path && s.policy.is_err()),
                "{name} {kind}: must be an Err source, got {sources:?}"
            );
            let locked = resolve_managed_settings_with(sources.clone(), |_| None);
            assert!(tool_denied(&locked, ToolFilter::Bash), "{name} {kind}: no copy denies every tool");
            assert!(locked.non_managed_hooks.is_disabled(), "{name} {kind}");
            let kept = resolve_managed_settings_with(sources, |_| Some(serde_json::Value::Null));
            assert!(!tool_denied(&kept, ToolFilter::Edit), "{name} {kind}: the copy, not a blanket deny");
            assert!(kept.non_managed_hooks.is_disabled(), "{name} {kind}");
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

/// The cache case: the same sources with and without a validated copy must not share an answer.
#[test]
fn managed_settings_cache_key_changes_with_copy_existence_p183r10() {
    let src = PolicySource {
        tier: PolicyLayerTier::SystemRequirements,
        ownership: PolicyLayerTier::SystemRequirements.ownership(),
        path: PathBuf::from(SYS_REQ),
        policy: Err("not a regular file".to_string()),
    };
    let with = crate::permission::resolution::managed_settings_cache_key(std::slice::from_ref(&src), |_| Some(1));
    let without = crate::permission::resolution::managed_settings_cache_key(std::slice::from_ref(&src), |_| None);
    assert_ne!(with, without);
    assert_eq!(
        with,
        crate::permission::resolution::managed_settings_cache_key(std::slice::from_ref(&src), |_| Some(1))
    );
    // P183 round 11 (Grok r7 H1): a REPLACED copy (same existence, other text) is another key
    assert_ne!(
        with,
        crate::permission::resolution::managed_settings_cache_key(std::slice::from_ref(&src), |_| Some(2))
    );
}

/// P183 round 11 (Grok r7 H1) end to end: v1 remembered, stricter v2 read and in force, the file breaks: the engine enforces
/// v2's rules (not v1's) and the cache is not served from v1.
#[test]
fn claude_file_break_after_a_newer_valid_read_enforces_the_newer_rules_p183r11() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed-settings.json");
    let v1 = r#"{"permissions":{"deny":["Bash(rm:*)"]}}"#;
    let v2 = r#"{"permissions":{"deny":["Bash(rm:*)","Bash(curl:*)"]}}"#;
    let src = |policy| PolicySource {
        tier: PolicyLayerTier::Vendor,
        ownership: PolicyLayerTier::Vendor.ownership(),
        path: path.clone(),
        policy,
    };
    std::fs::write(&path, v1).unwrap();
    let first = policy_sources_at(None, None, Some(&path), None);
    assert!(first.iter().all(|s| s.policy.is_ok()));
    let id1 = fuigo_config::admin_requirements_copy_id(&path);
    // v2 is read by the policy-sources reader (the live success path)
    std::fs::write(&path, v2).unwrap();
    let live = fuigo_config::policy_sources::policy_sources_at(None, None, Some(&path), None);
    assert!(live.iter().all(|s| s.policy.is_ok()));
    assert_ne!(fuigo_config::admin_requirements_copy_id(&path), id1);
    // the file breaks
    let broken = src(Err("unreadable".to_string()));
    let ms = load_managed_settings_from(vec![broken.clone()]);
    let denies = format!("{:?}", ms.permissions);
    assert!(denies.contains("curl"), "v2's rule must be enforced: {denies}");
    let k1 = crate::permission::resolution::managed_settings_cache_key(std::slice::from_ref(&broken), fuigo_config::admin_requirements_copy_id);
    std::fs::write(&path, v1).unwrap();
    let _ = policy_sources_at(None, None, Some(&path), None);
    let k2 = crate::permission::resolution::managed_settings_cache_key(std::slice::from_ref(&broken), fuigo_config::admin_requirements_copy_id);
    assert_ne!(k1, k2, "a replaced copy must not be served from the cache");
}

/// P183 round 12 (Grok r8) sequence 1: the validated Claude file denies Bash; it is rewritten (valid JSON, malformed
/// `permissions.deny`): the engine's next read is `Err`, still denies Bash from the copy, and locks MCP and hooks down.
/// With no validated copy every tool is denied.
#[test]
fn partly_invalid_claude_file_keeps_the_copy_and_locks_down_p183r12() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed-settings.json");
    std::fs::write(&path, r#"{"permissions":{"deny":["Bash"]}}"#).unwrap();
    let ok = load_managed_settings_from(policy_sources_at(None, None, Some(&path), None));
    assert!(tool_denied(&ok, ToolFilter::Bash));
    for bad in [
        r#"{"permissions":{"deny":"Bash"}}"#,
        r#"{"permissions":{"deny":[]},"allowedMcpServers":{}}"#,
    ] {
        std::fs::write(&path, bad).unwrap();
        let sources = policy_sources_at(None, None, Some(&path), None);
        assert!(sources.iter().all(|s| s.policy.is_err()), "{bad}");
        let ms = load_managed_settings_from(sources);
        assert!(tool_denied(&ms, ToolFilter::Bash), "{bad}: the copy's Bash deny must hold");
        assert!(ms.non_managed_hooks.is_disabled(), "{bad}");
        assert!(ms.project_mcp.is_disabled(), "{bad}");
    }
    // no validated copy: deny every tool
    let fresh = dir.path().join("fresh").join("managed-settings.json");
    std::fs::create_dir_all(fresh.parent().unwrap()).unwrap();
    std::fs::write(&fresh, r#"{"permissions":{"deny":"Bash"}}"#).unwrap();
    let ms = load_managed_settings_from(policy_sources_at(None, None, Some(&fresh), None));
    assert!(tool_denied(&ms, ToolFilter::Bash) && tool_denied(&ms, ToolFilter::Any));
    assert!(ms.non_managed_hooks.is_disabled());
}

/// P183 round 12 sequence 3: an MDM payload with a wrong-typed key (through the `mdm_override` seam) is broken for the
/// requirements reader and the policy engine alike; hooks-only engages.
#[test]
fn wrong_typed_mdm_payload_is_broken_on_both_paths_p183r12() {
    let v: toml::Value = toml::from_str("allow_managed_hooks_only = false\n[ui]\nyolo = \"no\"\n").unwrap();
    let _g = fuigo_config::mdm_override::set(Ok(Some(v.clone())));
    let sources = policy_sources_at(None, None, None, Some(Ok(v)));
    assert!(sources.iter().any(|s| s.tier == PolicyLayerTier::Mdm && s.policy.is_err()));
    let ms = load_managed_settings_from(sources);
    assert!(ms.non_managed_hooks.is_disabled());
    assert!(tool_denied(&ms, ToolFilter::Bash), "no copy of an MDM payload: every tool is denied");
}

fn engine_for(system_dir: Option<&Path>, claude: Option<&Path>) -> ManagedSettings {
    load_managed_settings_from(policy_sources_at(system_dir, None, claude, None))
}

/// P183 round 13 (Grok r9 M1) sequence 1: a validated Claude file denies Bash; a read that catches it blank while a writer is
/// still at it (unstable) keeps the copy, so Bash stays denied; only a STABLE blank from the trusted file clears it.
#[test]
fn unstable_claude_blank_keeps_the_copy_stable_blank_clears_it_p183r13() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed-settings.json");
    std::fs::write(&path, r#"{"permissions":{"deny":["Bash"]}}"#).unwrap();
    assert!(tool_denied(&engine_for(None, Some(&path)), ToolFilter::Bash));
    std::fs::write(&path, "").unwrap();
    // The writer is played at the re-check wait itself (test seam, this thread): every re-check sees the file changed.
    let writer_path = path.clone();
    let mut n = 0usize;
    fuigo_config::blank_recheck_seam::set(Some(Box::new(move || {
        n += 1;
        let _ = std::fs::write(&writer_path, " ".repeat(n));
    })));
    let during = engine_for(None, Some(&path));
    let waits = fuigo_config::blank_recheck_seam::fired();
    fuigo_config::blank_recheck_seam::set(None);
    assert!(waits > 0, "the read never reached the blank re-check");
    assert!(tool_denied(&during, ToolFilter::Bash), "an unstable blank must keep the copy's Bash deny");
    assert!(fuigo_config::admin_requirements_copy_exists(&path));
    // the owner really emptied it: the same blank, now holding still across the re-check interval
    std::fs::write(&path, "  \n").unwrap();
    let after = engine_for(None, Some(&path));
    assert!(!tool_denied(&after, ToolFilter::Bash), "a stable trusted blank is the admin clearing the policy");
    assert!(!fuigo_config::admin_requirements_copy_exists(&path));
}

/// Round 13 (Grok r9 M2) sequence 2: the Claude file is deleted; this process keeps denying Bash. A process that never saw
/// the file (a path with no copy) has no policy.
#[test]
fn deleted_claude_file_keeps_denying_bash_p183r13() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed-settings.json");
    std::fs::write(&path, r#"{"permissions":{"deny":["Bash"]}}"#).unwrap();
    assert!(tool_denied(&engine_for(None, Some(&path)), ToolFilter::Bash));
    std::fs::remove_file(&path).unwrap();
    assert!(tool_denied(&engine_for(None, Some(&path)), ToolFilter::Bash), "the copy holds after unlink");
    assert!(tool_denied(&engine_for(None, Some(&path)), ToolFilter::Bash), "and on every later read");
    let never_seen = dir.path().join("fresh").join("managed-settings.json");
    assert!(!tool_denied(&engine_for(None, Some(&never_seen)), ToolFilter::Bash));
}

/// Round 13 sequence 3: `requirements.toml` pins managed hooks only; it is deleted; the engine still engages the hooks pin.
#[test]
fn deleted_requirements_toml_keeps_the_hooks_pin_in_the_engine_p183r13() {
    let sys = tempfile::tempdir().unwrap();
    let path = sys.path().join("requirements.toml");
    std::fs::write(&path, "allow_managed_hooks_only = true\n").unwrap();
    assert!(engine_for(Some(sys.path()), None).non_managed_hooks.is_disabled());
    std::fs::remove_file(&path).unwrap();
    assert!(engine_for(Some(sys.path()), None).non_managed_hooks.is_disabled(), "the hooks pin survives the unlink");
    let never = tempfile::tempdir().unwrap();
    assert!(!engine_for(Some(never.path()), None).non_managed_hooks.is_disabled());
}

/// Round 13 sequence 4: unlink-then-create and rename-over both end with the NEW valid file enforced on the next read, and
/// the copy holds during the gap.
#[test]
fn unlink_then_create_and_rename_over_enforce_the_new_file_p183r13() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed-settings.json");
    std::fs::write(&path, r#"{"permissions":{"deny":["Bash"]}}"#).unwrap();
    assert!(tool_denied(&engine_for(None, Some(&path)), ToolFilter::Bash));
    // unlink, gap, create (stricter)
    std::fs::remove_file(&path).unwrap();
    assert!(tool_denied(&engine_for(None, Some(&path)), ToolFilter::Bash), "gap");
    std::fs::write(&path, r#"{"permissions":{"deny":["Edit"]}}"#).unwrap();
    let ms = engine_for(None, Some(&path));
    assert!(tool_denied(&ms, ToolFilter::Edit) && !tool_denied(&ms, ToolFilter::Bash), "new file replaces the copy");
    // rename a temp file over the name: never absent
    let tmp = dir.path().join("managed-settings.json.tmp");
    std::fs::write(&tmp, r#"{"permissions":{"deny":["Bash","WebFetch"]}}"#).unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    let ms = engine_for(None, Some(&path));
    assert!(tool_denied(&ms, ToolFilter::Bash) && !tool_denied(&ms, ToolFilter::Edit));
    // the same for the TOML hooks pin
    let sys = tempfile::tempdir().unwrap();
    let req = sys.path().join("requirements.toml");
    std::fs::write(&req, "allow_managed_hooks_only = false\n").unwrap();
    assert!(!engine_for(Some(sys.path()), None).non_managed_hooks.is_disabled());
    std::fs::remove_file(&req).unwrap();
    std::fs::write(&req, "allow_managed_hooks_only = true\n").unwrap();
    assert!(engine_for(Some(sys.path()), None).non_managed_hooks.is_disabled());
}
