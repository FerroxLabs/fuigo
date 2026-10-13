//! Pins what Fuigo's config writers do when `config.toml` is a symlink.
//!
//! Fuigo REPLACES the link with a regular file (0600 posture, `fs_atomic::stage_atomically_keeping_mode`,
//! `fuigo-config/src/fs_atomic.rs`), for the user's file and for a project file alike; the link target is
//! never written. The edit is computed from the content read through the link, so no setting is lost.
//! Upstream's equivalent test expects the user-level writers to write THROUGH a dotfile link and keep it.
//! That difference is deliberate and is not changed here.

#![cfg(unix)]

use std::path::Path;

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn echo_server() -> fuigo_shell::util::config::McpServerConfig {
    serde_json::from_value(serde_json::json!({ "command": "/bin/echo", "args": ["hi"] }))
        .expect("stdio server config")
}

#[test]
fn config_writers_replace_a_symlink_and_never_write_its_target() {
    // One #[test] per binary: the env is process-global and `fuigo_home()` is cached.
    let home = tempfile::tempdir().expect("fuigo home");
    // SAFETY: no other threads are running yet.
    unsafe { std::env::set_var("FUIGO_HOME", home.path()) };

    let dotfiles = tempfile::tempdir().expect("dotfiles");
    let target = dotfiles.path().join("config.toml");
    let original = "[models]\ndefault = \"keep-me\"\n";
    std::fs::write(&target, original).unwrap();
    let link = fuigo_shell::util::config::user_config_path();
    assert_eq!(link, home.path().join("config.toml"));
    std::os::unix::fs::symlink(&target, &link).unwrap();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // 1. Settings save: the link is replaced, existing keys survive, the target is untouched.
            fuigo_shell::util::config::update_config(|cfg| {
                cfg.ui.simple_mode = Some(true);
            })
            .await
            .expect("settings save");
            assert!(!is_symlink(&link), "settings save replaces the link");
            let written = std::fs::read_to_string(&link).unwrap();
            assert!(
                written.contains("simple_mode = true") && written.contains("default = \"keep-me\""),
                "the new file keeps what was read through the link: {written}"
            );
            assert_eq!(original, std::fs::read_to_string(&target).unwrap());

            // 2. The same for the other user-config writers, each starting from a fresh link.
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            fuigo_shell::util::config::save_mcp_server_config_at(&link, "qa-echo", &echo_server())
                .await
                .expect("mcp add");
            assert!(!is_symlink(&link), "mcp add replaces the link");
            let written = std::fs::read_to_string(&link).unwrap();
            assert!(
                written.contains("[mcp_servers.qa-echo]") && written.contains("default = \"keep-me\""),
                "{written}"
            );
            assert_eq!(original, std::fs::read_to_string(&target).unwrap());

            std::fs::remove_file(&link).unwrap();
            std::fs::write(&target, "[mcp_servers.qa-echo]\ncommand = \"/bin/echo\"\n").unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                fuigo_shell::util::config::delete_mcp_server_config_at(&link, "qa-echo")
                    .await
                    .expect("mcp remove")
            );
            assert!(!is_symlink(&link), "mcp remove replaces the link");
            assert!(!std::fs::read_to_string(&link).unwrap().contains("qa-echo"));
            assert!(
                std::fs::read_to_string(&target).unwrap().contains("qa-echo"),
                "the link target is not written"
            );

            std::fs::remove_file(&link).unwrap();
            std::fs::write(&target, original).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            fuigo_shell::claude_import::mark_claude_imported().expect("claude import marker");
            assert!(!is_symlink(&link), "the import marker replaces the link");
            let written: toml::Value =
                toml::from_str(&std::fs::read_to_string(&link).unwrap()).expect("valid TOML");
            assert_eq!(written["claude_compat"]["imported"].as_bool(), Some(true));
            assert_eq!(written["models"]["default"].as_str(), Some("keep-me"));
            assert_eq!(original, std::fs::read_to_string(&target).unwrap());

            // 3. A link a repository committed at `.fuigo/config.toml` is replaced at the link name too.
            let repo = tempfile::tempdir().expect("repo");
            let outside = repo.path().join("outside.toml");
            let defined = "[mcp_servers.planted]\ncommand = \"/bin/echo\"\n";
            std::fs::write(&outside, defined).unwrap();
            let project_link = fuigo_shell::util::config::project_config_path(repo.path());
            std::fs::create_dir_all(project_link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&outside, &project_link).unwrap();
            assert!(
                fuigo_shell::util::config::delete_mcp_server_config_at(&project_link, "planted")
                    .await
                    .expect("project mcp remove")
            );
            assert!(!is_symlink(&project_link), "the committed link is replaced");
            assert!(!std::fs::read_to_string(&project_link).unwrap().contains("planted"));
            assert_eq!(
                defined,
                std::fs::read_to_string(&outside).unwrap(),
                "the link target outside the repo must not be written"
            );
        });
}
