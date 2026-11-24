//! S1 (1.0.47) differential for unrecognised ACP clients (`ClientType::Generic`): every prompt behaviour except an
//! outside change in bypass is exactly base. This file uses only APIs that exist on base `0bc521fd`, so the same test
//! runs on base and branch; `BASE` is what base printed (`S1DIFF` lines), `branch_expected` is base with the S1 rows.

use super::*;
use crate::permission::auto_mode::{ClassifierVerdict, FixedClassifier};

/// `(mode, command, decision, prompts)` as base `0bc521fd` decides them for a Generic client that answers "allow once".
const BASE: &[(&str, &str, &str, usize)] = &[
    ("default", "outside", "allow", 1),
    ("default", "inside", "allow", 1),
    ("default", "read", "allow", 0),
    ("auto", "outside", "allow", 0),
    ("auto", "inside", "allow", 0),
    ("auto", "read", "allow", 0),
    ("bypass", "outside", "allow", 0),
    ("bypass", "inside", "allow", 0),
    ("bypass", "read", "allow", 0),
];

fn branch_expected(mode: &str, cmd: &str) -> (&'static str, usize) {
    match (mode, cmd) {
        // S1: an outside change prompts in Auto (the classifier is skipped) and is refused in bypass, where base had
        // no prompt path for this client.
        ("auto", "outside") => ("allow", 1),
        ("bypass", "outside") => ("deny", 0),
        _ => BASE
            .iter()
            .find(|row| row.0 == mode && row.1 == cmd)
            .map(|row| (row.2, row.3))
            .unwrap_or(("missing", 0)),
    }
}

#[test]
fn generic_client_prompts_are_base_except_an_outside_change_in_bypass() {
    // An existing file outside every root: under `$HOME` (the lane's private home), not in a temp dir or `$FUIGO_HOME`.
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
        return;
    };
    let dir = home.join(format!("s1-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("app.db");
    std::fs::write(&db, b"precious").unwrap();
    let on_branch = ON_BRANCH;
    let mut mismatches = Vec::new();
    for mode in ["default", "auto", "bypass"] {
        for cmd in ["outside", "inside", "read"] {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (decision, prompts) = tokio::task::LocalSet::new().block_on(&rt, async {
                let tmp = tempfile::tempdir().unwrap();
                let cwd = AbsPathBuf::new(dunce::canonicalize(tmp.path()).unwrap()).unwrap();
                std::fs::write(cwd.as_path().join("app.db"), b"w").unwrap();
                let client = IdSelectingClient::new("allow-once");
                let prompts = client.prompts.clone();
                let (mgr, _events) = manager_with_recording_client_remember(
                    &cwd,
                    None,
                    client,
                    ClientType::Generic,
                    true,
                );
                match mode {
                    "bypass" => mgr.set_yolo_mode(true),
                    "auto" => {
                        mgr.set_auto_mode(true);
                        mgr.set_classifier(Some(Arc::new(FixedClassifier(
                            ClassifierVerdict::Allow,
                        ))));
                    }
                    _ => {}
                }
                let command = match cmd {
                    "outside" => format!("rm -f {}", db.display()),
                    "inside" => "rm -f app.db".to_owned(),
                    _ => "cat app.db".to_owned(),
                };
                let request = PermissionRequest {
                    path_context: Some(RequestPathContext {
                        real_cwd: cwd.as_path().to_path_buf(),
                        display_cwd: None,
                    }),
                    ..PermissionRequest::new(AccessKind::Bash(command), tool_call())
                };
                let d = agent_message_completes(mgr.request(request)).await.decision;
                let class = match d {
                    Decision::Allow => "allow",
                    _ => "deny",
                };
                (class, prompts.borrow().len())
            });
            eprintln!("S1DIFF {mode} {cmd} {decision} {prompts}");
            let expected = if on_branch {
                branch_expected(mode, cmd)
            } else {
                BASE.iter()
                    .find(|row| row.0 == mode && row.1 == cmd)
                    .map(|row| (row.2, row.3))
                    .unwrap_or(("missing", 0))
            };
            if (decision, prompts) != expected {
                mismatches.push(format!(
                    "{mode} {cmd}: got {decision}/{prompts}, want {expected:?}"
                ));
            }
        }
    }
    std::fs::remove_dir_all(&dir).ok();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

/// `false` in the copy run on base (the only line that differs).
const ON_BRANCH: bool = true;
