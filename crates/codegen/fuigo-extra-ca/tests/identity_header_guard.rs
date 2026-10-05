//! P43 guard: every identity-class header name Fuigo writes is in a reviewed place.
//!
//! P43 routed every writer of `x-fuigo-user-id`, `-deployment-id`, `-agent-id`,
//! `-client-version`, `-client-identifier`, `x-userid`, `x-email` and `x-teamid` through
//! `IdentityDisclosure`. This test scans the source of `crates/` and `prod/` and counts, per
//! file, every way a new writer could spell one of those names:
//!
//! * a quoted literal of an identity name, in any letter case;
//! * a use of a `const`/`static` alias whose value is such a literal (e.g. `H_USER_ID`);
//! * a use of `IDENTITY_HEADER_NAMES` itself (iterating it could write every name);
//! * a name assembled from a fragment (`"x-fuigo-{…}"`, a bare `"x-fuigo-"` prefix).
//!
//! The per-file counts are pinned in [`EXPECTED`]. A new site, anywhere, changes a count and fails
//! here, which forces the writer to be reviewed against the P43 gate and the pin to be updated in
//! the same change. On failure the test prints the actual table, ready to paste after review.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const IDENTITY: [&str; 8] = [
    "x-fuigo-user-id",
    "x-fuigo-deployment-id",
    "x-fuigo-agent-id",
    "x-fuigo-client-version",
    "x-fuigo-client-identifier",
    "x-userid",
    "x-email",
    "x-teamid",
];

/// Reviewed per-file counts (path relative to the repo root). Every file not listed must count 0.
const EXPECTED: &[(&str, usize)] = &[
    // Reviewed at P43 (R039 §4): every writer here decides with `IdentityDisclosure`; the rest
    // are tests asserting absence or mocks reading headers (`extensions/bundle.rs`,
    // `fuigo-telemetry/src/external/providers.rs`).
    ("crates/codegen/fuigo-extra-ca/src/fluxrouter.rs", 28),
    ("crates/codegen/fuigo-file-utils/src/storage_client.rs", 7),
    ("crates/codegen/fuigo-memory/src/embedding.rs", 2),
    ("crates/codegen/fuigo-sampler/src/client.rs", 35),
    // P70b (R088): reads the `H_*` names only to leave their values OUT of the sent-credential registry
    // (`NON_CREDENTIAL_HEADERS`); it writes no header. 5 identity aliases, each imported once and listed once.
    ("crates/codegen/fuigo-sampler/src/sent_credentials.rs", 10),
    ("crates/codegen/fuigo-sampler/tests/fuigo_header_namespace_split.rs", 6),
    ("crates/codegen/fuigo-shell-session-support/src/managed_mcp.rs", 4),
    ("crates/codegen/fuigo-shell/src/agent/feedback_client.rs", 5),
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/mod.rs", 2),
    ("crates/codegen/fuigo-shell/src/agent/mvp_agent/tests.rs", 7),
    ("crates/codegen/fuigo-shell/src/agent/relay.rs", 5),
    ("crates/codegen/fuigo-shell/src/agent/subscription_check.rs", 1),
    ("crates/codegen/fuigo-shell/src/auth/device_code.rs", 3),
    ("crates/codegen/fuigo-shell/src/auth/manager/enrichment.rs", 1),
    ("crates/codegen/fuigo-shell/src/auth/oidc/protocol.rs", 1),
    ("crates/codegen/fuigo-shell/src/extensions/billing.rs", 4),
    ("crates/codegen/fuigo-shell/src/extensions/bundle.rs", 2),
    ("crates/codegen/fuigo-shell/src/extensions/consent.rs", 2),
    ("crates/codegen/fuigo-shell/src/extensions/privacy.rs", 1),
    ("crates/codegen/fuigo-shell/src/remote/client.rs", 15),
    ("crates/codegen/fuigo-shell/src/remote/client_tests.rs", 28),
    ("crates/codegen/fuigo-shell/src/remote/mod.rs", 9),
    ("crates/codegen/fuigo-shell/src/remote/model_source/oai.rs", 7),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/context_snapshot.rs", 1),
    ("crates/codegen/fuigo-shell/src/session/acp_session_impl/session_setup.rs", 2),
    ("crates/codegen/fuigo-telemetry/src/external/providers.rs", 4),
    ("crates/codegen/fuigo-telemetry/src/otel_layer/mod.rs", 14),
    ("crates/codegen/fuigo-voice/src/stt/batch.rs", 2),
    ("crates/codegen/fuigo-voice/src/stt/streaming.rs", 5),
    ("crates/codegen/fuigo-workspace/src/session/tool_config.rs", 5),
];

/// Occurrences of `word` in `line` on identifier boundaries.
fn word_count(line: &str, word: &str) -> usize {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(word)
        .filter(|(at, _)| {
            let before = line[..*at].chars().next_back();
            let after = line[at + word.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

/// `const`/`static` names whose initializer is an identity literal, e.g. `const H_USER_ID: &str = "x-fuigo-user-id";`.
fn aliases_in(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let lower = line.to_ascii_lowercase();
        if !IDENTITY.iter().any(|name| lower.contains(&format!("\"{name}\""))) {
            continue;
        }
        for keyword in ["const ", "static "] {
            if let Some(at) = line.find(keyword) {
                let name: String = line[at + keyword.len()..]
                    .trim_start()
                    .trim_start_matches("mut ")
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() && name.chars().all(|c| !c.is_ascii_lowercase()) {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// The identity-token count of one source text, given the workspace-wide alias names.
fn count_tokens(src: &str, aliases: &[String]) -> usize {
    let mut n = 0;
    for line in src.lines() {
        let lower = line.to_ascii_lowercase();
        n += IDENTITY
            .iter()
            .map(|name| lower.matches(&format!("\"{name}\"")).count())
            .sum::<usize>();
        n += lower.matches("\"x-fuigo-{").count() + lower.matches("\"x-fuigo-\"").count();
        n += word_count(line, "IDENTITY_HEADER_NAMES");
        n += aliases.iter().map(|alias| word_count(line, alias)).sum::<usize>();
    }
    n
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `(relative path, count)` for every scanned file with a non-zero count, plus the file total.
fn scan() -> (BTreeMap<String, usize>, usize) {
    let root = repo_root();
    let mut files = Vec::new();
    for top in ["crates", "prod"] {
        rust_files(&root.join(top), &mut files);
    }
    let this_file = Path::new(file!()).file_name().unwrap().to_owned();
    let sources: Vec<(String, String)> = files
        .iter()
        .filter(|path| {
            !(path.file_name() == Some(this_file.as_os_str())
                && path.parent().is_some_and(|p| p.ends_with("fuigo-extra-ca/tests")))
        })
        .filter_map(|path| {
            let rel = path.strip_prefix(&root).ok()?.to_string_lossy().replace('\\', "/");
            Some((rel, std::fs::read_to_string(path).ok()?))
        })
        .collect();
    let mut aliases: Vec<String> = sources.iter().flat_map(|(_, src)| aliases_in(src)).collect();
    aliases.sort();
    aliases.dedup();
    let counts = sources
        .iter()
        .map(|(rel, src)| (rel.clone(), count_tokens(src, &aliases)))
        .filter(|(_, n)| *n > 0)
        .collect();
    (counts, sources.len())
}

/// Positive control: the scanner sees every spelling a new writer could use.
#[test]
fn scanner_counts_every_spelling_of_an_identity_header() {
    let src = r#"
        const MY_ALIAS: &str = "X-UserId";
        fn f(b: B) -> B {
            b.header("x-email", e)
             .header(MY_ALIAS, u)
             .header(format!("x-fuigo-{}-id", k), v)
             .header(MY_ALIAS_LONGER, w)
        }
        for name in IDENTITY_HEADER_NAMES {}
        let not_one = "x-fuigo-client-mode";
    "#;
    let aliases = aliases_in(src);
    assert_eq!(aliases, vec!["MY_ALIAS".to_string()]);
    // literal "X-UserId" (1) + its alias definition (1) + "x-email" (1) + alias use (1)
    // + "x-fuigo-{" (1) + IDENTITY_HEADER_NAMES (1); MY_ALIAS_LONGER and client-mode are not tokens.
    assert_eq!(count_tokens(src, &aliases), 6);
    assert_eq!(count_tokens("let ok = \"x-fuigo-conv-id\";", &aliases), 0);
}

/// Positive control on the real tree: the walk reaches the workspace and finds the known writers.
#[test]
fn scan_reaches_the_known_writers() {
    let (counts, files) = scan();
    assert!(files > 1000, "only {files} .rs files scanned: the walk is not reaching the tree");
    for known in [
        "crates/codegen/fuigo-extra-ca/src/fluxrouter.rs",
        "crates/codegen/fuigo-sampler/src/client.rs",
        "crates/codegen/fuigo-shell/src/remote/mod.rs",
    ] {
        assert!(counts.get(known).is_some_and(|n| *n > 0), "{known} not found by the scan");
    }
}

/// The guard. A change here means a new or removed identity-header site: review it against the
/// P43 gate (`IdentityDisclosure`), then update [`EXPECTED`] from the printed table.
#[test]
fn identity_header_sites_are_exactly_the_reviewed_ones() {
    let (actual, _) = scan();
    let expected: BTreeMap<String, usize> =
        EXPECTED.iter().map(|(path, n)| ((*path).to_string(), *n)).collect();
    if actual != expected {
        let mut table = String::new();
        for (path, n) in &actual {
            table.push_str(&format!("    (\"{path}\", {n}),\n"));
        }
        let mut diff = String::new();
        for (path, n) in &actual {
            if expected.get(path) != Some(n) {
                diff.push_str(&format!("  {path}: expected {:?}, found {n}\n", expected.get(path)));
            }
        }
        for (path, n) in &expected {
            if !actual.contains_key(path) {
                diff.push_str(&format!("  {path}: expected {n}, found 0\n"));
            }
        }
        panic!(
            "identity-header sites changed (P43 guard). Review each against IdentityDisclosure:\n{diff}\nActual table:\n{table}"
        );
    }
}
