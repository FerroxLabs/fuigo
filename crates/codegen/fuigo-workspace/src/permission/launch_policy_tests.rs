//! 1.0.36 item a: the launch policy loader, strict decoder, pins and session bindings (design §4, tests 1, 2, 10).

use super::*;

fn code_of(text: &str) -> (&'static str, Option<usize>) {
    match decode(text, "/p.toml") {
        Ok(rules) => panic!("expected an error, got {} rules", rules.len()),
        Err(err) => (err.code, err.line),
    }
}

fn write(dir: &Path, name: &str, text: &str) -> (String, String) {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    (path.to_string_lossy().into_owned(), sha256_hex(text.as_bytes()))
}

#[test]
fn decoder_accepts_the_grammar() {
    let rules = decode(
        r#"[permission]
ask = ["Bash", "Read", "Grep", "*", "mcp__github", "mcp__github__get_issue", "mcp__x__*", "Read(~/.ssh/**)"]
deny = ["Bash(rm *)", "WebFetch(domain:example.com)", "Edit(/etc/**)"]
allow = ["Bash(npm test)"]
rules = [{ action = "ask", tool = "webfetch", pattern = "api.example.com", pattern_mode = "domain" }, { action = "deny", tool = "any" }]
"#,
        "/p.toml",
    )
    .unwrap();
    assert_eq!(rules.len(), 14);
    assert_eq!(rules.iter().filter(|r| r.action == RuleAction::Ask).count(), 9);
    assert!(rules.iter().any(|r| r.tool == ToolFilter::Mcp && r.pattern.as_deref() == Some("github__*")));
}

#[test]
fn decoder_refuses_every_bad_file_with_its_code_and_line() {
    let (code, line) = code_of("[permission\nask = []");
    assert_eq!(code, "toml_syntax");
    assert!(line.is_some());
    assert_eq!(code_of("[permission]\nask = [\"Bash\"]\nmode = \"x\"\n").0, "unknown_key");
    assert_eq!(code_of("[permission]\nask = [\"Bash\"]\n[ui]\nx = 1\n").0, "unknown_key");
    // An unknown key inside a `rules` entry, and a misspelled `pattern`.
    assert_eq!(code_of("[permission]\nrules = [{ action = \"ask\", tool = \"bash\", extra = 1 }]\n").0, "unknown_key");
    assert_eq!(code_of("[permission]\nrules = [{ action = \"ask\", tool = \"read\", patern = \"x\" }]\n").0, "unknown_key");
    // One bad compact element beside good ones: its own line.
    assert_eq!(code_of("[permission]\nask = [\n  \"Bash\",\n  \"Read(/secret)garbage\",\n]\n"), ("bad_rule", Some(4)));
    for bad in ["Bash(x) y", "Raed", "Any", "grep", " Bash", "mcp__", "mcp__a__", "Read(/x", "NotebookEdit"] {
        assert_eq!(code_of(&format!("[permission]\ndeny = [{bad:?}]\n")).0, "bad_rule", "{bad}");
    }
    for bad in ["Read([)", "WebFetch(domain:https://x/)", "WebFetch(domain:*.x.com)", "WebFetch(domain:a b)", "WebFetch(domain:a@b)"] {
        assert_eq!(code_of(&format!("[permission]\nask = [{bad:?}]\n")), ("bad_pattern", Some(2)), "{bad}");
    }
    assert_eq!(code_of("[permission]\nrules = [{ action = \"ask\", tool = \"read\", pattern = \"[\" }]\n"), ("bad_pattern", Some(2)));
    assert_eq!(code_of("").0, "empty");
    assert_eq!(code_of("[permission]\n").0, "empty");
    assert_eq!(code_of("[permission]\nask = 5\n").0, "bad_rule");
}

#[test]
fn error_line_is_one_json_object() {
    let err = PolicyError::new("hash_missing", "/p", "m");
    let value: serde_json::Value = serde_json::from_str(&err.json_line()).unwrap();
    assert_eq!(value["policy_error"], "hash_missing");
    assert_eq!(value["path"], "/p");
    assert!(value["line"].is_null());
    let acp = serde_json::to_value(err.into_acp_error()).unwrap();
    assert_eq!(acp["code"], -32602);
    assert_eq!(acp["data"]["policy_error"], "hash_missing");
}

#[test]
fn file_safety() {
    let dir = tempfile::tempdir().unwrap();
    let (good, sha) = write(dir.path(), "good.toml", "[permission]\nask = [\"Bash\"]\n");
    assert_eq!(check_file("relative/p.toml").unwrap_err().code, "not_absolute");
    assert_eq!(check_file("").unwrap_err().code, "not_absolute");
    assert_eq!(check_file(&dir.path().join("missing").to_string_lossy()).unwrap_err().code, "not_found");
    assert_eq!(check_file(&dir.path().to_string_lossy()).unwrap_err().code, "not_regular_file");
    let big = dir.path().join("big.toml");
    std::fs::write(&big, vec![b'#'; (MAX_BYTES + 1) as usize]).unwrap();
    assert_eq!(check_file(&big.to_string_lossy()).unwrap_err().code, "too_large");
    let latin = dir.path().join("latin.toml");
    std::fs::write(&latin, b"[permission]\nask = [\"Read(/\xe9)\"]\n").unwrap();
    assert_eq!(check_file(&latin.to_string_lossy()).unwrap_err().code, "not_utf8");
    let (rules, digest) = check_file(&good).unwrap();
    assert_eq!((rules.len(), digest), (1, sha));
    #[cfg(unix)]
    {
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert_eq!(check_file(&link.to_string_lossy()).unwrap_err().code, "symlink");
        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(check_file(&fifo.to_string_lossy()).unwrap_err().code, "not_regular_file");
    }
}

#[cfg(windows)]
#[test]
fn windows_path_forms() {
    assert_eq!(check_file(r"C:x.toml").unwrap_err().code, "not_absolute");
    assert_eq!(check_file(r"\x.toml").unwrap_err().code, "not_absolute");
    assert_ne!(check_file(r"\\srv\share\x.toml").unwrap_err().code, "not_absolute");
    assert_ne!(check_file(r"\\?\C:\nope\x.toml").unwrap_err().code, "not_absolute");
}

#[test]
fn the_launcher_hash_is_the_authority_and_pins_last_the_process() {
    let dir = tempfile::tempdir().unwrap();
    let (path, sha) = write(dir.path(), "pin.toml", "[permission]\nask = [\"Read\"]\n");
    assert_eq!(verify_and_pin(&path, None).unwrap_err().code, "hash_missing");
    assert_eq!(verify_and_pin(&path, Some("abc")).unwrap_err().code, "hash_missing");
    assert_eq!(verify_and_pin(&path, Some(&"0".repeat(64))).unwrap_err().code, "hash_mismatch");
    let pinned = verify_and_pin(&path, Some(&sha.to_ascii_uppercase())).unwrap();
    assert_eq!(pinned.sha256, sha);
    assert!(is_pinned_policy_file(Path::new(&path)));
    // The file changes on disk: its new hash is refused (a new process is needed), the old hash gets the snapshot.
    let new_text = "[permission]\nallow = [\"Read\"]\n";
    std::fs::write(&path, new_text).unwrap();
    assert_eq!(verify_and_pin(&path, Some(&sha256_hex(new_text.as_bytes()))).unwrap_err().code, "hash_mismatch");
    let again = verify_and_pin(&path, Some(&sha)).unwrap();
    assert!(Arc::ptr_eq(&again, &pinned));
    assert_eq!(again.rules[0].action, RuleAction::Ask);
    // Another name for the same file finds the pin.
    #[cfg(unix)]
    {
        let hard = dir.path().join("hard.toml");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(is_pinned_policy_file(&hard));
        assert_eq!(
            verify_and_pin(&hard.to_string_lossy(), Some(&sha256_hex(new_text.as_bytes()))).unwrap_err().code,
            "hash_mismatch"
        );
    }
}

#[test]
fn session_claims_bindings_and_markers() {
    let dir = tempfile::tempdir().unwrap();
    let (path, sha) = write(dir.path(), "session.toml", "[permission]\nask = [\"Bash\"]\n");
    let claim = |p: Option<&str>, s: Option<&str>| SessionPolicyClaim { path: p.map(str::to_owned), sha256: s.map(str::to_owned) };
    // Ungoverned, nothing bound: no policy.
    assert!(resolve_session_claim(&claim(None, None), Some("u36-s-none"), None).unwrap().is_none());
    assert_eq!(resolve_session_claim(&claim(Some(&path), None), Some("u36-s1"), None).unwrap_err().code, "hash_missing");
    assert_eq!(resolve_session_claim(&claim(None, Some(&sha)), Some("u36-s1"), None).unwrap_err().code, "not_absolute");
    let policy = resolve_session_claim(&claim(Some(&path), Some(&sha)), Some("u36-s1"), None).unwrap().unwrap();
    bind_session("u36-s1", policy.binding()).unwrap();
    // A released session reloaded without the key in this process: refused (its marker deleted or not).
    assert_eq!(resolve_session_claim(&claim(None, None), Some("u36-s1"), None).unwrap_err().code, "session_policy_missing");
    // A marker alone (new process) refuses a load that omits the key; it never supplies a hash.
    let marker = policy.binding();
    assert_eq!(
        resolve_session_claim(&claim(None, None), Some("u36-s2"), Some(&marker)).unwrap_err().code,
        "session_policy_missing"
    );
    // A different file for a bound session: conflict.
    let (other, other_sha) = write(dir.path(), "other.toml", "[permission]\ndeny = [\"Bash\"]\n");
    assert_eq!(
        resolve_session_claim(&claim(Some(&other), Some(&other_sha)), Some("u36-s1"), None).unwrap_err().code,
        "session_policy_conflict"
    );
    assert!(resolve_session_claim(&claim(Some(&path), Some(&sha)), Some("u36-s1"), Some(&marker)).unwrap().is_some());
    // Resident loads: equal attaches; added, dropped or different is a conflict.
    let same = claim(Some(&path), Some(&sha));
    assert!(check_resident_claim(&same, Some(&marker)).is_ok());
    assert!(check_resident_claim(&claim(None, None), None).is_ok());
    assert_eq!(check_resident_claim(&same, None).unwrap_err().code, "session_policy_conflict");
    assert_eq!(check_resident_claim(&claim(None, None), Some(&marker)).unwrap_err().code, "session_policy_conflict");
    assert_eq!(
        check_resident_claim(&claim(Some(&other), Some(&other_sha)), Some(&marker)).unwrap_err().code,
        "session_policy_conflict"
    );
}

#[test]
fn meta_claim_parsing() {
    let mut meta = serde_json::Map::new();
    assert!(!meta_has_policy_key(Some(&meta)));
    assert!(SessionPolicyClaim::from_meta(Some(&meta)).unwrap().is_empty());
    assert!(SessionPolicyClaim::from_meta(None).unwrap().is_empty());
    meta.insert(META_PATH.to_owned(), "/x".into());
    assert!(meta_has_policy_key(Some(&meta)));
    assert_eq!(SessionPolicyClaim::from_meta(Some(&meta)).unwrap().path.as_deref(), Some("/x"));
}

/// Astra r1 #3: a policy key present with a value that is not a string is `bad_claim`, never an ungoverned session.
#[test]
fn a_non_string_claim_value_is_bad_claim_not_unset() {
    for key in [META_PATH, META_SHA256] {
        for value in [serde_json::Value::Null, 7.into(), true.into(), serde_json::json!({"p": "/x"}), serde_json::json!(["/x"])] {
            let mut meta = serde_json::Map::new();
            meta.insert(key.to_owned(), value.clone());
            let err = SessionPolicyClaim::from_meta(Some(&meta)).unwrap_err();
            assert_eq!(err.code, "bad_claim", "{key} = {value}");
            let acp = serde_json::to_value(err.into_acp_error()).unwrap();
            assert_eq!(acp["code"], -32602);
            assert_eq!(acp["data"]["policy_error"], "bad_claim");
        }
    }
    // Both keys present but null: refused too (this was the ungoverned case).
    let meta: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(serde_json::json!({ META_PATH: null, META_SHA256: null })).unwrap();
    assert_eq!(SessionPolicyClaim::from_meta(Some(&meta)).unwrap_err().code, "bad_claim");
}

/// Astra r1 #4: an empty domain is not a tool-wide rule.
#[test]
fn an_empty_domain_rule_is_bad_rule() {
    for bad in ["WebFetch(domain:)", "WebSearch(domain:)"] {
        let text = format!("[permission]\nallow = [\"Bash\"]\nask = [{bad:?}]\n");
        if let Err(err) = decode(&text, "/p.toml") {
            assert_eq!((err.code, err.line), ("bad_rule", Some(3)), "{bad}");
        } else if bad.starts_with("WebFetch") {
            panic!("{bad} accepted");
        }
    }
    assert_eq!(
        code_of("[permission]\nrules = [{ action = \"allow\", tool = \"webfetch\", pattern_mode = \"domain\" }]\n"),
        ("bad_rule", Some(2))
    );
    assert_eq!(
        code_of("[permission]\nrules = [{ action = \"allow\", tool = \"webfetch\", pattern = \"\", pattern_mode = \"domain\" }]\n"),
        ("bad_rule", Some(2))
    );
    // A named host is still accepted.
    assert_eq!(decode("[permission]\nallow = [\"WebFetch(domain:example.com)\"]\n", "/p.toml").unwrap().len(), 1);
}

/// Astra r1 #1: a session id's binding is installed once; a different binding, or an ungoverned actor for a governed
/// id, is refused at the registration step instead of replacing it.
#[test]
fn bindings_and_registration_refuse_an_incompatible_actor() {
    let a = PolicyBinding { path: "/a.toml".into(), sha256: "a".repeat(64) };
    let b = PolicyBinding { path: "/b.toml".into(), sha256: "b".repeat(64) };
    // Ungoverned ids register freely and stay unbound.
    drop(begin_registration("u36-reg-free", None).unwrap());
    drop(begin_registration("u36-reg-free", None).unwrap());
    assert!(session_binding("u36-reg-free").is_none());
    // A governed actor binds an unbound id; the same binding registers again.
    drop(begin_registration("u36-reg", Some(&a)).unwrap());
    assert_eq!(session_binding("u36-reg"), Some(a.clone()));
    drop(begin_registration("u36-reg", Some(&a)).unwrap());
    // An overlapping ungoverned request for that id, or one under another policy, is refused and changes nothing.
    assert_eq!(begin_registration("u36-reg", None).err().unwrap().code, "session_policy_missing");
    assert_eq!(begin_registration("u36-reg", Some(&b)).err().unwrap().code, "session_policy_conflict");
    assert_eq!(bind_session("u36-reg", b.clone()).unwrap_err().code, "session_policy_conflict");
    assert_eq!(session_binding("u36-reg"), Some(a.clone()));
    assert!(bind_session("u36-reg", a.clone()).is_ok());
    // Interleaving: the governed request binds (spawn) before the ungoverned one reaches its registration step.
    bind_session("u36-reg-race", a.clone()).unwrap();
    assert_eq!(begin_registration("u36-reg-race", None).err().unwrap().code, "session_policy_missing");
    // Two threads racing registration for one id: exactly one binding wins, the other is refused.
    let results: Vec<_> = [a.clone(), b.clone()]
        .into_iter()
        .map(|binding| std::thread::spawn(move || begin_registration("u36-reg-two", Some(&binding)).map(drop)))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().find_map(|r| r.as_ref().err()).unwrap().code, "session_policy_conflict");
}

/// Astra r1 #6: a hard-link alias of a pinned file is bound by the name the client asserted and reloads with it.
#[cfg(unix)]
#[test]
fn an_alias_of_a_pinned_file_reloads_with_its_own_name() {
    let dir = tempfile::tempdir().unwrap();
    let (path, sha) = write(dir.path(), "aliased.toml", "[permission]\nask = [\"Grep\"]\n");
    let pinned = verify_and_pin(&path, Some(&sha)).unwrap();
    let alias = dir.path().join("alias.toml");
    std::fs::hard_link(&path, &alias).unwrap();
    let alias = alias.to_string_lossy().into_owned();
    let claim = SessionPolicyClaim { path: Some(alias.clone()), sha256: Some(sha.clone()) };
    let policy = resolve_session_claim(&claim, Some("u36-alias"), None).unwrap().unwrap();
    // The pinned snapshot, under the asserted name.
    assert_eq!(format!("{:?}", policy.rules), format!("{:?}", pinned.rules));
    assert_eq!(policy.binding(), PolicyBinding { path: alias.clone(), sha256: sha.clone() });
    bind_session("u36-alias", policy.binding()).unwrap();
    // Reload with the identical claim: accepted, in this process and against the stored marker.
    let again = resolve_session_claim(&claim, Some("u36-alias"), Some(&policy.binding())).unwrap().unwrap();
    assert_eq!(again.binding(), policy.binding());
    assert!(check_resident_claim(&claim, session_binding("u36-alias").as_ref()).is_ok());
    // The alias is a pinned policy file too, and a new hash through it is still refused.
    assert!(is_pinned_policy_file(Path::new(&alias)));
    assert_eq!(verify_and_pin(&alias, Some(&"1".repeat(64))).unwrap_err().code, "hash_mismatch");
}

#[test]
fn unset_store_is_empty() {
    // No test installs a process policy: the store stays unset (the unset path).
    assert!(process().is_none());
    assert!(!governs(false));
    assert!(governs(true));
}
