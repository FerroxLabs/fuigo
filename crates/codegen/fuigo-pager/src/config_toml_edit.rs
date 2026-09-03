//! Load `config.toml` as a [`toml_edit::DocumentMut`] for in-place edits.
//! A non-blank file that does not parse is left untouched (`None`).

use std::path::Path;

/// `None` means "do not write": either the file is unparseable, or it could not
/// be read at all.
///
/// The second case matters as much as the first. Every caller of this follows a
/// `Some` with an atomic whole-file replacement, so treating a hard read error
/// (EACCES, EIO) as an empty document would let a config this process cannot
/// even read be replaced by one holding only the key being set -- erasing every
/// other table in it, cleanly.
#[must_use]
pub(crate) fn read_config_document_for_edit(path: &Path) -> Option<toml_edit::DocumentMut> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "config.toml could not be read; refusing to overwrite it"
            );
            return None;
        }
    };
    match content.parse() {
        Ok(d) => Some(d),
        Err(e) => {
            if content.trim().is_empty() {
                return Some(toml_edit::DocumentMut::new());
            }
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "config.toml is not valid TOML; refusing to overwrite"
            );
            None
        }
    }
}

/// Set `[hints].<key>` to `value` in `~/.fuigo/config.toml`, preserving every other key and table.
/// Creates the file and parent dir when missing.
/// No-ops when the existing file is non-blank but unparseable, so a malformed config is never clobbered.
/// Performs blocking I/O.
pub(crate) fn set_hint(key: &str, value: impl Into<toml_edit::Value>) -> std::io::Result<()> {
    let path = fuigo_tools::util::fuigo_home::fuigo_home().join(fuigo_config::USER_CONFIG_FILENAME);
    set_hint_at(&path, key, value)
}

/// Core of [`set_hint`]; takes the path so tests can point it at a temp dir.
///
/// The read and the write both happen under `fuigo_config::fs_atomic`'s
/// `config.toml.lock`, so a concurrent writer that also takes that lock cannot
/// read the same original and rename its own document over this change.
/// Writers that do not take the lock still can; see `lock_config_for_write`.
///
/// The write itself is a temp-file-plus-rename rather than the `fs::write` this
/// used to do, which truncated the config in place and could leave it torn.
/// The existing file's mode is carried onto the replacement, since `rename`
/// swaps the inode; a config created here is `0600` because `config.toml`
/// supports `[model.<key>].api_key`.
fn set_hint_at(path: &Path, key: &str, value: impl Into<toml_edit::Value>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    fuigo_config::fs_atomic::locked_read_modify_write(path, || {
        let Some(mut doc) = read_config_document_for_edit(path) else {
            return Ok(());
        };
        doc["hints"][key] = toml_edit::value(value);
        fuigo_config::fs_atomic::write_atomically(
            path,
            &doc.to_string(),
            fuigo_config::fs_atomic::replacement_mode(path, 0o600),
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn merge_round_trip_preserves_sibling_tables() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(
            &path,
            "[ui]\ncompact_mode = false\n\n[mcpServers]\nx = \"y\"\n",
        )
        .unwrap();

        let mut doc = read_config_document_for_edit(&path).expect("parse");
        doc["ui"]["show_timestamps"] = toml_edit::value(false);
        fs::write(&path, doc.to_string()).unwrap();

        let body = fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("show_timestamps") && body.contains("mcpServers"),
            "expected merged TOML, got:\n{body}"
        );
    }

    #[test]
    fn nonempty_unparseable_returns_none_and_leaves_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        let bad = "this is [not valid toml\n";
        fs::write(&path, bad).unwrap();

        assert!(read_config_document_for_edit(&path).is_none());
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
    }

    #[test]
    fn missing_file_is_editable_empty_doc() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        let doc = read_config_document_for_edit(&path).expect("editable");
        assert!(!doc.contains_key("ui"));
    }

    #[test]
    fn blank_file_is_editable_empty_doc() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        for blank in ["", "   \n", "\n\t  \n"] {
            fs::write(&path, blank).unwrap();
            let doc = read_config_document_for_edit(&path)
                .unwrap_or_else(|| panic!("blank {blank:?} must be an empty document"));
            assert!(
                !doc.contains_key("ui"),
                "blank {blank:?} must not be treated as unparseable"
            );
        }
    }

    #[test]
    fn set_hint_at_round_trips_and_preserves_siblings() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ncompact_mode = false\n").unwrap();

        set_hint_at(&path, "memory_modal_fullscreen", true).unwrap();

        let doc = read_config_document_for_edit(&path).expect("reparse");
        assert_eq!(
            doc.get("hints")
                .and_then(|h| h.get("memory_modal_fullscreen"))
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert!(
            fs::read_to_string(&path).unwrap().contains("compact_mode"),
            "sibling [ui] should be preserved"
        );
    }

    #[test]
    fn set_hint_at_creates_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/config.toml");
        set_hint_at(&path, "memory_modal_fullscreen", true).unwrap();
        assert!(
            path.exists(),
            "missing file and parent dir should be created"
        );
    }

    #[test]
    fn set_hint_write_then_read_back_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ntheme = \"dark\"\n").unwrap();

        set_hint_at(&path, "memory_modal_fullscreen", true).unwrap();

        let doc = read_config_document_for_edit(&path).expect("reparse");
        let disabled = doc
            .get("hints")
            .and_then(|h| h.get("memory_modal_fullscreen"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(disabled, "should read back true after set_hint write");
    }

    /// Two hints written concurrently must BOTH survive. Without a lock across
    /// read-modify-write, both threads read the same original and the later
    /// write drops the earlier hint.
    #[test]
    fn concurrent_set_hint_at_writes_do_not_lose_each_other() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ntheme = \"dark\"\n").unwrap();
        let keys: Vec<String> = (0..8).map(|n| format!("hint_{n}")).collect();

        std::thread::scope(|scope| {
            for key in &keys {
                let path = path.clone();
                scope.spawn(move || set_hint_at(&path, key, true).unwrap());
            }
        });

        let doc = read_config_document_for_edit(&path).expect("reparse");
        for key in &keys {
            assert_eq!(
                doc.get("hints")
                    .and_then(|h| h.get(key))
                    .and_then(|v| v.as_bool()),
                Some(true),
                "{key} was lost"
            );
        }
        assert!(
            fs::read_to_string(&path).unwrap().contains("theme"),
            "the pre-existing table must survive too"
        );
    }

    /// A `chmod 600 config.toml` must survive a hint toggle: the write is now a
    /// rename, which swaps the inode, so the mode has to be re-applied.
    #[cfg(unix)]
    #[test]
    fn set_hint_at_preserves_an_existing_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ntheme = \"dark\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        set_hint_at(&path, "memory_modal_fullscreen", true).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    #[test]
    fn set_hint_at_leaves_unparseable_file_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        let bad = "this is [not valid toml\n";
        fs::write(&path, bad).unwrap();

        // No-op (no write, no clobber) when the existing file cannot be parsed.
        set_hint_at(&path, "memory_modal_fullscreen", true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
    }

    #[test]
    fn vim_mode_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ncompact_mode = false\n").unwrap();

        let mut doc = read_config_document_for_edit(&path).expect("parse");
        doc["ui"]["vim_mode"] = toml_edit::value(true);
        fs::write(&path, doc.to_string()).unwrap();

        let doc2 = read_config_document_for_edit(&path).expect("reparse");
        let enabled = doc2
            .get("ui")
            .and_then(|h| h.get("vim_mode"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(enabled, "expected vim_mode = true after round-trip");

        let body = fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("compact_mode"),
            "sibling [ui] keys should be preserved"
        );
    }
}
