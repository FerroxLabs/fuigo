//! P183 round 10: test support for the sites that ask "is an admin policy source broken?" (remote fetch, crash handler,
//! worktree hints). They read the real `/etc/fuigo`; `fuigo_config::admin_root_override` and `mdm_override` (cargo feature
//! `test-seams`, dev-dependencies only, so absent from every release build) point them at a temp directory.

use fuigo_config::{admin_root_override, mdm_override};

pub(crate) struct AdminSeam {
    _dir: tempfile::TempDir,
    _root: admin_root_override::Guard,
    _mdm: mdm_override::Guard,
}

/// An admin directory whose `requirements.toml` does not parse, and no MDM payload: a broken file with no validated copy.
pub(crate) fn broken_file() -> AdminSeam {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("requirements.toml"), "[[ this is not toml\n").unwrap();
    seam(dir, Ok(None))
}

/// An empty admin directory and a forced MDM payload that does not decode.
pub(crate) fn undecodable_mdm() -> AdminSeam {
    seam(tempfile::tempdir().unwrap(), Err("the forced MDM requirements value is not valid base64".to_owned()))
}

/// An empty admin directory and a decoded MDM payload whose `[[version_overrides]]` are invalid.
pub(crate) fn mdm_with_bad_overrides() -> AdminSeam {
    let v: toml::Value = toml::from_str(
        "[diagnostics]\ncrash_handler = true\n[[version_overrides]]\nminimum_version = \"not-a-version\"\n",
    )
    .unwrap();
    seam(tempfile::tempdir().unwrap(), Ok(Some(v)))
}

/// Nothing broken: an empty admin directory and no MDM payload.
pub(crate) fn healthy() -> AdminSeam {
    seam(tempfile::tempdir().unwrap(), Ok(None))
}

fn seam(dir: tempfile::TempDir, mdm: Result<Option<toml::Value>, String>) -> AdminSeam {
    let root = admin_root_override::set(dir.path().to_path_buf());
    let mdm = mdm_override::set(mdm);
    AdminSeam { _dir: dir, _root: root, _mdm: mdm }
}
