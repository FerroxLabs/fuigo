//! P118: the two K13 expansion holes (P70a Astra f8 #1 and #3). Red first.

use crate::credential_env::{read_first_party_key_references, resolve_first_party_key_references};
use crate::expand_env_vars_in_string;

const KEY: &str = "p118-key-FAKE-7f1c";

fn with_vars<R>(vars: &[(&str, &str)], f: impl FnOnce() -> R) -> R {
    for (k, v) in vars {
        // SAFETY: uniquely named P118_* variables, set before and removed after; no other test reads them.
        unsafe { std::env::set_var(k, v) };
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, _) in vars {
        unsafe { std::env::remove_var(k) };
    }
    r.unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// f8 #1: `${PREFIX}$${FUIGO_API_KEY}` with `PREFIX = "$"` is an alias that yields `$` followed by an ESCAPED reference.
/// The escape must survive the concatenation: at the destination the text is `$` then the literal `${FUIGO_API_KEY}`,
/// never the key, and a second load pass (MCP's `expand_strings`) changes nothing.
#[test]
fn a_reference_built_from_another_variable_does_not_defeat_the_escape() {
    with_vars(&[("P118_PREFIX", "$")], || {
        let loaded = expand_env_vars_in_string("${P118_PREFIX}$${FUIGO_API_KEY}");
        let at_destination = read_first_party_key_references(&loaded, Some(KEY));
        assert!(!at_destination.contains(KEY), "the escaped reference resolved to the key: {loaded} -> {at_destination}");
        assert_eq!(at_destination, "$${FUIGO_API_KEY}");
        assert_eq!(expand_env_vars_in_string(&loaded), loaded, "a second pass changed it");
        // Same with a bare name and with text around the alias.
        let loaded = expand_env_vars_in_string("a=${P118_PREFIX}$$FUIGO_API_KEY;b");
        assert_eq!(read_first_party_key_references(&loaded, Some(KEY)), "a=$$FUIGO_API_KEY;b");
        // An alias that yields several dollars: all of them stay text.
        with_vars(&[("P118_PREFIX2", "$$")], || {
            let loaded = expand_env_vars_in_string("${P118_PREFIX2}$${FUIGO_API_KEY}");
            assert!(!read_first_party_key_references(&loaded, Some(KEY)).contains(KEY), "{loaded}");
        });
        // Control: an alias that does NOT end in `$` keeps the plain behaviour.
        with_vars(&[("P118_PREFIX3", "pre")], || {
            let loaded = expand_env_vars_in_string("${P118_PREFIX3}$${FUIGO_API_KEY}");
            assert_eq!(read_first_party_key_references(&loaded, Some(KEY)), "pre${FUIGO_API_KEY}");
        });
    });
}

/// f8 #3: a `$$` run before the name INSIDE another variable's `${X:-default}` must not cut that expression in two.
/// The expression expands as it always did: the variable's value when it is set, else the default, which is kept
/// LITERAL (the run stays, so the destination still reads it as an escape and never as the key).
#[test]
fn a_kept_run_inside_another_variables_modifier_keeps_the_default_literal() {
    with_vars(&[("P118_PLAIN", "plainval"), ("P118_OTHER", "ready")], || {
        // Set: the variable's value, as before the escape existed.
        assert_eq!(expand_env_vars_in_string("${P118_OTHER:-$$FUIGO_API_KEY}"), "ready");
        // Unset: the default, literal (its own `$P118_PLAIN` is not expanded, the run is kept).
        for (written, loaded) in [
            ("${P118_UNSET:-$$FUIGO_API_KEY}", "$$FUIGO_API_KEY"),
            ("${P118_UNSET:-$P118_PLAIN$$FUIGO_API_KEY}", "$P118_PLAIN$$FUIGO_API_KEY"),
            ("x${P118_UNSET:-$$FUIGO_API_KEY}.y", "x$$FUIGO_API_KEY.y"),
        ] {
            let got = expand_env_vars_in_string(written);
            assert_eq!(got, loaded, "{written}");
            if !written.contains("$P118_PLAIN") {
                assert_eq!(expand_env_vars_in_string(&got), got, "a second pass changed it");
            }
            assert!(!read_first_party_key_references(&got, Some(KEY)).contains(KEY), "{written} resolved to the key");
        }
        // Around it, ordinary expansion still happens.
        assert_eq!(
            expand_env_vars_in_string("$P118_PLAIN ${P118_UNSET:-$$FUIGO_API_KEY} ${P118_PLAIN}"),
            "plainval $$FUIGO_API_KEY plainval"
        );
        // Control: the escape before a plain reference works as before.
        assert_eq!(expand_env_vars_in_string("$${FUIGO_API_KEY} $P118_PLAIN"), "$${FUIGO_API_KEY} plainval");
        let _ = resolve_first_party_key_references;
    });
}
