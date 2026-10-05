//! Where a credential that config names by environment variable is looked up (P70a).
//!
//! The agent no longer copies the API key the user saved (`auth.json`, `fuigo/setApiKey`) into its own
//! environment, so nothing it starts inherits that key implicitly. Config that names the key EXPLICITLY still
//! gets it, from the key the shell holds in memory:
//! - by name: an MCP server's `bearer_token_env_var` / OAuth client-secret variable (`fuigo-config-types`), a
//!   model's `env_key` (shell);
//! - by reference: `${FUIGO_API_KEY}` / `$FUIGO_API_KEY` written in a config string. LATE-BOUND: config loading
//!   ([`crate::expand_env_vars_in_string`]) expands it only from the process environment (a key the user exported,
//!   exactly as before), so an unexported reference stays the literal text `${FUIGO_API_KEY}` through everything that
//!   reads, shows, records or re-saves config (diagnostics, session events, `fuigo/mcp/list`, settings saves, OAuth
//!   store identifiers, `Debug`). It is resolved with [`resolve_first_party_key_references`] only where the value is
//!   used: an MCP server's spawn (`args`, `env`) and HTTP `headers` (`fuigo-mcp`), a model's `api_key` in the
//!   runtime credential (shell), a command hook's own child environment (`fuigo-hooks`). NOT a model's
//!   `extra_headers` (they also come from the remote model catalogue and its cache), nor a URL (an MCP server's
//!   `url`, an HTTP hook's `url`: identifiers that Fuigo and its HTTP stack log, persist and list), nor an MCP
//!   server's `command` or `cwd`.
//!
//! Escapes: before the first-party name, `$$` is an escape for `$` (`$${FUIGO_API_KEY}` is the text
//! `${FUIGO_API_KEY}`; an odd run ends in a real reference). Config values are expanded in several passes (this
//! loader, MCP's second `expand_strings`, the hooks parser, finally a shell), so the escape is kept by not expanding a
//! `$`-run that precedes the name until the destination reads it. LIMITS, stated rather than guarded: a reference
//! COMPOSED from another variable (`${PREFIX}$${FUIGO_API_KEY}` with `PREFIX = "$"`) reads as a reference at the
//! destination, and a kept run inside another variable's modifier (`${OTHER:-$$FUIGO_API_KEY}`) stops that outer
//! expression from expanding. Both need the config author to write them; the key still only goes to the destination
//! that author configured.
//!
//! Nothing here writes to the process environment. Only [`FIRST_PARTY_KEY_ENV_VAR`] is resolved from memory; every
//! other name is read from the process environment exactly as before.

use std::borrow::Cow;
use std::sync::OnceLock;

/// The first-party API key's environment variable, the only reference resolved from the in-memory key store.
pub const FIRST_PARTY_KEY_ENV_VAR: &str = "FUIGO_API_KEY";

/// Process-wide resolver for a credential variable config names. The shell installs one when it holds the user's
/// saved first-party key in memory: `FUIGO_API_KEY` then answers the environment and the saved key in the order the
/// old environment copy gave them (a `fuigo/setApiKey` key, an exported key, the key loaded from `auth.json`), and
/// never a runtime key an ACP client supplied for inference. Uninstalled, names read `std::env::var`. The first
/// install wins; later calls are no-ops.
static CREDENTIAL_ENV_RESOLVER: OnceLock<fn(&str) -> Option<String>> = OnceLock::new();

/// Install the [`CREDENTIAL_ENV_RESOLVER`].
pub fn install_credential_env_resolver(resolver: fn(&str) -> Option<String>) {
    let _ = CREDENTIAL_ENV_RESOLVER.set(resolver);
}

/// The value of the credential variable `name` as config that names it should see: through the installed resolver,
/// else the process environment.
pub fn resolve_credential_env_var(name: &str) -> Option<String> {
    match CREDENTIAL_ENV_RESOLVER.get() {
        Some(resolver) => resolver(name),
        None => std::env::var(name).ok(),
    }
}

/// `text` with every plain `${FUIGO_API_KEY}` / `$FUIGO_API_KEY` replaced by the first-party key
/// ([`resolve_credential_env_var`]); every other byte, other references included, is kept. Before the name, `$$` is an
/// escape for `$`, as in the config expander: `$${FUIGO_API_KEY}` is the text `${FUIGO_API_KEY}`, `$$${FUIGO_API_KEY}`
/// is `$` and the key. With no key, or no
/// reference, `text` comes back unchanged (borrowed). For the DESTINATION of a config value only (see the module
/// docs): the returned string holds the key.
pub fn resolve_first_party_key_references(text: &str) -> Cow<'_, str> {
    if !text.contains(FIRST_PARTY_KEY_ENV_VAR) {
        return Cow::Borrowed(text);
    }
    let key = resolve_credential_env_var(FIRST_PARTY_KEY_ENV_VAR);
    read_first_party_key_references(text, key.as_deref())
}

/// [`resolve_first_party_key_references`] with the key given, for a caller that must use ONE key (a snapshot shared by
/// several values and its own records of them, or the value in force at its destination). The escapes before the
/// name are read whether or not there is a key (Astra f9 #2); with `None` a plain reference is left as written.
pub fn read_first_party_key_references<'a>(text: &'a str, key: Option<&str>) -> Cow<'a, str> {
    if !text.contains(FIRST_PARTY_KEY_ENV_VAR) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + key.map_or(0, str::len));
    let mut rest = text;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let run = rest[dollar..].bytes().take_while(|b| *b == b'$').count();
        let after = &rest[dollar + run..];
        rest = after;
        if run >= 2 && !names_first_party_key(after) {
            // Not before the first-party name: untouched.
            out.push_str(&"$".repeat(run));
            continue;
        }
        // Before the name, `$$` is an escape for `$` (as the config expander reads it, and a shell close enough: an
        // even run never expands there either), so an even run is text and an odd run ends in a reference (Astra f4
        // #1, f7 #2).
        out.push_str(&"$".repeat(run / 2));
        if run % 2 == 1 {
            match (strip_first_party_reference(after), key) {
                (Some(tail), Some(key)) => {
                    out.push_str(key);
                    rest = tail;
                }
                (Some(_), None) => out.push('$'),
                (None, _) => match strip_defaulted_first_party_reference(after) {
                    // P147: `${FUIGO_API_KEY:-default}` reads as a shell does: the key when there is one (not empty),
                    // else the default.
                    Some((default, tail)) => {
                        match key.filter(|k| !k.is_empty()) {
                            Some(key) => out.push_str(key),
                            None => out.push_str(&unescape_kept_default(default)),
                        }
                        rest = tail;
                    }
                    None => out.push('$'),
                },
            }
        }
    }
    out.push_str(rest);
    if out == text { Cow::Borrowed(text) } else { Cow::Owned(out) }
}

/// `after` (the text right after a `$`) without a leading `{FUIGO_API_KEY}`, or a leading `FUIGO_API_KEY` that ends at
/// an identifier boundary; `None` when it starts with neither.
fn strip_first_party_reference(after: &str) -> Option<&str> {
    if let Some(tail) = after.strip_prefix('{').and_then(|a| a.strip_prefix(FIRST_PARTY_KEY_ENV_VAR)) {
        return tail.strip_prefix('}');
    }
    after
        .strip_prefix(FIRST_PARTY_KEY_ENV_VAR)
        .filter(|tail| !tail.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
}

/// A kept default holds its `$` doubled (it was expanded once already, and a later load pass must not expand it again):
/// read back, `$$` is `$`.
fn unescape_kept_default(default: &str) -> String {
    default.replace("$$", "$")
}

/// `text` with every `${FUIGO_API_KEY:-default}` (odd `$`-run) replaced by its default (P147, Astra r1 #4): for the
/// places that never receive the saved key (an MCP server's `command`, `cwd` and `url`), where the default is what
/// 1.0.20 used without a key and what these places always use now. Other text is unchanged.
pub fn apply_first_party_key_defaults(text: &str) -> Cow<'_, str> {
    if !text.contains(FIRST_PARTY_KEY_ENV_VAR) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let run = rest[dollar..].bytes().take_while(|b| *b == b'$').count();
        let after = &rest[dollar + run..];
        rest = after;
        match strip_defaulted_first_party_reference(after).filter(|_| run % 2 == 1) {
            Some((default, tail)) => {
                // The run's leading pairs are escapes for `$` (Astra r2 N2), as at a destination that reads the key.
                out.push_str(&"$".repeat(run / 2));
                out.push_str(&unescape_kept_default(default));
                rest = tail;
                changed = true;
            }
            None => out.push_str(&"$".repeat(run)),
        }
    }
    out.push_str(rest);
    if changed { Cow::Owned(out) } else { Cow::Borrowed(text) }
}

/// `after` (the text right after a `$`) split as `{FUIGO_API_KEY:-<default>}`: the default (up to the first `}`, as the
/// expanders read it) and the text after the `}`; `None` for any other form.
fn strip_defaulted_first_party_reference(after: &str) -> Option<(&str, &str)> {
    let body = after.strip_prefix('{')?.strip_prefix(FIRST_PARTY_KEY_ENV_VAR)?.strip_prefix(":-")?;
    let close = body.find('}')?;
    Some((&body[..close], &body[close + 1..]))
}

/// Whether `after` (the text right after a `$`-run) names the first-party key in ANY form a shell or the expanders
/// read: `FUIGO_API_KEY`, `{FUIGO_API_KEY}`, `{FUIGO_API_KEY:-…}` and other modifiers, `{#FUIGO_API_KEY}`,
/// `{!FUIGO_API_KEY}`; the name must end at an identifier boundary.
pub fn names_first_party_key(after: &str) -> bool {
    let rest = match after.strip_prefix('{') {
        Some(inner) => inner.strip_prefix(['#', '!']).unwrap_or(inner),
        None => after,
    };
    rest.strip_prefix(FIRST_PARTY_KEY_ENV_VAR)
        .is_some_and(|tail| !tail.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
}

/// Run `expand` (a `$VAR` expander with the `$$` escape) over `input`, keeping every `$`-run of two or more that
/// precedes the first-party name (in any form, [`names_first_party_key`]) exactly as written (P70a, Astra f4 #1, f6,
/// f7 #1). Without this the escape would turn `$${FUIGO_API_KEY}` into the plain reference a destination resolves to
/// the saved key. Kept, the run reaches the destination resolver ([`read_first_party_key_references`], which
/// reads it as escapes), a shell (an even run never expands there) or a record of the config, as written; `$$` keeps
/// meaning `$` for every other name.
///
/// No masking: `input` is cut at each such run, `expand` runs on the pieces between runs and the runs are copied
/// verbatim, so no text and no expanded value can be mistaken for a kept run.
pub fn expand_keeping_escaped_first_party_references(input: &str, expand: impl FnMut(&str) -> String) -> String {
    expand_keeping_first_party_references(input, false, expand)
}

/// [`expand_keeping_escaped_first_party_references`], and with `keep_defaulted` also a `${FUIGO_API_KEY:-default}`
/// reference (P147): the expander would replace it with its default whenever `FUIGO_API_KEY` is not exported, so a
/// trusted config that writes it would never get the saved key. Kept (its default expanded), it is read where the value
/// is used, as the plain reference is ([`read_first_party_key_references`]): the key when there is one, else the
/// default. The loader passes `keep_defaulted` only when the key is not exported (an exported key is expanded at load,
/// as before).
pub fn expand_keeping_first_party_references(
    input: &str,
    keep_defaulted: bool,
    mut expand: impl FnMut(&str) -> String,
) -> String {
    if !input.contains(FIRST_PARTY_KEY_ENV_VAR) || (!input.contains("$$") && !keep_defaulted) {
        return expand(input);
    }
    let mut out = String::with_capacity(input.len());
    let (mut piece_start, mut pos, mut cut) = (0, 0, false);
    while let Some(offset) = input[pos..].find('$') {
        let dollar = pos + offset;
        let run = input[dollar..].bytes().take_while(|b| *b == b'$').count();
        let after = dollar + run;
        if run >= 2 && names_first_party_key(&input[after..]) {
            let mut piece = expand(&input[piece_start..dollar]);
            // P118 (K13, Astra f8 #1): a `$` that ENDS the expanded piece came from an expansion (a literal one would
            // have been part of this run), so it must stay text next to the kept run: double it, or the alias
            // `${PREFIX}` with `PREFIX = "$"` would turn `$${FUIGO_API_KEY}` into `$$${FUIGO_API_KEY}`, a reference.
            let trailing = piece.bytes().rev().take_while(|b| *b == b'$').count();
            piece.push_str(&"$".repeat(trailing));
            out.push_str(&piece);
            out.push_str(&input[dollar..after]);
            piece_start = after;
            cut = true;
        } else if keep_defaulted
            && run == 1
            && let Some((default, _)) = strip_defaulted_first_party_reference(&input[after..])
            && let Some(expanded_default) = Some(expand(default)).filter(|d| !d.contains('}'))
        {
            // P147: keep `${FUIGO_API_KEY:-<default>}` for the destination, with its default expanded now (as the
            // expander would have). A `$` ending the piece before it stays text (doubled), as next to a kept run.
            let mut piece = expand(&input[piece_start..dollar]);
            let trailing = piece.bytes().rev().take_while(|b| *b == b'$').count();
            piece.push_str(&"$".repeat(trailing));
            out.push_str(&piece);
            out.push_str(&input[dollar..after]);
            out.push('{');
            out.push_str(FIRST_PARTY_KEY_ENV_VAR);
            out.push_str(":-");
            // Doubled, so a later load pass (MCP's `expand_strings`) does not expand it a second time (Astra r1 #3).
            out.push_str(&expanded_default.replace('$', "$$"));
            out.push('}');
            let close = after + 1 + FIRST_PARTY_KEY_ENV_VAR.len() + 2 + default.len();
            piece_start = close + 1;
            pos = close + 1;
            cut = true;
            continue;
        } else if run % 2 == 1
            && input[after..].starts_with('{')
            && let Some(close) = input[after..].find('}')
        {
            // P118 (K13, Astra f8 #3): a run inside another variable's braced expression (`${OTHER:-$$FUIGO_API_KEY}`)
            // must not cut that expression in two. The whole expression, up to its first `}` as the expanders read it,
            // goes to the expander as one piece, which keeps its default literal.
            pos = after + close + 1;
            continue;
        }
        pos = after;
    }
    if !cut {
        return expand(input);
    }
    out.push_str(&expand(&input[piece_start..]));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolver this test binary installs: it answers every name, so a test can tell whether it was consulted.
    fn answers_everything(name: &str) -> Option<String> {
        Some(format!("p70a-resolved-FAKE:{name}"))
    }

    /// P70a follow-up, late binding: loading config never resolves `${FUIGO_API_KEY}` from memory (only from the
    /// process environment, as before), so an unexported reference stays literal in config; the destination resolves
    /// it with `resolve_first_party_key_references`, which touches only the plain first-party spellings (not a longer
    /// name, not the legacy `FUIGO_CODE_API_KEY`, not other variables). Nothing is written to the process
    /// environment (`std::env::vars`, and `/proc/self/environ` on Linux, which shows only the environment the process
    /// started with).
    #[test]
    fn first_party_key_references_stay_literal_in_config_and_resolve_at_the_destination() {
        install_credential_env_resolver(answers_everything);
        assert!(
            std::env::var_os(FIRST_PARTY_KEY_ENV_VAR).is_none(),
            "precondition: FUIGO_API_KEY is not exported to this test"
        );
        let resolved = "p70a-resolved-FAKE:FUIGO_API_KEY";
        // Config loading: the reference survives, so no record of config holds the key.
        assert_eq!(crate::expand_env_vars_in_string("Bearer ${FUIGO_API_KEY}"), "Bearer ${FUIGO_API_KEY}");
        let mut table: toml::Value = toml::from_str(
            "[mcp_servers.s]\ncommand = \"x\"\nenv = { FUIGO_API_KEY = \"${FUIGO_API_KEY}\" }\n",
        )
        .expect("toml");
        crate::expand_env_vars_in_toml(&mut table);
        assert_eq!(table["mcp_servers"]["s"]["env"]["FUIGO_API_KEY"].as_str(), Some("${FUIGO_API_KEY}"));
        // Astra f4 #1, f6, f7: a `$`-run before the name is kept as written by loading (also over a second pass, as MCP
        // strings get); at the destination `$$` there is an escape for `$`, so an even run is text and an odd run ends
        // in the key. `$$` keeps meaning `$` for every other name.
        for (written, at_destination) in [
            ("$${FUIGO_API_KEY}", "${FUIGO_API_KEY}".to_owned()),
            ("$$FUIGO_API_KEY", "$FUIGO_API_KEY".to_owned()),
            ("x$${FUIGO_API_KEY}y", "x${FUIGO_API_KEY}y".to_owned()),
            ("$${FUIGO_API_KEY:-fallback}", "${FUIGO_API_KEY:-fallback}".to_owned()),
            ("$${#FUIGO_API_KEY}", "${#FUIGO_API_KEY}".to_owned()),
            ("$$$$FUIGO_API_KEY", "$$FUIGO_API_KEY".to_owned()),
            ("$$${FUIGO_API_KEY}", format!("${resolved}")),
            ("\u{E000}\u{F8FF} $${FUIGO_API_KEY}", "\u{E000}\u{F8FF} ${FUIGO_API_KEY}".to_owned()),
        ] {
            let loaded = crate::expand_env_vars_in_string(written);
            assert_eq!(loaded, written, "loading changed an escaped reference");
            assert_eq!(crate::expand_env_vars_in_string(&loaded), written, "a second pass changed it");
            assert_eq!(resolve_first_party_key_references(&loaded), at_destination, "{written}");
        }
        assert_eq!(crate::expand_env_vars_in_string("$$P70A_FOLLOWUP_OTHER"), "$P70A_FOLLOWUP_OTHER");
        assert_eq!(
            resolve_first_party_key_references("a$${FUIGO_API_KEY}b${FUIGO_API_KEY}"),
            format!("a${{FUIGO_API_KEY}}b{resolved}")
        );
        // The destination.
        assert_eq!(resolve_first_party_key_references("${FUIGO_API_KEY}"), resolved);
        assert_eq!(
            resolve_first_party_key_references("Bearer $FUIGO_API_KEY;k=${FUIGO_API_KEY}"),
            format!("Bearer {resolved};k={resolved}")
        );
        for untouched in [
            "$FUIGO_API_KEY_2",
            "${FUIGO_API_KEY_2}",
            "$FUIGO_CODE_API_KEY",
            "${OTHER} $OTHER $$ $ $$OTHER",
            "FUIGO_API_KEY",
            "no reference",
        ] {
            assert!(
                matches!(resolve_first_party_key_references(untouched), Cow::Borrowed(s) if s == untouched),
                "{untouched}"
            );
        }
        assert!(
            !std::env::vars().any(|(_, v)| v.contains("p70a-resolved-FAKE")),
            "resolving wrote to the process environment"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !String::from_utf8_lossy(&std::fs::read("/proc/self/environ").expect("environ"))
                .contains("p70a-resolved-FAKE")
        );
    }
}
