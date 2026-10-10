//! Bash request-level execution risk: argv flags that spawn programs, and ambient local/worktree git config.
//! Flag floors run inline; ambient git2 uses `spawn_blocking` from the permission actor.

use std::path::{Path, PathBuf};

use crate::permission::branch_switch::BranchSwitchPlan;

use crate::permission::bash_command_splitting::{
    MAX_TRANSPARENT_PREFIX_DEPTH, MAX_WRAPPER_DEPTH, TransparentPrefixPeel,
    peel_transparent_prefixes, unwrap_wrappers_checked,
};

#[cfg(test)]
use crate::permission::bash_command_splitting::{
    try_parse_shell, try_parse_word_only_commands_sequence,
};

/// Shared peel budget for nested `command env …` chains; remaining peelable layers fail closed.
const MAX_NORMALIZE_ROUNDS: usize = MAX_WRAPPER_DEPTH + MAX_TRANSPARENT_PREFIX_DEPTH;

enum NormalizedArgv<'a> {
    Ready(&'a [String]),
    FailClosed,
}

/// Alternate canonical wrappers and transparent prefixes until fixed point.
fn normalize_for_exec_risk(words: &[String]) -> NormalizedArgv<'_> {
    let mut current = words;
    for _ in 0..MAX_NORMALIZE_ROUNDS {
        let before = current;
        let checked = unwrap_wrappers_checked(current);
        if checked.exhausted || checked.has_split_string || checked.has_chdir {
            return NormalizedArgv::FailClosed;
        }
        let after_wrap = checked.words;
        let after_trans = match peel_transparent_prefixes(after_wrap) {
            TransparentPrefixPeel::Ambiguous => return NormalizedArgv::FailClosed,
            TransparentPrefixPeel::Ready(inner) => inner,
        };
        if std::ptr::eq(after_trans.as_ptr(), before.as_ptr()) && after_trans.len() == before.len()
        {
            return NormalizedArgv::Ready(after_trans);
        }
        if std::ptr::eq(after_trans.as_ptr(), after_wrap.as_ptr())
            && after_trans.len() == after_wrap.len()
        {
            return NormalizedArgv::Ready(after_trans);
        }
        current = after_trans;
    }
    NormalizedArgv::FailClosed
}

/// `min_len` is the shortest unique stem vs sibling options (e.g. sort `--co` vs `--check`).
pub(crate) fn is_accepted_long_option_prefix(flag: &str, full: &str, min_len: usize) -> bool {
    flag.starts_with("--")
        && flag.len() >= min_len
        && full.starts_with(flag)
        && flag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn normalized_program_name(words: &[String]) -> Option<String> {
    let raw = words.first()?;
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw.as_str());
    if base.is_empty() {
        return None;
    }
    let mut name = base.to_ascii_lowercase();
    if let Some(stem) = name.strip_suffix(".exe") {
        name = stem.to_owned();
    }
    Some(name)
}

/// Whether the branch-switch planner counts this raw segment as a `git` command: the planner's own predicate
/// (canonical wrappers peeled, program name `git`). `ShellWriteFacts::git_starts` uses this same function, so the two
/// ordinals cannot drift.
pub(crate) fn is_planned_git_segment(raw: &[String]) -> bool {
    matches!(normalize_for_exec_risk(raw), NormalizedArgv::Ready(inner) if normalized_program_name(inner).as_deref() == Some("git"))
}

fn is_git_program(words: &[String]) -> bool {
    normalized_program_name(words).as_deref() == Some("git")
}

fn is_sort_program(words: &[String]) -> bool {
    normalized_program_name(words).as_deref() == Some("sort")
}

fn normalized_token_basename(token: &str) -> String {
    let base = token.rsplit(['/', '\\']).next().unwrap_or(token);
    let mut name = base.to_ascii_lowercase();
    if let Some(stem) = name.strip_suffix(".exe") {
        name = stem.to_owned();
    }
    name
}

/// GNU `sort --compress-program`; stops at `--`. Min stem `--co` vs `--check`.
fn sort_has_compress_program_flag(words: &[String]) -> bool {
    for w in words.iter().skip(1) {
        if w == "--" {
            break;
        }
        if w == "--compress-program" || w.starts_with("--compress-program=") {
            return true;
        }
        let flag = w.split_once('=').map(|(f, _)| f).unwrap_or(w.as_str());
        if is_accepted_long_option_prefix(flag, "--compress-program", 4) {
            return true;
        }
    }
    false
}

pub(crate) fn is_git_config_env_flag(tok: &str) -> bool {
    if tok == "--config-env" || tok.starts_with("--config-env=") {
        return true;
    }
    let flag = tok.split_once('=').map(|(f, _)| f).unwrap_or(tok);
    // Sole git global `--config*`; min stem `--co` (len 4).
    is_accepted_long_option_prefix(flag, "--config-env", 4)
}

/// Presence fails closed: these retarget which config git reads.
pub(crate) fn is_git_repo_retarget_flag(tok: &str) -> bool {
    if tok == "--git-dir"
        || tok.starts_with("--git-dir=")
        || tok == "--work-tree"
        || tok.starts_with("--work-tree=")
    {
        return true;
    }
    let flag = tok.split_once('=').map(|(f, _)| f).unwrap_or(tok);
    // git.c globals: `--gi` unique vs `--glob-pathspecs`; `--wor` sole `--wor*`.
    // P166 r9: `--exec-path[=<dir>]` makes git run its sub-programs (and `git-<verb>` helpers) from another directory;
    // git accepts it down to `--exec-p` (`--exec` is ambiguous with nothing, but the stem below stays one past it).
    // `--namespace`, `--super-prefix` and `--list-cmds` only name a ref namespace, prefix output paths, or print: not
    // retargets, deliberately NOT flagged (tests: `git_exec_risk_r9_harmless_globals`).
    is_accepted_long_option_prefix(flag, "--git-dir", 4)
        || is_accepted_long_option_prefix(flag, "--work-tree", 4)
        || is_accepted_long_option_prefix(flag, "--exec-path", 7)
}

/// P166 r9: git environment variables that retarget the repository or make git run a program, so a prefix assignment
/// (`GIT_DIR=/tmp/evil git commit`) is the same exec risk as the matching flag. Case-sensitive: environment names are.
const GIT_EXEC_ENV_NAMES: &[&str] = &[
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_EXEC_PATH", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "GIT_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR",
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
];

/// `NAME=value` where NAME is one of [`GIT_EXEC_ENV_NAMES`], unless the value is an allowlisted harmless one
/// ([`HARMLESS_COMMAND_VALUES`], P166 r13B): that removes only this finding, not the unvetted-env classification.
pub(crate) fn is_git_exec_env_assignment(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, value)| {
        (GIT_EXEC_ENV_NAMES.contains(&name) && !harmless_env_value(name, value)) || is_git_config_env_name(name)
    })
}

/// One row of the harmless-value allowlist: environment names and config key patterns (same pattern syntax as
/// [`COMMAND_VALUED_CONFIG_KEYS`]) that accept exactly the listed values.
pub(crate) struct HarmlessValueRow {
    pub env: &'static [&'static str],
    pub keys: &'static [&'static str],
    pub values: &'static [&'static str],
}

/// P166 r13B (owner-approved 2026-10-08): the ONE table of exact-value allowlists for editor, pager and
/// credential-helper values. Matching is the exact full string: no whitespace, no option, no path, no case folding.
/// `GIT_SSH_COMMAND` is deliberately absent. Read by the env path (`is_git_exec_env_assignment`) and the config-key
/// path (`command_valued_config`).
pub(crate) const HARMLESS_COMMAND_VALUES: &[HarmlessValueRow] = &[
    HarmlessValueRow { env: &["GIT_PAGER", "PAGER"], keys: &["core.pager", "pager.*"], values: &["cat"] },
    HarmlessValueRow {
        env: &["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"],
        keys: &["core.editor", "sequence.editor"],
        values: &["true", "nano"],
    },
    HarmlessValueRow {
        env: &[],
        keys: &["credential.helper", "credential.*.helper"],
        values: &["store", "cache", "osxkeychain", "manager"],
    },
];

/// The shell-decoded value of an env assignment's right-hand side: one pair of plain quotes around a quote-free,
/// expansion-free word is removed; anything else is returned unchanged (and so will not match the allowlist).
fn decode_plain_quotes(value: &str) -> &str {
    for quote in ['\'', '"'] {
        if let Some(inner) = value.strip_prefix(quote).and_then(|rest| rest.strip_suffix(quote))
            && !inner.contains(['\'', '"', '$', '`', '\\'])
        {
            return inner;
        }
    }
    value
}

/// Whether `NAME=value` (value as written, maybe plainly quoted) is an allowlisted harmless env value.
pub(crate) fn harmless_env_value(name: &str, value: &str) -> bool {
    let value = decode_plain_quotes(value);
    HARMLESS_COMMAND_VALUES.iter().any(|row| row.env.contains(&name) && row.values.contains(&value))
}

/// Whether the config `key` (any case) set to exactly `value` is an allowlisted harmless value.
pub(crate) fn harmless_config_value(key: &str, value: &str) -> bool {
    let key = key.to_ascii_lowercase();
    HARMLESS_COMMAND_VALUES
        .iter()
        .any(|row| row.values.contains(&value) && row.keys.iter().any(|pattern| config_key_matches(pattern, &key)))
}

/// P166 r11 rule 3(c): ANY assignment of git's config-by-environment variables fails closed (keys and values are not
/// paired): `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`, `GIT_CONFIG_PARAMETERS`.
pub(crate) fn is_git_config_env_name(name: &str) -> bool {
    name == "GIT_CONFIG_COUNT"
        || name == "GIT_CONFIG_PARAMETERS"
        || ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"].iter().any(|prefix| name.starts_with(prefix))
}

/// How a command-valued config key's value decides whether it is a command.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigValue {
    /// Any value (even a path) is run or retargets execution.
    Any,
    /// A boolean spelling is harmless (`core.fsmonitor=true`, `pager.log=false`); anything else is a command.
    NotBool,
    /// P166 r10: the command is the KEY's middle segment, not the value (`url.<base>.insteadOf`: git rewrites a URL
    /// that starts with the value so it starts with `<base>`, so a `<base>` of `ext::...` runs on the next fetch).
    ExtBase,
    /// Only a value that starts with `!` is a shell command (`submodule.<name>.update`).
    Bang,
    /// Only a path (`/usr/bin/x`, `./x`, `~/x`) is a command (`sendemail.smtpServer` is otherwise a host name).
    PathLike,
    /// Any value but `never` (`protocol.ext.allow`).
    NotNever,
    /// P166 r12 item 4: a repository URL; a value that is not an ordinary [`UrlRole::Source`] URL is a command.
    Url,
}

/// P166 r9: the ONE table of command-valued git config keys. Lower-case; `*` is a middle segment (a section's
/// subsection: a driver, tool, remote or URL base, which may itself contain dots); a trailing `.*` is any non-empty
/// name. Read by the `git config` SET classifier (`git_config_key_redirects_hooks`) and by the ambient scan
/// (`local_git_config_entry_is_exec`), so the two cannot drift.
pub(crate) const COMMAND_VALUED_CONFIG_KEYS: &[(&str, ConfigValue)] = &[
    ("core.hookspath", ConfigValue::Any),
    ("core.fsmonitor", ConfigValue::NotBool),
    ("core.sshcommand", ConfigValue::Any),
    ("core.pager", ConfigValue::Any),
    ("core.editor", ConfigValue::Any),
    ("core.askpass", ConfigValue::Any),
    ("core.gitproxy", ConfigValue::Any),
    ("core.alternaterefscommand", ConfigValue::Any),
    ("diff.external", ConfigValue::Any),
    ("diff.*.command", ConfigValue::Any),
    ("diff.*.textconv", ConfigValue::Any),
    ("diff.*.external", ConfigValue::Any),
    ("filter.*.clean", ConfigValue::Any),
    ("filter.*.smudge", ConfigValue::Any),
    ("filter.*.process", ConfigValue::Any),
    ("credential.helper", ConfigValue::Any),
    ("credential.*.helper", ConfigValue::Any),
    ("uploadpack.packobjectshook", ConfigValue::Any),
    ("remote.*.receivepack", ConfigValue::Any),
    ("remote.*.uploadpack", ConfigValue::Any),
    ("sequence.editor", ConfigValue::Any),
    ("gpg.program", ConfigValue::Any),
    ("gpg.*.program", ConfigValue::Any),
    ("gpg.ssh.defaultkeycommand", ConfigValue::Any),
    ("merge.*.driver", ConfigValue::Any),
    ("mergetool.*.cmd", ConfigValue::Any),
    ("mergetool.*.path", ConfigValue::Any),
    ("difftool.*.cmd", ConfigValue::Any),
    ("difftool.*.path", ConfigValue::Any),
    ("browser.*.cmd", ConfigValue::Any),
    ("browser.*.path", ConfigValue::Any),
    ("pager.*", ConfigValue::NotBool),
    ("sendemail.smtpserver", ConfigValue::PathLike),
    ("protocol.ext.allow", ConfigValue::NotNever),
    ("url.*.insteadof", ConfigValue::ExtBase),
    ("url.*.pushinsteadof", ConfigValue::ExtBase),
    // P166 r10 (Grok r9 MEDIUM).
    ("trailer.*.command", ConfigValue::Any),
    ("trailer.*.cmd", ConfigValue::Any),
    ("submodule.*.update", ConfigValue::Bang),
    ("interactive.difffilter", ConfigValue::Any),
    ("init.templatedir", ConfigValue::Any),
    ("remote.*.vcs", ConfigValue::Any),
    ("man.*.cmd", ConfigValue::Any),
    ("man.*.path", ConfigValue::Any),
    ("instaweb.httpd", ConfigValue::Any),
    ("guitool.*.cmd", ConfigValue::Any),
    // P166 r11 (Grok r10 MEDIUM 8).
    ("tar.*.command", ConfigValue::Any),
    ("imap.tunnel", ConfigValue::Any),
    ("sendemail.tocmd", ConfigValue::Any),
    ("sendemail.cccmd", ConfigValue::Any),
    ("sendemail.headercmd", ConfigValue::Any),
    ("protocol.allow", ConfigValue::NotNever),
    ("protocol.*.allow", ConfigValue::NotNever),
    // P166 r12 item 4 (Grok r11 HIGH 5): a URL that names a remote helper or a transport option runs on the next fetch.
    ("remote.*.url", ConfigValue::Url),
    ("remote.*.pushurl", ConfigValue::Url),
    ("submodule.*.url", ConfigValue::Url),
];

/// P166 r11 rule 3(b): the suffix fail-safe. A key whose LAST segment names a program, hook or command is
/// command-valued (a boolean value is harmless) even when the full key is not in the table. Exemption: `alias.*`
/// (the alias NAME is the user's choice, `alias.cmd`; an alias runs a command only when its value starts with `!`,
/// which `local_git_config_entry_is_exec` and the SET classifier judge separately).
fn config_key_has_command_suffix(key: &str) -> bool {
    let Some((section, last)) = key.rsplit_once('.') else {
        return false;
    };
    if section.is_empty() || section == "alias" || section.starts_with("alias.") {
        return false;
    }
    matches!(
        last,
        "command" | "cmd" | "program" | "helper" | "tunnel" | "driver" | "editor" | "pager" | "textconv" | "hook" | "hookspath"
    ) || last.ends_with("cmd")
        || last.ends_with("command")
}

/// Where a git URL appears (P166 r12 item 4).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlRole {
    /// A repository the user names (command line, `remote.<n>.url`, `submodule.<n>.url`): a `file://` URL or a local
    /// path is an ordinary source.
    Source,
    /// The `<base>` of `url.<base>.insteadOf|pushInsteadOf`: rewrites other URLs to it, so a `file://` base would make
    /// a later fetch run the local repository's configured programs. Not ordinary.
    InsteadOfBase,
}

/// `::` marks a remote helper (`ext::...`) or a daemon module, but not inside a bracketed IPv6 host (`[2001:db8::1]`).
fn contains_helper_colons(url: &str) -> bool {
    let mut outside = String::with_capacity(url.len());
    let mut depth = 0u32;
    for c in url.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => outside.push(c),
            _ => {}
        }
    }
    outside.contains("::")
}

/// P166 r12 item 4: the ONE predicate for every git URL. Ordinary: scheme `http`, `https`, `ssh`, `git`, `ftp`, `ftps`
/// followed by `://` and a host not starting with `-`; scp-like `[user@]host:path` with a plain host not starting with
/// `-`; and, only for [`UrlRole::Source`], `file://` and a bare local path. Everything else (`ext::...`, any `word::`,
/// a `-` host, an unknown scheme) is a command (a remote helper, a transport option or an unrecognised form).
pub(crate) fn url_is_ordinary(url: &str, role: UrlRole) -> bool {
    if url.is_empty() || url.starts_with('-') || url.contains(char::is_whitespace) || contains_helper_colons(url) {
        return false;
    }
    // P166 r13 item 6: `file:` with any number of slashes is the file scheme (`file:/tmp/x.git`).
    if url.len() >= 5 && url[..5].eq_ignore_ascii_case("file:") {
        return role == UrlRole::Source;
    }
    if let Some((scheme, rest)) = url.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if scheme == "file" {
            return role == UrlRole::Source;
        }
        if !matches!(scheme.as_str(), "http" | "https" | "ssh" | "git" | "ftp" | "ftps") {
            return false;
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        return !host.is_empty() && !host.starts_with(['-', ':']);
    }
    // scp-like `host:path` needs the colon before any slash; otherwise this is a local path.
    match (url.find(':'), url.find('/')) {
        (Some(colon), slash) if slash.is_none_or(|slash| colon < slash) => {
            let host = &url[..colon];
            let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
            !host.is_empty()
                && !host.starts_with('-')
                && (host.starts_with('[') && host.ends_with(']')
                    || host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
        }
        _ => role == UrlRole::Source,
    }
}

fn config_key_matches(pattern: &str, key: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return key.strip_prefix(prefix).and_then(|rest| rest.strip_prefix('.')).is_some_and(|rest| !rest.is_empty());
    }
    let Some((head, tail)) = pattern.split_once(".*.") else {
        return pattern == key;
    };
    key.strip_prefix(head)
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(tail))
        .and_then(|rest| rest.strip_suffix('.'))
        .is_some_and(|mid| !mid.is_empty())
}

fn config_value_is_command(rule: ConfigValue, key: &str, value: Option<&str>) -> bool {
    if rule == ConfigValue::ExtBase {
        // The subsection between `url.` and the last `.`; the value is irrelevant.
        let mid = key.strip_prefix("url.").and_then(|rest| rest.rsplit_once('.')).map_or("", |(mid, _)| mid);
        return !url_is_ordinary(mid, UrlRole::InsteadOfBase);
    }
    let Some(value) = value.map(str::trim) else {
        // No value known (a key named without one): fail closed.
        return true;
    };
    match rule {
        ConfigValue::Any => true,
        ConfigValue::NotBool => git2::Config::parse_bool(value).is_err(),
        ConfigValue::ExtBase => false,
        ConfigValue::Bang => value.starts_with('!'),
        ConfigValue::PathLike => value.starts_with(['/', '.', '~']),
        ConfigValue::NotNever => !value.eq_ignore_ascii_case("never"),
        ConfigValue::Url => !url_is_ordinary(value, UrlRole::Source),
    }
}

/// Whether `key` (any case) names a command-valued git config key whose `value` is a command. `None` value: fail closed.
pub(crate) fn command_valued_config(key: &str, value: Option<&str>) -> bool {
    let key = key.to_ascii_lowercase();
    // P166 r13B: an exact allowlisted value (matched on the untrimmed text) is not a command.
    if value.is_some_and(|value| harmless_config_value(&key, value)) {
        return false;
    }
    COMMAND_VALUED_CONFIG_KEYS
        .iter()
        .any(|(pattern, rule)| config_key_matches(pattern, &key) && config_value_is_command(*rule, &key, value))
        || (config_key_has_command_suffix(&key) && config_value_is_command(ConfigValue::NotBool, &key, value))
}

/// A `git config` SET's argument words (`key value ...`) or `-c`/env `key=value` text: some word names a
/// command-valued key whose following word (or inline `=value`) is a command.
pub(crate) fn config_words_set_command_valued<S: AsRef<str>>(words: &[S]) -> bool {
    words.iter().enumerate().any(|(at, word)| {
        let word = word.as_ref();
        match word.split_once('=') {
            Some((key, value)) => command_valued_config(key, Some(value)),
            None => command_valued_config(word, words.get(at + 1).map(|next| next.as_ref())),
        }
    })
}

pub(crate) fn is_attached_git_config_c(tok: &str) -> bool {
    tok.starts_with("-c") && tok.len() > 2 && !tok.starts_with("--")
}

pub(crate) fn attached_git_c_path(tok: &str) -> Option<&str> {
    tok.strip_prefix("-C")
        .filter(|rest| !rest.is_empty() && !tok.starts_with("--"))
}

pub(crate) fn git_global_option_takes_value(tok: &str) -> bool {
    matches!(
        tok,
        "-C" | "-c"
            | "--git-dir"
            | "--work-tree"
            | "--namespace"
            | "--super-prefix"
            | "--exec-path"
            | "--list-cmds"
            | "--attr-source"
            | "--config-env"
    ) || is_accepted_long_option_prefix(tok, "--config-env", 4)
        || is_accepted_long_option_prefix(tok, "--git-dir", 4)
        || is_accepted_long_option_prefix(tok, "--work-tree", 4)
        || is_accepted_long_option_prefix(tok, "--namespace", 7)
        || is_accepted_long_option_prefix(tok, "--super-prefix", 8)
        || is_accepted_long_option_prefix(tok, "--exec-path", 7)
        || is_accepted_long_option_prefix(tok, "--list-cmds", 7)
        || is_accepted_long_option_prefix(tok, "--attr-source", 8)
}

/// Pre-subcommand only; missing values fail closed. Post-subcommand `git log -c` is not scanned.
pub(crate) fn git_has_exec_risk_global(words: &[String]) -> bool {
    let mut i = 1;
    while i < words.len() {
        let tok = words[i].as_str();
        if tok == "--" {
            return false;
        }
        if !tok.starts_with('-') || tok == "-" {
            return false;
        }
        if tok == "-c"
            || is_attached_git_config_c(tok)
            || is_git_config_env_flag(tok)
            || is_git_repo_retarget_flag(tok)
        {
            return true;
        }
        // `-Cpath` is cwd-only (ambient); skip so it is not treated as the subcommand.
        if attached_git_c_path(tok).is_some() {
            i += 1;
            continue;
        }
        if !tok.contains('=')
            && git_global_option_takes_value(tok)
            && words
                .get(i + 1)
                .is_some_and(|n| !n.starts_with('-') || n == "-")
        {
            i += 1;
        }
        i += 1;
    }
    false
}

pub(crate) fn segment_has_exec_risk_flag(words: &[String]) -> bool {
    if is_sort_program(words) {
        return sort_has_compress_program_flag(words);
    }
    if is_git_program(words) {
        return git_has_exec_risk_global(words)
            || git_config_sets_shell_alias(words)
            || git_command_url_operand(words);
    }
    false
}

/// `git config [opts] alias.<name> '!<shell text>'`: stores a shell command that a later `git <name>` runs (P166 r8B).
/// The stored text is the risk, so the SET is exec risk whatever the alias is called.
pub(crate) fn git_config_sets_shell_alias(words: &[String]) -> bool {
    let Some(config_at) = words.iter().position(|word| word == "config") else {
        return false;
    };
    words[config_at + 1..].windows(2).any(|pair| {
        pair[0].to_ascii_lowercase().starts_with("alias.") && pair[1].starts_with('!')
    })
}

/// How a git URL verb treats one option (P166 r13 rule 2).
#[derive(Clone, Copy, PartialEq, Eq)]
enum GitOpt {
    /// Runs its value as a command (`--upload-pack`, `--receive-pack`, `--exec`, `clone -u`, `clone --template`):
    /// exec risk whatever the value, in `--opt=VALUE`, `--opt VALUE` and attached short forms.
    Exec,
    /// `clone -c|--config KEY=VALUE`: exec risk when the key is command-valued (the config table applies).
    Config,
    /// The value is a repository URL (`push --repo`, `archive --remote`): judged like the URL operand.
    Url,
    /// Consumes a value that is not a URL.
    Value,
}

/// Per-verb table of value-taking git options (long and short). An option that is not listed does not consume
/// the next word; the word after it is ALSO judged as a possible URL so a command URL cannot hide behind it.
/// Sources: git-clone, git-fetch, git-pull, git-push, git-ls-remote, git-archive, git-remote, git-submodule manuals.
/// `fetch -u` is `--update-head-ok` and `push -u` is `--set-upstream` (both boolean), so `-u` is Exec for `clone` only.
fn git_url_verb_option(verb: &str, option: &str) -> Option<GitOpt> {
    use GitOpt::{Config, Exec, Url, Value};
    let table: &[(&str, GitOpt)] = match verb {
        "clone" => &[
            ("-u", Exec), ("--upload-pack", Exec), ("--template", Exec), ("--exec", Exec), ("--receive-pack", Exec),
            ("-c", Config), ("--config", Config),
            ("-o", Value), ("--origin", Value), ("-b", Value), ("--branch", Value), ("--reference", Value),
            ("--reference-if-able", Value), ("--separate-git-dir", Value), ("--depth", Value),
            ("--shallow-since", Value), ("--shallow-exclude", Value), ("--filter", Value), ("-j", Value),
            ("--jobs", Value), ("--server-option", Value), ("--bundle-uri", Value), ("--ref-format", Value),
            ("--revision", Value),
        ],
        "fetch" | "pull" => &[
            ("--upload-pack", Exec), ("--exec", Exec), ("--receive-pack", Exec),
            ("--depth", Value), ("--deepen", Value), ("--shallow-since", Value), ("--shallow-exclude", Value),
            ("--filter", Value), ("-j", Value), ("--jobs", Value), ("--refmap", Value), ("--negotiation-tip", Value),
            ("--recurse-submodules-default", Value), ("-o", Value), ("--server-option", Value), ("-s", Value),
            ("--strategy", Value), ("-X", Value), ("--strategy-option", Value),
        ],
        "push" => &[
            ("--receive-pack", Exec), ("--exec", Exec), ("--upload-pack", Exec),
            ("--repo", Url), ("--push-option", Value), ("-o", Value),
        ],
        "ls-remote" => &[
            ("--upload-pack", Exec), ("--exec", Exec), ("--receive-pack", Exec),
            ("--sort", Value), ("-o", Value), ("--server-option", Value),
        ],
        "remote" => &[("-t", Value), ("-m", Value), ("--track", Value), ("--master", Value)],
        "submodule" => &[
            ("-b", Value), ("--branch", Value), ("--name", Value), ("--reference", Value), ("--depth", Value),
            ("--jobs", Value), ("-j", Value),
        ],
        "archive" => &[
            ("--exec", Exec), ("--upload-pack", Exec), ("--receive-pack", Exec), ("--remote", Url),
            ("--format", Value), ("--prefix", Value), ("--output", Value), ("-o", Value), ("--add-file", Value),
            ("--add-virtual-file", Value),
        ],
        _ => &[],
    };
    table.iter().find(|(name, _)| *name == option).map(|(_, kind)| *kind)
}

/// P166 r12 item 4: whether a git URL operand of `clone`, `fetch`, `pull`, `push`, `ls-remote`, `remote add|set-url`,
/// `submodule add` or `archive --remote` is not ordinary ([`url_is_ordinary`], role [`UrlRole::Source`]): a remote
/// helper (`ext::`, any `word::`), a transport option as host (`ssh://-oProxyCommand=...`) or an unrecognised form.
/// Pre-verb global options are skipped; the `-c`/repo-retarget globals are judged by [`git_has_exec_risk_global`].
pub(crate) fn git_command_url_operand(words: &[String]) -> bool {
    let mut i = 1;
    while i < words.len() {
        let tok = words[i].as_str();
        if !tok.starts_with('-') || tok == "-" {
            break;
        }
        if !tok.contains('=') && git_global_option_takes_value(tok) {
            i += 1;
        }
        i += 1;
    }
    let Some(verb) = words.get(i).map(String::as_str) else {
        return false;
    };
    if !matches!(verb, "clone" | "fetch" | "pull" | "push" | "ls-remote" | "remote" | "submodule" | "archive") {
        return false;
    }
    let mut operands: Vec<&str> = Vec::new();
    // URLs named by option, and words after an unlisted option (a possible value, or the URL itself).
    let mut urls: Vec<&str> = Vec::new();
    let mut unlisted_value_seen = false;
    let mut rest = words[i + 1..].iter();
    let mut dashdash = false;
    while let Some(word) = rest.next() {
        if !dashdash && word == "--" {
            dashdash = true;
            continue;
        }
        if dashdash || !word.starts_with('-') || word == "-" {
            operands.push(word);
            continue;
        }
        let (name, mut value) = match word.split_once('=') {
            Some((name, value)) if word.starts_with("--") => (name, Some(value)),
            _ => (word.as_str(), None),
        };
        let mut kind = git_url_verb_option(verb, name);
        // An attached short value: `clone -ush`, `-cKEY=V`, `-b main`.
        if kind.is_none()
            && !word.starts_with("--")
            && word.len() > 2
            && word.is_char_boundary(2)
            && let Some(found) = git_url_verb_option(verb, &word[..2])
        {
            kind = Some(found);
            value = Some(&word[2..]);
        }
        match kind {
            Some(GitOpt::Exec) => return true,
            Some(kind) => {
                let value = match value {
                    Some(value) => Some(value.to_owned()),
                    None => rest.next().cloned(),
                };
                match (kind, value) {
                    (GitOpt::Config, Some(value)) => {
                        if config_words_set_command_valued(&[value]) {
                            return true;
                        }
                    }
                    (GitOpt::Config, None) => return true,
                    (GitOpt::Url, Some(value)) => {
                        if !url_is_ordinary(&value, UrlRole::Source) {
                            return true;
                        }
                    }
                    (GitOpt::Url, None) => return true,
                    _ => {}
                }
            }
            None => {
                // Unlisted: `--opt=VALUE` is skipped; `--opt WORD` leaves WORD possibly a URL.
                if value.is_none()
                    && !word.contains('=')
                    && let Some(next) = rest.as_slice().first().filter(|next| !next.starts_with('-'))
                {
                    urls.push(next);
                    unlisted_value_seen = true;
                }
            }
        }
    }
    if urls.iter().any(|url| !url_is_ordinary(url, UrlRole::Source)) {
        return true;
    }
    if verb == "archive" {
        return false;
    }
    let judged: &[&str] = match verb {
        // `git clone URL [DIR]`, `fetch|pull|push|ls-remote REPO …`.
        // After an unlisted option that was followed by a word, the real URL may be the second operand.
        "clone" | "fetch" | "pull" | "push" | "ls-remote" => {
            operands.get(..if unlisted_value_seen { 2 } else { 1 }).or(Some(&operands[..])).unwrap_or_default()
        }
        // `git remote add NAME URL`, `git remote set-url NAME NEWURL [OLDURL]` (a `--delete` URL is a pattern).
        "remote" => match operands.first() {
            Some(&"add") => operands.get(2..3).unwrap_or_default(),
            Some(&"set-url") if !words.iter().any(|word| word == "--delete") => operands.get(2..3).unwrap_or_default(),
            _ => &[],
        },
        // `git submodule add [-b B] URL [PATH]`.
        _ => match operands.first() {
            Some(&"add") => operands.get(1..2).unwrap_or_default(),
            _ => &[],
        },
    };
    judged.iter().any(|url| !url_is_ordinary(url, UrlRole::Source))
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SegmentExecFacts {
    pub exec_risk: bool,
    pub has_git: bool,
}

/// Normalize raw segment words, then inspect git/sort. Unmodeled peels fail closed.
pub(crate) fn segment_exec_facts(words: &[String]) -> SegmentExecFacts {
    // P166 r9: `env GIT_DIR=/tmp/evil git commit` keeps the assignment as a word; the wrapper peel below drops it.
    if words.iter().any(|word| is_git_exec_env_assignment(word)) {
        return SegmentExecFacts { exec_risk: true, has_git: words.iter().any(|word| normalized_token_basename(word) == "git") };
    }
    match normalize_for_exec_risk(words) {
        NormalizedArgv::FailClosed => SegmentExecFacts {
            exec_risk: true,
            has_git: false,
        },
        NormalizedArgv::Ready(inner) => SegmentExecFacts {
            exec_risk: segment_has_exec_risk_flag(inner),
            has_git: is_git_program(inner),
        },
    }
}

/// Read-only git query verbs, the SINGLE SOURCE for every git allow decision.
/// Both [`git_words_are_read_only_query`] and the `alias.<verb> = !cmd` shadowing check in the ambient config scan below read it.
/// Add a new read-only verb here and every consumer inherits it; do not grow per-consumer prefix lists.
pub(crate) const SAFE_GIT_SUBCOMMANDS: &[&str] = &[
    "status",
    "branch",
    "log",
    "diff",
    "ls-files",
    "show",
    "rev-parse",
    "blame",
    "grep",
    "describe",
    "merge-base",
    "check-ignore",
    "check-attr",
    "cat-file",
    "ls-tree",
    "show-ref",
    "for-each-ref",
    "rev-list",
    "name-rev",
    "count-objects",
    "shortlog",
];

/// Options that make an otherwise read-only git verb run repo-configured content drivers or write arbitrary paths.
/// One table applied to EVERY [`SAFE_GIT_SUBCOMMANDS`] verb, so a new safe verb inherits the policy.
/// `--filters`/`--textconv` run `filter.*.smudge` / `diff.*.textconv` (`filter.*.smudge` is outside the ambient local-config exec scan).
/// `--ext-diff` runs the external diff driver; `--output` writes an arbitrary file; `--open-files-in-pager` executes a pager command.
/// `git grep`'s short-attached `-O<cmd>` form is guarded in [`git_words_have_unsafe_query_option`].
const GIT_QUERY_UNSAFE_OPTIONS: &[&str] = &[
    "--filters",
    "--textconv",
    "--output",
    "--ext-diff",
    "--open-files-in-pager",
];

/// Git accepts uniquely-abbreviated long options, so any `--` word (pre-`=`, at least 3 chars) that prefixes a table entry fails closed.
/// That includes abbreviations a specific verb would resolve to a benign sibling (`git grep --text` collides with `--textconv` and prompts).
fn git_query_option_is_unsafe(word: &str) -> bool {
    let flag = word.split('=').next().unwrap_or(word);
    flag.len() > 2
        && GIT_QUERY_UNSAFE_OPTIONS
            .iter()
            .any(|full| full.starts_with(flag))
}

/// Resolve the subcommand index, skipping only the globals modeled as benign: `-C <path>` / `-C<path>` and `--no-pager` / `-P`.
/// The ambient config scan tracks the cwd that `-C` retargets.
/// Every other pre-subcommand option fails closed (`None`).
/// `-c`, `--config-env`, `--git-dir`, `--exec-path`, `--paginate`, `--attr-source`, and more can change what executes or which config is read.
fn git_safe_query_verb_index(words: &[String]) -> Option<usize> {
    let mut i = 1;
    loop {
        let tok = words.get(i).map(String::as_str)?;
        if tok == "-" || tok == "--" {
            return None;
        }
        if !tok.starts_with('-') {
            return Some(i);
        }
        if tok == "-C" {
            i += 2;
            continue;
        }
        if attached_git_c_path(tok).is_some() || tok == "--no-pager" || tok == "-P" {
            i += 1;
            continue;
        }
        return None;
    }
}

/// True when a `git` invocation carries an option from [`GIT_QUERY_UNSAFE_OPTIONS`] or `git grep`'s short-attached `-O<cmd>`, whatever the verb.
/// Used by [`git_words_are_read_only_query`] and on its own, so a session whitelist-prefix grant cannot override a driver/write flag.
pub(crate) fn git_words_have_unsafe_query_option(words: &[String]) -> bool {
    if words.first().map(String::as_str) != Some("git") {
        return false;
    }
    if words.iter().skip(1).any(|w| git_query_option_is_unsafe(w)) {
        return true;
    }
    // `git grep -O<cmd>` / `-O <cmd>` executes <cmd>; the short-attached form is not a long-option abbreviation, so guard it verb-specifically
    matches!(git_safe_query_verb_index(words), Some(i) if words[i] == "grep")
        && words.iter().skip(1).any(|w| w.starts_with("-O"))
}

/// Single decision point for auto-approvable read-only `git` queries, shared by the manager safe lists and the auto-mode routine heuristic.
/// Verb policy and flag policy therefore live in one place.
/// The [`git_has_exec_risk_global`] check is a redundant belt over [`git_safe_query_verb_index`] for odd `-C` value shapes.
///
/// Callers pass wrapper-peeled words, and `words[0]` must be literally `git`.
/// Path-qualified or case-variant "git" binaries fail closed: a different binary with the same basename must not inherit the allowlist.
pub(crate) fn git_words_are_read_only_query(words: &[String]) -> bool {
    if words.first().map(String::as_str) != Some("git") {
        return false;
    }
    if git_has_exec_risk_global(words) {
        return false;
    }
    let Some(verb_idx) = git_safe_query_verb_index(words) else {
        return false;
    };
    if !SAFE_GIT_SUBCOMMANDS.contains(&words[verb_idx].as_str()) {
        return false;
    }
    !git_words_have_unsafe_query_option(words)
}

pub(crate) fn local_git_config_entry_is_exec(name: &str, value: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    // P166 r9: the shared command-valued key table (also read by the `git config` SET classifier).
    if command_valued_config(&name, Some(value)) {
        return true;
    }
    // P166 r8B: a shell alias (`alias.<any> = !cmd`) runs a stored command on a later `git <alias>`; the alias name
    // need not shadow a safe verb for the later command to execute it.
    name.starts_with("alias.") && value.starts_with('!')
}

/// Local/worktree only via libgit2 (include/includeIf). Fail closed on read errors.
pub(crate) fn local_repo_config_has_exec_risk(cwd: &Path) -> bool {
    match crate::git_content_filters::read_local_git_config_entries(cwd) {
        None => true,
        Some(entries) => entries
            .iter()
            .any(|(name, value)| local_git_config_entry_is_exec(name, value)),
    }
}

fn is_static_path_operand(p: &str) -> bool {
    !p.is_empty()
        && p != "-"
        && !p.starts_with('-')
        && !p.as_bytes().contains(&b'$')
        && !p.as_bytes().contains(&b'`')
        && !p.contains("$(")
}

fn join_cwd(base: &Path, operand: &str) -> PathBuf {
    let p = Path::new(operand);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn apply_literal_chdir(cwd: &Path, words: &[String]) -> Option<PathBuf> {
    let mut args = words.iter().skip(1).map(String::as_str);
    let mut target = None;
    while let Some(tok) = args.next() {
        if tok == "--" {
            target = args.next();
            break;
        }
        if tok.starts_with('-') {
            return None;
        }
        if target.is_some() {
            return None;
        }
        target = Some(tok);
    }
    let target = target?;
    if !is_static_path_operand(target) {
        return None;
    }
    Some(join_cwd(cwd, target))
}

/// P175d: the first line (up to `\n` or `\r`) of a git pointer file (`follow`: a symlink is followed, as git follows a
/// symlinked `.git` or `commondir`), read as git reads it: at most 4096 bytes, any
/// bytes. The file is opened `O_NONBLOCK` (and, when `follow` is false, `O_NOFOLLOW`) so a FIFO cannot block the
/// caller, and only a REGULAR file is accepted, judged on the open handle (fstat), so a swap between a check and the
/// open cannot make this wait. Non-unix: a metadata check then a plain open (unverified).
fn read_pointer_first_line(path: &Path, follow: bool) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
        if !follow {
            flags |= libc::O_NOFOLLOW;
        }
        options.custom_flags(flags);
    }
    #[cfg(not(unix))]
    {
        let meta = if follow { std::fs::metadata(path) } else { std::fs::symlink_metadata(path) }.ok()?;
        if !meta.is_file() {
            return None;
        }
    }
    let file = options.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(4096).read_to_end(&mut bytes).ok()?;
    let end = bytes.iter().position(|b| matches!(b, b'\n' | b'\r')).unwrap_or(bytes.len());
    bytes.truncate(end);
    Some(bytes)
}

fn bytes_to_path(bytes: &[u8]) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes).ok().map(PathBuf::from)
    }
}

/// P175d: a pointer's canonical target counts only if it is an existing directory holding a `HEAD` that is a regular file or a symlink (git follows it; looked
/// at with `symlink_metadata`, never opened) and is neither `/`, the worktree root, nor an ancestor of it (which
/// would make every write in the tree look like a git-directory write).
fn plausible_git_dir(dir: &Path, worktree_root: &Path) -> bool {
    dir.parent().is_some()
        && !worktree_root.starts_with(dir)
        && std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir())
        && std::fs::symlink_metadata(dir.join("HEAD")).is_ok_and(|m| m.is_file() || m.file_type().is_symlink())
}

/// P175d: the git directories a write must not touch before a branch switch in `effective`: the nearest `.git`
/// directory above it (as before) AND, when a nearer `.git` is a FILE (linked worktree, submodule checkout; or a
/// symlink to one, as git follows it), the `gitdir:` it names plus that directory's `commondir` (where the shared
/// refs live). A pointer that cannot be read as git reads it adds nothing, so the result is never smaller than before.
fn protected_git_dirs(effective: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = effective.ancestors().map(|dir| dir.join(".git")).filter(|dir| dir.is_dir()).take(1).collect();
    let pointer_dirs = || -> Option<Vec<PathBuf>> {
        let (root, file, is_link) = effective.ancestors().find_map(|dir| {
            let dot_git = dir.join(".git");
            let meta = std::fs::symlink_metadata(&dot_git).ok()?;
            (meta.is_dir() || meta.is_file() || meta.file_type().is_symlink()).then_some((dir, dot_git, meta.file_type().is_symlink()))
        })?;
        // A symlink is followed one level (open without O_NOFOLLOW; the handle must still be a regular file).
        let line = read_pointer_first_line(&file, is_link)?;
        let rest = line.strip_prefix(b"gitdir:")?;
        let start = rest.iter().position(|b| !b.is_ascii_whitespace())?;
        let end = rest.iter().rposition(|b| !b.is_ascii_whitespace())?;
        let gitdir = dunce::canonicalize(root.join(bytes_to_path(&rest[start..=end])?)).ok()?;
        if !plausible_git_dir(&gitdir, root) {
            return None;
        }
        let mut found = vec![gitdir.clone()];
        if let Some(line) = read_pointer_first_line(&gitdir.join("commondir"), true) {
            let trimmed = line.trim_ascii();
            if !trimmed.is_empty()
                && let Some(named) = bytes_to_path(trimmed)
                && let Ok(common) = dunce::canonicalize(gitdir.join(named))
                && plausible_git_dir(&common, root)
            {
                found.push(common);
            }
        }
        Some(found)
    };
    dirs.extend(pointer_dirs().unwrap_or_default());
    dirs
}

/// Pre-subcommand `git -C` / `-Cpath` chains. Returns `None` on an unmodeled path or a repo-retarget global.
fn git_effective_cwd(words: &[String], start_cwd: &Path) -> Option<PathBuf> {
    let mut cwd = start_cwd.to_path_buf();
    let mut i = 1;
    while i < words.len() {
        let tok = words[i].as_str();
        if tok == "--" || !tok.starts_with('-') || tok == "-" {
            break;
        }
        if is_git_repo_retarget_flag(tok) {
            return None;
        }
        if tok == "-C" {
            let path = words.get(i + 1).map(String::as_str)?;
            if !is_static_path_operand(path) {
                return None;
            }
            cwd = join_cwd(&cwd, path);
            i += 2;
            continue;
        }
        if let Some(path) = attached_git_c_path(tok) {
            if !is_static_path_operand(path) {
                return None;
            }
            cwd = join_cwd(&cwd, path);
            i += 1;
            continue;
        }
        if !tok.contains('=')
            && git_global_option_takes_value(tok)
            && words
                .get(i + 1)
                .is_some_and(|n| !n.starts_with('-') || n == "-")
        {
            i += 1;
        }
        i += 1;
    }
    Some(cwd)
}

#[derive(Debug, Clone)]
pub(crate) enum AmbientScanPlan {
    FailClosed,
    CheckDirs(Vec<PathBuf>),
}

/// Same normalization as [`segment_exec_facts`], then track cd/git cwd.
pub(crate) fn ambient_scan_plan_from_segments(
    raw_segments: &[Vec<String>],
    session_cwd: &Path,
) -> AmbientScanPlan {
    let mut cwd = session_cwd.to_path_buf();
    let mut git_cwds = Vec::new();
    for raw in raw_segments {
        let words = match normalize_for_exec_risk(raw) {
            NormalizedArgv::FailClosed => return AmbientScanPlan::FailClosed,
            NormalizedArgv::Ready(inner) => inner,
        };
        match normalized_program_name(words).as_deref() {
            Some("cd") | Some("pushd") => match apply_literal_chdir(&cwd, words) {
                Some(next) => cwd = next,
                None => return AmbientScanPlan::FailClosed,
            },
            Some("popd") => return AmbientScanPlan::FailClosed,
            Some("git") => match git_effective_cwd(words, &cwd) {
                Some(effective) => git_cwds.push(effective),
                None => return AmbientScanPlan::FailClosed,
            },
            _ => {}
        }
    }
    if git_cwds.is_empty() {
        AmbientScanPlan::FailClosed
    } else {
        AmbientScanPlan::CheckDirs(git_cwds)
    }
}

/// P166 r13B feature 1: which trees a branch-moving git verb involves, per git segment, with the same cwd tracking as
/// the ambient scan (`cd`, `git -C`). Only the verbs `checkout|switch|merge|rebase|pull|stash pop|apply` are modelled;
/// any other segment is ignored. A listed verb in a form not modelled (flags, pathspecs, `--detach`, ...) is
/// [`BranchSwitchPlan::Undetermined`]. `switch -c <name>` / `checkout -b <name>` (a new branch at HEAD) rewrite
/// nothing and need no probe.
pub(crate) fn branch_switch_plan(raw_segments: &[Vec<String>], session_cwd: &Path) -> BranchSwitchPlan {
    branch_switch_plan_with(raw_segments, session_cwd, None)
}

/// [`branch_switch_plan`] with the script's write targets (P175 part B, decision 11): an EARLIER non-git command that
/// writes inside the git directory of the repository the switch runs in unsettles the plan like an earlier git verb.
pub(crate) fn branch_switch_plan_with(
    raw_segments: &[Vec<String>],
    session_cwd: &Path,
    facts: Option<&crate::permission::shell_access::ShellWriteFacts>,
) -> BranchSwitchPlan {
    use crate::permission::branch_switch::{TreeProbe, TreeRef};
    let mut cwd = session_cwd.to_path_buf();
    let mut probes = Vec::new();
    let mut undetermined = false;
    let req = |rev: &str| TreeRef::new(rev, true);
    let opt = |rev: String| TreeRef::new(rev, false);
    // HEAD: an unborn HEAD is skipped, only the target tree is judged.
    let head = || TreeRef { unborn_ok: true, ..TreeRef::new("HEAD", true) };
    // Set once an earlier segment can move refs or is not a recognised read-only git command: the trees git would
    // read later no longer match what a probe sees now.
    let mut unsettled = false;
    let mut git_ordinal = 0usize;
    for raw in raw_segments {
        if raw.iter().any(|word| word.contains("GIT_NO_REPLACE_OBJECTS") || word.contains("GIT_REPLACE_REF_BASE")) {
            return BranchSwitchPlan::Undetermined;
        }
        let words = match normalize_for_exec_risk(raw) {
            NormalizedArgv::FailClosed => return BranchSwitchPlan::Undetermined,
            NormalizedArgv::Ready(inner) => inner,
        };
        match normalized_program_name(words).as_deref() {
            Some("cd") | Some("pushd") => match apply_literal_chdir(&cwd, words) {
                Some(next) => cwd = next,
                None => return BranchSwitchPlan::Undetermined,
            },
            Some("popd") => return BranchSwitchPlan::Undetermined,
            Some("git") => {
                let this_git = git_ordinal;
                git_ordinal += 1;
                // The verb: after the global options (`-C <dir>` and the value-less ones; exec-risk ones never get here).
                let mut at = 1;
                while let Some(tok) = words.get(at) {
                    if tok == "--" || !tok.starts_with('-') || tok == "-" {
                        break;
                    }
                    // `-c submodule.recurse=true` / `--config-env`: recursion the config child cannot see.
                    if matches!(tok.as_str(), "-c") || tok.starts_with("--config-env") {
                        let value = words.get(at + 1).map(|v| v.to_ascii_lowercase()).unwrap_or_default();
                        if tok.to_ascii_lowercase().contains("recurse") || value.contains("recurse") || value.contains("submodule") {
                            return BranchSwitchPlan::Undetermined;
                        }
                    }
                    at += if !tok.contains('=') && git_global_option_takes_value(tok) { 2 } else { 1 };
                }
                let Some(verb) = words.get(at).map(String::as_str) else {
                    continue;
                };
                if !matches!(verb, "checkout" | "switch" | "merge" | "rebase" | "pull" | "stash") {
                    // Read-only verbs (and `add`, which only touches the index) leave refs alone; every other verb
                    // (fetch, remote, commit, push, an alias, ...) may move one.
                    let rest = &words[at + 1..];
                    // `add -f` can stage an ignored file, which the work-tree listing does not show.
                    let forced_add = verb == "add" && git_add_is_force(rest);
                    // `git commit` runs hooks (`.git/hooks/post-commit` can move any ref), so like every verb that is
                    // not read-only it makes the later probes unsettled. Bare listing forms of branch/tag/reflog are
                    // read-only.
                    if forced_add
                        || !(matches!(
                            verb,
                            "status" | "log" | "diff" | "show" | "rev-parse" | "ls-tree" | "ls-files" | "cat-file" | "describe"
                                | "blame" | "grep" | "shortlog" | "add" | "for-each-ref" | "show-ref" | "rev-list"
                        ) || git_readonly_listing(verb, rest))
                    {
                        unsettled = true;
                    }
                    continue;
                }
                let args: Vec<&str> = words[at + 1..].iter().map(String::as_str).collect();
                let plain = |arg: &&str| !arg.starts_with('-') && !arg.is_empty() && !arg.contains(['\\', ':', '^', '~', '@', '*', '?', '[']);
                let trees: Option<Vec<TreeRef>> = match (verb, args.as_slice()) {
                    ("stash", [sub @ ("pop" | "apply"), rest @ ..]) => {
                        let _ = sub;
                        let rest: Vec<&&str> = rest.iter().filter(|arg| !matches!(**arg, "--index" | "-q" | "--quiet")).collect();
                        let stash = match rest.as_slice() {
                            [] => Some("stash@{0}".to_owned()),
                            [one] if one.len() > 8 && one.starts_with("stash@{") && one.ends_with('}') && one[7..one.len() - 1].bytes().all(|b| b.is_ascii_digit()) => Some(one.to_string()),
                            [one] if one.bytes().all(|b| b.is_ascii_digit()) => Some(format!("stash@{{{one}}}")),
                            _ => None,
                        };
                        // No such stash: git errors out and rewrites nothing.
                        stash.map(|stash| {
                            let na = TreeRef { na_if_absent: true, ..TreeRef::new(stash.as_str(), true) };
                            vec![na, head(), opt(format!("{stash}^3"))]
                        })
                    }
                    // `stash -u` / `-a` (push, save, or bare) deletes untracked (and ignored) files: judge them.
                    ("stash", _) => match git_stash_untracked_scope(&words[at + 1..]) {
                        Some(rev) => Some(vec![TreeRef::new(rev, false)]),
                        None => continue,
                    },
                    ("checkout" | "switch", ["-"]) => Some(vec![head(), req("@{-1}")]),
                    ("switch", ["-c" | "-C" | "--create", name]) | ("checkout", ["-b" | "-B", name]) if plain(name) => {
                        continue;
                    }
                    // New branch at a start point: the working tree goes from HEAD to the start point's tree.
                    ("switch", ["-c" | "-C" | "--create", name, start]) | ("checkout", ["-b" | "-B", name, start])
                        if plain(name) && plain(start) =>
                    {
                        Some(vec![head(), req(start)])
                    }
                    ("checkout" | "switch", [target]) if plain(target) => {
                        Some(vec![head(), TreeRef { guess_remote: true, ..TreeRef::new(*target, true) }])
                    }
                    ("merge" | "rebase", [target]) if plain(target) => Some(vec![head(), req(target)]),
                    ("pull", rest) => {
                        let mut positional = Vec::new();
                        let mut ok = true;
                        for arg in rest {
                            if matches!(
                                *arg,
                                "--rebase" | "--no-rebase" | "--ff" | "--ff-only" | "--no-ff" | "--no-edit" | "--autostash"
                                    | "--no-autostash" | "-q" | "--quiet" | "-v" | "--verbose" | "-r" | "--rebase=true"
                                    | "--rebase=false" | "--rebase=merges"
                            ) {
                                continue;
                            }
                            if plain(arg) && !arg.contains('/') || (plain(arg) && positional.len() == 1) {
                                positional.push(*arg);
                            } else {
                                ok = false;
                            }
                        }
                        if !ok || positional.len() > 2 {
                            None
                        } else {
                            let mut trees = vec![head(), opt("@{upstream}".to_owned())];
                            if let [remote, branch] = positional.as_slice() {
                                trees.push(opt(format!("refs/remotes/{remote}/{branch}")));
                            }
                            Some(trees)
                        }
                    }
                    _ => None,
                };
                let effective_cwd = git_effective_cwd(words, &cwd);
                if !unsettled
                    && trees.is_some()
                    && let (Some(facts), Some(effective)) = (facts, effective_cwd.as_deref())
                    && protected_git_dirs(effective).iter().any(|git_dir| {
                        facts.writes_into_git_dir_before(
                            session_cwd,
                            &crate::permission::shell_access::lexical_clean(git_dir),
                            this_git,
                        )
                    })
                {
                    unsettled = true;
                }
                match (trees, effective_cwd) {
                    (Some(_), Some(_)) if unsettled => undetermined = true,
                    (Some(trees), Some(effective)) => probes.push(TreeProbe { cwd: effective, trees }),
                    _ => undetermined = true,
                }
                // A pull fetches: later segments read refs it moves.
                if verb == "pull" {
                    unsettled = true;
                }
            }
            _ => {}
        }
    }
    // Safety net: the write facts and this planner must see the same git commands. If they ever disagree, the ordinal
    // that places an earlier write is not trustworthy, so a plan that would probe is not.
    if !probes.is_empty() && facts.is_some_and(|facts| facts.git_start_count() != git_ordinal) {
        undetermined = true;
    }
    if undetermined {
        BranchSwitchPlan::Undetermined
    } else if probes.is_empty() {
        BranchSwitchPlan::NotApplicable
    } else {
        BranchSwitchPlan::Probe(probes)
    }
}

/// `git add` options that force-add ignored files: `-f` in a short cluster, `--force`, `--force=<bool>`, or any
/// unique prefix of `--force` git accepts (`--f` ... `--forc`, with or without `=<value>`).
fn git_add_is_force(args: &[String]) -> bool {
    args.iter().take_while(|a| a.as_str() != "--").any(|a| {
        if let Some(long) = a.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or(""));
            name == "--force" || is_accepted_long_option_prefix(&name, "--force", 3)
        } else {
            a.starts_with('-') && a.contains('f')
        }
    })
}

#[cfg(test)]
pub(crate) fn git_add_is_force_for_tests(args: &[String]) -> bool {
    git_add_is_force(args)
}

/// Read-only listing forms of `branch`, `tag` and `reflog`. Anything else on those verbs (and any unknown flag) is not.
fn git_readonly_listing(verb: &str, args: &[String]) -> bool {
    let valued = |flag: &str| {
        let name = flag.split('=').next().unwrap_or(flag);
        ["--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort"].contains(&name)
    };
    let optional_value = |flag: &str| {
        let name = flag.split('=').next().unwrap_or(flag);
        !flag.contains('=') && ["--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort"].contains(&name)
    };
    match verb {
        "reflog" => {
            // `reflog [show] <rev>` lists; a flag or a reflog subcommand name in the revision slot does not.
            let rev_ok = |rev: &str| {
                !rev.starts_with('-') && !["expire", "delete", "exists", "list", "drop", "write"].contains(&rev)
            };
            match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                [] | ["show"] => true,
                [rev] => rev_ok(rev),
                ["show", rev] => rev_ok(rev),
                _ => false,
            }
        }
        "branch" | "tag" => {
            let mut list_mode = false;
            let mut positional = false;
            let mut i = 0;
            while i < args.len() {
                let a = args[i].as_str();
                i += 1;
                if let Some(long) = a.strip_prefix("--") {
                    let name = long.split('=').next().unwrap_or("");
                    match name {
                        "list" => list_mode = true,
                        "show-current" | "verbose" | "all" | "remotes" | "no-color" | "color" | "column" | "no-column" => {
                            if name == "show-current" && verb == "tag" {
                                return false;
                            }
                        }
                        _ if valued(a) => {
                            if optional_value(a) && args.get(i).is_some_and(|v| !v.starts_with('-')) {
                                i += 1;
                            }
                        }
                        _ => return false,
                    }
                } else if a.starts_with('-') && a.len() > 1 {
                    let flags = &a[1..];
                    if verb == "tag" {
                        // A cluster of only `l` and `n` with an optional trailing digit run: -l, -n, -n3, -ln, -nl, -ln5
                        let letters = flags.trim_end_matches(|c: char| c.is_ascii_digit());
                        if !letters.is_empty() && letters.bytes().all(|b| matches!(b, b'l' | b'n')) {
                            list_mode = true;
                        } else {
                            return false;
                        }
                    } else if flags.bytes().all(|b| matches!(b, b'l' | b'a' | b'r' | b'v')) {
                        list_mode |= flags.contains('l');
                    } else {
                        return false;
                    }
                } else {
                    positional = true;
                }
            }
            // A positional is a name to create unless a list flag turns it into a pattern.
            !positional || list_mode
        }
        _ => false,
    }
}

/// For `stash` (bare, `push`, `save`) carrying an untracked flag: the pseudo revision of the files it would remove.
fn git_stash_untracked_scope(args: &[String]) -> Option<&'static str> {
    use crate::permission::branch_switch::{UNTRACKED_ALL_REV, UNTRACKED_REV};
    let first = args.first().map(String::as_str);
    if !matches!(first, None | Some("push") | Some("save")) && !first.is_some_and(|f| f.starts_with('-')) {
        return None;
    }
    let mut scope = None;
    for a in args.iter().take_while(|a| a.as_str() != "--") {
        if let Some(long) = a.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or(""));
            if is_accepted_long_option_prefix(&name, "--all", 3) {
                return Some(UNTRACKED_ALL_REV);
            }
            if is_accepted_long_option_prefix(&name, "--include-untracked", 3) {
                scope = Some(UNTRACKED_REV);
            }
        } else if a.starts_with('-') {
            if a.contains('a') {
                return Some(UNTRACKED_ALL_REV);
            }
            if a.contains('u') {
                scope = Some(UNTRACKED_REV);
            }
        }
    }
    scope
}

pub(crate) fn ambient_exec_risk_from_plan(plan: &AmbientScanPlan) -> bool {
    match plan {
        AmbientScanPlan::FailClosed => true,
        AmbientScanPlan::CheckDirs(dirs) => dirs.iter().any(|c| local_repo_config_has_exec_risk(c)),
    }
}

#[cfg(test)]
pub(crate) fn ambient_scan_plan_from_cmd(cmd: &str, session_cwd: &Path) -> Option<AmbientScanPlan> {
    let tree = try_parse_shell(cmd)?;
    let segments = try_parse_word_only_commands_sequence(&tree, cmd)?;
    let raw: Vec<Vec<String>> = segments.iter().map(|s| s.words().to_vec()).collect();
    Some(ambient_scan_plan_from_segments(&raw, session_cwd))
}

/// Token probe for unparseable scripts. Bare `git` tokens fail closed (e.g. `echo git $(true)`).
pub(crate) fn script_may_invoke_git(cmd: &str) -> bool {
    for token in cmd.split(|c: char| {
        c.is_whitespace() || matches!(c, '|' | '&' | ';' | '(' | ')' | '`' | '\n' | '<' | '>')
    }) {
        let trimmed = token.trim_matches(|c| matches!(c, '\'' | '"' | '`'));
        if trimmed.is_empty() {
            continue;
        }
        if normalized_token_basename(trimmed) == "git" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(cmd: &str) -> Vec<String> {
        cmd.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn sort_compress_program_flags() {
        for cmd in [
            "sort --compress-program=tools/x in",
            "sort --compress-program tools/x in",
            "sort --compress-prog=tools/x in",
            "sort --co=tools/x in",
            "/usr/bin/sort --compress-program=/tmp/pwn in",
            "SORT.EXE --compress-program=/tmp/pwn in",
        ] {
            assert!(segment_has_exec_risk_flag(&words(cmd)), "{cmd}");
        }
        for cmd in [
            "sort in.csv",
            "sort --check big.csv",
            "sort -- --compress-program=foo",
        ] {
            assert!(!segment_has_exec_risk_flag(&words(cmd)), "{cmd}");
        }
    }

    #[test]
    fn git_exec_risk_globals() {
        for cmd in [
            "git -c core.fsmonitor=/tmp/pwn status",
            "git -ccore.fsmonitor=/tmp/pwn status",
            "git --config-env=core.fsmonitor=EVIL status",
            "git --config-env core.fsmonitor=EVIL status",
            "git --config-e=core.fsmonitor=EVIL status",
            "git -c status",
            "git -C /tmp -c core.fsmonitor=/tmp/pwn status",
            "git --git-dir=/evil/.git status",
            "git --git-dir /evil/.git status",
            "git --work-tree=/evil status",
            "git --work-tree /evil status",
            "git --gi=/evil/.git status",
            "git --wor=/evil status",
            "/usr/bin/git -c core.fsmonitor=/tmp/pwn status",
            "Git -c core.fsmonitor=/tmp/pwn status",
            r"C:\Git\cmd\git.exe -c core.fsmonitor=/tmp/pwn status",
        ] {
            assert!(segment_has_exec_risk_flag(&words(cmd)), "{cmd}");
        }
        for cmd in [
            "git log -c",
            "git status",
            "git -C /tmp status",
            "git -C/tmp status",
        ] {
            assert!(!segment_has_exec_risk_flag(&words(cmd)), "{cmd}");
        }
    }

    #[test]
    fn read_only_git_queries() {
        // Safe verbs, benign globals, ordinary flags.
        for cmd in [
            "git status",
            "git -C sub status",
            "git -C/abs/path log --oneline --graph",
            "git --no-pager diff --stat",
            "git -P show HEAD",
            "git cat-file -p HEAD:src/main.rs",
            "git grep --only-matching pattern",
            "git grep --or -e a -e b",
            "git rev-parse --show-toplevel",
            "git shortlog -sn",
        ] {
            assert!(git_words_are_read_only_query(&words(cmd)), "{cmd}");
        }
        // Non-query verbs, unmodeled/exec globals, non-bare git.
        for cmd in [
            "git push --force",
            "git checkout main",
            "git",
            "git -C sub",
            "git -c core.fsmonitor=/x status",
            "git --git-dir=/evil/.git status",
            "git --exec-path=/evil status",
            "git -p status",
            "git --paginate status",
            "git --attr-source=evil check-attr -a f",
            "git -- status",
            "/usr/bin/git status",
            "Git status",
            "rm -rf /",
        ] {
            assert!(!git_words_are_read_only_query(&words(cmd)), "{cmd}");
        }
    }

    #[test]
    fn unsafe_query_options_apply_to_every_verb() {
        // Driver / write flags block on any verb, abbreviations fail closed.
        for cmd in [
            "git cat-file --filters HEAD:data.bin",
            "git cat-file --textconv HEAD:data.bin",
            "git cat-file --filt HEAD:data.bin",
            "git show --textconv HEAD:data.bin",
            "git log --textconv -p",
            "git log --ext-diff",
            "git show --output=/tmp/out HEAD",
            "git log --output /tmp/out",
            "git grep -Ovim TODO",
            "git grep -O touch-evil TODO",
            "git grep --open-files-in-pager=sh TODO",
            "git grep --op=sh TODO",
        ] {
            assert!(git_words_have_unsafe_query_option(&words(cmd)), "{cmd}");
            assert!(!git_words_are_read_only_query(&words(cmd)), "{cmd}");
        }
        for cmd in [
            "git cat-file -p HEAD:src/main.rs",
            "git log --oneline",
            "git log --only-matching",
            "git grep --or -e a -e b",
            "git show --stat HEAD",
        ] {
            assert!(!git_words_have_unsafe_query_option(&words(cmd)), "{cmd}");
        }
        // `-O` outside `git grep` is not the pager flag.
        assert!(!git_words_have_unsafe_query_option(&words(
            "git log -O/tmp/orderfile"
        )));
    }

    #[test]
    fn interleaved_wrapper_transparent_facts() {
        let f = segment_exec_facts(&words("command git status"));
        assert!(f.has_git && !f.exec_risk);
        let f = segment_exec_facts(&words("exec sort --compress-program=/tmp/pwn in"));
        assert!(f.exec_risk && !f.has_git);
        let f = segment_exec_facts(&words("builtin git -c core.fsmonitor=/tmp/pwn status"));
        assert!(f.exec_risk && f.has_git);

        for cmd in [
            "command env git status",
            "exec env RUST_LOG=debug git status",
            "command timeout 1 git status",
            "timeout 1 command env git status",
            "command exec env git status",
            "/usr/bin/command env /usr/bin/git status",
            "command env command env command env git status",
        ] {
            let f = segment_exec_facts(&words(cmd));
            assert!(f.has_git || f.exec_risk, "{cmd} → {f:?}");
        }
        assert!(
            segment_exec_facts(&words("command env sort --compress-program=/tmp/pwn in")).exec_risk
        );
        assert!(
            segment_exec_facts(&words(
                "command timeout 1 env git -c core.fsmonitor=/x status"
            ))
            .exec_risk
        );
        assert!(segment_exec_facts(&words("command env -C /evil git status")).exec_risk);
        assert!(segment_exec_facts(&words("command --unknown git status")).exec_risk);
        assert!(segment_exec_facts(&words("command exec git status")).has_git);
    }

    #[test]
    fn interleaved_ambient_plans() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path();
        for cmd in [
            "command env git -C sub status",
            "command timeout 1 git -C sub status",
            "timeout 1 command env git -C sub status",
        ] {
            match ambient_scan_plan_from_cmd(cmd, base).unwrap() {
                AmbientScanPlan::CheckDirs(d) => assert_eq!(d, vec![base.join("sub")], "{cmd}"),
                other => panic!("{cmd}: expected CheckDirs, got {other:?}"),
            }
        }
        assert!(matches!(
            ambient_scan_plan_from_cmd("command env -C /evil git status", base).unwrap(),
            AmbientScanPlan::FailClosed
        ));
        assert!(matches!(
            ambient_scan_plan_from_cmd("command --unknown git status", base).unwrap(),
            AmbientScanPlan::FailClosed
        ));
    }

    #[test]
    fn attached_and_chained_c_paths() {
        let plan = |cmd: &str, cwd: &Path| ambient_scan_plan_from_cmd(cmd, cwd).unwrap();
        let root = tempfile::tempdir().unwrap();
        let base = root.path();
        match plan("git -C sub status", base) {
            AmbientScanPlan::CheckDirs(d) => {
                assert_eq!(d, vec![base.join("sub")]);
            }
            other => panic!("expected CheckDirs, got {other:?}"),
        }
        match plan("git -C/abs/path status", base) {
            AmbientScanPlan::CheckDirs(d) => {
                assert_eq!(d, vec![PathBuf::from("/abs/path")]);
            }
            other => panic!("expected CheckDirs, got {other:?}"),
        }
        match plan("git -C a -C b status", base) {
            AmbientScanPlan::CheckDirs(d) => {
                assert_eq!(d, vec![base.join("a").join("b")]);
            }
            other => panic!("expected CheckDirs, got {other:?}"),
        }
        assert!(matches!(
            plan("git --git-dir=evil/.git status", base),
            AmbientScanPlan::FailClosed
        ));
    }

    #[test]
    fn ambient_config_fixtures() {
        for (cfg, should_flag) in [
            ("[core]\n\tfsmonitor = /tmp/pwn\n", true),
            ("[diff \"evil\"]\n\tcommand = /tmp/pwn\n", true),
            ("[diff \"evil\"]\n\ttextconv = /tmp/pwn\n", true),
            ("[alias]\n\tstatus = !/tmp/pwn\n", true),
            // P166 r8B: a configured hooks path, and a shell alias whatever its name, are ambient exec
            ("[core]\n\thooksPath = /tmp/evil\n", true),
            ("[alias]\n\tx = !sh -c 'cp e .git/hooks/pre-commit'\n", true),
            ("[alias]\n\tco = checkout\n", false),
            // P158 (upstream 75810042): a repo-local content filter runs on status/diff
            ("[filter \"pwn\"]\n\tclean = /tmp/pwn ; cat\n", true),
            ("[filter \"pwn\"]\n\tsmudge = /tmp/pwn\n", true),
            ("[filter \"pwn\"]\n\tprocess = /tmp/pwn\n", true),
            (
                "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = true\n\
                 [filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\
                 \tsmudge = git-lfs smudge -- %f\n\
                 \tprocess = git-lfs filter-process\n\
                 [alias]\n\tst = status\n",
                true,
            ),
            (
                "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = true\n\
                 [filter \"lfs\"]\n\trequired = true\n\
                 [alias]\n\tst = status\n",
                false,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            git2::Repository::init(tmp.path()).unwrap();
            std::fs::write(tmp.path().join(".git/config"), cfg).unwrap();
            assert_eq!(
                local_repo_config_has_exec_risk(tmp.path()),
                should_flag,
                "cfg={cfg:?}"
            );
        }

        // Plain include.
        {
            let tmp = tempfile::tempdir().unwrap();
            git2::Repository::init(tmp.path()).unwrap();
            std::fs::write(
                tmp.path().join(".git/extra"),
                "[core]\nfsmonitor = /tmp/pwn\n",
            )
            .unwrap();
            std::fs::write(
                tmp.path().join(".git/config"),
                "[core]\n\trepositoryformatversion = 0\n\
                 [include]\n\tpath = extra\n",
            )
            .unwrap();
            assert!(local_repo_config_has_exec_risk(tmp.path()));
        }

        // includeIf.gitdir: exact absolute gitdir (no trailing slash).
        // libgit2 appends `**` when the pattern ends with `/`, and wildmatch `dir/**` does not match `dir` itself, so trailing-slash patterns fail
        // Use repo.path() as libgit2 reports it (not a re-canonicalized twin).
        {
            let tmp = tempfile::tempdir().unwrap();
            let repo = git2::Repository::init(tmp.path()).unwrap();
            let gitdir_pat = repo
                .path()
                .to_string_lossy()
                .trim_end_matches(['/', '\\'])
                .to_owned();
            std::fs::write(
                tmp.path().join(".git/extra-if"),
                "[core]\nfsmonitor = /tmp/pwn\n",
            )
            .unwrap();
            std::fs::write(
                tmp.path().join(".git/config"),
                format!(
                    "[core]\n\trepositoryformatversion = 0\n\
                     [includeIf \"gitdir:{gitdir_pat}\"]\n\tpath = extra-if\n"
                ),
            )
            .unwrap();
            assert!(
                local_repo_config_has_exec_risk(tmp.path()),
                "includeIf.gitdir must be honored"
            );
        }

        // A config path that is a directory opens on Linux but is not a regular file, so it fails closed
        {
            let tmp = tempfile::tempdir().unwrap();
            git2::Repository::init(tmp.path()).unwrap();
            let cfg = tmp.path().join(".git/config");
            std::fs::remove_file(&cfg).unwrap();
            std::fs::create_dir(&cfg).unwrap();
            assert!(
                local_repo_config_has_exec_risk(tmp.path()),
                "unopenable config path must fail closed"
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            git2::Repository::init(tmp.path()).unwrap();
            let cfg = tmp.path().join(".git/config");
            let mut perms = std::fs::metadata(&cfg).unwrap().permissions();
            perms.set_mode(0o000);
            std::fs::set_permissions(&cfg, perms).unwrap();
            // Root and CAP_DAC_OVERRIDE can still open mode 000 files.
            if std::fs::File::open(&cfg).is_err() {
                assert!(
                    local_repo_config_has_exec_risk(tmp.path()),
                    "unreadable config must fail closed"
                );
            }
            let mut perms = std::fs::metadata(&cfg).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&cfg, perms).unwrap();
        }
    }

    #[test]
    fn script_may_invoke_git_probe() {
        assert!(script_may_invoke_git("git status $(true)"));
        assert!(script_may_invoke_git("/usr/bin/git status"));
        assert!(script_may_invoke_git("cd x && git diff"));
        assert!(script_may_invoke_git(r"C:\Git\cmd\git.exe status $(true)"));
        assert!(!script_may_invoke_git("echo hello"));
        assert!(!script_may_invoke_git("mygit status"));
        // Fail-closed false positive: bare `git` token in unparseable script.
        assert!(script_may_invoke_git("echo git $(true)"));
    }

    #[test]
    fn ambient_cd_and_git_c() {
        let root = tempfile::tempdir().unwrap();
        let clean = root.path().join("clean");
        let evil = root.path().join("evil");
        std::fs::create_dir_all(&clean).unwrap();
        std::fs::create_dir_all(&evil).unwrap();
        git2::Repository::init(&clean).unwrap();
        git2::Repository::init(&evil).unwrap();
        std::fs::write(evil.join(".git/config"), "[core]\nfsmonitor = /tmp/pwn\n").unwrap();

        let plan = ambient_scan_plan_from_cmd("git -C evil status", &clean).unwrap();
        assert!(ambient_exec_risk_from_plan(&plan));

        let plan = ambient_scan_plan_from_cmd("cd evil && git status", &clean).unwrap();
        assert!(ambient_exec_risk_from_plan(&plan));

        // `$HOME` expansion is rejected by word-only parse, so the ambient plan is unavailable (`None`)
        // Production maps that to fail-closed via `unparseable_exec_risk`, which calls `script_may_invoke_git`
        // Do not invent a word-only plan that weakens the expansion boundary
        let expansion = "cd \"$HOME\" && git status";
        assert!(
            ambient_scan_plan_from_cmd(expansion, &clean).is_none(),
            "expansion must stay outside word-only ambient planning"
        );
        assert!(
            script_may_invoke_git(expansion),
            "unparseable git-bearing script must fail closed"
        );

        let plan = ambient_scan_plan_from_cmd("git status", &clean).unwrap();
        assert!(!ambient_exec_risk_from_plan(&plan));
    }

    #[test]
    fn worktree_common_and_config_worktree() {
        let main = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(main.path()).unwrap();
        let sig = git2::Signature::now("t", "t@t").unwrap();
        {
            let mut index = repo.index().unwrap();
            let tree_id = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();
            repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
                .unwrap();
        }
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        repo.branch("wt-branch", &head, false).unwrap();
        let wt_dir = main.path().join("wt");
        let mut opts = git2::WorktreeAddOptions::new();
        let branch = repo
            .find_branch("wt-branch", git2::BranchType::Local)
            .unwrap();
        opts.reference(Some(branch.get()));
        repo.worktree("wt", &wt_dir, Some(&opts)).unwrap();

        std::fs::write(
            main.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = /tmp/pwn\n",
        )
        .unwrap();
        assert!(local_repo_config_has_exec_risk(&wt_dir));

        std::fs::write(
            main.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = true\n\
             [extensions]\n\tworktreeConfig = true\n",
        )
        .unwrap();
        std::fs::write(
            main.path().join(".git/worktrees/wt/config.worktree"),
            "[core]\nfsmonitor = /tmp/pwn\n",
        )
        .unwrap();
        assert!(local_repo_config_has_exec_risk(&wt_dir));
    }
}
