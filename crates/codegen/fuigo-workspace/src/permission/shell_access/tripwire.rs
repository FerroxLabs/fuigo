//! The class tripwire (P166 r7, input rebuilt in r8).
//!
//! The tripwire judges every path-like string a non-reader command can hand to its program or its environment, with
//! the same protected-target matcher as any other write target. Round 8 fixes its INPUT, once: the candidate strings
//! are a DECODED VIEW of the command, not the parser's raw spelling:
//!
//! * every word after quote removal, with ANSI-C `$'...'` escapes decoded (the parser decodes `$'...'` words itself);
//! * every result of brace expansion (`{x,.git}/hooks/x` is `x/hooks/x` and `.git/hooks/x`), capped; an over-cap or
//!   unparseable expansion fails closed when any alternative could form a protected name;
//! * every glob word, matched against the names the protected matcher knows ([`GLOB_NAMES`]): `.git/hook?` names
//!   `.git/hooks`, `src/*.rs` names nothing;
//! * the VALUE of every leading `NAME=value` assignment and of `env`'s assignments and wrapper words;
//! * the directory of `env -C` / `--chdir`, and every other token resolved against it;
//! * here-string and here-document bodies (for programs that read them as input);
//! * words the parser could not decode: decoded best-effort and scanned; if `$`/backticks remain, the command gets
//!   the protected floor only when the text still contains a protected NAME as a substring after quote and
//!   backslash removal (`echo $'a\n'` and `printf '%s\n' "$x"` contain none, so they stay silent).
//!
//! Which words are skipped is positive, per program: only the words a program's shape identifies as INPUT operands
//! (sources of a copy, members of an archive, URLs, files a reader reads). An option's separate value, and any
//! operand no shape classified, is scanned.

use super::shell_program_name;

/// What the parser saw but did not turn into a literal word, for one command.
#[derive(Clone, Debug, Default)]
pub(super) struct CommandExtras {
    /// Raw source text of words that could not be decoded (`$x`, `$(...)`, `"a"$'b'`).
    pub raw_ambiguous: Vec<String>,
    /// Raw text of the value of each leading `NAME=value` assignment.
    pub assignments: Vec<String>,
    /// Raw text of here-strings and here-documents attached to the command.
    pub stdin_bodies: Vec<String>,
    /// P166 r11: an undecodable word sits among a `git` command's global options (a `-C` / `--git-dir` /
    /// `--work-tree` / `--exec-path` value could be it): the repository directory is unknown.
    pub git_option_untrusted: bool,
}

/// The result of the tripwire for one command.
#[derive(Default)]
pub(super) struct Tripwire {
    pub tokens: Vec<String>,
    /// A word that cannot be decoded or expanded within the cap could name a protected path.
    pub unpinned: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Pure readers: operands are inputs; option words (and their dangerous values) are scanned.
    Reader,
    /// Shells, `find`, `xargs`: judged by their own classifiers (launched commands, nested scripts).
    Skip,
    /// `sed`/`awk`: the program text is scanned, later operands are input files.
    Script,
    /// `cp`, `rsync`, `scp`, `install`, `ln`, `ditto`: every operand but the last is a source.
    Copy,
    /// `tar`, `zip`, `curl`, `wget`, `patch`, `yq`...: operands are archive members, URLs or classified files.
    Sources,
    /// `docker`, `podman`, `kubectl`: everything is scanned except the host-side sources of `cp`.
    Docker,
    /// `git`: owned by the git findings (part B); non-dash words are still skipped as before.
    Git,
    /// Everything else: every word is scanned.
    ScanAll,
}

fn shape_of(program: &str) -> Shape {
    match program {
        "cat" | "bat" | "less" | "more" | "head" | "tail" | "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ls" | "stat"
        | "file" | "wc" | "diff" | "cmp" | "sha1sum" | "sha256sum" | "sha512sum" | "md5sum" | "cksum" | "du" | "tree"
        | "realpath" | "readlink" | "basename" | "dirname" | "echo" | "printf" | "test" | "[" | "jq" | "true"
        | "false" | "type" | "which" | "cd" | "pushd" | "popd" | "source" | "." | "chmod" | "chown" | "chgrp" => {
            Shape::Reader
        }
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "find" | "xargs" => Shape::Skip,
        "sed" | "gsed" | "awk" | "gawk" | "mawk" | "nawk" => Shape::Script,
        "cp" | "rsync" | "scp" | "install" | "ln" | "ditto" => Shape::Copy,
        "tar" | "gtar" | "bsdtar" | "zip" | "unzip" | "7z" | "7za" | "7zz" | "7zr" | "cpio" | "pax" | "curl" | "wget"
        | "patch" | "yq" => Shape::Sources,
        "docker" | "podman" | "kubectl" => Shape::Docker,
        "git" => Shape::Git,
        _ => Shape::ScanAll,
    }
}

/// Separate-value options of one program: `(scan letters, skip letters, scan longs, skip longs)`. A scanned value is
/// judged; a skipped value is a known input or a non-path. Short letters not listed are flags.
struct Opts {
    short_scan: &'static str,
    short_skip: &'static str,
    long_scan: &'static [&'static str],
    long_skip: &'static [&'static str],
}

const fn opts(
    short_scan: &'static str,
    short_skip: &'static str,
    long_scan: &'static [&'static str],
    long_skip: &'static [&'static str],
) -> Opts {
    Opts { short_scan, short_skip, long_scan, long_skip }
}

fn opts_of(program: &str) -> Opts {
    match program {
        "cp" | "ln" => opts("tS", "", &["target-directory", "suffix"], &["context"]),
        "chmod" | "chown" | "chgrp" => opts("", "", &[], &["reference"]),
        "install" => opts("tSmog", "", &["target-directory", "suffix", "mode", "owner", "group"], &["context"]),
        "rsync" => opts(
            "eT",
            "BfM@",
            &["rsh", "rsync-path", "backup-dir", "partial-dir", "temp-dir", "log-file", "write-batch", "only-write-batch"],
            &[
                "exclude", "include", "exclude-from", "include-from", "filter", "files-from", "read-batch", "password-file",
                "port", "address", "sockopts", "bwlimit", "timeout", "contimeout", "max-size", "min-size", "modify-window",
                "block-size", "out-format", "info", "debug", "iconv", "protocol", "outbuf", "max-delete", "stop-after",
                "stop-at", "early-input", "checksum-choice", "compress-choice", "compress-level", "skip-compress", "suffix",
                "link-dest", "compare-dest", "copy-dest", "chmod", "chown", "usermap", "groupmap",
            ],
        ),
        "scp" => opts("oSJ", "FiPclDX", &[], &[]),
        "curl" => opts(
            "oDc",
            "HXdubAeFwxEKTCmrYyzQtU",
            &[
                "output", "output-dir", "dump-header", "cookie-jar", "trace", "trace-ascii", "stderr", "libcurl",
                "etag-save", "hsts", "alt-svc",
            ],
            &[
                "header", "request", "data", "data-raw", "data-binary", "data-urlencode", "user", "cookie", "user-agent",
                "referer", "form", "url", "proxy", "write-out", "cacert", "cert", "key", "upload-file", "max-time",
                "connect-timeout", "retry", "range", "config", "limit-rate", "max-redirs", "continue-at", "interface",
                "resolve", "connect-to", "etag-compare", "json", "variable", "expand-data", "capath", "proxy-user",
            ],
        ),
        "wget" => opts(
            "OoaPe",
            "iBUtTwQlARDIXY",
            &["output-document", "output-file", "append-output", "directory-prefix", "execute", "save-cookies", "warc-file"],
            &[
                "input-file", "user-agent", "tries", "timeout", "wait", "quota", "level", "accept", "reject", "header",
                "load-cookies", "post-data", "post-file", "referer", "user", "password", "base", "limit-rate",
                "ca-certificate", "certificate", "private-key",
            ],
        ),
        "tar" | "gtar" | "bsdtar" => opts(
            "fCIF",
            "TXbHLVgKN",
            &[
                "file", "directory", "index-file", "use-compress-program", "info-script", "new-volume-script",
                "to-command", "checkpoint-action", "rsh-command",
            ],
            &[
                "files-from", "exclude-from", "exclude", "transform", "xform", "newer", "newer-mtime", "blocking-factor",
                "format", "label", "owner", "group", "mode", "strip-components", "exclude-tag", "newer-than",
                "after-date", "checkpoint", "totals",
            ],
        ),
        "zip" => opts("bO", "ixnPt", &["output-file", "temp-path"], &["include", "exclude", "suffixes"]),
        "unzip" => opts("d", "x", &[], &[]),
        "cpio" => opts("FIO", "RHEMC", &["file"], &["format", "pattern-file", "owner"]),
        "pax" => opts("f", "sxbEGgopTUD", &[], &[]),
        "patch" => opts("ord", "ipVBzDFgxY", &["output", "reject-file", "directory"], &["strip", "input", "prefix"]),
        "less" => opts("oO", "bhjkpPtTxyzD", &["log-file", "LOG-FILE"], &["pattern", "tag", "prompt"]),
        "tree" => opts("o", "LPIHT", &[], &[]),
        "diff" => opts("", "", &["output"], &[]),
        "rg" => opts("", "efgjmtTAB", &["pre"], &["file", "glob", "regexp", "type", "max-count"]),
        "bat" => opts("", "", &["pager"], &[]),
        "sed" | "gsed" => opts("e", "fl", &["expression"], &["file", "line-length"]),
        "awk" | "gawk" | "mawk" | "nawk" => opts("v", "fF", &["assign"], &["file", "field-separator"]),
        _ => opts("", "", &[], &[]),
    }
}

/// Whether `word` is (or starts with) one of the program's value options that are scanned: `--long`, `--long=VALUE`,
/// `-x`, `-xVALUE`, or a short cluster whose first value letter is a scanned one.
fn word_is_scan_option(table: &Opts, word: &str) -> bool {
    if let Some(long) = word.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or(long);
        return !name.is_empty() && table.long_scan.contains(&name);
    }
    let Some(cluster) = word.strip_prefix('-') else {
        return false;
    };
    for ch in cluster.chars() {
        if table.short_scan.contains(ch) {
            return true;
        }
        if table.short_skip.contains(ch) {
            return false;
        }
    }
    false
}

/// Long flags that take no value in the copy and fetch programs (so the word after them is an operand).
fn is_boolean_long(name: &str) -> bool {
    const BOOLEANS: &[&str] = &[
        "archive", "verbose", "recursive", "force", "dry-run", "progress", "update", "compress", "checksum", "quiet",
        "links", "times", "perms", "owner", "group", "devices", "specials", "inplace", "partial", "stats", "relative",
        "backup", "one-file-system", "numeric-ids", "remove-source-files", "existing", "whole-file", "sparse",
        "hard-links", "itemize-changes", "human-readable", "dirs", "prune-empty-dirs", "interactive", "symbolic",
        "dereference", "parents", "silent", "show-error", "fail", "location", "insecure", "include", "head",
        "remote-name", "remote-name-all", "compressed", "progress-bar", "globoff", "create", "extract", "list",
        "append", "gzip", "bzip2", "xz", "zstd", "bzip", "gunzip", "preserve", "no-clobber", "continue", "mirror",
        "timestamping", "spider", "recursive", "xattrs", "acls", "executability", "cvs-exclude", "from0", "list-only",
        "version", "help", "copy-links", "safe-links", "verify", "totals", "overwrite", "keep-old-files",
    ];
    BOOLEANS.contains(&name)
        || ["no-", "delete", "preserve", "copy-", "keep-", "ignore-", "force-", "skip-", "remove-"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Split `inner[1..]` into operand indexes (inputs candidates) and the rest. Option words are never operands; the
/// separate value of a known value option is not an operand (it is scanned or, for known inputs, skipped).
fn operand_indexes(shape: Shape, program: &str, inner: &[String], skipped_values: &mut Vec<usize>) -> Vec<usize> {
    let table = opts_of(program);
    let unknown_long_takes_value = !matches!(shape, Shape::Reader | Shape::Script);
    let plus_is_option = shape == Shape::Reader;
    let mut operands = Vec::new();
    let mut after_dashes = false;
    // `Some(true)`: the next word is a scanned value; `Some(false)`: a skipped (input) value.
    let mut expect: Option<bool> = None;
    for (i, word) in inner.iter().enumerate().skip(1) {
        if let Some(scan) = expect.take() {
            if !scan {
                skipped_values.push(i);
            }
            continue;
        }
        if after_dashes {
            operands.push(i);
            continue;
        }
        if word == "--" {
            after_dashes = true;
        } else if word == "-" {
            operands.push(i);
        } else if let Some(long) = word.strip_prefix("--") {
            if long.contains('=') {
                // `chmod --reference=FILE` names a file that is only read (P166 r8B).
                if matches!(program, "chmod" | "chown" | "chgrp") && long.starts_with("reference=") {
                    skipped_values.push(i);
                }
                continue;
            }
            if table.long_scan.contains(&long) {
                expect = Some(true);
            } else if table.long_skip.contains(&long) {
                expect = Some(false);
            } else if unknown_long_takes_value && !is_boolean_long(long) {
                expect = Some(true);
            }
        } else if let Some(cluster) = word.strip_prefix('-') {
            let chars: Vec<char> = cluster.chars().collect();
            for (at, ch) in chars.iter().enumerate() {
                let scan = table.short_scan.contains(*ch);
                if scan || table.short_skip.contains(*ch) {
                    if at + 1 == chars.len() {
                        expect = Some(scan);
                    }
                    break;
                }
            }
        } else if plus_is_option && word.starts_with('+') {
            // `less +cmd`: an initial command, scanned as an option word.
        } else {
            operands.push(i);
        }
    }
    operands
}

/// Names the protected matcher knows, for glob words (A8). Dot-names only match a pattern that starts with a dot.
const GLOB_NAMES: &[&str] = &[
    ".git", "hooks", "modules", ".mcp.json", ".claude", "settings.json", "settings.local.json", ".cursor", "hooks.json",
    ".fuigo", "hooks-paths", ".ssh", "etc", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc", ".login", ".logout",
    ".inputrc", ".xprofile", "pre-commit", "commit-msg", "pre-push", "post-commit", "post-merge", "pre-rebase",
    "prepare-commit-msg", "post-checkout", "pre-receive", "update", "post-receive", "pre-applypatch", "applypatch-msg",
    "post-update", "pre-merge-commit", "fsmonitor-watchman", "push-to-checkout", "reference-transaction",
];

/// Substrings that make an undecodable word potentially protected (after quote and backslash removal).
const PROTECTED_NEEDLES: &[&str] = &[
    ".git/hooks", ".git/modules", ".mcp.json", ".fuigo", ".claude/settings", ".cursor/hooks", ".ssh", "/etc/", ".bashrc",
    ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".kshrc",
    ".cshrc", ".tcshrc", ".inputrc", "hooks-paths",
];

pub(super) const BRACE_CAP: usize = 256;
const GLOB_CAP: usize = 64;

/// P166 r12: an undecodable word whose text still shows a protected name (`"$x/.git/hooks/pre-commit"`).
pub(super) fn raw_has_protected_needle(text: &str) -> bool {
    contains_protected_needle(text)
}

fn contains_protected_needle(text: &str) -> bool {
    let plain: String = text.chars().filter(|c| !matches!(c, '\'' | '"' | '\\')).collect();
    PROTECTED_NEEDLES.iter().any(|needle| plain.contains(needle))
}

/// Decode ANSI-C `$'...'` escapes (the body between the quotes).
pub(super) fn decode_ansi_c_body(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            None => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('a') => out.push('\u{7}'),
            Some('b') => out.push('\u{8}'),
            Some('e' | 'E') => out.push('\u{1b}'),
            Some('f') => out.push('\u{c}'),
            Some('v') => out.push('\u{b}'),
            Some('x') => {
                let mut value = 0u32;
                let mut digits = 0;
                while digits < 2 && let Some(d) = chars.peek().and_then(|c| c.to_digit(16)) {
                    value = value * 16 + d;
                    chars.next();
                    digits += 1;
                }
                out.push(char::from_u32(value).unwrap_or('?'));
            }
            Some(u @ ('u' | 'U')) => {
                let max = if u == 'u' { 4 } else { 8 };
                let mut value = 0u32;
                let mut digits = 0;
                while digits < max && let Some(d) = chars.peek().and_then(|c| c.to_digit(16)) {
                    value = value.saturating_mul(16).saturating_add(d);
                    chars.next();
                    digits += 1;
                }
                out.push(char::from_u32(value).unwrap_or('?'));
            }
            Some(first @ '0'..='7') => {
                let mut value = first.to_digit(8).unwrap_or(0);
                let mut digits = 1;
                while digits < 3 && let Some(d) = chars.peek().and_then(|c| c.to_digit(8)) {
                    value = value * 8 + d;
                    chars.next();
                    digits += 1;
                }
                out.push(char::from_u32(value).unwrap_or('?'));
            }
            Some(other) => out.push(other),
        }
    }
    out
}

/// Quote removal over raw shell text: `'..'`, `".."`, `$'..'` (decoded), `\x`. Expansions (`$x`, `` `..` ``) stay.
pub(super) fn decode_view(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    out.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() && matches!(chars[i + 1], '$' | '`' | '"' | '\\' | '\n') {
                        i += 1;
                    }
                    out.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '$' if chars.get(i + 1) == Some(&'\'') => {
                i += 2;
                let mut body = String::new();
                while i < chars.len() && chars[i] != '\'' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        body.push(chars[i]);
                        i += 1;
                    }
                    body.push(chars[i]);
                    i += 1;
                }
                i += 1;
                out.push_str(&decode_ansi_c_body(&body));
            }
            '\\' => {
                if let Some(next) = chars.get(i + 1) {
                    out.push(*next);
                }
                i += 2;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

/// How bash reads the body of a brace group that has no top-level comma.
enum Sequence {
    /// Not a simple `x..y[..step]` range: bash leaves the braces literal.
    Literal,
    /// The values, in bash's order.
    Values(Vec<String>),
    /// An integer range with more values than the budget (or too large to count). A protected name contains no digit,
    /// so one representative digit judges the word exactly as every member would.
    OverCapInts,
    /// A character range over the budget.
    OverCapChars,
}

fn sequence_int(text: &str) -> Option<i128> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Longer than an i64 holds: counted as "too large", not parsed.
    if digits.len() > 18 { return Some(i128::MAX); }
    text.parse::<i128>().ok()
}

/// Bash's sequence expression: `{x..y}` / `{x..y..incr}` with integers, or with single (ASCII) characters. An
/// increment of 0 counts as 1 and its sign is ignored (the direction follows x and y); an operand with a leading zero
/// pads every integer to the longer operand's width. Anything else is not a sequence and stays literal.
fn parse_sequence(body: &str, budget: usize) -> Sequence {
    let parts: Vec<&str> = body.split("..").collect();
    if !(parts.len() == 2 || parts.len() == 3) {
        return Sequence::Literal;
    }
    let step = match parts.get(2) {
        None => 1,
        Some(text) => match sequence_int(text) {
            Some(step) => step.unsigned_abs().max(1) as i128,
            None => return Sequence::Literal,
        },
    };
    if let (Some(from), Some(to)) = (sequence_int(parts[0]), sequence_int(parts[1])) {
        if from == i128::MAX || to == i128::MAX || step == i128::MAX {
            return Sequence::OverCapInts;
        }
        let count = (to - from).abs() / step + 1;
        if count > budget as i128 {
            return Sequence::OverCapInts;
        }
        let padded = |text: &str| {
            let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
            digits.len() > 1 && digits.starts_with('0')
        };
        let width = if padded(parts[0]) || padded(parts[1]) { parts[0].len().max(parts[1].len()) } else { 0 };
        let direction = if to >= from { 1 } else { -1 };
        let mut values = Vec::new();
        let mut at = from;
        loop {
            let digits = format!("{:0>width$}", at.abs(), width = width.saturating_sub(usize::from(at < 0)));
            values.push(if at < 0 { format!("-{digits}") } else { digits });
            let next = at + direction * step;
            if (direction > 0 && next > to) || (direction < 0 && next < to) {
                break;
            }
            at = next;
        }
        return Sequence::Values(values);
    }
    let single = |text: &str| {
        let mut chars = text.chars();
        match (chars.next(), chars.next()) {
            // Bash takes a single LETTER (any ASCII letter, in code order); a digit or punctuation is not a range end.
            (Some(c), None) if c.is_ascii_alphabetic() => Some(c as i128),
            _ => None,
        }
    };
    if let (Some(from), Some(to)) = (single(parts[0]), single(parts[1])) {
        let count = (to - from).abs() / step + 1;
        if count > budget as i128 {
            return Sequence::OverCapChars;
        }
        let direction = if to >= from { 1 } else { -1 };
        let mut values = Vec::new();
        let mut at = from;
        loop {
            values.push(char::from(at as u8).to_string());
            let next = at + direction * step;
            if (direction > 0 && next > to) || (direction < 0 && next < to) {
                break;
            }
            at = next;
        }
        return Sequence::Values(values);
    }
    Sequence::Literal
}

/// Brace expansion of one word: comma groups and sequence ranges (`{a,b}`, `{1..3}`, `{a..e..2}`), as bash does.
/// `Err(())`: over the cap, so the word cannot be fully expanded and the caller must fail closed (the real path may
/// be spelled across alternatives). A group that is neither is returned unchanged, braces literal.
pub(super) fn brace_expand(word: &str, budget: &mut usize) -> Result<Vec<String>, ()> {
    let chars: Vec<char> = word.chars().collect();
    // Find the first `{` whose matching `}` closes a group.
    let mut start = 0;
    while start < chars.len() {
        if chars[start] == '{' {
            let mut depth = 0usize;
            let mut commas = Vec::new();
            let mut end = None;
            for (at, ch) in chars.iter().enumerate().skip(start) {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(at);
                            break;
                        }
                    }
                    ',' if depth == 1 => commas.push(at),
                    _ => {}
                }
            }
            if let Some(end) = end {
                let prefix: String = chars[..start].iter().collect();
                let suffix: String = chars[end + 1..].iter().collect();
                let alternatives: Vec<String> = if !commas.is_empty() {
                    let mut bounds = vec![start];
                    bounds.extend(commas);
                    bounds.push(end);
                    bounds.windows(2).map(|pair| chars[pair[0] + 1..pair[1]].iter().collect()).collect()
                } else {
                    let body: String = chars[start + 1..end].iter().collect();
                    match parse_sequence(&body, *budget) {
                        Sequence::Literal => {
                            start += 1;
                            continue;
                        }
                        Sequence::Values(values) => values,
                        Sequence::OverCapInts => vec!["0".to_owned()],
                        Sequence::OverCapChars => return Err(()),
                    }
                };
                let mut out = Vec::new();
                for alternative in alternatives {
                    for expanded in brace_expand(&format!("{prefix}{alternative}{suffix}"), budget)? {
                        if *budget == 0 {
                            return Err(());
                        }
                        *budget -= 1;
                        out.push(expanded);
                    }
                }
                return Ok(out);
            }
        }
        start += 1;
    }
    Ok(vec![word.to_owned()])
}

fn glob_match(pattern: &[char], name: &[char]) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some('*') => (0..=name.len()).any(|skip| glob_match(&pattern[1..], &name[skip..])),
        Some('?') => !name.is_empty() && glob_match(&pattern[1..], &name[1..]),
        Some('[') => {
            let Some(close) = pattern.iter().skip(2).position(|c| *c == ']').map(|at| at + 2) else {
                return !name.is_empty() && name[0] == '[' && glob_match(&pattern[1..], &name[1..]);
            };
            let Some(&first) = name.first() else { return false };
            let set = &pattern[1..close];
            let (negate, set) = match set.first() {
                Some('!' | '^') => (true, &set[1..]),
                _ => (false, set),
            };
            let mut hit = false;
            let mut at = 0;
            while at < set.len() {
                if at + 2 < set.len() && set[at + 1] == '-' {
                    hit |= set[at] <= first && first <= set[at + 2];
                    at += 3;
                } else {
                    hit |= set[at] == first;
                    at += 1;
                }
            }
            hit != negate && glob_match(&pattern[close + 1..], &name[1..])
        }
        Some(c) => name.first() == Some(c) && glob_match(&pattern[1..], &name[1..]),
    }
}

/// Glob word: the paths made of the names the protected matcher knows that the pattern could match.
fn glob_expand(word: &str) -> (Vec<String>, bool) {
    let mut capped = false;
    // P166 r10: every protected needle holds a dot-name (or `/etc/`), and a component that starts with `*`, `?` or `[`
    // cannot match one. A word with no absolute root and no component starting with `.` can therefore never reach a
    // protected path, so reaching the cap there is not a reason to give up (`rm */*`).
    let anchored = word.starts_with('/') || word.split('/').any(|component| component.starts_with('.'));
    let mut paths = vec![Vec::<String>::new()];
    for component in word.split('/') {
        let options: Vec<String> = if component.contains(['*', '?', '[']) {
            let pattern: Vec<char> = component.chars().collect();
            GLOB_NAMES
                .iter()
                .filter(|name| !name.starts_with('.') || component.starts_with('.'))
                .filter(|name| glob_match(&pattern, &name.chars().collect::<Vec<_>>()))
                .map(|name| (*name).to_owned())
                .collect()
        } else {
            vec![component.to_owned()]
        };
        if options.is_empty() {
            return (Vec::new(), capped);
        }
        let mut next = Vec::new();
        for path in &paths {
            for option in &options {
                if next.len() >= GLOB_CAP {
                    capped |= anchored;
                    break;
                }
                let mut grown = path.clone();
                grown.push(option.clone());
                next.push(grown);
            }
        }
        paths = next;
    }
    (paths.into_iter().map(|parts| parts.join("/")).collect(), capped)
}

/// Path-like tokens of one expanded chunk (the r7 splitter: option values glued with `=`, `,`, `:`...).
fn emit_plain(chunk: &str, out: &mut Vec<String>) {
    for raw in chunk.split([',', '{', '}']) {
        let token = raw.trim_start_matches('+');
        if token.is_empty() || token == "-" || token == "--" {
            continue;
        }
        if token.starts_with('-') {
            let stripped = token.trim_start_matches('-');
            if !stripped.is_empty() {
                out.push(stripped.to_owned());
            }
            if !token.starts_with("--") && token.len() > 2 {
                out.push(token[2..].to_owned());
            }
        } else {
            out.push(token.to_owned());
        }
    }
}

fn emit_chunk(chunk: &str, tw: &mut Tripwire) {
    emit_plain(chunk, &mut tw.tokens);
    let mut expansions = vec![chunk.to_owned()];
    if chunk.contains('{') {
        let mut budget = BRACE_CAP;
        match brace_expand(chunk, &mut budget) {
            Ok(list) => expansions = list,
            Err(()) => {
                // Cannot be fully expanded: the protected name may be spelled across alternatives (`{.gi,a,..}t/hooks`),
                // so this word takes the protected floor whatever the pieces say. No false negative by construction.
                tw.unpinned = true;
                return;
            }
        }
    }
    for expansion in expansions {
        if expansion != chunk {
            emit_plain(&expansion, &mut tw.tokens);
        }
        if expansion.contains(['*', '?', '[']) {
            let (matches, capped) = glob_expand(&expansion);
            // Matches beyond the cap are not examined: fail closed, like an over-cap brace.
            tw.unpinned |= capped;
            for matched in matches {
                emit_plain(&matched, &mut tw.tokens);
            }
        }
    }
}

/// Scan decoded text: cut at whitespace, quotes and the punctuation that glues a path to an option value, an ex
/// command or a script, then expand braces and globs per chunk.
fn scan_text(text: &str, tw: &mut Tripwire) {
    for chunk in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '=' | ';' | ':' | '|' | '<' | '>' | '(' | ')' | '&' | '!')
    }) {
        if !chunk.is_empty() {
            emit_chunk(chunk, tw);
        }
    }
}

/// Whether the raw word holds a brace expansion that is over the cap (and so was not expanded).
fn brace_over_cap(raw: &str) -> bool {
    let decoded = decode_view(raw);
    decoded.contains('{')
        && !decoded.contains(['$', '`'])
        && decoded.split_whitespace().any(|chunk| {
            let mut budget = BRACE_CAP;
            brace_expand(chunk, &mut budget).is_err()
        })
}

/// An undecodable raw word: scanned when it decodes completely, else protected only when a protected name remains.
fn scan_raw(raw: &str, tw: &mut Tripwire) {
    let decoded = decode_view(raw);
    if decoded.contains(['$', '`']) {
        if contains_protected_needle(&decoded) {
            tw.unpinned = true;
        }
    } else {
        scan_text(&decoded, tw);
    }
}

/// The directory of `env -C DIR` / `--chdir DIR` among a command's wrapper words.
fn env_chdir_dir(wrapper: &[String]) -> Option<String> {
    let at = wrapper.iter().position(|word| shell_program_name(word) == "env")?;
    let mut words = wrapper[at + 1..].iter();
    while let Some(word) = words.next() {
        if word == "-C" || word == "--chdir" {
            return words.next().cloned();
        }
        if let Some(dir) = word.strip_prefix("--chdir=") {
            return Some(dir.to_owned());
        }
        if let Some(dir) = word.strip_prefix("-C")
            && !word.starts_with("--")
            && !dir.is_empty()
        {
            return Some(dir.to_owned());
        }
        if !word.starts_with('-') && !word.contains('=') {
            break;
        }
    }
    None
}

pub(super) fn tripwire(program: &str, words: &[String], inner: &[String], extras: &CommandExtras) -> Tripwire {
    let mut tw = Tripwire::default();
    let shape = shape_of(program);
    let start = words.len().saturating_sub(inner.len());
    let wrapper: &[String] = if words[start..] == *inner { &words[..start] } else { &[] };

    let mut skipped_values = Vec::new();
    let operands = operand_indexes(shape, program, inner, &mut skipped_values);
    let skip: Vec<usize> = match shape {
        Shape::Skip => (1..inner.len()).collect(),
        Shape::Reader => operands.iter().copied().chain(skipped_values.iter().copied()).collect(),
        Shape::Script => {
            let own_script = inner.iter().skip(1).any(|word| {
                matches!(word.as_str(), "-e" | "-f" | "--expression" | "--file" | "--program" | "--source")
                    || (word.starts_with("-e") || word.starts_with("-f")) && !word.starts_with("--") && word.len() > 2
                    || word.starts_with("--expression=")
                    || word.starts_with("--file=")
            });
            let first = usize::from(!own_script);
            operands.iter().skip(first).copied().chain(skipped_values.iter().copied()).collect()
        }
        Shape::Copy => {
            let target_dir = inner
                .iter()
                .skip(1)
                .any(|word| word == "-t" || word.starts_with("--target-directory") || (word.starts_with("-t") && !word.starts_with("--")));
            let keep_last = usize::from(!target_dir);
            let sources = operands.len().saturating_sub(keep_last);
            operands
                .iter()
                .take(sources)
                .copied()
                .chain(skipped_values.iter().copied())
                .collect()
        }
        Shape::Sources => operands.iter().copied().chain(skipped_values.iter().copied()).collect(),
        Shape::Docker => {
            let cp_at = operands.iter().position(|&i| inner[i] == "cp");
            match cp_at {
                Some(at) => operands[at + 1..operands.len().saturating_sub(1).max(at + 1)].to_vec(),
                None => Vec::new(),
            }
        }
        Shape::Git => (1..inner.len()).filter(|&i| !inner[i].starts_with('-')).collect(),
        Shape::ScanAll => Vec::new(),
    };

    let mut own = Tripwire::default();
    for (i, word) in inner.iter().enumerate().skip(1) {
        if skip.contains(&i) {
            continue;
        }
        // `./host:file` is a local file whose name has a colon in it, not a host: judge the whole word as the path.
        if shape == Shape::Copy
            && matches!(program, "scp" | "rsync")
            && operands.contains(&i)
            && word.split_once(':').is_some_and(|(host, _)| host.contains('/'))
        {
            own.tokens.push(word.clone());
            continue;
        }
        scan_text(word, &mut own);
    }
    let reader = shape == Shape::Reader;
    // An over-cap brace word cannot be judged whatever the command: a reader or git option value may still name the
    // file the program writes (`less -o {.gi,a,...}t/hooks/x`, `git config --file {...}`).
    if (reader || shape == Shape::Git) && extras.raw_ambiguous.iter().any(|raw| brace_over_cap(raw)) {
        own.unpinned = true;
    }
    if !reader && shape != Shape::Skip {
        for word in wrapper {
            scan_text(word, &mut own);
        }
    }
    // P166 r12 item 5: a reader's undecodable words and same-command assignments are scanned where the program can
    // write or change something: every `chmod`/`chown`/`chgrp` operand, and the value of an output option (`less -o`,
    // `sort -o`, `diff --output`). Plain reads (`cat "$x/.git/hooks/y"`) stay silent.
    let chmod_like = matches!(program, "chmod" | "chown" | "chgrp");
    // P166 r13 item 4: ONE table (`opts_of`: scanned short letters and long names) decides which reader option takes
    // a path the reader writes (`less -o -O --log-file --LOG-FILE`, `tree -o`, `diff --output`, `rg --pre`, `bat
    // --pager`); both the literal and the undecodable value path use it, in `--opt=VALUE` and `--opt VALUE` forms.
    let reader_table = opts_of(program);
    let reader_writes = reader
        && (chmod_like
            || (!extras.raw_ambiguous.is_empty()
                && inner.iter().skip(1).any(|word| word_is_scan_option(&reader_table, word)))
            || extras.raw_ambiguous.iter().any(|raw| word_is_scan_option(&reader_table, raw)));
    // `find` only reads unless it has an action that writes or runs something (P166 r12 item 5).
    let read_only_find = program == "find"
        && !inner.iter().any(|word| {
            matches!(word.as_str(), "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-fprint" | "-fprint0" | "-fprintf" | "-fls")
        });
    if (!reader || reader_writes) && !read_only_find {
        for value in &extras.assignments {
            scan_raw(value, &mut own);
        }
        // P166 r11 rule 4(b): git takes the same undecodable-word rule as every other writer.
        for raw in &extras.raw_ambiguous {
            scan_raw(raw, &mut own);
        }
        let reads_stdin_as_input = matches!(shape, Shape::ScanAll | Shape::Skip | Shape::Script);
        if reads_stdin_as_input && !reader {
            for body in &extras.stdin_bodies {
                scan_text(&decode_view(body), &mut own);
            }
        }
    }
    tw.unpinned |= own.unpinned;
    if let Some(dir) = env_chdir_dir(wrapper) {
        if !reader {
            tw.tokens.push(dir.clone());
        }
        for token in &own.tokens {
            if !token.starts_with('/') && !token.starts_with('~') {
                tw.tokens.push(format!("{dir}/{token}"));
            }
        }
    }
    tw.tokens.extend(own.tokens);
    tw
}
