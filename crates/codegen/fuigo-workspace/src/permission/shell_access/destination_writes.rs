use super::*;

/// What a directory-destination operand of `cp`/`mv`/`ln`/`install` writes (P166/S5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DestinationKind {
    /// `-t DIR` / `--target-directory DIR`: the directory written into.
    TargetDirectory,
    /// `DEST/<source name>`: written only if `DEST` is an existing directory.
    ViaDirectory,
    /// `DEST/<source name>` where the destination's spelling does not say it is a directory (a remote source's file
    /// name, P166 r12): written only if `DEST` is an existing directory; otherwise `DEST` is itself the new file.
    ViaExistingDirectory,
    /// A directory source copied or moved to `DEST`: its tree lands at `DEST/<rel>` (contents copy: `-T`, `SRC/.`, BSD
    /// `SRC/`) or `DEST/<source name>/<rel>`; the source is walked at evaluation time. `follow_links` when the copy
    /// dereferences symlinks inside the tree (`cp -L`, macOS `cp -r`, `rsync -L`/`-k`), so a linked directory's
    /// contents land in the copy.
    CopiedTree { follow_links: bool },
    /// A write whose landing place the command line does not pin (archive members, names a diff or a server picks,
    /// names `xargs`/`find -exec` supply, a git worktree rewrite): fails closed to `Sensitive`.
    Unpinned,
    /// A git pathspec (P166 Grok r5 HIGH 1): the file it names is written from the index or a commit. It is pinned only
    /// when it names an existing non-directory; a directory, or a path not there now (it may be a directory in the
    /// commit), fails closed.
    Pathspec,
    /// A name prefix the program appends a suffix to (`split`, `csplit`): a dot-name prefix could complete to a
    /// protected dotfile (`.mcp.jso` + `n`), so it fails closed; otherwise the prefix's directory is judged.
    GeneratedNames,
    /// A class-tripwire candidate (P166 r7): a path-like token from a non-reader command's words. Judged like a plain
    /// write target but never counts as a write by itself (a `moved` cwd or an `xargs` chain is not made `Unpinned`
    /// by a mere token).
    Watch,
    /// A metadata-only change (`chmod`/`chown`/`chgrp`, P166 r8B): silent in general, a protected hit only when the
    /// operand is a hook root or hooks directory (`.git/hooks`, `~/.fuigo/hooks`), or, with `recursive`, a directory
    /// that contains one (`chmod -R +x .git`). Never counts as a write by itself.
    HookMetadata { recursive: bool },
    /// Peer scope only: an operand of `ln` or `cp -l`/`-s`. Source or destination, it is judged as a write target (a
    /// link lets a later write reach the other end), and a bare `.claude`/`.fuigo`/`.cursor` operand counts.
    LinkOperand,
    /// Peer scope only: a `rm`/`mv`/`shred`/`truncate` operand. Judged as a write target, and a directory that holds a
    /// protected name (bounded check of the fixed well-known names) counts too.
    Container,
}

/// One directory-destination write: the path, its kind and, for [`DestinationKind::CopiedTree`], the source operand.
pub(super) type DestinationWrite = (String, DestinationKind, Option<String>);

/// GNU `cp` long options (coreutils 9.4), for abbreviated `--parents`.
pub(super) const CP_LONG_OPTIONS: [&str; 30] = [
    "archive",
    "attributes-only",
    "backup",
    "context",
    "copy-contents",
    "debug",
    "dereference",
    "force",
    "interactive",
    "keep-directory-symlink",
    "link",
    "no-clobber",
    "no-dereference",
    "no-preserve",
    "no-target-directory",
    "one-file-system",
    "parents",
    "preserve",
    "recursive",
    "reflink",
    "remove-destination",
    "sparse",
    "strip-trailing-slashes",
    "suffix",
    "symbolic-link",
    "target-directory",
    "update",
    "verbose",
    "help",
    "version",
];

/// GNU `install` long options (coreutils 9.4), for abbreviated `--directory`.
pub(super) const INSTALL_LONG_OPTIONS: [&str; 18] = [
    "backup",
    "compare",
    "context",
    "debug",
    "directory",
    "group",
    "mode",
    "no-target-directory",
    "owner",
    "preserve-context",
    "preserve-timestamps",
    "strip",
    "strip-program",
    "suffix",
    "target-directory",
    "verbose",
    "help",
    "version",
];

/// Whether the long option `name` (no `--`, no `=value`) is `want` by getopt's unique-prefix rule, or is an
/// ambiguous prefix that could be (fails closed).
pub(super) fn long_option_may_be(name: &str, table: &[&'static str], want: &str) -> bool {
    match unique_long_option(name, table) {
        Some(found) => found == want,
        None => !name.is_empty() && want.starts_with(name),
    }
}

/// `cp --parents` (any unique prefix; an ambiguous prefix counts): sources keep their path under the directory.
pub(super) fn cp_uses_parents(inner: &[String]) -> bool {
    inner.iter().skip(1).take_while(|w| *w != "--").any(|word| {
        word.strip_prefix("--").is_some_and(|long| {
            long_option_may_be(
                long.split_once('=').map_or(long, |(n, _)| n),
                &CP_LONG_OPTIONS,
                "parents",
            )
        })
    })
}

/// `install -d` / `--directory` (any unique prefix; an ambiguous prefix counts): every operand is a directory made.
pub(super) fn install_makes_directories(inner: &[String]) -> bool {
    for word in inner.iter().skip(1) {
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(n, _)| n);
            if long_option_may_be(name, &INSTALL_LONG_OPTIONS, "directory") {
                return true;
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for option in cluster.chars() {
            match option {
                'd' => return true,
                'g' | 'm' | 'o' | 'S' | 't' => break,
                _ => {}
            }
        }
    }
    false
}

/// `-t DIR` / `--target-directory[=]DIR` of a `cp`/`mv`/`ln`/`install`, parsed like getopt: a short-option cluster ends
/// at the first option that takes an argument (`-S SUFFIX`, and `install`'s `-g`/`-m`/`-o`), so `install -oroot` is the
/// owner `root`, not `-t oot`.
pub(super) fn target_directory_operands<'a>(program: &str, inner: &'a [String]) -> Vec<&'a str> {
    let takes_argument: &[char] = if program == "install" {
        &['g', 'm', 'o', 'S', 't']
    } else {
        &['S', 't']
    };
    let mut dirs = Vec::new();
    for (i, word) in inner.iter().enumerate().skip(1) {
        if word == "--" {
            break;
        }
        let next = || inner.get(i + 1).map(String::as_str);
        if let Some(long) = word.strip_prefix("--") {
            match long.split_once('=') {
                Some((name, dir)) if may_be_target_directory(name) => dirs.push(dir),
                None if may_be_target_directory(long) => dirs.extend(next()),
                _ => {}
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for (at, option) in cluster.char_indices() {
            if takes_argument.contains(&option) {
                if option == 't' {
                    let glued = &cluster[at + option.len_utf8()..];
                    if glued.is_empty() {
                        dirs.extend(next());
                    } else {
                        dirs.push(glued);
                    }
                }
                break;
            }
        }
    }
    dirs
}

/// Whether a `cp` dereferences symlinks inside a copied tree (P166 Grok r4 HIGH 2): `-L`/`--dereference`, or a
/// lowercase `-r` without `-P`/`-d`/`-a`/`--no-dereference` (macOS and FreeBSD `cp -r` walk logically; GNU `-r` does
/// not, which only makes the check stricter there). `-H` follows command-line operands only, which the walk already
/// does for the source itself. Short clusters are read like getopt: `-S SUFFIX` and `-t DIR` end the cluster.
pub(super) fn cp_follows_links(inner: &[String]) -> bool {
    let (mut follow, mut lower_r, mut physical) = (false, false, false);
    for word in inner.iter().skip(1) {
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            match long {
                "dereference" => follow = true,
                "no-dereference" | "archive" => physical = true,
                _ => {}
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for option in cluster.chars() {
            match option {
                'L' => follow = true,
                'r' => lower_r = true,
                'P' | 'd' | 'a' => physical = true,
                'S' | 't' => break,
                _ => {}
            }
        }
    }
    follow || (lower_r && !physical)
}

/// `rsync`'s operands, and whether it copies a symlinked directory as a directory (`-L`, `-k`, `--copy-links`,
/// `--copy-dirlinks`, `--copy-unsafe-links`). Options that take a value (`-e CMD`, `--exclude PATTERN`, …) keep their
/// value out of the operands, so the last operand stays the destination.
pub(super) fn rsync_operands(inner: &[String]) -> (Vec<&str>, bool) {
    const LONG_WITH_VALUE: &[&str] = &[
        "rsh",
        "rsync-path",
        "exclude",
        "include",
        "exclude-from",
        "include-from",
        "files-from",
        "filter",
        "temp-dir",
        "partial-dir",
        "backup-dir",
        "suffix",
        "compare-dest",
        "copy-dest",
        "link-dest",
        "chmod",
        "chown",
        "usermap",
        "groupmap",
        "max-size",
        "min-size",
        "bwlimit",
        "timeout",
        "contimeout",
        "port",
        "block-size",
        "password-file",
        "log-file",
        "log-file-format",
        "out-format",
        "remote-option",
        "iconv",
        "skip-compress",
        "max-delete",
        "modify-window",
        "sockopts",
        "outbuf",
        "info",
        "debug",
        "stop-after",
        "stop-at",
        "checksum-choice",
        "compress-choice",
        "compress-level",
        "address",
        "write-batch",
        "only-write-batch",
        "read-batch",
        "protocol",
        "checksum-seed",
        "max-alloc",
    ];
    let mut operands = Vec::new();
    let mut follow = false;
    let mut end_of_options = false;
    let mut skip_next = false;
    for word in inner.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if end_of_options || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end_of_options = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            if matches!(long, "copy-links" | "copy-dirlinks" | "copy-unsafe-links") {
                follow = true;
            }
            skip_next = !long.contains('=') && LONG_WITH_VALUE.contains(&long);
            continue;
        }
        for (at, option) in word[1..].char_indices() {
            match option {
                'L' | 'k' => follow = true,
                'e' | 'f' | 'T' | 'B' | 'M' => {
                    skip_next = word[1 + at + option.len_utf8()..].is_empty();
                    break;
                }
                _ => {}
            }
        }
    }
    (operands, follow)
}

/// An rsync/scp-style remote operand (`host:path`, `user@host:path`, `rsync://…`), which is not a local write.
/// Split `host:path` (scp/rsync operand syntax), including a bracketed IPv6 host. A host containing `/` is a local file
/// name (`./host:file`), not a host.
pub(super) fn split_host_path(operand: &str) -> Option<(&str, &str)> {
    // An optional `user@` prefix (no `:` or `/` inside) may precede a bracketed IPv6 host.
    let user_len = operand
        .split_once('@')
        .filter(|(user, _)| !user.contains([':', '/', '[']))
        .map_or(0, |(user, _)| user.len() + 1);
    if let Some(rest) = operand[user_len..].strip_prefix('[') {
        let (inside, path) = rest.split_once("]:")?;
        return (!inside.is_empty() && !inside.contains('/'))
            .then_some((&operand[..user_len + inside.len() + 2], path));
    }
    operand
        .split_once(':')
        .filter(|(host, _)| !host.is_empty() && !host.contains('/'))
}

/// What an scp/rsync operand is: not a host operand at all, or a host operand with the path judged (P166 r12 class
/// rule: the PATH part of EVERY destination is judged whatever the host; nothing resolves or classifies hosts).
pub(super) enum Operand {
    Plain,
    Local(String),
}

/// The path to judge for the path part of a host operand: absolute stays; a relative one (or none) is relative to the
/// remote home, judged as `~/path`; a one-letter host is a drive letter (`c:.mcp.json`): a local path.
pub(super) fn host_operand_path(host: &str, path: &str) -> String {
    if host.len() == 1 && host.as_bytes()[0].is_ascii_alphabetic() {
        return path.to_owned();
    }
    if path.is_empty() {
        "~".to_owned()
    } else if path.starts_with(['/', '~']) {
        path.to_owned()
    } else {
        format!("~/{path}")
    }
}

/// `scheme://[user@]host[:port]/path` (scp, sftp, rsync, ssh, any scheme); `None` when it does not parse.
pub(super) fn parse_uri_operand(operand: &str) -> Option<Operand> {
    let (scheme, rest) = operand.split_once("://")?;
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return None;
    }
    let end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if authority.starts_with('[') {
        &authority[..authority.find(']')? + 1]
    } else {
        &authority[..authority.find(':').unwrap_or(authority.len())]
    };
    // `scp://host/x` is home-relative (`scp://host//x` is absolute); every other scheme's path is absolute as given.
    let path = if scheme.eq_ignore_ascii_case("scp") {
        path.strip_prefix('/').unwrap_or(path)
    } else {
        path
    };
    Some(Operand::Local(host_operand_path(host, path)))
}

pub(super) fn parse_operand(operand: &str) -> Operand {
    if operand.contains("://") {
        // A URI that does not parse is judged whole, as a local path.
        return parse_uri_operand(operand).unwrap_or_else(|| Operand::Local(operand.to_owned()));
    }
    match split_host_path(operand) {
        None => Operand::Plain,
        // rsync daemon `host::module/path`: the landing place is unknowable, judge the whole word.
        Some((_, path)) if path.starts_with(':') => Operand::Local(operand.to_owned()),
        Some((host, path)) => Operand::Local(host_operand_path(
            host.rsplit_once('@').map_or(host, |(_, h)| h),
            path,
        )),
    }
}

/// `host:path` syntax, local or not (a source that lands unknown names, or one that is not a local file).
pub(super) fn is_host_operand(operand: &str) -> bool {
    !matches!(parse_operand(operand), Operand::Plain)
}

/// The path to judge for an operand: the path part of a host operand, else the operand itself.
pub(super) fn operand_local_path(operand: &str) -> String {
    match parse_operand(operand) {
        Operand::Local(path) => path,
        Operand::Plain => operand.to_owned(),
    }
}

/// P166 r11 rule 4(b): whether an undecodable word sits among the global options of a `git` command (after the `git`
/// word, before its subcommand). It could be the value of `-C`, `--git-dir`, `--work-tree` or `--exec-path`, so the
/// directory the command runs in is unknown.
pub(super) fn git_global_option_untrusted(words: &[InvocationWord]) -> bool {
    let Some(at) = words.iter().position(
        |word| matches!(word, InvocationWord::Literal(w) if shell_program_name(w) == "git"),
    ) else {
        return false;
    };
    let mut rest = words[at + 1..].iter();
    while let Some(word) = rest.next() {
        match word {
            InvocationWord::Untrusted => return true,
            InvocationWord::Literal(w) if w == "--" || !w.starts_with('-') => return false,
            InvocationWord::Literal(w) => {
                if crate::permission::exec_risk::git_global_option_takes_value(w)
                    && matches!(rest.next(), Some(InvocationWord::Untrusted))
                {
                    return true;
                }
            }
        }
    }
    false
}

/// How a word that may start with `~` expands (P166 r11 rule 2). `~` and `~/..` are home; `~+`, `~+0`, `~0` and the
/// same with any number of zeros, followed by the end or `/`, are the tracked working directory; any other `~+..`,
/// `~-..` or `~<digits>..` names a directory-stack entry or OLDPWD (unknowable: fail closed); `~name` with a valid
/// user name is the home only when it is the current user (r12); every other `~` word fails closed too.
pub(super) enum TildeWord<'a> {
    NotTilde,
    Home,
    Cwd(&'a str),
    Unknown,
}

pub(super) fn tilde_word(word: &str) -> TildeWord<'_> {
    let Some(rest) = word.strip_prefix('~') else {
        return TildeWord::NotTilde;
    };
    let (name, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if name.is_empty() {
        return TildeWord::Home;
    }
    let (sign, digits) = match name.as_bytes()[0] {
        b'+' => (Some('+'), &name[1..]),
        b'-' => (Some('-'), &name[1..]),
        _ => (None, name),
    };
    if digits.bytes().all(|b| b.is_ascii_digit()) && (sign.is_some() || !digits.is_empty()) {
        return if sign != Some('-') && digits.bytes().all(|b| b == b'0') {
            TildeWord::Cwd(tail)
        } else {
            TildeWord::Unknown
        };
    }
    let valid_user = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    // P166 r12 class rule (no user lookup): `~name` is the home only for the current user; any other name is an
    // unknown directory (`~root/../../etc/passwd`), so a write there fails closed.
    if valid_user && current_user_name().is_some_and(|user| user == name) {
        TildeWord::Home
    } else {
        TildeWord::Unknown
    }
}

/// The current user's name: the process environment (never an assignment on the command line), else the last
/// component of the home directory. `None` (the user cannot be determined) makes `~name` fail closed for writes.
pub(crate) fn current_user_name() -> Option<String> {
    ["USER", "LOGNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .or_else(|| {
            let home = std::env::var("HOME").ok()?;
            let name = Path::new(home.trim_end_matches('/'))
                .file_name()?
                .to_str()?
                .to_owned();
            (!name.is_empty()).then_some(name)
        })
}

/// P166 r13 rule 3: a current-user `~name` / `~name/...` is spelled `~` / `~/...`, the form every later step
/// resolves (`resolve_model_path` expands only `~` and `~/`). Every other word is returned as given.
pub(super) fn home_spelling(word: &str) -> String {
    if let Some(rest) = word.strip_prefix('~') {
        let (name, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        if !name.is_empty() && matches!(tilde_word(word), TildeWord::Home) {
            return format!("~{tail}");
        }
    }
    word.to_owned()
}

/// `ditto`'s operands (the last is the destination); `--arch`/`--bom` take a value.
pub(super) fn ditto_operands(inner: &[String]) -> Vec<&str> {
    let mut operands = Vec::new();
    let mut skip_next = false;
    for word in inner.iter().skip(1) {
        if skip_next {
            skip_next = false;
        } else if matches!(word.as_str(), "--arch" | "--bom") {
            skip_next = true;
        } else if !word.starts_with('-') {
            operands.push(word.as_str());
        }
    }
    operands
}

/// Directory-destination writes of a `cp`/`mv`/`ln`/`install`/`rsync`/`ditto` (P166/S5, Grok r4), and whether a
/// target directory was given. The destination operand alone names only the directory, so `cp mcp.json ~/.fuigo/`
/// would be invisible to the protected-target floor. With `-t DIR` every operand is a source; otherwise the last
/// operand is the destination.
pub(super) fn command_words_destination_writes(words: &[String]) -> (Vec<DestinationWrite>, bool) {
    let inner = peel_write_command(words).words;
    let Some(program) = inner
        .first()
        .map(|w| shell_program_name(w).to_ascii_lowercase())
    else {
        return (Vec::new(), false);
    };
    // P166 Grok r5 HIGH 1: `scp` (remote sources name only the file they bring) and `pax -rw` (operands keep their
    // relative paths under the destination).
    if program == "scp" {
        return (scp_destination_writes(inner), false);
    }
    if program == "pax" {
        return (pax_destination_writes(inner), false);
    }
    let rsync_paths: Vec<String>;
    let mut operand_hosts: Vec<bool> = Vec::new();
    let (target_dirs, operands, follow_links) = match program.as_str() {
        "cp" | "mv" | "ln" | "install" => (
            target_directory_operands(&program, inner),
            shell_file_candidates(inner),
            program == "cp" && cp_follows_links(inner),
        ),
        "rsync" => {
            let (operands, follow) = rsync_operands(inner);
            operand_hosts = operands
                .iter()
                .map(|operand| is_host_operand(operand))
                .collect();
            rsync_paths = operands.into_iter().map(operand_local_path).collect();
            (
                Vec::new(),
                rsync_paths.iter().map(String::as_str).collect(),
                follow,
            )
        }
        "ditto" => (Vec::new(), ditto_operands(inner), false),
        _ => return (Vec::new(), false),
    };
    let mut out = Vec::new();
    let parents = program == "cp" && cp_uses_parents(inner);
    let mut into = |dir: &str, source: &str, from_host: bool, out: &mut Vec<DestinationWrite>| {
        // P175b r6: `cp --parents` recreates the source path as given under the directory.
        if parents {
            let kept = source.trim_end_matches('/').trim_start_matches('/');
            if !kept.is_empty() {
                out.push((
                    Path::new(dir).join(kept).to_string_lossy().into_owned(),
                    via_kind(dir, from_host),
                    None,
                ));
            }
        }
        if let Some(name) = Path::new(source.trim_end_matches('/')).file_name() {
            out.push((
                Path::new(dir).join(name).to_string_lossy().into_owned(),
                via_kind(dir, from_host),
                None,
            ));
        }
        // A remote source is not a local tree: nothing to walk.
        if !from_host {
            out.push((
                dir.to_owned(),
                DestinationKind::CopiedTree { follow_links },
                Some(source.to_owned()),
            ));
        }
    };
    if target_dirs.is_empty() {
        if let Some((dest, sources)) = operands.split_last() {
            for (i, source) in sources.iter().enumerate() {
                into(
                    dest,
                    source,
                    operand_hosts.get(i).copied().unwrap_or(false),
                    &mut out,
                );
            }
        }
    } else {
        for dir in &target_dirs {
            out.push(((*dir).to_owned(), DestinationKind::TargetDirectory, None));
            for source in operands.iter().filter(|source| *source != dir) {
                into(dir, source, false, &mut out);
            }
        }
    }
    // A host destination: the copied tree lands on another machine, only the destination path itself and the file
    // names that land in it are judged (r12), not the tree walk of the local source.
    if operand_hosts.last().copied().unwrap_or(false) {
        out.retain(|(_, kind, _)| !matches!(kind, DestinationKind::CopiedTree { .. }));
    }
    (out, !target_dirs.is_empty())
}

/// `scp SRC… DEST`: a local source is copied like `cp -r` (scp follows links in a tree); a remote source brings a file
/// named after its last path component into a directory destination.
pub(super) fn scp_destination_writes(inner: &[String]) -> Vec<DestinationWrite> {
    let (operands, _) = scp_operands(inner);
    let mut out = Vec::new();
    let Some((dest, sources)) = operands.split_last() else {
        return out;
    };
    let dest_is_host = is_host_operand(dest);
    let dest = operand_local_path(dest);
    let dest = dest.as_str();
    for source in sources {
        let path = operand_local_path(source);
        if let Some(name) = Path::new(path.trim_end_matches('/')).file_name() {
            out.push((
                Path::new(dest).join(name).to_string_lossy().into_owned(),
                via_kind(dest, is_host_operand(source)),
                None,
            ));
        }
        if !is_host_operand(source) && !dest_is_host {
            out.push((
                (*dest).to_owned(),
                DestinationKind::CopiedTree { follow_links: true },
                Some((*source).to_owned()),
            ));
        }
    }
    out
}

/// `pax -rw SRC… DIR` copies each operand to `DIR/SRC` (its path as given), so the tree walk is rooted at the operand's
/// parent under `DIR`.
pub(super) fn pax_destination_writes(inner: &[String]) -> Vec<DestinationWrite> {
    let pax = pax_args(inner);
    let mut out = Vec::new();
    if !(pax.read && pax.write) {
        return out;
    }
    let Some((dest, sources)) = pax.operands.split_last() else {
        return out;
    };
    for source in sources {
        let relative = !is_absolute_shell_path(source);
        let landing = if relative {
            Path::new(dest).join(source)
        } else {
            Path::new(dest).join(Path::new(source).file_name().unwrap_or_default())
        };
        out.push((
            landing.to_string_lossy().into_owned(),
            DestinationKind::ViaDirectory,
            None,
        ));
        let tree_dest = match Path::new(source).parent() {
            Some(parent) if relative && !parent.as_os_str().is_empty() => {
                Path::new(dest).join(parent)
            }
            _ => Path::new(dest).to_path_buf(),
        };
        out.push((
            tree_dest.to_string_lossy().into_owned(),
            DestinationKind::CopiedTree {
                follow_links: pax.follow,
            },
            Some((*source).to_owned()),
        ));
    }
    out
}
