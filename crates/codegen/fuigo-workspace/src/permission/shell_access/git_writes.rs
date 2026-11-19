use super::*;

/// `path` with `.` and `..` folded lexically (no filesystem access).
pub(crate) fn lexical_clean(path: &Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// [`DestinationKind::Pathspec`]: a protected name keeps its reason; otherwise only an existing non-directory is pinned.
pub(super) fn pathspec_protection(path: &Path) -> Option<ProtectedEditReason> {
    edit_target_protection(path).or_else(|| {
        (!std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_dir()))
            .then_some(ProtectedEditReason::Sensitive)
    })
}

/// [`DestinationKind::HookMetadata`]: only a hook root or git hooks directory (or, recursively, a directory above one).
pub(super) fn hook_metadata_protection(
    path: &Path,
    recursive: bool,
) -> Option<ProtectedEditReason> {
    let hook = |candidate: &Path| {
        edit_target_protection(candidate).filter(|reason| {
            matches!(
                reason,
                ProtectedEditReason::HookRoot | ProtectedEditReason::GitHooks
            )
        })
    };
    let walk = |path: &Path| -> Option<ProtectedEditReason> {
        // P166 r9: `-R` on a directory inside a `.git` whose subtree can hold a `hooks` directory: `modules`,
        // `modules/<name>` (nested submodules repeat the pair), `worktrees`, `worktrees/<name>`. Lexical only: nothing is
        // walked, so an absent directory is judged the same as a present one.
        let names: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect();
        if let Some(git_at) = names.iter().rposition(|name| name == ".git") {
            let tail = &names[git_at + 1..];
            let mut rest = tail;
            while let [kind, _name, more @ ..] = rest
                && kind == "modules"
            {
                rest = more;
            }
            let container_below = matches!(rest, [] | [_] | [_, _])
                && (rest.is_empty() || matches!(rest[0].as_str(), "modules" | "worktrees"));
            if container_below && !tail.iter().any(|name| name == "hooks") {
                return Some(ProtectedEditReason::GitHooks);
            }
        }
        // `-R` on the hook container itself, or on a parent in which a hook directory really exists.
        let container = path
            .file_name()
            .is_some_and(|name| matches!(name.to_string_lossy().as_ref(), ".git" | ".fuigo"));
        let inside: &[&str] = if container {
            &["hooks"]
        } else {
            &[".git/hooks", ".fuigo/hooks"]
        };
        inside
            .iter()
            .map(|below| path.join(below))
            .filter(|candidate| container || candidate.exists())
            .find_map(|candidate| hook(&candidate))
    };
    hook(path).or_else(|| {
        if !recursive {
            return None;
        }
        // P166 r10: `.` and `..` components are folded first (`.git/modules/foo/.`, `.git/./modules`,
        // `.git/modules/foo/..`), and a symlinked component is followed the way every other target is.
        walk(&fuigo_paths::normalize_lexically(path))
            .or_else(|| resolve_following_symlinks(path).and_then(|real| walk(&real)))
    })
}

/// [`DestinationKind::GeneratedNames`]: `spelled_as_dir` is a prefix ending in `/` (names are suffixes in that dir).
pub(super) fn generated_names_protection(
    prefix: &Path,
    spelled_as_dir: bool,
) -> Option<ProtectedEditReason> {
    if spelled_as_dir {
        return edit_target_protection(prefix);
    }
    if prefix
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
    {
        return Some(ProtectedEditReason::Sensitive);
    }
    edit_target_protection(prefix).or_else(|| prefix.parent().and_then(edit_target_protection))
}

/// The git verbs that rewrite worktree files (P166 Grok r5 HIGH 1). `pathspecs` are literal file pathspecs judged as
/// [`DestinationKind::Pathspec`]; `paths` are plain write targets (`git mv` destination, `git merge-file`'s current file,
/// `git config --file`, `git bundle create`); `unpinned` is a rewrite whose files the command line does not name
/// (`git apply`, `git reset --hard`, a branch switch, `pull`/`merge`/`rebase`/`am`/`cherry-pick`/`revert`, `stash`
/// apply/pop/push, `clone`, `worktree add`, a `--template`), or a non-literal pathspec, or a moved worktree (`-C`,
/// `--work-tree`, `--git-dir`). `moves` are `git mv` operands, judged like `mv`.
#[derive(Debug, Default)]
pub(super) struct GitWrites {
    pub(super) pathspecs: Vec<String>,
    pub(super) paths: Vec<String>,
    pub(super) moves: Vec<String>,
    /// Text judged only by the tripwire (the shell text of a stored `!` alias).
    pub(super) watch: Vec<String>,
    pub(super) unpinned: bool,
}

/// A pathspec that names a file literally: no glob, no `:` magic, no escape.
pub(super) fn literal_pathspec(spec: &str) -> bool {
    !spec.is_empty() && !spec.starts_with(':') && !spec.contains(['*', '?', '[', '\\'])
}

pub(super) fn git_worktree_writes(inner: &[String]) -> GitWrites {
    let mut writes = GitWrites::default();
    let (mut moved, mut template, mut hooks, mut i) = (false, false, false, 1);
    let mut moved_dirs: Vec<String> = Vec::new();
    while let Some(word) = inner.get(i) {
        if !word.starts_with('-') {
            break;
        }
        i += 1;
        // The `key=value` text a `-c` / `--config-env` option carries, in every spelling git accepts: `-c k=v`,
        // `-ck=v`, `--config-env K=ENV`, `--config-env=K=ENV` and unique abbreviations of `--config-env`.
        let config: Option<String> = if word == "-c" {
            i += 1;
            inner.get(i - 1).cloned()
        } else if is_attached_git_config_c(word) {
            Some(word[2..].to_owned())
        } else if is_git_config_env_flag(word) {
            match word.split_once('=') {
                Some((_, value)) => Some(value.to_owned()),
                None => {
                    i += 1;
                    inner.get(i - 1).cloned()
                }
            }
        } else {
            None
        };
        if let Some(config) = config {
            let config = config.to_ascii_lowercase();
            template |= config.starts_with("init.templatedir");
            hooks |= git_config_key_redirects_hooks(&config);
        } else if word == "-C" {
            moved = true;
            moved_dirs.extend(inner.get(i).cloned());
            i += 1;
        } else if let Some(dir) = attached_git_c_path(word) {
            moved = true;
            moved_dirs.push(dir.to_owned());
        } else if is_git_repo_retarget_flag(word) {
            moved = true;
            match word.split_once('=') {
                Some((_, dir)) => moved_dirs.push(dir.to_owned()),
                None => {
                    moved_dirs.extend(inner.get(i).cloned());
                    i += 1;
                }
            }
        } else if git_global_takes_next(word) {
            i += 1;
        }
    }
    writes.unpinned = hooks;
    let Some(verb) = inner.get(i).map(String::as_str) else {
        writes.paths.extend(moved_dirs);
        return writes;
    };
    // P166 r9 (a): a word that cannot be a git subcommand name sits where the verb should be (`git -C {a,.git/hooks}
    // checkout main` brace-expands to `git -C a .git/hooks checkout main`). Git runs nothing then, but the command
    // line points at those paths and at the directories it moved into: judge them rather than guess.
    if verb.is_empty()
        || !verb
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        writes.paths.push(verb.to_owned());
        writes.paths.extend(moved_dirs);
        return writes;
    }
    let args = &inner[i + 1..];
    // Split args into options, operands before `--`, and operands after it.
    let mut options: Vec<&str> = Vec::new();
    let (mut before, mut after, mut dashdash) = (Vec::new(), Vec::new(), false);
    let takes_value: &[&str] = match verb {
        "checkout" => &["-b", "-B", "--orphan", "--conflict", "-t", "--track"],
        "switch" => &[
            "-c",
            "-C",
            "--orphan",
            "--conflict",
            "--create",
            "--force-create",
        ],
        "restore" => &["-s", "--source", "--conflict"],
        "stash" => &["-m", "--message"],
        "merge-file" => &["-L"],
        "config" => &["-f", "--file", "--blob", "--type"],
        "am" | "apply" => &[
            "-p",
            "-C",
            "--directory",
            "--include",
            "--exclude",
            "--whitespace",
        ],
        _ => &[],
    };
    let mut j = 0;
    while let Some(word) = args.get(j) {
        j += 1;
        if dashdash {
            after.push(word.as_str());
        } else if word == "--" {
            dashdash = true;
        } else if word.starts_with('-') && word != "-" {
            options.push(word.as_str());
            // `-t`/`--track` take no value in `checkout`; a lone `-t` here is the flag.
            if takes_value.contains(&word.as_str()) && !matches!(word.as_str(), "-t" | "--track") {
                if let Some(value) = args.get(j) {
                    options.push(value.as_str());
                }
                j += 1;
            }
        } else {
            before.push(word.as_str());
        }
    }
    let has = |names: &[&str]| {
        options.iter().any(|option| {
            names
                .iter()
                .any(|name| option == name || option.starts_with(&format!("{name}=")))
        })
    };
    let pathspecs = |specs: &[&str], writes: &mut GitWrites| {
        for spec in specs {
            if literal_pathspec(spec) {
                writes.pathspecs.push((*spec).to_owned());
            } else {
                writes.unpinned = true;
            }
        }
    };
    // `git -C DIR checkout main`: a lone branch-like operand is a branch name, not a path (P166 r8B, Grok r7 MEDIUM 5).
    // P166 r12 item 4: `git remote add|set-url` stores a URL in `.git/config`; one that names a command is a
    // command-valued SET like `git config remote.<n>.url`.
    if verb == "remote" {
        let words: Vec<String> = std::iter::once("git".to_owned())
            .chain(inner[i..].iter().cloned())
            .collect();
        writes.unpinned |= crate::permission::exec_risk::git_command_url_operand(&words);
    }
    let mut branch_switch = false;
    match verb {
        "checkout" => {
            if has(&["--pathspec-from-file"]) {
                writes.unpinned = true;
            } else if dashdash {
                pathspecs(&after, &mut writes);
                writes.unpinned |= after.is_empty() || before.len() > 1;
            } else if moved && before.len() == 1 && branch_like(before[0]) {
                branch_switch = true;
            } else if !before.is_empty() {
                // `git checkout X …` without `--`: X may be a branch (a switch), a start point or a path. A branch
                // switch is the ordinary FileWrite floor (P166 r7); a literal operand that names a protected target
                // is still a protected write, and a glob or `.` fails closed.
                for operand in &before {
                    if literal_pathspec(operand)
                        && !matches!(*operand, "." | "..")
                        && !operand.ends_with('/')
                    {
                        writes.paths.push((*operand).to_owned());
                    } else {
                        writes.unpinned = true;
                    }
                }
            } else {
                writes.unpinned = has(&["-p", "--patch"]);
            }
        }
        "switch" => {
            // A branch switch is the ordinary FileWrite floor (P166 r7); only a literal operand naming a protected
            // target is a protected write.
            if moved && before.len() == 1 && branch_like(before[0]) {
                branch_switch = true;
            } else {
                writes.paths.extend(
                    before
                        .iter()
                        .filter(|operand| literal_pathspec(operand))
                        .map(|operand| (*operand).to_owned()),
                );
            }
        }
        "restore" => {
            let staged_only = has(&["--staged", "-S"]) && !has(&["--worktree", "-W"]);
            if has(&["--pathspec-from-file"]) {
                writes.unpinned = !staged_only;
            } else if !staged_only {
                let specs: Vec<&str> = before.iter().chain(&after).copied().collect();
                pathspecs(&specs, &mut writes);
            }
        }
        "reset" => writes.unpinned = has(&["--hard", "--merge", "--keep"]),
        "stash" => {
            let sub = before.first().copied();
            match sub {
                Some("list" | "show" | "drop" | "clear" | "create" | "store" | "pop") => {}
                Some("push") | None if !after.is_empty() => pathspecs(&after, &mut writes),
                _ => writes.unpinned = true,
            }
        }
        "apply" => {
            let read_only =
                has(&["--check", "--stat", "--numstat", "--summary"]) && !has(&["--apply"]);
            let index_only = has(&["--cached"]) && !has(&["--index"]);
            writes.unpinned = !(read_only || index_only);
        }
        "am" | "merge" | "cherry-pick" | "revert" | "rebase" | "clone" | "checkout-index" => {
            writes.unpinned = true;
        }
        "read-tree" => writes.unpinned = has(&["-u"]),
        "bisect" => {
            writes.unpinned = !matches!(
                before.first().copied(),
                Some("log" | "visualize" | "view" | "terms" | "help")
            );
        }
        "sparse-checkout" => {
            writes.unpinned = !matches!(before.first().copied(), Some("list") | None)
        }
        "submodule" => writes.unpinned = matches!(before.first().copied(), Some("update" | "add")),
        "worktree" => writes.unpinned = before.first() == Some(&"add"),
        "init" => writes.unpinned = template || has(&["--template"]),
        "mv" => {
            writes.moves = before
                .iter()
                .chain(&after)
                .map(|operand| (*operand).to_owned())
                .collect()
        }
        "merge-file" if !has(&["-p", "--stdout"]) => {
            writes
                .paths
                .extend(before.first().map(|current| (*current).to_owned()));
        }
        "config" => {
            let sub = before.first().copied();
            let sub_read = matches!(sub, Some("get" | "list"));
            let reads = sub_read
                || has(&[
                    "--get",
                    "--get-all",
                    "--get-regexp",
                    "--get-urlmatch",
                    "--list",
                    "-l",
                    "--get-color",
                    "--get-colorbool",
                ]);
            let sub_write = matches!(
                sub,
                Some("set" | "unset" | "edit" | "rename-section" | "remove-section")
            );
            let edit = sub == Some("edit") || has(&["-e", "--edit"]);
            let write_flag = has(&[
                "--add",
                "--unset",
                "--unset-all",
                "--replace-all",
                "--rename-section",
                "--remove-section",
                "-e",
                "--edit",
            ]);
            let file = options
                .windows(2)
                .find(|pair| matches!(pair[0], "-f" | "--file"))
                .map(|pair| pair[1])
                .or_else(|| {
                    options
                        .iter()
                        .find_map(|option| option.strip_prefix("--file="))
                });
            let key_value = !sub_read && !sub_write && before.len() >= 2;
            if !reads && (sub_write || write_flag || key_value || file.is_some()) {
                // P166 r7: every non-read `git config` writes the file it selects.
                let selected = if let Some(file) = file {
                    file
                } else if has(&["--global"]) {
                    "~/.gitconfig"
                } else if has(&["--system"]) {
                    "/etc/gitconfig"
                } else if has(&["--worktree"]) {
                    ".git/config.worktree"
                } else {
                    ".git/config"
                };
                writes.paths.push(selected.to_owned());
                let keys = if sub_write { &before[1..] } else { &before[..] };
                // A `!` alias is a shell command stored for a later `git <alias>`: exec risk (exec_risk.rs) and its
                // text goes through the tripwire, so a protected path inside it is a protected write.
                // P166 r10: the same for every command-valued key of the shared table (`trailer.x.cmd`, ...).
                // P166 r12 item 6: the forms that never set a value (`--unset`, `--get*`, `-l`, `unset|get|list`) are not
                // command-valued whatever the key.
                let sets_no_value = sub_read
                    || sub == Some("unset")
                    || has(&[
                        "--unset",
                        "--unset-all",
                        "--get",
                        "--get-all",
                        "--get-regexp",
                        "--get-urlmatch",
                        "-l",
                        "--list",
                        "--name-only",
                        "--show-origin",
                    ]);
                if !sets_no_value
                    && let [key, value, ..] = keys
                    && ((key.to_ascii_lowercase().starts_with("alias.") && value.starts_with('!'))
                        || crate::permission::exec_risk::command_valued_config(key, Some(value)))
                {
                    let text: Vec<String> = std::iter::once("alias-text".to_owned())
                        .chain(
                            value
                                .split_whitespace()
                                .map(|word| word.trim_matches(['\'', '"', '`', ';']).to_owned()),
                        )
                        .collect();
                    writes.watch =
                        tripwire::tripwire("alias-text", &text, &text, &CommandExtras::default())
                            .tokens;
                }
                if edit
                    || (!sets_no_value && config_words_set_command_valued(keys))
                    || keys.iter().any(|key| config_key_pulls_in_include(key))
                {
                    writes.unpinned = true;
                }
            }
        }
        "bundle" if before.first() == Some(&"create") => {
            writes
                .paths
                .extend(before.get(1).map(|file| (*file).to_owned()));
        }
        _ => {}
    }
    if verb == "clone" && template {
        writes.unpinned = true;
    }
    let glob_dir = moved_dirs
        .iter()
        .any(|dir| dir.contains(['{', '}', '*', '?', '[', '\\', '$', '`']));
    if branch_switch && glob_dir {
        writes.unpinned = true;
    } else {
        // The directory git is moved into (`-C`, `--git-dir`, `--work-tree`) is itself judged for EVERY verb (P166 r10,
        // Grok r9 M6): `git -C .git/hooks init` is a protected write, `git -C ../other checkout main` is not.
        if moved
            && !branch_switch
            && (writes.unpinned
                || !writes.pathspecs.is_empty()
                || !writes.paths.is_empty()
                || !writes.moves.is_empty())
        {
            writes.unpinned = true;
        }
        writes.paths.extend(moved_dirs);
    }
    writes
}

/// A bare operand that reads as a branch name and could not be a protected file: no leading dot in any component
/// (`.mcp.json`, `.git/hooks`), no alphabetic extension (`mcp.json`, `settings.json`), no glob or revision syntax.
pub(super) fn branch_like(operand: &str) -> bool {
    if operand.is_empty() || operand.starts_with('/') || operand.ends_with('/') {
        return false;
    }
    let plain = operand
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'));
    let dotted_component = operand
        .split('/')
        .any(|part| part.is_empty() || part.starts_with('.'));
    let alpha_extension = operand
        .rsplit_once('.')
        .is_some_and(|(_, ext)| ext.chars().any(|c| c.is_ascii_alphabetic()));
    plain && !dotted_component && !alpha_extension && !operand.contains("..")
}

/// A (lowercased) git config key, or `key=value` text, that can retarget hook execution or pull in another config file
/// that does: `core.hooksPath`, `include.path`, `includeIf.*.path`.
///
/// The `-c` / `GIT_CONFIG_*` text forms keep this set: those are already exec risk (classifier), and only a hooks
/// redirect or include additionally takes the protected floor. The `git config` SET adds every command-valued key of
/// `exec_risk::COMMAND_VALUED_CONFIG_KEYS` (P166 r9, `config_words_set_command_valued`).
pub(super) fn git_config_key_redirects_hooks(key: &str) -> bool {
    key.starts_with("core.hookspath") || config_key_pulls_in_include(key)
}

pub(super) fn config_key_pulls_in_include(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.starts_with("include.") || key.starts_with("includeif.")
}

/// `GIT_CONFIG_*` assignment text (`NAME=value`) that redirects git config: a key or value naming `core.hooksPath`, or a
/// pointer at another global/system config file.
pub(super) fn git_env_assignment_redirects_config(assignment: &str) -> bool {
    let lower = assignment.to_ascii_lowercase();
    let Some((name, value)) = lower.split_once('=') else {
        return false;
    };
    name.starts_with("git_config")
        && (git_config_key_redirects_hooks(value.trim_start_matches(['\'', '"']))
            || matches!(name, "git_config_global" | "git_config_system" | "git_config" | "git_config_parameters")
            || value.contains("hookspath")
            // P166 r11: the config-by-environment names (count, key_n, value_n) with a protected name in the value.
            || (crate::permission::exec_risk::is_git_config_env_name(&assignment[..name.len()])
                && [".git", ".fuigo", ".claude", ".mcp.json", "hooks"].iter().any(|p| value.contains(p))))
}

/// u35: what a script's redirect destinations can be, judged on the words bash makes of them (u35 r1: quotes, escapes
/// and brace expansion through the shared word normaliser, then a lexically normalised path).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedirectDestinationRisk {
    /// A destination is bash's socket pseudo-device (`/dev/tcp/HOST/PORT`, `/dev/udp/HOST/PORT`), which opens a network
    /// connection in either direction instead of a file.
    pub(crate) socket: bool,
    /// A destination the normaliser cannot pin to one literal path (an expansion, a glob, a multi-word brace group).
    pub(crate) unresolved: bool,
    /// u35 r2: a destination that reads a process environment (`< /proc/self/environ`).
    pub(crate) environ: bool,
}

pub(crate) fn tree_redirect_destination_risk(root: Node<'_>, src: &str) -> RedirectDestinationRisk {
    use crate::permission::shell_words::{GlobMark, normalise_word_marking_globs};
    let is_socket = |path: &str| {
        // `/dev//tcp/x`, `/dev/./tcp/x`: compare on the path with empty and `.` components dropped.
        let parts: Vec<&str> = path
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        path.starts_with('/') && matches!(parts.as_slice(), ["dev", "tcp" | "udp", _, ..])
    };
    let mut risk = RedirectDestinationRisk::default();
    for target in shell_redirect_targets(root, src) {
        match normalise_word_marking_globs(&target.raw).as_deref() {
            Ok([word]) if word.glob == GlobMark::Literal => {
                risk.socket |= is_socket(&word.text);
                risk.environ |= crate::permission::exec_surface::names_environ_file(&word.text);
            }
            _ => {
                risk.unresolved = true;
                risk.socket |= target.raw.contains("/dev/tcp") || target.raw.contains("/dev/udp");
                risk.environ |= target.raw.contains("environ") || target.raw.contains("/proc");
            }
        }
    }
    risk
}

/// u35 r2: whether a `declare`/`typeset`/`export`/`readonly`/`local` declaration prints variables: options only, or
/// `-p` with or without names (the parser makes these `declaration_command` nodes, which the word-level checks never
/// see). An argument the normaliser cannot pin may be `-p`, so it counts too.
pub(crate) fn tree_has_environment_dump_declaration(root: Node<'_>, src: &str) -> bool {
    use crate::permission::exec_surface::{
        UNRESOLVED_WORD, is_unresolved, segment_has_exec_surface,
    };
    use crate::permission::shell_words::{GlobMark, normalise_word_marking_globs};
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "declaration_command" {
            let mut words: Vec<String> = Vec::new();
            for i in 0..node.child_count() {
                let Some(child) = node.child(i) else { continue };
                let Ok(text) = child.utf8_text(src.as_bytes()) else {
                    return true;
                };
                if matches!(
                    child.kind(),
                    "variable_assignment" | "variable_name" | "comment"
                ) {
                    // A name or an assignment, never an option.
                    words.push(text.to_owned());
                    continue;
                }
                match normalise_word_marking_globs(text) {
                    Ok(list) if list.iter().all(|word| word.glob == GlobMark::Literal) => {
                        words.extend(list.into_iter().map(|word| word.text));
                    }
                    _ => words.push(UNRESOLVED_WORD.to_owned()),
                }
            }
            if words.iter().skip(1).any(|word| is_unresolved(word))
                || segment_has_exec_surface(&words)
            {
                return true;
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    false
}

/// u35: whether a `cd`/`pushd`/`popd` has an uncertain effect on the commands after it: it runs in a pipeline or a
/// subshell (so it never moves the shell that runs the next command), or inside an `||` list (so whether it ran depends
/// on another command's exit status). The ambient git scan follows `cd` in script order, so either shape would have it
/// scan a directory git does not run in.
///
/// u35 r2 (Fable M): a `cd` on the LEFT of an `||` is uncertain only for what can run after it: the right-hand side
/// (when it may run git) and anything after the whole `||` list. `cd repo && git status || true` runs git only where
/// the scan looks, so it is certain; `cd repo || git status` and `cd repo && x || y; git log` are not. A `cd` on the
/// right of an `||` stays uncertain.
pub(crate) fn tree_has_uncertain_cwd_change(root: Node<'_>, src: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command" && command_node_may_change_cwd(node, src) {
            if execution_scope(node)
                != (ExecutionScope {
                    start: 0,
                    end: usize::MAX,
                })
            {
                return true;
            }
            // u35 r3 (Astra r2 H5): a `cd` on the right of an `&&` runs only if the left succeeded; when the script goes
            // on after the whole `&&`/`||` list (`ls /missing && cd clean; git status`), what follows may run in
            // either directory.
            let mut top_list = None;
            let mut current = node;
            while let Some(parent) = current.parent().filter(|parent| parent.kind() == "list") {
                let after_and = (0..parent.child_count())
                    .filter_map(|i| parent.child(i))
                    .any(|op| op.kind() == "&&" && op.end_byte() <= current.start_byte());
                if after_and {
                    top_list = Some(parent);
                }
                current = parent;
            }
            if let Some(list) = top_list {
                let mut outer = list;
                while let Some(parent) = outer.parent().filter(|parent| parent.kind() == "list") {
                    outer = parent;
                }
                if node_has_later_sibling(outer) {
                    return true;
                }
            }
            let mut current = node;
            while let Some(parent) = current.parent() {
                if parent.kind() == "list" {
                    let or_op = (0..parent.child_count())
                        .filter_map(|i| parent.child(i))
                        .find(|op| op.kind() == "||");
                    if let Some(op) = or_op {
                        if current.start_byte() >= op.end_byte() {
                            return true;
                        }
                        let right_may_run_git = (0..parent.named_child_count())
                            .filter_map(|i| parent.named_child(i))
                            .filter(|child| child.start_byte() >= op.end_byte())
                            .any(|child| subtree_may_run_git(child, src));
                        if right_may_run_git || node_has_later_sibling(parent) {
                            return true;
                        }
                    }
                }
                current = parent;
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    false
}

/// u35 r2: whether anything runs after `node` in the script: a later named sibling (not a comment) of it or of any
/// ancestor.
pub(super) fn node_has_later_sibling(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(at) = current {
        let mut next = at.next_named_sibling();
        while let Some(sibling) = next {
            if sibling.kind() != "comment" {
                return true;
            }
            next = sibling.next_named_sibling();
        }
        current = at.parent();
    }
    false
}

/// u35 r2: whether a subtree holds a command that may be git: a normalised `git` program, a program word the
/// normaliser cannot pin, or a wrapper chain it cannot see through.
pub(super) fn subtree_may_run_git(root: Node<'_>, src: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command" && command_node_head_matches(node, src, &["git"]) {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    false
}

/// u35 r1: whether a `command` node may be `cd`/`pushd`/`popd`, judged on its NORMALISED identity: the words bash makes
/// (`'c'd`, `\cd`) after the one classifier normalisation (`command cd`, `builtin cd`). A program word the normaliser
/// cannot pin, or a wrapper chain it cannot see through, may be one.
pub(super) fn command_node_may_change_cwd(node: Node<'_>, src: &str) -> bool {
    command_node_head_matches(node, src, &["cd", "pushd", "popd"])
}

/// Whether a `command` node's normalised program may be one of `programs` (an unpinnable program word or wrapper
/// chain may be any of them).
pub(super) fn command_node_head_matches(node: Node<'_>, src: &str, programs: &[&str]) -> bool {
    use crate::permission::shell_words::{GlobMark, normalise_word_node_marking_globs};
    const UNKNOWN: &str = "\0";
    let mut words: Vec<String> = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let word_node = match child.kind() {
            "variable_assignment"
            | "file_redirect"
            | "heredoc_redirect"
            | "herestring_redirect" => continue,
            "command_name" => match child.named_child(0) {
                Some(inner) => inner,
                None => return true,
            },
            _ => child,
        };
        match normalise_word_node_marking_globs(word_node, src) {
            Ok(list) if list.iter().all(|word| word.glob == GlobMark::Literal) => {
                words.extend(list.into_iter().map(|word| word.text));
            }
            _ => words.push(UNKNOWN.to_owned()),
        }
    }
    let norm = normalize_for_classification(&words);
    if norm.fail_closed {
        return true;
    }
    norm.words
        .first()
        .is_some_and(|head| head == UNKNOWN || programs.contains(&shell_program_name(head)))
}

/// P166 r9: whether any variable assignment in the script (prefix assignment, `export`, `declare`) sets a git
/// environment variable that retargets the repository or names a program git runs (`GIT_DIR=/tmp/evil git commit`).
pub(crate) fn tree_has_git_exec_env_assignment(root: Node<'_>, src: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_assignment"
            && node
                .utf8_text(src.as_bytes())
                .is_ok_and(is_git_exec_env_assignment)
        {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    false
}

/// A `GIT_CONFIG_*` variable assignment anywhere in the script (prefix assignment, `export`, `declare`) that redirects
/// git config: judged `Unpinned` where it appears.
pub(super) fn git_config_assignments(root: Node<'_>, src: &str) -> Vec<(usize, ExecutionScope)> {
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_assignment"
            && node
                .utf8_text(src.as_bytes())
                .is_ok_and(git_env_assignment_redirects_config)
        {
            found.push((node.start_byte(), execution_scope(node)));
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    found
}

/// `DIR/<name>` is a write only when `DIR` is a directory. An existing regular file there means `DIR` itself is the
/// (separately checked) destination, so the candidate is skipped instead of failing closed on `ENOTDIR`.
pub(super) fn via_existing_directory_protection(path: &Path) -> Option<ProtectedEditReason> {
    let dir = path.parent()?;
    if std::fs::metadata(dir).is_ok_and(|metadata| metadata.is_dir()) {
        edit_target_protection(path)
    } else {
        None
    }
}

/// Whether a destination operand's spelling says it is a directory (`dir/`, `.`, `..`, `~`).
pub(super) fn destination_spelled_as_directory(dest: &str) -> bool {
    dest.ends_with('/')
        || matches!(dest, "." | ".." | "~")
        || dest.ends_with("/.")
        || dest.ends_with("/..")
}

/// The kind of the `DEST/<name>` write of one source: a remote source into a destination not spelled as a directory is
/// judged only when `DEST` really is a directory.
pub(super) fn via_kind(dest: &str, from_host: bool) -> DestinationKind {
    if from_host && !destination_spelled_as_directory(dest) {
        DestinationKind::ViaExistingDirectory
    } else {
        DestinationKind::ViaDirectory
    }
}

pub(super) fn via_directory_protection(path: &Path) -> Option<ProtectedEditReason> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return None;
    };
    if let Some(reason) = peer_container_destination(dir) {
        return Some(reason);
    }
    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => edit_target_protection(path),
        Ok(_) => None,
        // Not there yet (created earlier in the same script): judge the spelling.
        Err(_) => scoped_protected_reason(&fuigo_paths::normalize_lexically(
            &Path::new(dir).join(name),
        )),
    }
}

/// Entries walked in a copied source tree. Past it the copy still prompts (`Sensitive`): an unchecked tree is never
/// allowed silently, so `cp -R node_modules /tmp/bak` under `Bash(cp:*)` or an exact grant asks (receipt R166, round 4).
pub(super) const MAX_COPIED_TREE_ENTRIES: usize = 10_000;

/// A directory `source` copied or moved to `dest` writes its tree at `dest/<rel>` (a contents copy: GNU `-T`, `SRC/.`,
/// BSD `SRC/`) or at `dest/<source name>/<rel>`. Both are judged for every entry, so a payload carrying `.mcp.json`,
/// `.claude/settings.json` or `.fuigo/` anywhere prompts while an ordinary tree copies freely. A symlinked directory in
/// the tree is copied as a link unless the copy dereferences (`follow_links`: `cp -L`, `rsync -L`), and then its
/// contents are walked too (a link back to an ancestor directory is a cycle and ends there). A file source is covered by the
/// `DEST/<name>` and destination checks; a source that is not there yet adds nothing. A directory that cannot be read
/// or resolved, or a tree over [`MAX_COPIED_TREE_ENTRIES`], prompts.
pub(super) fn copied_tree_protection(
    dest: &Path,
    source: &Path,
    follow_links: bool,
) -> Option<ProtectedEditReason> {
    if !std::fs::metadata(source).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    if let Some(reason) = peer_container_destination(dest) {
        return Some(reason);
    }
    // With `follow_links`, each pending directory carries the physical directories above it: a link back to one of
    // them is a cycle (fts reports it and copies nothing more there), so it is not walked again.
    let mut root_chain = Vec::new();
    if follow_links {
        let Ok(root) = dunce::canonicalize(source) else {
            return Some(ProtectedEditReason::Sensitive);
        };
        root_chain.push(root);
    }
    let mut prefixes = vec![dest.to_path_buf()];
    if let Some(name) = source.file_name() {
        prefixes.push(dest.join(name));
    }
    if let Some(resolved) = resolve_following_symlinks(dest) {
        prefixes.push(resolved.clone());
        if let Some(name) = source.file_name() {
            prefixes.push(resolved.join(name));
        }
    }
    let mut walked = 0usize;
    let mut pending = vec![(std::path::PathBuf::new(), root_chain)];
    while let Some((rel, chain)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(source.join(&rel)) else {
            return Some(ProtectedEditReason::Sensitive);
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return Some(ProtectedEditReason::Sensitive);
            };
            walked += 1;
            if walked > MAX_COPIED_TREE_ENTRIES {
                return Some(ProtectedEditReason::Sensitive);
            }
            let rel_entry = rel.join(entry.file_name());
            if let Some(reason) = prefixes.iter().find_map(|prefix| {
                scoped_protected_reason(&fuigo_paths::normalize_lexically(&prefix.join(&rel_entry)))
            }) {
                return Some(reason);
            }
            let Ok(file_type) = entry.file_type() else {
                return Some(ProtectedEditReason::Sensitive);
            };
            if !follow_links {
                if file_type.is_dir() {
                    pending.push((rel_entry, Vec::new()));
                }
                continue;
            }
            // Dereferencing copy: a directory, or a link resolving to one, is walked unless it is its own ancestor.
            let path = source.join(&rel_entry);
            if file_type.is_dir()
                || (file_type.is_symlink()
                    && std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()))
            {
                let Ok(physical) = dunce::canonicalize(&path) else {
                    return Some(ProtectedEditReason::Sensitive);
                };
                if !chain.contains(&physical) {
                    let mut below = chain.clone();
                    below.push(physical);
                    pending.push((rel_entry, below));
                }
            }
        }
    }
    None
}

/// Every `cd`/`pushd`/`popd` with its literal target, in script order.
pub(super) fn shell_cwd_changes(root: Node<'_>, src: &str) -> Vec<ShellCwdChange> {
    let mut changes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command"
            && let Some(program) = node
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(src.as_bytes()).ok())
            && matches!(shell_program_name(program), "cd" | "pushd" | "popd")
        {
            let target = (shell_program_name(program) != "popd")
                .then(|| literal_cwd_target(node, src))
                .flatten();
            // The change takes effect after the whole statement, so the command's own redirects (`cd /etc > cd.log`)
            // still write in the old cwd.
            let statement = node
                .parent()
                .filter(|parent| parent.kind() == "redirected_statement")
                .unwrap_or(node);
            changes.push(ShellCwdChange {
                at: statement.end_byte(),
                scope: execution_scope(node),
                target,
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    changes.sort_by_key(|change| change.at);
    changes
}

/// The literal directory a `cd`/`pushd` node changes to (`~` without an operand); `None` if it is not a literal path.
pub(super) fn literal_cwd_target(node: Node<'_>, src: &str) -> Option<String> {
    let mut operands = Vec::new();
    for i in 0..node.named_child_count() {
        let child = node.named_child(i)?;
        if child.kind() == "command_name" {
            continue;
        }
        // Anything but a literal word (an expansion, a quoted `$X`) leaves the new cwd unknown.
        match shell_node_arg(child, src)? {
            ArgText::Literal(word) if word.starts_with('-') && word != "-" => {}
            ArgText::Literal(word) => operands.push(word),
            ArgText::Ambiguous => return None,
        }
    }
    match operands.as_slice() {
        [] => Some("~".to_owned()),
        [target] if target != "-" && !matches!(tilde_word(target), TildeWord::Unknown) => {
            Some(home_spelling(target))
        }
        _ => None,
    }
}
