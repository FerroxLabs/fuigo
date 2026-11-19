use super::*;

/// One write target of a shell script and where it runs (P166/S5).
#[derive(Clone, Debug)]
pub(super) struct ShellWriteTarget {
    pub(super) path: String,
    pub(super) at: usize,
    pub(super) scope: ExecutionScope,
    /// `None` for a direct write (redirect, writer operand, `mkdir`/`touch`).
    pub(super) destination: Option<DestinationKind>,
    /// The copied source of a [`DestinationKind::CopiedTree`].
    pub(super) source: Option<String>,
}

/// A `cd`/`pushd`/`popd` and its literal target; `None` when the new cwd cannot be pinned (`cd -`, `cd "$X"`, `popd`).
#[derive(Clone, Debug)]
pub(super) struct ShellCwdChange {
    pub(super) at: usize,
    pub(super) scope: ExecutionScope,
    pub(super) target: Option<String>,
}

/// Every write target of a parsed script plus its cwd changes, for the protected-target floor (P166/S5).
#[derive(Clone, Debug, Default)]
pub(crate) struct ShellWriteFacts {
    pub(super) targets: Vec<ShellWriteTarget>,
    pub(super) cwd_changes: Vec<ShellCwdChange>,
    /// Literal `sh -c`/`bash -c` scripts (P166 Grok r5 sweep), judged in the cwds their invocation can run in.
    pub(super) nested: Vec<NestedWriteFacts>,
    /// A write redirect whose target is an expansion (`> "$1"`): unknown, which counts only when the script runs with
    /// names `xargs`/`find -exec` supply.
    pub(super) opaque_write: bool,
    /// Start byte of every `git` command, in script order (P175 part B: lets the branch-switch plan ask whether a
    /// write into the git directory came BEFORE the n-th git command).
    pub(super) git_starts: Vec<usize>,
    /// Symbolic `ln` commands (P175 part B rounds 2-3): a link made earlier on the same line does not exist yet when
    /// the plan runs, so its target is judged by what it will point at.
    pub(super) symlinks: Vec<SymlinkFact>,
}

#[derive(Clone, Debug)]
pub(super) struct SymlinkFact {
    pub(super) form: LnForm,
    pub(super) at: usize,
    pub(super) scope: ExecutionScope,
}

/// The git directory in both spellings: as found (lexically cleaned) and with symlinks resolved.
pub(super) struct GitDirSpelling<'a> {
    pub(super) lexical: &'a Path,
    pub(super) real: &'a Path,
}

impl GitDirSpelling<'_> {
    /// Whether `path` is the git directory or inside it, by spelling or by what it physically is. A path that cannot
    /// be resolved (symlink loop, depth cap, unreadable link) counts: the check only ever adds a prompt to a switch
    /// that already follows a write, so failing closed cannot touch everyday commands.
    pub(super) fn contains(&self, path: &Path) -> bool {
        lexical_clean(path).starts_with(self.lexical)
            || resolve_kernel_order(path).is_none_or(|real| real.starts_with(self.real))
    }
}

/// An unparsed symbolic `ln`: every word is a possible source and a possible destination (or destination directory),
/// so a word counts when it, or it read from the directory of any other word, is the git directory or inside it.
pub(super) fn unparsed_ln_hits_git(
    base: &Path,
    words: &[String],
    git: &GitDirSpelling<'_>,
    join: &dyn Fn(&Path, &str) -> std::path::PathBuf,
) -> bool {
    let spelled: Vec<String> = words
        .iter()
        .filter_map(|word| ln_word_path(word, base))
        .collect();
    let mut dirs = vec![base.to_path_buf()];
    for word in &spelled {
        let full = join(base, word.trim_end_matches('/'));
        dirs.extend(full.parent().map(Path::to_path_buf));
        dirs.push(full);
    }
    dirs.iter()
        .any(|dir| spelled.iter().any(|word| git.contains(&join(dir, word))))
}

/// Resolve `path` the way the kernel does: each component is resolved (symlinks followed) BEFORE a following `..` is
/// applied, so `deep/../config` with `deep -> .git/objects` is `.git/config`. Folding the `..` lexically first would
/// give `config` in the cwd. `None` (loop, depth cap, unreadable link) is the caller's fail-closed case.
pub(super) fn resolve_kernel_order(path: &Path) -> Option<std::path::PathBuf> {
    use std::path::Component;
    let mut resolved = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                resolved = resolve_following_symlinks_for_comparison(&resolved)?;
            }
            other => resolved.push(other.as_os_str()),
        }
    }
    Some(resolved)
}

/// The long options `ln` parses, for GNU unique-prefix matching (an exact name wins; an ambiguous prefix is `None`).
pub(super) const LN_LONG_OPTIONS: [&str; 15] = [
    "backup",
    "directory",
    "force",
    "interactive",
    "logical",
    "no-dereference",
    "no-target-directory",
    "physical",
    "relative",
    "suffix",
    "symbolic",
    "target-directory",
    "verbose",
    "help",
    "version",
];

/// getopt's long-option match: an exact name, else the one option of `table` that `name` is a prefix of (ambiguous or
/// unknown is `None`). The one shared matcher for every command that takes abbreviated long options.
pub(super) fn unique_long_option(name: &str, table: &[&'static str]) -> Option<&'static str> {
    if let Some(exact) = table.iter().find(|option| **option == name) {
        return Some(exact);
    }
    let mut matches = table
        .iter()
        .filter(|option| !name.is_empty() && option.starts_with(name));
    let first = matches.next()?;
    matches.next().is_none().then_some(*first)
}

pub(super) fn ln_long_option(name: &str) -> Option<&'static str> {
    unique_long_option(name, &LN_LONG_OPTIONS)
}

/// The GNU long options of `cp`, `mv`, `install` and `ln` that start with `t`: only `--target-directory` for each, so
/// every `--t...` prefix is that option. An ambiguous prefix would be treated as a target directory too (fail closed
/// for the write floor); everyday commands do not abbreviate long options, so no new prompt for them.
pub(super) const T_LONG_OPTIONS: &[&str] = &["target-directory"];

/// Whether the long option `name` (without `--` and without `=value`) may be `--target-directory`.
pub(super) fn may_be_target_directory(name: &str) -> bool {
    unique_long_option(name, T_LONG_OPTIONS).is_some()
        || (!name.is_empty() && T_LONG_OPTIONS.iter().any(|option| option.starts_with(name)))
}

/// A word of an unparsed `ln` as a path to resolve: `~+/x` is `./x`, `~/x` the home directory; another `~user` is
/// unknown (no path).
pub(super) fn ln_word_path(word: &str, base: &Path) -> Option<String> {
    match tilde_word(word) {
        TildeWord::NotTilde => Some(word.to_owned()),
        // Bash expands `~+` to the command's cwd, whatever directory the link is made in.
        TildeWord::Cwd(tail) => Some(base.join(format!(".{tail}")).to_string_lossy().into_owned()),
        TildeWord::Home => {
            let home = std::env::var("HOME").ok().filter(|home| !home.is_empty())?;
            let tail = word.find('/').map_or("", |at| &word[at..]);
            Some(format!("{}{tail}", home.trim_end_matches('/')))
        }
        TildeWord::Unknown => None,
    }
}

/// Where a symbolic `ln` creates its link(s), relative to the command's cwd.
#[derive(Clone, Debug)]
pub(super) enum LinkSite {
    /// `-r` (sources are read from the cwd) or the one-operand form (link made in the cwd).
    Cwd,
    /// `-t DIR`: the link(s) are made inside `DIR`.
    Dir(String),
    /// `SRC DEST` / `SRC... DIR`: `DEST` is the link name (its parent holds the link) or, when it is an existing
    /// directory, the directory the link is made in. `-T` allows only the first reading.
    Name { dest: String, no_target_dir: bool },
}

/// A parsed symbolic `ln`, or one that could not be parsed (judged by resolving every word both ways).
#[derive(Clone, Debug)]
pub(super) enum LnForm {
    Parsed {
        sources: Vec<String>,
        site: LinkSite,
        target_dir: Option<String>,
    },
    /// Every non-flag word and every `--opt=value` value, each a possible source and a possible destination.
    Unparsed { words: Vec<String> },
}

pub(super) fn names_git_component(word: &str) -> bool {
    Path::new(word)
        .components()
        .any(|part| part.as_os_str() == ".git")
}

/// Parse a symbolic `ln` (`-s`, `--symbolic`, or `s` in a short cluster); `None` for any other command.
pub(super) fn symlink_operands(words: &[String]) -> Option<LnForm> {
    let program = shell_program_name(words.first()?);
    if !program.eq_ignore_ascii_case("ln") {
        return None;
    }
    let args = &words[1..];
    let mut symbolic = false;
    let mut relative = false;
    let mut no_target_dir = false;
    let mut target_dir: Option<String> = None;
    let mut operands: Vec<String> = Vec::new();
    let mut ok = true;
    let mut index = 0;
    while index < args.len() {
        let word = &args[index];
        index += 1;
        if word == "--" {
            operands.extend(args[index..].iter().cloned());
            break;
        } else if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (long, None),
            };
            let mut take_value = |value: Option<String>| {
                value.or_else(|| {
                    index += 1;
                    args.get(index - 1).cloned()
                })
            };
            let Some(name) = ln_long_option(name) else {
                ok = false;
                continue;
            };
            match name {
                "symbolic" => symbolic = true,
                "relative" => relative = true,
                "no-target-directory" => no_target_dir = true,
                "target-directory" => match take_value(value) {
                    Some(dir) => target_dir = Some(dir),
                    None => ok = false,
                },
                "suffix" => ok &= take_value(value).is_some(),
                "backup" => {}
                "force" | "no-dereference" | "interactive" | "verbose" | "directory"
                | "logical" | "physical" | "help" | "version" => ok &= value.is_none(),
                _ => ok = false,
            }
        } else if word.len() > 1 && word.starts_with('-') {
            let cluster: Vec<char> = word[1..].chars().collect();
            let mut at = 0;
            while at < cluster.len() {
                let flag = cluster[at];
                at += 1;
                match flag {
                    's' => symbolic = true,
                    'r' => relative = true,
                    'T' => no_target_dir = true,
                    'f' | 'n' | 'h' | 'w' | 'i' | 'v' | 'b' | 'd' | 'F' | 'L' | 'P' | 'H' => {}
                    't' | 'S' => {
                        let rest: String = cluster[at..].iter().collect();
                        at = cluster.len();
                        let value = if rest.is_empty() {
                            index += 1;
                            args.get(index - 1).cloned()
                        } else {
                            Some(rest)
                        };
                        match (flag, value) {
                            ('t', Some(dir)) => target_dir = Some(dir),
                            ('S', Some(_)) => {}
                            _ => ok = false,
                        }
                    }
                    _ => ok = false,
                }
            }
        } else {
            operands.push(word.clone());
        }
    }
    if !symbolic {
        return None;
    }
    let unparsed = || {
        let mut words = Vec::new();
        let mut after_dashes = false;
        for word in args {
            if after_dashes || !word.starts_with('-') || word == "-" {
                words.push(word.clone());
            } else if word == "--" {
                after_dashes = true;
            } else if word.starts_with("--")
                && let Some((_, value)) = word.split_once('=')
            {
                words.push(value.to_owned());
            }
        }
        Some(LnForm::Unparsed { words })
    };
    if !ok || (no_target_dir && target_dir.is_some()) {
        return unparsed();
    }
    let parsed_dir = target_dir.clone();
    let (sources, site) = match (target_dir, operands.as_slice()) {
        (_, []) => return unparsed(),
        (Some(dir), _) => (operands.clone(), LinkSite::Dir(dir)),
        (None, [only]) => (vec![only.clone()], LinkSite::Cwd),
        (None, _) if no_target_dir && operands.len() != 2 => return unparsed(),
        (None, [sources @ .., dest]) => (
            sources.to_vec(),
            LinkSite::Name {
                dest: dest.clone(),
                no_target_dir,
            },
        ),
    };
    // `-r` makes the link relative to its own directory: the sources are read from the cwd.
    let site = if relative { LinkSite::Cwd } else { site };
    Some(LnForm::Parsed {
        sources,
        site,
        target_dir: parsed_dir,
    })
}

/// An inline script and where its shell runs.
#[derive(Clone, Debug)]
pub(super) struct NestedWriteFacts {
    pub(super) at: usize,
    pub(super) scope: ExecutionScope,
    pub(super) facts: ShellWriteFacts,
}

/// The write targets of one command before they are placed in a script: `(path, kind, copied source)`.
pub(super) type CommandTarget = (String, Option<DestinationKind>, Option<String>);

#[derive(Default)]
pub(super) struct CommandTargets {
    pub(super) targets: Vec<CommandTarget>,
    pub(super) nested: Vec<ShellWriteFacts>,
}

impl CommandTargets {
    pub(super) fn has_writes(&self) -> bool {
        self.targets.iter().any(|target| {
            !matches!(
                target.1,
                Some(DestinationKind::Watch | DestinationKind::HookMetadata { .. })
            )
        }) || self.nested.iter().any(ShellWriteFacts::has_writes)
    }

    pub(super) fn unpinned(&mut self) {
        self.targets
            .push((".".to_owned(), Some(DestinationKind::Unpinned), None));
    }
}

/// `ln` (any form) or `cp` asked to link (`-l`, `-s`, `--link`, `--symbolic-link`, any unique prefix).
pub(super) fn links_files(program: &str, inner: &[String]) -> bool {
    match program {
        "ln" => true,
        "cp" => inner.iter().skip(1).take_while(|w| *w != "--").any(|word| {
            word.strip_prefix("--").map_or_else(
                || word.starts_with('-') && word.len() > 1 && word[1..].contains(['l', 's']),
                |long| {
                    let name = long.split_once('=').map_or(long, |(n, _)| n);
                    !name.is_empty()
                        && ("link".starts_with(name) || "symbolic-link".starts_with(name))
                },
            )
        }),
        _ => false,
    }
}

/// Every write target of one command (its literal words): redirect-free writer operands, creation operands,
/// directory destinations, the extra writers of [`tool_writes`], git worktree writes, awk's literal print redirects,
/// what `xargs`/`find -exec` run, and literal `sh -c` scripts (parsed, up to `depth` levels).
pub(super) fn command_targets(
    words: &[String],
    depth: usize,
    extras: &CommandExtras,
) -> CommandTargets {
    let mut out = CommandTargets::default();
    let peel = peel_write_command(words);
    if peel.opaque {
        out.unpinned();
        return out;
    }
    let inner = peel.words;
    let Some(program) = inner
        .first()
        .map(|word| shell_program_name(word).to_ascii_lowercase())
    else {
        return out;
    };
    let (destinations, has_target_directory) = command_words_destination_writes(inner);
    // With `-t DIR` the last operand is a source; the generic extractor's last-positional destination is not a write.
    let operand_writes = if has_target_directory {
        peel.writes.iter().map(|path| (*path).to_owned()).collect()
    } else {
        command_words_write_paths_depth(words, depth)
    };
    out.targets.extend(
        operand_writes
            .into_iter()
            .chain(command_words_creation_paths(inner))
            .map(|path| (path, None, None)),
    );
    out.targets.extend(
        destinations
            .into_iter()
            .map(|(path, kind, source)| (path, Some(kind), source)),
    );
    if let Some(writes) = tool_writes(&program, inner) {
        out.targets.extend(
            writes
                .generated
                .into_iter()
                .map(|prefix| (prefix, Some(DestinationKind::GeneratedNames), None)),
        );
        if writes.unpinned {
            out.unpinned();
        }
    }
    if peer_extended_set_active() {
        peer_cmd::peer_command_targets(&program, inner, &mut out);
    }
    if peer_extended_set_active() && links_files(&program, inner) {
        out.targets.extend(
            shell_file_candidates(inner)
                .into_iter()
                .map(|operand| (operand.to_owned(), Some(DestinationKind::LinkOperand), None)),
        );
    }
    let tripwire = tripwire::tripwire(&program, words, inner, extras);
    out.targets.extend(
        tripwire
            .tokens
            .into_iter()
            .map(|token| (token, Some(DestinationKind::Watch), None)),
    );
    if tripwire.unpinned {
        out.unpinned();
    }
    // A `GIT_CONFIG_*` assignment given as a word (`env GIT_CONFIG_KEY_0=core.hooksPath git …`) redirects hooks.
    if words
        .iter()
        .any(|word| git_env_assignment_redirects_config(word))
    {
        out.unpinned();
    }
    if program == "git" {
        if extras.git_option_untrusted {
            out.unpinned();
        }
        let git = git_worktree_writes(inner);
        out.targets.extend(
            git.pathspecs
                .into_iter()
                .map(|spec| (spec, Some(DestinationKind::Pathspec), None)),
        );
        out.targets
            .extend(git.paths.into_iter().map(|path| (path, None, None)));
        out.targets.extend(
            git.watch
                .into_iter()
                .map(|token| (token, Some(DestinationKind::Watch), None)),
        );
        if !git.moves.is_empty() {
            let mv: Vec<String> = std::iter::once("mv".to_owned()).chain(git.moves).collect();
            let (moves, _) = command_words_destination_writes(&mv);
            out.targets.extend(
                shell_file_candidates(&mv)
                    .last()
                    .map(|dest| ((*dest).to_owned(), None, None)),
            );
            out.targets.extend(
                moves
                    .into_iter()
                    .map(|(path, kind, source)| (path, Some(kind), source)),
            );
        }
        if git.unpinned {
            out.unpinned();
        }
    }
    if matches!(program.as_str(), "chmod" | "chown" | "chgrp") {
        // Every non-flag word is a candidate (the mode or owner word is never a hook root, so it stays silent);
        // `--reference=FILE` names a file that is only read.
        let recursive = inner.iter().skip(1).any(|word| {
            word == "--recursive"
                || (word.starts_with('-') && !word.starts_with("--") && word.contains('R'))
        });
        let mut skip_value = false;
        for word in inner.iter().skip(1) {
            if std::mem::take(&mut skip_value) {
                continue;
            }
            if word == "--reference" || word == "--from" {
                skip_value = true;
            } else if !word.starts_with("--") && word != "-" {
                // A short cluster of flags (`-R`, `-vR`) or a symbolic mode that begins with `-` (`-x`): not a path.
                let cluster =
                    word.starts_with('-') && word[1..].chars().all(|c| c.is_ascii_alphabetic());
                if !cluster {
                    out.targets.push((
                        word.clone(),
                        Some(DestinationKind::HookMetadata { recursive }),
                        None,
                    ));
                }
            }
        }
    }
    if matches!(program.as_str(), "awk" | "gawk" | "mawk" | "nawk") {
        out.targets.extend(
            awk_literal_redirects(inner)
                .into_iter()
                .map(|path| (path, None, None)),
        );
    }
    if depth > 0 {
        for command in launched_commands(&program, inner) {
            let launched = command_targets(command, depth - 1, &CommandExtras::default());
            out.targets.extend(launched.targets);
            out.nested.extend(launched.nested);
            if launched_command_writes(command, depth - 1, false) {
                out.unpinned();
            }
        }
        let shell_words: Vec<ShellWord<'_>> = inner.iter().map(ShellWord::from).collect();
        if let InlineShellScript::Literal(index) = shell_dash_c_script(&shell_words)
            && let Some(script) = inner.get(index)
        {
            match try_parse_shell(script) {
                Some(tree) => out.nested.push(ShellWriteFacts::from_tree_depth(
                    tree.root_node(),
                    script,
                    depth - 1,
                )),
                None => out.unpinned(),
            }
        }
    }
    // Peer scope (S6.4): a shell interpreter whose script is not a literal `-c` string that was parsed above (`sh -c
    // "$X"`, `... | sh`, `sh <<EOF`, `bash script.sh`) runs text nothing here can read: it touches the protected set.
    if peer_extended_set_active()
        && matches!(
            program.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "fish" | "csh" | "tcsh" | "busybox"
        )
    {
        let shell_words: Vec<ShellWord<'_>> = inner.iter().map(ShellWord::from).collect();
        let literal = depth > 0
            && matches!(shell_dash_c_script(&shell_words), InlineShellScript::Literal(i)
                if inner.get(i).is_some_and(|script| try_parse_shell(script).is_some()));
        if !literal {
            out.unpinned();
        }
    }
    if peel.moved && out.has_writes() {
        out.unpinned();
    }
    out
}

impl ShellWriteFacts {
    /// Redirect targets, writer and creation operands, and directory-destination writes, each with its position.
    pub(crate) fn from_tree(root: Node<'_>, src: &str) -> Self {
        Self::from_tree_depth(root, src, MAX_INLINE_SHELL_DEPTH)
    }

    pub(super) fn from_tree_depth(root: Node<'_>, src: &str, depth: usize) -> Self {
        let mut facts = Self {
            cwd_changes: shell_cwd_changes(root, src),
            ..Self::default()
        };
        for redirect in shell_redirect_targets_with(root, src, true) {
            if !matches!(redirect.mode, ShellFileMode::Write) {
                continue;
            }
            let Some(path) = redirect.path else {
                // P166 r12: an undecodable target that still shows a protected name takes the floor; any other is
                // an unknown write target (`opaque_write`: it counts as a write, nothing is pinned).
                if tripwire::raw_has_protected_needle(&redirect.raw) {
                    facts.targets.push(ShellWriteTarget {
                        path: ".".to_owned(),
                        at: redirect.opens_at,
                        scope: redirect.scope,
                        destination: Some(DestinationKind::Unpinned),
                        source: None,
                    });
                } else {
                    facts.opaque_write = true;
                }
                continue;
            };
            facts.targets.push(ShellWriteTarget {
                path,
                at: redirect.opens_at,
                scope: redirect.scope,
                destination: None,
                source: None,
            });
        }
        for (at, scope) in git_config_assignments(root, src) {
            facts.targets.push(ShellWriteTarget {
                path: ".".to_owned(),
                at,
                scope,
                destination: Some(DestinationKind::Unpinned),
                source: None,
            });
        }
        for invocation in shell_command_invocations_with(root, src, true) {
            let words = InvocationSlice {
                words: &invocation.words,
            }
            .literal_words();
            if crate::permission::exec_risk::is_planned_git_segment(&words) {
                facts.git_starts.push(invocation.start_byte);
            }
            if let Some(form) = symlink_operands(peel_write_command(&words).words) {
                facts.symlinks.push(SymlinkFact {
                    form,
                    at: invocation.start_byte,
                    scope: invocation.scope,
                });
            }
            let command = command_targets(&words, depth, &invocation.extras);
            for (path, destination, source) in command.targets {
                facts.targets.push(ShellWriteTarget {
                    path,
                    at: invocation.start_byte,
                    scope: invocation.scope,
                    destination,
                    source,
                });
            }
            facts
                .nested
                .extend(command.nested.into_iter().map(|nested| NestedWriteFacts {
                    at: invocation.start_byte,
                    scope: invocation.scope,
                    facts: nested,
                }));
        }
        facts
    }

    /// Whether some write of this script could not be pinned to a path: an expansion redirect, a `cd` to a computed
    /// directory, an `Unpinned` target, an unknown `~user` word, or such a thing in a nested script (S6.4 refusal text).
    pub(crate) fn has_unresolved(&self) -> bool {
        self.opaque_write
            || self
                .cwd_changes
                .iter()
                .any(|change| change.target.is_none())
            || self.targets.iter().any(|target| {
                (peer_extended_set_active()
                    && !is_safe_write_sink(&target.path)
                    && peer_unpinnable_word(&target.path))
                    || matches!(target.destination, Some(DestinationKind::Unpinned))
                    || matches!(tilde_word(&target.path), TildeWord::Unknown)
            })
            || self
                .nested
                .iter()
                .any(|nested| nested.facts.has_unresolved())
    }

    /// Whether the script writes anything (a target, an expansion redirect, or a nested script that does).
    pub(super) fn has_writes(&self) -> bool {
        self.targets.iter().any(|target| {
            !matches!(
                target.destination,
                Some(DestinationKind::Watch | DestinationKind::HookMetadata { .. })
            )
        }) || self.opaque_write
            || self.nested.iter().any(|nested| nested.facts.has_writes())
    }

    /// The cwds a write at `at` in `scope` can run in: the session cwd and each prefix of the chain of literal `cd`
    /// targets that PRECEDE it in its scope (plus each such target alone, for `cd a || cd b`). A preceding unpinnable
    /// `cd` is `Err(Sensitive)`.
    pub(super) fn bases(
        &self,
        real_cwd: &Path,
        at: usize,
        scope: ExecutionScope,
        pinned: bool,
        resolve: &dyn Fn(&Path, &str) -> std::path::PathBuf,
    ) -> Result<Vec<std::path::PathBuf>, ProtectedEditReason> {
        let mut bases = vec![real_cwd.to_path_buf()];
        if pinned {
            return Ok(bases);
        }
        let mut chained = real_cwd.to_path_buf();
        for change in self.cwd_changes.iter().filter(|change| {
            change.at <= at && (change.scope == scope || change.scope.contains(scope))
        }) {
            let Some(dir) = change.target.as_deref() else {
                return Err(ProtectedEditReason::Sensitive);
            };
            chained = resolve(&chained, dir);
            bases.push(chained.clone());
            bases.push(resolve(real_cwd, dir));
        }
        Ok(bases)
    }

    /// P175 part B (decision 11): whether a write target of this script (the same targets the protected-file floor
    /// judges, `cd`/`pushd` chain included) lands inside `git_dir` in a command that starts BEFORE the
    /// `git_ordinal`-th git command (0-based; no such command known = any position). A target the floor cannot pin
    /// (`cd "$X"` before it, `~user`) counts, as the floor treats it as sensitive. A `Watch`/`HookMetadata` target
    /// is no write, and an `Unpinned` one names no path, so neither counts.
    pub(crate) fn writes_into_git_dir_before(
        &self,
        real_cwd: &Path,
        git_dir: &Path,
        git_ordinal: usize,
    ) -> bool {
        let limit = self
            .git_starts
            .get(git_ordinal)
            .copied()
            .unwrap_or(usize::MAX);
        // Both sides are compared physically (symlinks followed, on-disk spelling on a case-insensitive volume) AND
        // lexically. A git dir that cannot be resolved is compared by its lexical spelling only.
        let real_git = resolve_following_symlinks(git_dir).unwrap_or_else(|| git_dir.to_path_buf());
        self.writes_into(
            real_cwd,
            &GitDirSpelling {
                lexical: git_dir,
                real: &real_git,
            },
            limit,
        )
    }

    /// Number of git commands this script has (the planner cross-checks it against its own count).
    pub(crate) fn git_start_count(&self) -> usize {
        self.git_starts.len()
    }

    pub(super) fn writes_into(
        &self,
        real_cwd: &Path,
        git: &GitDirSpelling<'_>,
        limit: usize,
    ) -> bool {
        let join = |base: &Path, path: &str| {
            let p = Path::new(path);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };
        let direct = self.targets.iter().any(|target| {
            if target.at >= limit
                || is_safe_write_sink(&target.path)
                || matches!(
                    target.destination,
                    Some(
                        DestinationKind::Watch
                            | DestinationKind::HookMetadata { .. }
                            | DestinationKind::Unpinned
                    )
                )
            {
                return false;
            }
            let (spelled, pinned) = match tilde_word(&target.path) {
                TildeWord::Cwd(tail) => (format!(".{tail}"), false),
                TildeWord::Unknown => return true,
                TildeWord::Home => (home_spelling(&target.path), true),
                TildeWord::NotTilde => (target.path.clone(), Path::new(&target.path).is_absolute()),
            };
            match self.bases(real_cwd, target.at, target.scope, pinned, &join) {
                Err(_) => true,
                Ok(bases) => bases.iter().any(|base| git.contains(&join(base, &spelled))),
            }
        });
        direct
            || self.symlinks.iter().any(|link| {
                if link.at >= limit {
                    return false;
                }
                let (sources, site, target_dir) = match &link.form {
                    LnForm::Unparsed { words } => {
                        if words.iter().any(|word| names_git_component(word)) {
                            return true;
                        }
                        return match self.bases(real_cwd, link.at, link.scope, false, &join) {
                            Err(_) => true,
                            Ok(bases) => bases
                                .iter()
                                .any(|base| unparsed_ln_hits_git(base, words, git, &join)),
                        };
                    }
                    LnForm::Parsed {
                        sources,
                        site,
                        target_dir,
                    } => (sources, site, target_dir),
                };
                match self.bases(real_cwd, link.at, link.scope, false, &join) {
                    Err(_) => true,
                    // A relative symlink source is read from the directory that holds the new link (never from the
                    // cwd): that is the link's parent, or the destination when it is an existing directory.
                    Ok(bases) => bases.iter().any(|base| {
                        // A link CREATED inside `.git` is a write into it, wherever its text points.
                        if target_dir.as_deref().is_some_and(|dir| {
                            ln_word_path(dir, base)
                                .is_some_and(|spelled| git.contains(&join(base, &spelled)))
                        }) {
                            return true;
                        }
                        let dirs: Vec<std::path::PathBuf> = match site {
                            LinkSite::Cwd => vec![base.clone()],
                            LinkSite::Dir(dir) => vec![join(base, dir)],
                            LinkSite::Name {
                                dest,
                                no_target_dir,
                            } => {
                                // A trailing slash names a directory: the link is made inside it.
                                let directory_only = dest.len() > 1 && dest.ends_with('/');
                                let dest = join(base, dest.trim_end_matches('/'));
                                if directory_only {
                                    vec![dest]
                                } else {
                                    let mut dirs: Vec<std::path::PathBuf> =
                                        dest.parent().map(Path::to_path_buf).into_iter().collect();
                                    if !*no_target_dir {
                                        dirs.push(dest);
                                    }
                                    dirs
                                }
                            }
                        };
                        dirs.iter().any(|dir| {
                            sources.iter().any(|source| {
                                ln_word_path(source, base)
                                    .is_some_and(|spelled| git.contains(&join(dir, &spelled)))
                            })
                        })
                    }),
                }
            })
            || self.nested.iter().any(|nested| {
                nested.at < limit
                    && match self.bases(real_cwd, nested.at, nested.scope, false, &join) {
                        Err(_) => true,
                        Ok(bases) => bases
                            .iter()
                            .any(|base| nested.facts.writes_into(base, git, usize::MAX)),
                    }
            })
    }

    /// The protected-edit reason for these writes, resolving each like the edit tools resolve paths.
    /// A relative target is checked against every cwd it can run in ([`Self::bases`]); a nested `sh -c` script is
    /// judged from each cwd its shell can start in.
    pub(crate) fn protection(
        &self,
        real_cwd: &Path,
        resolve: impl Fn(&Path, &str) -> std::path::PathBuf,
    ) -> Option<ProtectedEditReason> {
        self.protection_in(real_cwd, &resolve)
    }

    pub(super) fn protection_in(
        &self,
        real_cwd: &Path,
        resolve: &dyn Fn(&Path, &str) -> std::path::PathBuf,
    ) -> Option<ProtectedEditReason> {
        // Peer scope (S6.4): a write target nothing can pin (`> "$OUT"`) may be any protected file.
        if peer_extended_set_active() && self.opaque_write {
            return Some(ProtectedEditReason::Sensitive);
        }
        let direct = strongest_protection(self.targets.iter().map(|target| {
            if is_safe_write_sink(&target.path) {
                return None;
            }
            // Peer scope (S6.4): a glob word cannot be pinned to the name it will match, so it is unpinned.
            if peer_extended_set_active() && peer_unpinnable_word(&target.path) {
                return Some(ProtectedEditReason::Sensitive);
            }
            // P166 r11 rule 2: ONE function decides every word that starts with `~`.
            let (spelled, pinned) = match tilde_word(&target.path) {
                TildeWord::Cwd(tail) => (format!(".{tail}"), false),
                TildeWord::Unknown => return Some(ProtectedEditReason::Sensitive),
                TildeWord::Home => (home_spelling(&target.path), true),
                TildeWord::NotTilde => (target.path.clone(), Path::new(&target.path).is_absolute()),
            };
            let bases = match self.bases(real_cwd, target.at, target.scope, pinned, resolve) {
                Ok(bases) => bases,
                Err(reason) => return Some(reason),
            };
            strongest_protection(bases.iter().map(|base| {
                let path = resolve(base, &spelled);
                match target.destination {
                    None | Some(DestinationKind::TargetDirectory | DestinationKind::Watch) => {
                        edit_target_protection(&path)
                    }
                    Some(DestinationKind::ViaDirectory) => via_directory_protection(&path),
                    Some(DestinationKind::ViaExistingDirectory) => {
                        via_existing_directory_protection(&path)
                    }
                    Some(DestinationKind::CopiedTree { follow_links }) => {
                        let source = resolve(
                            base,
                            &home_spelling(target.source.as_deref().unwrap_or_default()),
                        );
                        copied_tree_protection(&path, &source, follow_links)
                    }
                    Some(DestinationKind::Unpinned) => Some(ProtectedEditReason::Sensitive),
                    Some(DestinationKind::LinkOperand) => {
                        edit_target_protection(&path).or_else(|| peer_container_destination(&path))
                    }
                    Some(DestinationKind::Container) => {
                        edit_target_protection(&path).or_else(|| {
                            crate::permission::peer_guard::peer_holds_protected(&path)
                                .then_some(ProtectedEditReason::Sensitive)
                        })
                    }
                    Some(DestinationKind::Pathspec) => pathspec_protection(&path),
                    Some(DestinationKind::HookMetadata { recursive }) => {
                        hook_metadata_protection(&path, recursive)
                    }
                    Some(DestinationKind::GeneratedNames) => {
                        generated_names_protection(&path, target.path.ends_with('/'))
                    }
                }
            }))
        }));
        // 1.0.36 item a: a pinned launch policy file among later targets outranks an earlier target's reason.
        strongest_protection(
            std::iter::once(direct).chain(self.nested.iter().map(|nested| {
                let bases = match self.bases(real_cwd, nested.at, nested.scope, false, resolve) {
                    Ok(bases) => bases,
                    Err(reason) => return Some(reason),
                };
                strongest_protection(
                    bases
                        .iter()
                        .map(|base| nested.facts.protection_in(base, resolve)),
                )
            })),
        )
    }

    /// Whether every write of this script is a concrete path that `within` accepts, each resolved like the
    /// protected floor resolves it and judged from every cwd it can run in. For the sandbox card: it vouches
    /// for a write only when it can name it, so these are all "no": a script that runs git (a switch, a pull
    /// or a clean rewrites files no target names), a symbolic link, a write nothing can pin (`> "$X"`, a
    /// computed `cd`, `~user`, a glob), a destination kind that is more than a plain path, and a script with
    /// no concrete write at all.
    pub(crate) fn writes_stay_within(
        &self,
        real_cwd: &Path,
        resolve: impl Fn(&Path, &str) -> std::path::PathBuf,
        within: impl Fn(&Path) -> bool,
    ) -> bool {
        if !self.git_starts.is_empty() || !self.symlinks.is_empty() {
            return false;
        }
        let mut concrete = 0_usize;
        self.writes_stay_within_in(real_cwd, &resolve, &within, &mut concrete) && concrete > 0
    }

    pub(super) fn writes_stay_within_in(
        &self,
        real_cwd: &Path,
        resolve: &dyn Fn(&Path, &str) -> std::path::PathBuf,
        within: &dyn Fn(&Path) -> bool,
        concrete: &mut usize,
    ) -> bool {
        if self.opaque_write {
            return false;
        }
        for target in &self.targets {
            if is_safe_write_sink(&target.path) {
                continue;
            }
            match target.destination {
                None | Some(DestinationKind::TargetDirectory) => {}
                // Watching or reading metadata writes nothing.
                Some(DestinationKind::Watch | DestinationKind::HookMetadata { .. }) => continue,
                Some(_) => return false,
            }
            if peer_unpinnable_word(&target.path) || target.path.contains(['$', '`']) {
                return false;
            }
            let (spelled, pinned) = match tilde_word(&target.path) {
                TildeWord::Cwd(tail) => (format!(".{tail}"), false),
                TildeWord::Unknown => return false,
                TildeWord::Home => (home_spelling(&target.path), true),
                TildeWord::NotTilde => (target.path.clone(), Path::new(&target.path).is_absolute()),
            };
            let Ok(bases) = self.bases(real_cwd, target.at, target.scope, pinned, resolve) else {
                return false;
            };
            *concrete += 1;
            if !bases.iter().all(|base| within(&resolve(base, &spelled))) {
                return false;
            }
        }
        self.nested.iter().all(|nested| {
            let Ok(bases) = self.bases(real_cwd, nested.at, nested.scope, false, resolve) else {
                return false;
            };
            bases.iter().all(|base| {
                nested
                    .facts
                    .writes_stay_within_in(base, resolve, within, concrete)
            })
        })
    }
}
