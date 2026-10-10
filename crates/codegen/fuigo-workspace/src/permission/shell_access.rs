//! Detect file reads/writes inside a shell command so a managed `Read`/`Edit` deny/ask can't be bypassed via a shell reader/writer/redirect.

use std::path::Path;

use tree_sitter::Node;

mod tripwire;
use tripwire::CommandExtras;

use crate::permission::bash_command_splitting::{
    MAX_INLINE_SHELL_DEPTH, MAX_WRAPPER_DEPTH, decode_shell_literal_spelling,
    normalize_command_words, try_parse_shell,
};
use crate::permission::exec_risk::{
    attached_git_c_path, config_words_set_command_valued, is_accepted_long_option_prefix,
    is_attached_git_config_c, is_git_config_env_flag, is_git_exec_env_assignment, is_git_repo_retarget_flag,
};
use crate::permission::policy::{
    CompiledPolicy, GateDecision, InlineShellScript, RuleBase, ShellWord, SymlinkFollow,
    combine_gate_decisions, follow_absolute_symlink, path_has_parent_dir,
    resolve_following_symlinks, resolve_following_symlinks_for_comparison, shell_dash_c_script,
};
use crate::permission::types::{AccessKind, Decision};

impl CompiledPolicy {
    /// Escalate (never auto-allow) a shell reader/writer/redirect touching a restricted path; unpinnable operands return `Ask`.
    pub fn evaluate_shell_file_access(&self, cmd: &str, cwd: &Path) -> Option<Decision> {
        self.evaluate_shell_file_access_gate(cmd, cwd)
            .map(GateDecision::into_decision)
    }

    /// [`Self::evaluate_shell_file_access`] with `Ask` provenance kept.
    /// A rule-match Ask stays binding while the manager may defer a fail-closed Ask to the auto-mode classifier.
    pub(crate) fn evaluate_shell_file_access_gate(
        &self,
        cmd: &str,
        cwd: &Path,
    ) -> Option<GateDecision> {
        if !self.has_file_restrictions {
            return None;
        }
        let base = RuleBase::new(cwd);
        self.evaluate_shell_file_access_inner(cmd, &base, MAX_INLINE_SHELL_DEPTH, false, false)
    }

    fn evaluate_shell_file_access_inner(
        &self,
        cmd: &str,
        base: &RuleBase<'_>,
        inline_depth_remaining: usize,
        cwd_unpinned: bool,
        entered_inline: bool,
    ) -> Option<GateDecision> {
        let Some(tree) = try_parse_shell(cmd) else {
            return entered_inline.then_some(GateDecision::AskFailClosed);
        };
        let root = tree.root_node();
        let parse_failed = root.has_error();
        // WHY: only recursively entered scripts gain a general malformed-script Ask floor.
        let mut forced_ask = entered_inline && parse_failed;
        let mut decision: Option<GateDecision> = None;

        let invocations = shell_command_invocations(root, cmd);

        // We don't track cwd across `cd`/`pushd`/`env -C`; a relative operand after one is unpinnable and must Ask
        // Managed denies are `**/` basename globs, so they still match; only exact-path rules are affected
        let cwd_changes = cwd_poison_positions(root, cmd);

        for redirect in shell_redirect_targets(root, cmd) {
            if redirect.ambiguous {
                forced_ask = true;
            }
            if let Some(path) = redirect.path {
                let path_cwd_unpinned = cwd_unpinned
                    || cwd_unpinned_before(&cwd_changes, redirect.start_byte, redirect.scope);
                decision = combine_gate_decisions(
                    decision,
                    self.evaluate_shell_path(&path, base, redirect.mode, path_cwd_unpinned),
                );
            }
        }

        for invocation in &invocations {
            let peeled = unwrap_invocation_checked(invocation);
            let words = peeled.words;
            let invocation_cwd_unpinned = cwd_unpinned
                || cwd_unpinned_before(&cwd_changes, invocation.start_byte, invocation.scope)
                || peeled.has_chdir;
            forced_ask |= peeled.exhausted;
            forced_ask |= peeled.has_split_string;
            forced_ask |= peeled.env_options_uncertain;
            forced_ask |= peeled.transparent_ambiguous;
            let shell_words = words.shell_words();
            let inline_script = shell_dash_c_script(&shell_words);
            if parse_failed && !matches!(inline_script, InlineShellScript::NotInline) {
                forced_ask = true;
            }
            match inline_script {
                InlineShellScript::Literal(index) => {
                    if inline_depth_remaining == 0 {
                        forced_ask = true;
                    } else if let ShellWord::Literal(inner) = shell_words[index] {
                        decision = combine_gate_decisions(
                            decision,
                            self.evaluate_shell_file_access_inner(
                                inner,
                                base,
                                inline_depth_remaining - 1,
                                invocation_cwd_unpinned,
                                true,
                            ),
                        );
                    }
                }
                // Potential -c (Untrusted) and unmodeled options without -c (Unrecognized) both fail closed; only Literal may recurse
                InlineShellScript::Untrusted | InlineShellScript::Unrecognized => {
                    forced_ask = true;
                }
                InlineShellScript::NotInline => {}
            }
            let literal_words = words.literal_words();
            let has_ambiguous_word = words
                .words
                .iter()
                .any(|word| matches!(word, InvocationWord::Untrusted));
            let Some(InvocationWord::Literal(program)) = words.words.first() else {
                continue;
            };
            let program = shell_program_name(program);
            let program_lower = program.to_ascii_lowercase();
            if matches!(program_lower.as_str(), "cd" | "pushd" | "popd") {
                continue;
            }
            let candidates = shell_file_candidates(&literal_words);
            let path_operands = shell_path_command_operands(&program_lower, &literal_words);
            let is_known = program_lower == "dd"
                || shell_file_mode(&program_lower).is_some()
                || path_operands.is_some();
            if is_known && (invocation_cwd_unpinned || has_ambiguous_word || parse_failed) {
                forced_ask = true;
            }
            for (path, mode) in special_file_operands(&program_lower, &literal_words) {
                if shell_arg_is_ambiguous(&path) {
                    forced_ask = true;
                }
                decision = combine_gate_decisions(
                    decision,
                    self.evaluate_shell_path(&path, base, mode, invocation_cwd_unpinned),
                );
            }
            if program_lower == "dd" {
                continue;
            }
            if let Some(operands) = path_operands {
                for (path, mode) in operands {
                    if shell_arg_is_ambiguous(path) {
                        forced_ask = true;
                    }
                    decision = combine_gate_decisions(
                        decision,
                        self.evaluate_shell_path(path, base, mode, invocation_cwd_unpinned),
                    );
                }
                continue;
            }
            let modes: &[ShellFileMode] = match shell_file_mode(&program_lower) {
                Some(_) if program_lower == "sed" && shell_sed_in_place(&literal_words) => {
                    &[ShellFileMode::Read, ShellFileMode::Write]
                }
                Some(ShellFileMode::Read) => &[ShellFileMode::Read],
                Some(ShellFileMode::Write) => &[ShellFileMode::Write],
                Some(ShellFileMode::Create) | None => continue,
            };
            for &token in &candidates {
                if shell_arg_is_ambiguous(token) {
                    forced_ask = true;
                }
                for &mode in modes {
                    decision = combine_gate_decisions(
                        decision,
                        self.evaluate_shell_path(token, base, mode, invocation_cwd_unpinned),
                    );
                }
            }
            if shell_reader_can_recurse(&program_lower, &literal_words, &candidates) {
                forced_ask = true;
            }
        }
        combine_gate_decisions(decision, forced_ask.then_some(GateDecision::AskFailClosed))
    }

    fn evaluate_shell_path(
        &self,
        token: &str,
        base: &RuleBase<'_>,
        mode: ShellFileMode,
        cwd_unpinned: bool,
    ) -> Option<GateDecision> {
        let cwd = base.lexical;
        let path = normalize_shell_path(token);
        let raw = normalize_shell_path_raw(token);
        let is_absolute = is_absolute_shell_path(&path);
        // Cwd-aware rule match mirrors the direct Read/Edit tool gate
        // A rooted rule like `Read(src/**)` also keys on the same file spelled absolutely
        // An unpinned cwd anchors nothing: relative operands then keep text-only matching (absolute operands are cwd-independent)
        let rule_base = (is_absolute || !cwd_unpinned).then_some(base);
        // As for a native `..` path, the collapsed text gets physical-cwd forms only from the resolved re-check
        let has_parent_dir = path_has_parent_dir(Path::new(&raw));
        let lexical_base = has_parent_dir.then(|| base.without_physical());
        let path_rule_base = rule_base.map(|base| lexical_base.as_ref().unwrap_or(base));
        // Escalate only: drop Allow so a file allow-rule can't auto-approve here.
        let escalate = |access: &AccessKind, rule_base: Option<&RuleBase<'_>>| match self
            .evaluate_rules_with_base(access, rule_base)
        {
            Some(Decision::Reject(reason)) => Some(GateDecision::Reject(reason)),
            Some(Decision::Ask) => Some(GateDecision::AskRuleMatch),
            _ => None,
        };
        // Also re-check the resolved symlink target so a deny keyed on the real path can't be dodged via an in-workspace symlink (`ln -s /etc x`)
        // Resolve the *uncollapsed* operand so a `..` after a link is applied physically, not erased textually before the link is followed
        let raw_absolute = if is_absolute_shell_path(&raw) {
            Some(raw)
        } else if cwd_unpinned {
            None
        } else {
            Some(normalize_shell_path_raw(&cwd.join(&raw).to_string_lossy()))
        };
        let resolved_decision = raw_absolute.and_then(|raw_absolute| {
            let absolute = if is_absolute {
                path.clone()
            } else {
                normalize_shell_path(&cwd.join(&path).to_string_lossy())
            };
            match follow_absolute_symlink(&raw_absolute, &absolute) {
                SymlinkFollow::Target(resolved) => {
                    escalate(&shell_access(mode, resolved), rule_base)
                }
                SymlinkFollow::None if has_parent_dir => {
                    escalate(&shell_access(mode, absolute), rule_base)
                }
                SymlinkFollow::Unresolvable => Some(GateDecision::AskFailClosed),
                SymlinkFollow::None => None,
            }
        });
        let path_decision = escalate(&shell_access(mode, path.clone()), path_rule_base);
        // WHY: unknown cwd permits text matches only, never original-cwd resolution.
        let anchored_decision = if cwd_unpinned && !is_absolute {
            None
        } else {
            let absolute = if is_absolute {
                path.clone()
            } else {
                normalize_shell_path(&cwd.join(&path).to_string_lossy())
            };
            combine_gate_decisions(
                escalate(&shell_access(mode, absolute), path_rule_base),
                resolved_decision,
            )
        };
        let decision = combine_gate_decisions(path_decision, anchored_decision);
        combine_gate_decisions(
            decision,
            (cwd_unpinned && !is_absolute).then_some(GateDecision::AskFailClosed),
        )
    }
}

/// Writes of a program the generic word classifier does not see (P166 Grok r4 HIGH 3, r5 HIGH 1 and sweep): archive,
/// sync, in-place, patch, copy-over-ssh, download, split, decompress and `sed w` writers. `paths` are the places
/// written (an extraction directory, an archive file, a destination, a file edited in place, a downloaded file);
/// `generated` are name prefixes the program appends a suffix to (`split`); `unpinned` means some write may land where
/// the command line does not say (archive members, absolute or `..` member names, names the diff or the server picks),
/// which fails closed to the protected prompt. Archive members are not inspected (receipt R166, rounds 4 and 5).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ToolWrites {
    pub(crate) paths: Vec<String>,
    pub(crate) generated: Vec<String>,
    pub(crate) unpinned: bool,
}

/// [`ToolWrites`] for `tar`, `unzip`, `rsync`, `ditto`, `cpio`, `7z`, `pax`, `perl -i`, `ruby -i`, `patch`, `scp`,
/// `curl`, `wget`, `split`, `csplit`, the gzip/bzip2/xz/zstd/lz4 family and `sed`; `None` for any other program. An
/// extraction with no destination flag writes into the cwd (`.`).
pub(crate) fn tool_writes(program: &str, inner: &[String]) -> Option<ToolWrites> {
    let args = inner.get(1..).unwrap_or_default();
    let family = |name: &str| {
        program
            .strip_prefix(name)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    };
    Some(match program {
        "tar" | "gtar" | "bsdtar" => tar_writes(args),
        "unzip" => unzip_writes(args),
        "rsync" => {
            let (operands, _) = rsync_operands(inner);
            let mut writes = ToolWrites::default();
            // P166 r13: a host destination writes a remote tree; its path is judged by the destination-writes floor.
            if let [_, .., dest] = operands.as_slice()
                && !is_host_operand(dest)
            {
                writes.paths.push(operand_local_path(dest));
            }
            // P166 r7: the log and batch files rsync writes besides the destination.
            for (i, word) in inner.iter().enumerate().skip(1) {
                for flag in ["--log-file", "--write-batch", "--only-write-batch"] {
                    if word == flag {
                        writes.paths.extend(inner.get(i + 1).cloned());
                    } else if let Some(value) = word.strip_prefix(&format!("{flag}=")) {
                        writes.paths.push(value.to_owned());
                    }
                }
            }
            writes
        }
        "ditto" => ToolWrites {
            paths: match ditto_operands(inner).as_slice() {
                [_, .., dest] => vec![(*dest).to_owned()],
                _ => Vec::new(),
            },
            generated: Vec::new(),
            // Grok r5 MEDIUM 2: `ditto -x` extracts an archive whose members are not inspected.
            unpinned: ditto_extracts(inner),
        },
        "cpio" => cpio_writes(args),
        "7z" | "7za" | "7zz" | "7zr" => seven_zip_writes(args),
        "pax" => pax_writes(inner),
        // P166 r6 sweep: `ar rcs ARCHIVE FILE…` writes the archive (second word); `ar x` extracts members (not
        // inspected, like `tar -x`).
        "ar" => {
            let mode = inner.get(1).map(|word| word.trim_start_matches('-')).unwrap_or_default();
            // With a dashed mode word (`ar -r ARCHIVE`) the mode is not a file candidate, so the archive is the first.
            let skip = usize::from(!inner.get(1).is_some_and(|word| word.starts_with('-')));
            let archive = shell_file_candidates(inner).into_iter().nth(skip).map(str::to_owned);
            ToolWrites {
                paths: if mode.chars().any(|c| matches!(c, 'r' | 'q' | 'd' | 's' | 'm')) {
                    archive.into_iter().collect()
                } else {
                    Vec::new()
                },
                generated: Vec::new(),
                unpinned: mode.contains('x'),
            }
        }
        "patch" => patch_writes(args),
        "scp" => scp_writes(inner),
        "curl" => curl_writes(args),
        "wget" => wget_writes(args),
        "split" | "csplit" => split_writes(program, args),
        "sed" | "gsed" => sed_writes(inner),
        // `yq -i EXPR FILE…` rewrites each file in place (the first operand is the expression).
        "yq" => ToolWrites {
            paths: if inner
                .iter()
                .skip(1)
                .any(|word| matches!(word.as_str(), "-i" | "--inplace") || word.starts_with("--inplace="))
            {
                shell_file_candidates(inner).into_iter().skip(1).map(str::to_owned).collect()
            } else {
                Vec::new()
            },
            ..ToolWrites::default()
        },
        _ if family("perl") => in_place_writes(args, &PERL_OPTIONS),
        _ if family("ruby") => in_place_writes(args, &RUBY_OPTIONS),
        _ => return decompress_writes(program, args),
    })
}

/// Peeled launch wrappers of a command, for the write classifiers (P166 Grok r5 sweep).
struct WritePeel<'a> {
    /// The command that actually runs.
    words: &'a [String],
    /// A wrapper moved the cwd or root (`env -C`, `sudo -D`/`-i`/`-R`, `chroot`): relative targets cannot be pinned.
    moved: bool,
    /// The inner command is hidden (`env -S`, unreadable wrapper options, `flock -c`, `sudoedit`): fails closed.
    opaque: bool,
    /// A wrapper's own output file (`time -o FILE`).
    writes: Vec<&'a str>,
}

/// Peel the canonical wrappers and transparent prefixes (`env`, `timeout`, `nice`, `ionice`, `chrt`, `stdbuf`,
/// `command`, `exec`, `builtin`) and the launchers `sudo`, `doas`, `nohup`, `setsid`, `time`, `caffeinate`, `flock`,
/// `watch` and `chroot`, so `sudo cp evil .mcp.json` is judged as the `cp` it runs.
fn peel_write_command(words: &[String]) -> WritePeel<'_> {
    let mut peel = WritePeel {
        words,
        moved: false,
        opaque: false,
        writes: Vec::new(),
    };
    for _ in 0..MAX_WRAPPER_DEPTH {
        let normalized = normalize_command_words(peel.words);
        peel.moved |= normalized.has_chdir;
        peel.opaque |= normalized.has_split_string
            || normalized.env_options_uncertain
            || normalized.exhausted
            || normalized.ambiguous;
        peel.words = normalized.words;
        if peel.opaque {
            return peel;
        }
        match strip_launch_wrapper(peel.words) {
            LaunchStrip::NotWrapper => return peel,
            LaunchStrip::Opaque => {
                peel.opaque = true;
                return peel;
            }
            LaunchStrip::Inner {
                inner,
                moved,
                writes,
            } => {
                peel.words = inner;
                peel.moved |= moved;
                peel.writes.extend(writes);
            }
        }
    }
    peel.opaque = true;
    peel
}

enum LaunchStrip<'a> {
    NotWrapper,
    Opaque,
    Inner {
        inner: &'a [String],
        moved: bool,
        writes: Vec<&'a str>,
    },
}

/// Option grammar of one launcher, for [`strip_launch_wrapper`].
struct LauncherOptions {
    /// Short options that take a value (the rest of the cluster, else the next word).
    short_value: &'static str,
    long_value: &'static [&'static str],
    /// Options that move the cwd or root.
    short_moving: &'static str,
    long_moving: &'static [&'static str],
    /// Options that hide the command (a shell string, an editor).
    short_opaque: &'static str,
    long_opaque: &'static [&'static str],
    /// Options whose value is a file the launcher itself writes.
    short_write: &'static str,
    long_write: &'static [&'static str],
}

const NO_LAUNCHER_OPTIONS: LauncherOptions = LauncherOptions {
    short_value: "",
    long_value: &[],
    short_moving: "",
    long_moving: &[],
    short_opaque: "",
    long_opaque: &[],
    short_write: "",
    long_write: &[],
};

/// Strip one privilege/session launcher and its options.
fn strip_launch_wrapper(words: &[String]) -> LaunchStrip<'_> {
    let Some(head) = words.first() else {
        return LaunchStrip::NotWrapper;
    };
    let options = match shell_program_name(head).to_ascii_lowercase().as_str() {
        "sudo" => LauncherOptions {
            short_value: "CDghpRrTtUu",
            long_value: &[
                "close-from", "chdir", "group", "host", "prompt", "chroot", "role", "type",
                "command-timeout", "other-user", "user",
            ],
            short_moving: "DiR",
            long_moving: &["chdir", "login", "chroot"],
            short_opaque: "e",
            long_opaque: &["edit"],
            ..NO_LAUNCHER_OPTIONS
        },
        "doas" => LauncherOptions {
            short_value: "uC",
            ..NO_LAUNCHER_OPTIONS
        },
        "nohup" | "setsid" => NO_LAUNCHER_OPTIONS,
        "caffeinate" => LauncherOptions {
            short_value: "tw",
            ..NO_LAUNCHER_OPTIONS
        },
        "time" => LauncherOptions {
            short_value: "fo",
            long_value: &["format", "output"],
            short_write: "o",
            long_write: &["output"],
            ..NO_LAUNCHER_OPTIONS
        },
        "watch" => LauncherOptions {
            short_value: "nq",
            long_value: &["interval", "equexit"],
            ..NO_LAUNCHER_OPTIONS
        },
        "flock" => LauncherOptions {
            short_value: "wEc",
            long_value: &["wait", "timeout", "conflict-exit-code", "command"],
            short_opaque: "c",
            long_opaque: &["command"],
            ..NO_LAUNCHER_OPTIONS
        },
        "chroot" => LauncherOptions {
            long_value: &["userspec", "groups"],
            ..NO_LAUNCHER_OPTIONS
        },
        _ => return LaunchStrip::NotWrapper,
    };
    let program = shell_program_name(head).to_ascii_lowercase();
    let (mut moved, mut writes, mut i) = (program == "chroot", Vec::new(), 1);
    while let Some(word) = words.get(i) {
        if word == "--" {
            i += 1;
            break;
        }
        if word == "-" || !word.starts_with('-') {
            break;
        }
        i += 1;
        if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let value = match glued {
                Some(value) => Some(value),
                None if options.long_value.contains(&name) => {
                    i += 1;
                    words.get(i - 1).map(String::as_str)
                }
                None => None,
            };
            if options.long_opaque.contains(&name) {
                return LaunchStrip::Opaque;
            }
            moved |= options.long_moving.contains(&name);
            if options.long_write.contains(&name) {
                writes.extend(value);
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if options.short_opaque.contains(option) {
                return LaunchStrip::Opaque;
            }
            moved |= options.short_moving.contains(option);
            if options.short_value.contains(option) {
                let value = short_option_value(cluster, at, words, &mut i);
                if options.short_write.contains(option) {
                    writes.extend(value);
                }
                break;
            }
        }
    }
    // `sudo NAME=VALUE cmd`; `flock FILE cmd`; `chroot DIR cmd`.
    if program == "sudo" {
        while words.get(i).is_some_and(|word| {
            word.split_once('=')
                .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'))
        }) {
            i += 1;
        }
    }
    if matches!(program.as_str(), "flock" | "chroot") {
        i += 1;
    }
    match words.get(i..) {
        Some(inner) if !inner.is_empty() => LaunchStrip::Inner {
            inner,
            moved,
            writes,
        },
        // `sudo -l`, `sudo -v`: no command.
        _ => LaunchStrip::NotWrapper,
    }
}

/// The value of a short option at `cluster[at]`: the rest of the cluster, else the next word (`i` is advanced past it).
fn short_option_value<'a>(cluster: &'a str, at: usize, args: &'a [String], i: &mut usize) -> Option<&'a str> {
    let rest = &cluster[at + 1..];
    if rest.is_empty() {
        let value = args.get(*i).map(String::as_str);
        *i += 1;
        value
    } else {
        Some(rest)
    }
}

/// `tar`: extract (`x`, `--extract`, `--get`) writes into each `-C`/`--directory` (else `.`); create/append/update
/// (`c`, `r`, `u`, `A`, `--delete`) write the `-f`/`--file` archive (and `-g` snapshot); list/diff (`t`, `d`) write
/// nothing. An extraction's members are not inspected, so it is unpinned (Grok r5 MEDIUM 2; `-P` would also let them
/// land anywhere). A mode that cannot be told fails closed to `.`.
/// The old bundled form (`tar xzf a.tar`) takes option values from the following words.
fn tar_writes(args: &[String]) -> ToolWrites {
    // Short options taking a value in both GNU tar and bsdtar (`-L`, `-H`, `-s` differ between them and are read as
    // flags: a value misread as an operand is ignored, while a flag misread as taking a value could hide `-f`).
    const TAKES_VALUE: &str = "bCfFgIKNTVX";
    #[derive(Default)]
    struct Tar<'a> {
        extract: bool,
        archive_write: bool,
        list: bool,
        file: Option<&'a str>,
        dirs: Vec<&'a str>,
        snapshot: Option<&'a str>,
        other: bool,
    }
    impl<'a> Tar<'a> {
        fn short(&mut self, option: char, value: Option<&'a str>) {
            match option {
                'x' => self.extract = true,
                'c' | 'r' | 'u' | 'A' => self.archive_write = true,
                't' | 'd' => self.list = true,
                'f' => self.file = value,
                'C' => self.dirs.extend(value),
                'g' => self.snapshot = value,
                _ => {}
            }
        }
        fn long(&mut self, name: &str, value: Option<&'a str>) {
            match name {
                "extract" | "get" => self.extract = true,
                "create" | "append" | "update" | "catenate" | "concatenate" | "delete" => {
                    self.archive_write = true
                }
                "list" | "diff" | "compare" => self.list = true,
                "file" => self.file = value,
                "directory" => self.dirs.extend(value),
                "listed-incremental" => self.snapshot = value,
                "help" | "usage" | "version" | "show-defaults" => {}
                _ => self.other = true,
            }
        }
    }
    let mut tar = Tar::default();
    let mut i = 0;
    if let Some(bundle) = args.first().filter(|word| !word.starts_with('-')) {
        i = 1;
        for option in bundle.chars() {
            let value = TAKES_VALUE.contains(option).then(|| {
                i += 1;
                args.get(i - 1).map(String::as_str)
            });
            tar.short(option, value.flatten());
        }
    }
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if word == "--" {
            break;
        }
        if word == "-" || !word.starts_with('-') {
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None if matches!(long, "file" | "directory" | "listed-incremental") => {
                    i += 1;
                    (long, args.get(i - 1).map(String::as_str))
                }
                None => (long, None),
            };
            tar.long(name, value);
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if TAKES_VALUE.contains(option) {
                let value = short_option_value(cluster, at, args, &mut i);
                tar.short(option, value);
                break;
            }
            tar.short(option, None);
        }
    }
    let mut writes = ToolWrites::default();
    writes.paths.extend(tar.snapshot.map(str::to_owned));
    if tar.archive_write {
        writes
            .paths
            .extend(tar.file.filter(|file| *file != "-").map(str::to_owned));
    }
    // Extraction, or a mode that cannot be told (other than help/version), writes into the target directories.
    let unknown_mode = !tar.extract && !tar.archive_write && !tar.list && (tar.other || tar.file.is_some());
    if tar.extract || unknown_mode {
        if tar.dirs.is_empty() {
            writes.paths.push(".".to_owned());
        } else {
            writes.paths.extend(tar.dirs.iter().map(|dir| (*dir).to_owned()));
        }
        writes.unpinned = true;
    }
    writes
}

/// `unzip`: extracts into `-d DIR` (else `.`); list/test/pipe/comment/zipinfo modes (`-l`, `-t`, `-p`, `-v`, `-z`,
/// `-Z`) write nothing. An extraction's members are not inspected (and `-:` keeps `../` names), so it is unpinned.
fn unzip_writes(args: &[String]) -> ToolWrites {
    let mut dirs = Vec::new();
    let (mut no_write, mut i) = (false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            continue;
        };
        for (at, option) in cluster.char_indices() {
            match option {
                'd' => {
                    dirs.extend(short_option_value(cluster, at, args, &mut i));
                    break;
                }
                'l' | 't' | 'p' | 'v' | 'z' | 'Z' => no_write = true,
                _ => {}
            }
        }
    }
    if no_write {
        return ToolWrites::default();
    }
    if dirs.is_empty() {
        dirs.push(".");
    }
    ToolWrites {
        paths: dirs.into_iter().map(str::to_owned).collect(),
        generated: Vec::new(),
        unpinned: true,
    }
}

/// `cpio`: copy-in (`-i`, `--extract`) writes into `-D DIR` (else `.`); pass-through (`-p`) writes into its directory
/// operand; copy-out (`-o`) writes the `-O`/`-F` archive. Copy-in members and pass-through names (read from stdin) are
/// not inspected, so both are unpinned (Grok r5 MEDIUM 2; GNU also honours absolute member names by default).
fn cpio_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "CDEFHIMOR";
    let (mut copy_in, mut pass, mut copy_out) = (false, false, false);
    let (mut dirs, mut archives, mut operands) = (Vec::new(), Vec::new(), Vec::new());
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None if matches!(long, "directory" | "file") => {
                    i += 1;
                    (long, args.get(i - 1).map(String::as_str))
                }
                None => (long, None),
            };
            match name {
                "extract" => copy_in = true,
                "pass-through" => pass = true,
                "create" => copy_out = true,
                "directory" => dirs.extend(value),
                "file" => archives.extend(value),
                _ => {}
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            operands.push(word.as_str());
            continue;
        };
        for (at, option) in cluster.char_indices() {
            match option {
                'i' => copy_in = true,
                'p' => pass = true,
                'o' => copy_out = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'D' => dirs.extend(value),
                        'F' | 'O' => archives.extend(value),
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites::default();
    if copy_in {
        if dirs.is_empty() {
            dirs.push(".");
        }
        writes.paths.extend(dirs.iter().map(|dir| (*dir).to_owned()));
        writes.unpinned = true;
    }
    if pass {
        writes.paths.extend(operands.last().map(|dir| (*dir).to_owned()));
        writes.unpinned = true;
    }
    if copy_out {
        writes.paths.extend(archives.iter().map(|file| (*file).to_owned()));
    }
    writes
}

/// `7z`: `x`/`e` extract into `-oDIR` (else `.`), unpinned because members are not inspected (and `-spf` keeps
/// absolute paths); `a`/`u`/`d`/`rn` write the archive (the first operand after the command); other commands (`l`,
/// `t`, `h`, `i`, `b`) write nothing.
fn seven_zip_writes(args: &[String]) -> ToolWrites {
    let operands: Vec<&str> = args
        .iter()
        .filter(|word| !word.starts_with('-'))
        .map(String::as_str)
        .collect();
    let switches = || args.iter().filter_map(|word| word.strip_prefix('-'));
    let mut writes = ToolWrites::default();
    match operands.first().map(|command| command.to_ascii_lowercase()).as_deref() {
        Some("x" | "e") => {
            let dirs: Vec<String> = switches()
                .filter_map(|switch| switch.strip_prefix('o'))
                .map(str::to_owned)
                .collect();
            writes.paths = if dirs.is_empty() { vec![".".to_owned()] } else { dirs };
            writes.unpinned = true;
        }
        Some("a" | "u" | "d" | "rn") => {
            writes.paths.extend(operands.get(1).map(|archive| (*archive).to_owned()));
        }
        _ => {}
    }
    writes
}

/// Short-option grammar of an in-place-capable interpreter, for [`in_place_writes`].
struct InterpreterOptions {
    /// Options whose value is the rest of the cluster (`-Mstrict`, `-I/dir`), so an `i` inside it is not `-i`.
    glued_value: &'static str,
    /// Of those, the ones whose value may instead be the next word (`-e CODE`, `-I DIR`).
    next_word_value: &'static str,
    /// Options carrying inline code, so the first operand is a file rather than the script.
    code: &'static str,
}

const PERL_OPTIONS: InterpreterOptions = InterpreterOptions {
    glued_value: "eEIMmFxdDCV",
    next_word_value: "eEI",
    code: "eE",
};

const RUBY_OPTIONS: InterpreterOptions = InterpreterOptions {
    glued_value: "eIrCEFxKTW",
    next_word_value: "eIrCE",
    code: "e",
};

/// `perl -i` / `ruby -i` (also clustered: `-pi`, `-i.bak`, `-lpi`): every file operand is rewritten in place.
/// Without inline code (`-e`) the first operand is the script, not a write. `-l`/`-0` take only octal digits.
fn in_place_writes(args: &[String], options: &InterpreterOptions) -> ToolWrites {
    let (mut in_place, mut inline_code, mut i) = (false, false, 0);
    while i < args.len() {
        let word = &args[i];
        if word == "--" {
            i += 1;
            break;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            break;
        };
        i += 1;
        let mut chars = cluster.char_indices().peekable();
        while let Some((at, option)) = chars.next() {
            if option == 'i' {
                // The rest of the cluster is the backup extension.
                in_place = true;
                break;
            }
            if matches!(option, 'l' | '0') {
                while chars.next_if(|(_, c)| ('0'..='7').contains(c)).is_some() {}
                continue;
            }
            if options.glued_value.contains(option) {
                inline_code |= options.code.contains(option);
                if cluster[at + 1..].is_empty() && options.next_word_value.contains(option) {
                    i += 1;
                }
                break;
            }
        }
    }
    if !in_place {
        return ToolWrites::default();
    }
    let operands = args.get(i..).unwrap_or_default();
    let files = if inline_code {
        operands
    } else {
        operands.get(1..).unwrap_or_default()
    };
    ToolWrites {
        paths: files.to_vec(),
        ..ToolWrites::default()
    }
}

/// Long options whose value is the next word unless glued with `=`, and every option seen, for the small getopt
/// parsers below. Returns `(name, value)`; `i` is advanced past a consumed value.
fn long_option<'a>(
    long: &'a str,
    args: &'a [String],
    i: &mut usize,
    takes_value: &[&str],
) -> (&'a str, Option<&'a str>) {
    match long.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None if takes_value.contains(&long) => {
            *i += 1;
            (long, args.get(*i - 1).map(String::as_str))
        }
        None => (long, None),
    }
}

/// `ditto -x` (also clustered, `-xk`) extracts an archive.
fn ditto_extracts(inner: &[String]) -> bool {
    inner.iter().skip(1).any(|word| {
        word.strip_prefix('-')
            .is_some_and(|cluster| !cluster.starts_with('-') && cluster.contains('x'))
    })
}

/// `pax` modes and operands (P166 Grok r5 HIGH 1).
struct PaxArgs<'a> {
    read: bool,
    write: bool,
    archive: Option<&'a str>,
    operands: Vec<&'a str>,
    /// `-s` renames members, `-L` follows links.
    renames: bool,
    follow: bool,
}

fn pax_args(inner: &[String]) -> PaxArgs<'_> {
    const TAKES_VALUE: &str = "bfopsxBEGTU";
    let args = inner.get(1..).unwrap_or_default();
    let mut pax = PaxArgs {
        read: false,
        write: false,
        archive: None,
        operands: Vec::new(),
        renames: false,
        follow: false,
    };
    let (mut i, mut end) = (0, false);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            pax.operands.push(word);
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'r' => pax.read = true,
                'w' => pax.write = true,
                'L' => pax.follow = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'f' => pax.archive = value,
                        's' => pax.renames = true,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    pax
}

/// `pax -r` extracts into the cwd (members not inspected: unpinned); `pax -rw` copies its operands' trees into the last
/// operand (from stdin without operands, or renamed by `-s`: unpinned); `pax -w -f FILE` writes the archive.
fn pax_writes(inner: &[String]) -> ToolWrites {
    let pax = pax_args(inner);
    let mut writes = ToolWrites::default();
    match (pax.read, pax.write) {
        (true, true) => {
            writes.paths.extend(pax.operands.last().map(|dest| (*dest).to_owned()));
            writes.unpinned = pax.operands.len() < 2 || pax.renames;
        }
        (true, false) => {
            writes.paths.push(".".to_owned());
            writes.unpinned = true;
        }
        (false, true) => writes
            .paths
            .extend(pax.archive.filter(|file| *file != "-").map(str::to_owned)),
        (false, false) => {}
    }
    writes
}

/// `patch` (P166 Grok r5 HIGH 1): `-o`/`--output` is the only file written (`-` is stdout); otherwise the original-file
/// operand; with neither, the files named inside the diff (unpinned). `-r` writes the reject file. `-d DIR` moves the
/// cwd and `--dry-run`/`-C` writes nothing.
fn patch_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "BDdFgioprVYz";
    const LONG_WITH_VALUE: &[&str] = &[
        "output", "input", "reject-file", "directory", "strip", "prefix", "basename-prefix", "suffix",
        "fuzz", "get", "ifdef", "version-control", "quoting-style", "reject-format",
    ];
    let (mut outputs, mut rejects, mut operands) = (Vec::new(), Vec::new(), Vec::new());
    let (mut dry_run, mut moved, mut end, mut i) = (false, false, false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "output" => outputs.extend(value),
                "reject-file" => rejects.extend(value),
                "directory" => moved = true,
                "dry-run" | "check" => dry_run = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if option == 'C' {
                dry_run = true;
            } else if TAKES_VALUE.contains(option) {
                let value = short_option_value(cluster, at, args, &mut i);
                match option {
                    'o' => outputs.extend(value),
                    'r' => rejects.extend(value),
                    'd' => moved = true,
                    _ => {}
                }
                break;
            }
        }
    }
    let mut writes = ToolWrites::default();
    if dry_run {
        return writes;
    }
    writes
        .paths
        .extend(rejects.into_iter().filter(|file| *file != "-").map(str::to_owned));
    match (outputs.last(), operands.first()) {
        (Some(output), _) => writes
            .paths
            .extend((*output != "-").then(|| (*output).to_owned())),
        (None, Some(original)) => writes.paths.push((*original).to_owned()),
        (None, None) => writes.unpinned = true,
    }
    writes.unpinned |= moved;
    writes
}

/// `scp`'s operands (the last is the destination) and whether it copies recursively (`-r`).
fn scp_operands(inner: &[String]) -> (Vec<&str>, bool) {
    const TAKES_VALUE: &str = "cDFiJloPSX";
    let args = inner.get(1..).unwrap_or_default();
    let (mut operands, mut recursive, mut end, mut i) = (Vec::new(), false, false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if option == 'r' {
                recursive = true;
            } else if TAKES_VALUE.contains(option) {
                short_option_value(cluster, at, args, &mut i);
                break;
            }
        }
    }
    (operands, recursive)
}

/// `scp` writes its local destination; a remote tree (`-r host:dir`) or a remote glob lands unknown names (unpinned).
fn scp_writes(inner: &[String]) -> ToolWrites {
    let (operands, recursive) = scp_operands(inner);
    let mut writes = ToolWrites::default();
    if let Some((dest, sources)) = operands.split_last()
        && !sources.is_empty()
        && !is_host_operand(dest)
    {
        writes.paths.push(operand_local_path(dest));
        writes.unpinned = sources.iter().any(|source| {
            is_host_operand(source) && (recursive || shell_arg_is_ambiguous(source))
        });
    }
    writes
}

/// The file name `curl -O` / `wget` derive from a URL: its last path segment, raw and percent-decoded. Empty when the
/// URL has no path segment; `None` when a curl glob (`[1-3]`, `{a,b}`) makes the names unknown.
fn url_file_names(url: &str) -> Option<Vec<String>> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let Some((_, path)) = rest.split_once('/') else {
        return Some(Vec::new());
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    if path.contains(['[', '{']) {
        return None;
    }
    let name = path.rsplit('/').next().unwrap_or_default();
    if name.is_empty() {
        return Some(Vec::new());
    }
    let decoded = percent_decode(name);
    let mut names = vec![name.to_owned()];
    // A decoded `/` would not be a single name; the raw spelling is still checked.
    if decoded != name && !decoded.contains('/') {
        names.push(decoded);
    }
    Some(names)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Join an output name to a directory option (`curl --output-dir`, `wget -P`) unless it is absolute.
fn place_in_dir(dir: Option<&str>, name: &str) -> String {
    match dir {
        Some(dir) if !is_absolute_shell_path(name) => Path::new(dir).join(name).to_string_lossy().into_owned(),
        _ => name.to_owned(),
    }
}

/// `curl` (P166 Grok r5 sweep): `-o FILE` (in `--output-dir`), `-O` names from the URLs, and the files it writes as
/// side outputs (`-D`, `-c`, `--trace`, `--stderr`, `--libcurl`, `--etag-save`, `--hsts`, `--alt-svc`). `-J` (the
/// server picks the name), a `-o` glob variable (`#1`), a URL glob and `-K` (a config file can set any output) are
/// unpinned. Only the known value-taking options consume a value, so an unknown option can only add a URL name.
fn curl_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
    const LONG_WITH_VALUE: &[&str] = &[
        "output", "output-dir", "dump-header", "cookie-jar", "trace", "trace-ascii", "stderr", "libcurl",
        "etag-save", "etag-compare", "hsts", "alt-svc", "config", "url", "data", "data-raw", "data-binary",
        "data-urlencode", "data-ascii", "json", "header", "request", "user", "user-agent", "referer", "cookie",
        "form", "form-string", "upload-file", "proxy", "max-time", "connect-timeout", "write-out", "range",
        "cert", "key", "cacert", "capath", "continue-at", "retry", "retry-delay", "retry-max-time", "resolve",
        "connect-to", "interface", "limit-rate", "max-filesize", "oauth2-bearer", "proxy-user", "pass",
        "cert-type", "key-type", "ciphers", "tls-max", "expect100-timeout", "keepalive-time", "max-redirs",
        "netrc-file", "unix-socket", "abstract-unix-socket", "variable", "url-query", "aws-sigv4", "dns-servers",
        "doh-url", "local-port", "noproxy", "preproxy", "proto", "proto-redir", "proxy-header", "request-target",
        "speed-limit", "speed-time", "telnet-option", "time-cond", "create-file-mode", "ftp-port", "quote",
        "mail-from", "mail-rcpt", "mail-auth", "socks4", "socks4a", "socks5", "socks5-hostname", "engine",
        "crlfile", "pinnedpubkey", "proxy-cacert", "proxy-capath", "proxy-cert", "proxy-key", "proxy-pass",
        "login-options", "delegation", "ip-tos", "happy-eyeballs-timeout-ms",
    ];
    let (mut outputs, mut side, mut urls) = (Vec::new(), Vec::new(), Vec::new());
    let (mut output_dir, mut remote_name, mut header_name, mut config) = (None, false, false, false);
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if word == "-" || !word.starts_with('-') {
            urls.push(word.as_str());
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "output" => outputs.extend(value),
                "output-dir" => output_dir = value,
                "remote-name" | "remote-name-all" => remote_name = true,
                "remote-header-name" => header_name = true,
                "dump-header" | "cookie-jar" | "trace" | "trace-ascii" | "stderr" | "libcurl"
                | "etag-save" | "hsts" | "alt-svc" => side.extend(value),
                "config" => config = true,
                "url" => urls.extend(value),
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'O' => remote_name = true,
                'J' => header_name = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'o' => outputs.extend(value),
                        'D' | 'c' => side.extend(value),
                        'K' => config = true,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites::default();
    for output in outputs.into_iter().filter(|output| *output != "-") {
        writes.unpinned |= output.contains('#');
        writes.paths.push(place_in_dir(output_dir, output));
    }
    writes
        .paths
        .extend(side.into_iter().filter(|file| *file != "-").map(str::to_owned));
    if remote_name || header_name {
        writes.unpinned |= header_name;
        for url in urls {
            match url_file_names(url) {
                Some(names) => writes
                    .paths
                    .extend(names.iter().map(|name| place_in_dir(output_dir, name))),
                None => writes.unpinned = true,
            }
        }
    }
    writes.unpinned |= config;
    writes
}

/// `wget` (P166 Grok r5 sweep): `-O FILE` (`-` is stdout), else each URL's name (`index.html` for a bare URL) in `-P DIR`;
/// log and cookie files. Recursive and server-named downloads (`-r`, `-m`, `-p`, `-x`, `-i`, `--content-disposition`,
/// `--trust-server-names`) and `-e` (a `.wgetrc` command can set any output) are unpinned.
fn wget_writes(args: &[String]) -> ToolWrites {
    const TAKES_VALUE: &str = "aABDeiIlOoPQRtTUwX";
    const LONG_WITH_VALUE: &[&str] = &[
        "output-document", "directory-prefix", "output-file", "append-output", "input-file", "base", "execute",
        "tries", "timeout", "dns-timeout", "connect-timeout", "read-timeout", "wait", "waitretry", "user-agent",
        "header", "post-data", "post-file", "body-data", "body-file", "method", "user", "password", "http-user",
        "http-password", "ftp-user", "ftp-password", "load-cookies", "save-cookies", "referer", "accept",
        "reject", "accept-regex", "reject-regex", "domains", "exclude-domains", "include-directories",
        "exclude-directories", "level", "quota", "limit-rate", "bind-address", "cut-dirs", "default-page",
        "ca-certificate", "ca-directory", "certificate", "private-key", "certificate-type", "private-key-type",
        "progress", "restrict-file-names", "local-encoding", "remote-encoding", "secure-protocol", "report-speed",
        "rejected-log", "warc-file", "warc-header", "warc-max-size", "config", "proxy-user", "proxy-password",
        "prefer-family", "crl-file", "pinnedpubkey", "ciphers", "hsts-file", "compression", "use-askpass",
        "retry-on-http-error", "max-redirect",
    ];
    let (mut document, mut prefix, mut side, mut urls) = (None, None, Vec::new(), Vec::new());
    let mut unpinned = false;
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if !word.starts_with('-') || word == "-" {
            urls.push(word.as_str());
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "output-document" => document = value,
                "directory-prefix" => prefix = value,
                "output-file" | "append-output" | "save-cookies" | "rejected-log" | "hsts-file"
                | "warc-file" => side.extend(value),
                "recursive" | "mirror" | "page-requisites" | "force-directories" | "input-file"
                | "content-disposition" | "trust-server-names" | "execute" | "config" => unpinned = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'r' | 'm' | 'p' | 'x' => unpinned = true,
                _ if TAKES_VALUE.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'O' => document = value,
                        'P' => prefix = value,
                        'o' | 'a' => side.extend(value),
                        'i' | 'e' => unpinned = true,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites {
        unpinned,
        ..ToolWrites::default()
    };
    writes.paths.extend(side.into_iter().map(str::to_owned));
    match document {
        Some("-") => {}
        Some(file) => writes.paths.push(file.to_owned()),
        None => {
            for url in urls {
                match url_file_names(url) {
                    Some(names) if names.is_empty() => {
                        writes.paths.push(place_in_dir(prefix, "index.html"));
                    }
                    Some(names) => writes
                        .paths
                        .extend(names.iter().map(|name| place_in_dir(prefix, name))),
                    None => writes.unpinned = true,
                }
            }
        }
    }
    writes
}

/// `split [INPUT [PREFIX]]` and `csplit -f PREFIX` write files named PREFIX plus a suffix (`x`/`xx` by default).
fn split_writes(program: &str, args: &[String]) -> ToolWrites {
    let (takes_value, long_with_value): (&str, &[&str]) = if program == "csplit" {
        ("bfn", &["suffix-format", "prefix", "digits"])
    } else {
        (
            "abClnt",
            &["suffix-length", "additional-suffix", "bytes", "line-bytes", "lines", "number", "separator", "filter"],
        )
    };
    let (mut prefix, mut operands, mut end, mut i) = (None, Vec::new(), false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, long_with_value);
            if name == "prefix" {
                prefix = value;
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            if takes_value.contains(option) {
                let value = short_option_value(cluster, at, args, &mut i);
                if program == "csplit" && option == 'f' {
                    prefix = value;
                }
                break;
            }
        }
    }
    let prefix = match program {
        "csplit" => prefix.unwrap_or("xx"),
        _ => operands.get(1).copied().unwrap_or("x"),
    };
    ToolWrites {
        generated: vec![prefix.to_owned()],
        ..ToolWrites::default()
    }
}

/// The gzip/bzip2/xz/lzma/zstd/lz4/brotli family (P166 Grok r5 sweep): decompressing writes each operand without its
/// suffix (`.tgz` -> `.tar`), or `-o FILE` (zstd, brotli) or lz4's second operand; compressing writes the operand plus
/// the suffix. `-c`/`--stdout` writes nothing; gzip `-N` restores the name stored in the archive (unpinned).
fn decompress_writes(program: &str, args: &[String]) -> Option<ToolWrites> {
    let always = matches!(
        program,
        "gunzip" | "bunzip2" | "unxz" | "unlzma" | "unzstd" | "unlz4" | "uncompress" | "unpigz"
    );
    let suffix = match program {
        "gzip" | "pigz" => ".gz",
        "bzip2" | "pbzip2" | "lbzip2" => ".bz2",
        "xz" => ".xz",
        "lzma" => ".lzma",
        "zstd" => ".zst",
        "lz4" => ".lz4",
        "brotli" => ".br",
        "compress" => ".Z",
        _ if always => "",
        _ => return None,
    };
    let takes_value = if program == "brotli" { "oSTDMqw" } else { "oSTDM" };
    const LONG_WITH_VALUE: &[&str] = &["suffix", "output", "threads", "dict", "memlimit", "format"];
    let (mut decompress, mut stdout, mut restore_name) = (always, false, false);
    let (mut output, mut custom_suffix, mut operands, mut end, mut i) = (None, None, Vec::new(), false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "decompress" | "uncompress" => decompress = true,
                "stdout" | "to-stdout" => stdout = true,
                "name" => restore_name = true,
                "output" => output = value,
                "suffix" => custom_suffix = value,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'd' => decompress = true,
                'c' => stdout = true,
                'N' if program.contains("gz") || program.contains("pigz") => restore_name = true,
                _ if takes_value.contains(option) => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'o' => output = value,
                        'S' => custom_suffix = value,
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    let mut writes = ToolWrites::default();
    if stdout {
        return Some(writes);
    }
    if let Some(output) = output.filter(|output| *output != "-") {
        writes.paths.push(output.to_owned());
        return Some(writes);
    }
    if !decompress {
        let suffix = custom_suffix.unwrap_or(suffix);
        writes
            .paths
            .extend(operands.iter().map(|operand| format!("{operand}{suffix}")));
        return Some(writes);
    }
    writes.unpinned = restore_name;
    if program.contains("lz4")
        && let [_, output] = operands.as_slice()
    {
        writes.paths.push((*output).to_owned());
        return Some(writes);
    }
    const SUFFIXES: &[(&str, &str)] = &[
        (".tgz", ".tar"), (".taz", ".tar"), (".tbz2", ".tar"), (".tbz", ".tar"), (".txz", ".tar"),
        (".tlz", ".tar"), (".tzst", ".tar"), (".gz", ""), ("-gz", ""), (".z", ""), ("-z", ""), ("_z", ""),
        (".bz2", ""), (".bz", ""), (".xz", ""), (".lzma", ""), (".lz", ""), (".zst", ""), (".lz4", ""), (".br", ""),
    ];
    for operand in operands {
        let lower = operand.to_ascii_lowercase();
        let stripped = custom_suffix
            .filter(|suffix| !suffix.is_empty() && operand.ends_with(suffix))
            .map(|suffix| operand[..operand.len() - suffix.len()].to_owned())
            .or_else(|| {
                SUFFIXES.iter().find_map(|(suffix, replacement)| {
                    lower
                        .ends_with(suffix)
                        .then(|| format!("{}{replacement}", &operand[..operand.len() - suffix.len()]))
                })
            });
        writes.paths.extend(stripped);
    }
    Some(writes)
}

/// `sed` writes: every file operand of `-i` (as before), and the files of `w FILE`, `W FILE` and the `s///w FILE` flag
/// in a literal script (P166 Grok r5 LOW 4). A script that cannot be parsed but holds a `w` fails closed. A `-f` script
/// file is not read (interpreter-limit class).
fn sed_writes(inner: &[String]) -> ToolWrites {
    const LONG_WITH_VALUE: &[&str] = &["expression", "file", "line-length"];
    let args = inner.get(1..).unwrap_or_default();
    let (mut scripts, mut script_file, mut bare_in_place) = (Vec::new(), false, false);
    let (mut operands, mut end, mut i) = (Vec::new(), false, 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if end || word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            end = true;
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, LONG_WITH_VALUE);
            match name {
                "expression" => scripts.extend(value),
                "file" => script_file = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            match option {
                'e' | 'f' | 'l' => {
                    let value = short_option_value(cluster, at, args, &mut i);
                    match option {
                        'e' => scripts.extend(value),
                        'f' => script_file = true,
                        _ => {}
                    }
                    break;
                }
                'i' => {
                    bare_in_place = cluster[at + 1..].is_empty();
                    break;
                }
                _ => {}
            }
        }
    }
    if scripts.is_empty() && !script_file {
        // The first operand is the script; BSD `sed -i '' SCRIPT` puts the empty backup suffix first.
        let script = match operands.as_slice() {
            ["", script, ..] if bare_in_place => Some(*script),
            [script, ..] => Some(*script),
            [] => None,
        };
        scripts.extend(script);
    }
    let mut writes = ToolWrites::default();
    if shell_sed_in_place(inner) {
        writes
            .paths
            .extend(shell_file_candidates(inner).into_iter().map(str::to_owned));
    }
    for script in scripts {
        match sed_script_write_files(script) {
            Some(files) => writes.paths.extend(files),
            None => writes.unpinned |= script.contains(['w', 'W']),
        }
    }
    writes
}

/// A sed address: a line number (`N`, `first~step`), `$`, or `/regex/` / `\cregexc`, with `I`/`M` flags.
fn sed_address(s: &[char], i: &mut usize) -> Option<()> {
    match s.get(*i) {
        Some(c) if c.is_ascii_digit() => {
            while s.get(*i).is_some_and(char::is_ascii_digit) {
                *i += 1;
            }
            if s.get(*i) == Some(&'~') {
                *i += 1;
                while s.get(*i).is_some_and(char::is_ascii_digit) {
                    *i += 1;
                }
            }
        }
        Some('$') => *i += 1,
        Some('/') => {
            *i += 1;
            sed_delimited(s, i, '/')?;
        }
        Some('\\') => {
            let delimiter = *s.get(*i + 1)?;
            *i += 2;
            sed_delimited(s, i, delimiter)?;
        }
        _ => return Some(()),
    }
    while matches!(s.get(*i), Some('I' | 'M')) {
        *i += 1;
    }
    Some(())
}

/// Skip to just past the next unescaped `delimiter`; a raw newline or the end of the script is a parse failure.
fn sed_delimited(s: &[char], i: &mut usize, delimiter: char) -> Option<()> {
    while let Some(&c) = s.get(*i) {
        *i += 1;
        if c == '\\' {
            *i += 1;
        } else if c == delimiter {
            return Some(());
        } else if c == '\n' {
            return None;
        }
    }
    None
}

/// The files a sed script writes (`w`, `W`, `s///w`); `None` when it cannot be parsed.
fn sed_script_write_files(script: &str) -> Option<Vec<String>> {
    let s: Vec<char> = script.chars().collect();
    let mut i = 0;
    let mut files = Vec::new();
    let skip_blanks = |i: &mut usize| {
        while matches!(s.get(*i), Some(' ' | '\t')) {
            *i += 1;
        }
    };
    let rest_of_line = |i: &mut usize| -> String {
        let start = *i;
        while s.get(*i).is_some_and(|c| *c != '\n') {
            *i += 1;
        }
        s[start..*i].iter().collect()
    };
    let until = |i: &mut usize, stops: &[char]| {
        while s.get(*i).is_some_and(|c| *c != '\n' && !stops.contains(c)) {
            *i += 1;
        }
    };
    loop {
        while s.get(i).is_some_and(|c| c.is_whitespace() || *c == ';') {
            i += 1;
        }
        let Some(&first) = s.get(i) else {
            return Some(files);
        };
        if first == '#' {
            rest_of_line(&mut i);
            continue;
        }
        sed_address(&s, &mut i)?;
        skip_blanks(&mut i);
        if s.get(i) == Some(&',') {
            i += 1;
            skip_blanks(&mut i);
            if matches!(s.get(i), Some('+' | '~')) {
                i += 1;
                while s.get(i).is_some_and(char::is_ascii_digit) {
                    i += 1;
                }
            } else {
                sed_address(&s, &mut i)?;
            }
            skip_blanks(&mut i);
        }
        while s.get(i) == Some(&'!') {
            i += 1;
            skip_blanks(&mut i);
        }
        let command = *s.get(i)?;
        i += 1;
        match command {
            '{' | '}' | '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'p' | 'P' | 'x' | 'z' | 'F' => {}
            'l' | 'L' | 'q' | 'Q' => {
                skip_blanks(&mut i);
                while s.get(i).is_some_and(char::is_ascii_digit) {
                    i += 1;
                }
            }
            ':' | 'v' => until(&mut i, &[';']),
            'b' | 't' | 'T' => until(&mut i, &[';', '}']),
            'r' | 'R' | 'e' => {
                rest_of_line(&mut i);
            }
            'a' | 'i' | 'c' => {
                // Text to the end of the line; a line ending in an odd run of backslashes continues on the next.
                loop {
                    let line = rest_of_line(&mut i);
                    let trailing = line.chars().rev().take_while(|c| *c == '\\').count();
                    if trailing % 2 == 1 && i < s.len() {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            'w' | 'W' => {
                skip_blanks(&mut i);
                let file = rest_of_line(&mut i);
                if file.is_empty() {
                    return None;
                }
                files.push(file);
            }
            's' | 'y' => {
                let delimiter = *s.get(i)?;
                if matches!(delimiter, '\n' | '\\') {
                    return None;
                }
                i += 1;
                sed_delimited(&s, &mut i, delimiter)?;
                sed_delimited(&s, &mut i, delimiter)?;
                if command == 's' {
                    while let Some(&flag) = s.get(i) {
                        if flag == 'w' {
                            i += 1;
                            skip_blanks(&mut i);
                            let file = rest_of_line(&mut i);
                            if file.is_empty() {
                                return None;
                            }
                            files.push(file);
                            break;
                        }
                        if !(flag.is_ascii_digit() || "gpiImMe".contains(flag)) {
                            break;
                        }
                        i += 1;
                    }
                }
            }
            _ => return None,
        }
    }
}

/// A literal `print … > "FILE"` / `printf … >> "FILE"` in an awk program (P166 Grok r5 sweep). awk is an interpreter
/// (the interpreter-limit class), so this is a tripwire for the plain case: it feeds only the protected-target check,
/// never the `FileWrite` floor, because `>` is also awk's comparison operator.
fn awk_literal_redirects(inner: &[String]) -> Vec<String> {
    const TAKES_VALUE: &str = "Ffvile";
    let args = inner.get(1..).unwrap_or_default();
    let (mut programs, mut program_file, mut operands, mut i) = (Vec::new(), false, Vec::new(), 0);
    while i < args.len() {
        let word = &args[i];
        i += 1;
        if word == "--" {
            operands.extend(args[i..].iter().map(String::as_str));
            break;
        }
        if word == "-" || !word.starts_with('-') {
            operands.push(word.as_str());
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long_option(long, args, &mut i, &["file", "source", "assign", "field-separator", "include", "load"]);
            match name {
                "source" => programs.extend(value),
                "file" => program_file = true,
                _ => {}
            }
            continue;
        }
        let cluster = &word[1..];
        if let Some(option) = cluster.chars().next()
            && TAKES_VALUE.contains(option)
        {
            let value = short_option_value(cluster, 0, args, &mut i);
            match option {
                'e' => programs.extend(value),
                'f' => program_file = true,
                _ => {}
            }
        }
    }
    if programs.is_empty() && !program_file {
        programs.extend(operands.first().copied());
    }
    programs.into_iter().flat_map(awk_print_redirect_files).collect()
}

fn awk_print_redirect_files(program: &str) -> Vec<String> {
    let c: Vec<char> = program.chars().collect();
    let mut files = Vec::new();
    let (mut i, mut in_print, mut depth) = (0, false, 0i32);
    let read_string = |i: &mut usize| -> String {
        // `c[*i]` is the opening quote.
        *i += 1;
        let start = *i;
        while let Some(&ch) = c.get(*i) {
            if ch == '\\' {
                *i += 2;
                continue;
            }
            if ch == '"' {
                break;
            }
            *i += 1;
        }
        let text: String = c[start..(*i).min(c.len())].iter().collect();
        *i += 1;
        text
    };
    while let Some(&ch) = c.get(i) {
        let at_word = i == 0 || !c[i - 1].is_ascii_alphanumeric() && c[i - 1] != '_';
        if ch == '"' {
            read_string(&mut i);
            continue;
        }
        if at_word && !in_print {
            let rest: String = c[i..].iter().take(7).collect();
            for keyword in ["printf", "print"] {
                if rest.starts_with(keyword)
                    && !rest[keyword.len()..]
                        .chars()
                        .next()
                        .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_')
                {
                    in_print = true;
                    depth = 0;
                    i += keyword.len();
                    break;
                }
            }
            if in_print {
                continue;
            }
        }
        if in_print {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ';' | '\n' | '}' | '|' if depth <= 0 => in_print = false,
                '>' if depth <= 0 => {
                    i += 1;
                    if c.get(i) == Some(&'>') {
                        i += 1;
                    }
                    while matches!(c.get(i), Some(' ' | '\t')) {
                        i += 1;
                    }
                    if c.get(i) == Some(&'"') {
                        files.push(read_string(&mut i));
                    }
                    in_print = false;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }
    files
}

/// Output files named by a flag of a compiler, linker, converter or decoder (P166 Grok r5 sweep): `-o FILE` for the C
/// family, `as`/`ld`/`nasm`/`strip`/`swiftc`, `iconv`, `uudecode`, `pandoc`, `dot`, `base64`; `openssl … -out FILE`;
/// `xxd`'s second operand. Mirrors the existing `rustc`/`go -o` writes, so `cc -o .git/hooks/pre-commit x.c` is seen.
fn flag_output_writes(program: &str, inner: &[String]) -> Vec<String> {
    let c_family = ["gcc", "g++", "clang", "clang++", "cc", "c++"].iter().any(|name| {
        program == *name
            || program.ends_with(&format!("-{name}"))
            || program
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('-'))
                .is_some_and(|version| !version.is_empty() && version.chars().all(|c| c.is_ascii_digit() || c == '.'))
    });
    let output_flag = c_family
        || matches!(
            program,
            "tcc" | "swiftc" | "nasm" | "yasm" | "as" | "ld" | "ld.lld" | "ld64.lld" | "ld.gold" | "ld.bfd" | "lld"
                | "strip" | "iconv" | "uudecode" | "pandoc" | "dot" | "base64"
        );
    if output_flag {
        return simple_output_flag_values(inner)
            .filter(|output| *output != "-")
            .map(str::to_owned)
            .collect();
    }
    match program {
        "openssl" => inner
            .iter()
            .enumerate()
            .filter(|(_, word)| *word == "-out")
            .filter_map(|(i, _)| inner.get(i + 1).cloned())
            .collect(),
        "xxd" => {
            const TAKES_VALUE: &str = "cglnoRs";
            let mut operands = Vec::new();
            let mut i = 1;
            while let Some(word) = inner.get(i) {
                i += 1;
                if word == "-" || !word.starts_with('-') {
                    operands.push(word.clone());
                } else if word[1..].chars().next().is_some_and(|option| TAKES_VALUE.contains(option))
                    && word.len() == 2
                {
                    i += 1;
                }
            }
            operands.into_iter().nth(1).filter(|output| output != "-").into_iter().collect()
        }
        // P166 r6 sweep: editors and in-place filters write each file operand; FIFO/node makers and `rename` create or
        // move the names they are given; `mogrify` rewrites its images in place.
        "sponge" | "ed" | "ex" | "vi" | "vim" | "nvim" | "emacs" | "nano" | "mkfifo" | "mknod" | "rename" | "mogrify" => {
            shell_file_candidates(inner).into_iter().map(str::to_owned).collect()
        }
        // `zip ARCHIVE FILE…` writes its first operand.
        "zip" => shell_file_candidates(inner).into_iter().take(1).map(str::to_owned).collect(),
        // The output file is the last word (`ffmpeg … OUT`, `convert IN… OUT`).
        // P166 r7: ImageMagick `-write FILE` is an output wherever it stands; the rest of the outputs are caught by the
        // class tripwire ([`tripwire::tripwire`]).
        "ffmpeg" | "convert" | "magick" => {
            let mut outputs: Vec<String> = inner
                .last()
                .filter(|last| inner.len() > 1 && !last.starts_with('-') && *last != "-")
                .map(|last| vec![last.clone()])
                .unwrap_or_default();
            outputs.extend(
                inner
                    .windows(2)
                    .filter(|pair| pair[0] == "-write")
                    .map(|pair| pair[1].clone()),
            );
            outputs
        }
        // `docker|podman|kubectl cp SRC DEST`: a DEST without `host:` is a local file.
        "docker" | "podman" | "kubectl" if inner.get(1).is_some_and(|word| word == "cp") => shell_file_candidates(inner)
            .into_iter()
            .skip(1)
            .last()
            .filter(|dest| !dest.contains(':'))
            .map(str::to_owned)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// `--output=F`, `-oF`, `-o F` and `--output F` (compilers, linkers and converters: no short-option clusters).
fn simple_output_flag_values(words: &[String]) -> impl Iterator<Item = &str> {
    words.iter().enumerate().filter_map(|(i, token)| {
        token
            .strip_prefix("--output=")
            .or_else(|| token.strip_prefix("-o").filter(|value| !value.is_empty()))
            .or_else(|| {
                (token == "--output" || token == "-o")
                    .then(|| words.get(i + 1).map(String::as_str))
                    .flatten()
            })
    })
}

/// The parts of a `find` that write: `-exec`/`-execdir`/`-ok`/`-okdir` commands (each up to its `;` or `+`), and the
/// `-fprint`/`-fprint0`/`-fls`/`-fprintf` output files.
fn find_parts(inner: &[String]) -> (Vec<&[String]>, Vec<&str>) {
    let (mut commands, mut files, mut i) = (Vec::new(), Vec::new(), 1);
    while let Some(word) = inner.get(i) {
        i += 1;
        match word.as_str() {
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                let start = i;
                while inner.get(i).is_some_and(|word| word != ";" && word != "+") {
                    i += 1;
                }
                commands.push(&inner[start..i.min(inner.len())]);
                i += 1;
            }
            "-fprint" | "-fprint0" | "-fls" => {
                files.extend(inner.get(i).map(String::as_str));
                i += 1;
            }
            "-fprintf" => {
                files.extend(inner.get(i).map(String::as_str));
                i += 2;
            }
            _ => {}
        }
    }
    (commands, files)
}

/// The command `xargs` runs (after its options), `None` for the default `echo`.
fn xargs_command(inner: &[String]) -> Option<&[String]> {
    const TAKES_VALUE: &str = "aEdILnPRsJS";
    const LONG_WITH_VALUE: &[&str] = &[
        "arg-file", "delimiter", "max-args", "max-procs", "process-slot-var", "max-chars",
    ];
    let mut i = 1;
    while let Some(word) = inner.get(i) {
        if word == "--" {
            i += 1;
            break;
        }
        if word == "-" || !word.starts_with('-') {
            break;
        }
        i += 1;
        if let Some(long) = word.strip_prefix("--") {
            long_option(long, inner, &mut i, LONG_WITH_VALUE);
            continue;
        }
        let cluster = &word[1..];
        for (at, option) in cluster.char_indices() {
            // `-e[EOF]`, `-i[REPLACE]`, `-l[MAX]` take only a glued value.
            if matches!(option, 'e' | 'i' | 'l') {
                break;
            }
            if TAKES_VALUE.contains(option) {
                short_option_value(cluster, at, inner, &mut i);
                break;
            }
        }
    }
    inner.get(i..).filter(|command| !command.is_empty())
}

/// Commands `xargs`/`find -exec` run with names the command line does not show (P166 Grok r5 sweep).
fn launched_commands<'a>(program: &str, inner: &'a [String]) -> Vec<&'a [String]> {
    match program {
        "xargs" => xargs_command(inner).into_iter().collect(),
        "find" => find_parts(inner).0,
        _ => Vec::new(),
    }
}

/// Placeholder for a name `xargs` appends or `find` substitutes; a NUL never comes from a real shell word.
const LAUNCHED_NAME_PROBE: &str = "\0launched-name";

/// Whether a command launched with unknown names writes a file: it writes something once a name is appended. Deleting
/// programs are excluded (a deletion plants nothing), as are reads.
fn launched_command_writes(command: &[String], depth: usize, file_write_only: bool) -> bool {
    let peel = peel_write_command(command);
    let Some(program) = peel.words.first().map(|word| shell_program_name(word).to_ascii_lowercase()) else {
        return false;
    };
    if matches!(program.as_str(), "rm" | "rmdir" | "unlink" | "shred") {
        return false;
    }
    let mut probe = command.to_vec();
    probe.push(LAUNCHED_NAME_PROBE.to_owned());
    if file_write_only {
        return !command_words_write_paths_depth(&probe, depth).is_empty();
    }
    let shell_words: Vec<ShellWord<'_>> = peel.words.iter().map(ShellWord::from).collect();
    matches!(shell_dash_c_script(&shell_words), InlineShellScript::Untrusted)
        || command_targets(&probe, depth, &CommandExtras::default()).has_writes()
}

/// Write paths from a SINGLE already-split command's words (no redirects; the caller handles those at the tree level).
/// Reused both per parsed command and to re-check the inner command of a package-manager launcher (`uv run`, `npm exec`, ...).
/// The outer program name would hide those inner writes.
pub(crate) fn command_words_write_paths(words: &[String]) -> Vec<String> {
    command_words_write_paths_depth(words, MAX_INLINE_SHELL_DEPTH)
}

fn command_words_write_paths_depth(words: &[String], depth: usize) -> Vec<String> {
    // P166 Grok r5: `sudo`/`command`/`exec`/`nohup`/… are peeled too, and a launcher's own output (`time -o`) counts.
    let peel = peel_write_command(words);
    let inner = peel.words;
    let mut out: Vec<String> = peel.writes.iter().map(|path| (*path).to_owned()).collect();
    let Some(program) = inner.first().map(|w| shell_program_name(w)) else {
        return out;
    };
    let program = program.to_ascii_lowercase();

    // Flag-named write operands (`dd of=`, `sort`/`go`/`rustc -o`, `git --output`).
    for (path, mode) in special_file_operands(&program, inner) {
        if matches!(mode, ShellFileMode::Write) {
            out.push(path);
        }
    }
    // P166 Grok r5 sweep: compiler/converter `-o`, `openssl -out`, `xxd` output operand.
    out.extend(flag_output_writes(&program, inner));
    // P166 Grok r5 sweep: `find -fprint FILE`, and what `xargs`/`find -exec` run. Names they append or substitute are
    // unknown, so a command that writes once a name is appended writes somewhere (`.`).
    if program == "find" {
        out.extend(find_parts(inner).1.into_iter().map(str::to_owned));
    }
    if depth > 0 {
        for command in launched_commands(&program, inner) {
            out.extend(command_words_write_paths_depth(command, depth - 1));
            if launched_command_writes(command, depth - 1, true) {
                out.push(".".to_owned());
            }
        }
    }
    // P166 Grok r4/r5: archive extraction/creation, sync destinations, in-place edits, patch/scp/pax/curl/wget/split,
    // decompressors and `sed w`.
    if let Some(writes) = tool_writes(&program, inner) {
        out.extend(writes.paths);
        out.extend(writes.generated);
        if writes.unpinned && out.is_empty() {
            out.push(".".to_owned());
        }
        return out;
    }
    // Path-moving destinations (`cp`/`mv`/`ln`/`install` dest; `rm`/`touch`/…; `uniq` output operand)
    if let Some(operands) = shell_path_command_operands(&program, inner) {
        for (path, mode) in operands {
            if matches!(mode, ShellFileMode::Write) {
                out.push(path.to_owned());
            }
        }
        return out;
    }
    // Named-argument writers (`tee`/`truncate`/...) and in-place `sed -i`, which rewrites each file operand
    let writes_operands = matches!(shell_file_mode(&program), Some(ShellFileMode::Write))
        || (program == "sed" && shell_sed_in_place(inner));
    if writes_operands {
        for token in shell_file_candidates(inner) {
            out.push(token.to_owned());
        }
    }
    out
}

/// Every path a shell command WRITES, from an ALREADY-PARSED tree so a caller that already parsed `src` shares the one parse.
/// Output redirects plus the per-command writers from [`command_words_write_paths`]. No safe-sink filtering; the caller decides.
pub(crate) fn command_write_paths_in_tree(root: Node<'_>, src: &str) -> Vec<String> {
    let split = command_write_paths_split(root, src);
    let mut out = split.redirect_paths;
    out.extend(split.word_paths);
    out
}

/// [`command_write_paths_in_tree`] split by provenance: redirect targets (`> f`, `>> f`) vs command-word operands (`touch f`, `sed -i`).
/// Redirect targets are invisible to allow-rule word matching, while command words are what a rule matches.
/// The distinction decides whether a narrow allow rule can vouch for the write.
pub(crate) struct WritePathsSplit {
    pub(crate) redirect_paths: Vec<String>,
    /// A write redirect had no extractable target (`> $OUT`, `> "$(…)"`).
    /// Fail-closed signal: the write exists but nothing can vouch for it.
    pub(crate) unextracted_write_redirect: bool,
    pub(crate) word_paths: Vec<String>,
    /// A command rewrites unspecified files of the working tree (`git checkout main`, `git pull`, `git stash pop`): the
    /// ordinary FileWrite floor, not a protected-path hit (P166 r8B).
    pub(crate) worktree_rewrite: bool,
}

pub(crate) fn command_write_paths_split(root: Node<'_>, src: &str) -> WritePathsSplit {
    // Output redirects (`> f`, `>> f`); fd-dups/heredocs are already skipped.
    let mut redirect_paths = Vec::new();
    let mut unextracted_write_redirect = false;
    for r in shell_redirect_targets(root, src) {
        if matches!(r.mode, ShellFileMode::Write) {
            match r.path {
                Some(path) => redirect_paths.push(path),
                None => unextracted_write_redirect = true,
            }
        }
    }
    // Per-command writers, after peeling env/timeout/... wrappers.
    let mut word_paths = Vec::new();
    let mut worktree_rewrite = false;
    for invocation in shell_command_invocations(root, src) {
        let words = InvocationSlice {
            words: &invocation.words,
        }
        .literal_words();
        word_paths.extend(command_words_write_paths(&words));
        worktree_rewrite |= git_words_rewrite_worktree(&words);
    }
    WritePathsSplit {
        redirect_paths,
        unextracted_write_redirect,
        word_paths,
        worktree_rewrite,
    }
}

/// A `git` command whose verb rewrites working-tree files it does not name: a branch switch, `pull`, `merge`,
/// `rebase`, `stash pop/apply`, `reset --hard`, `clean`, `rm`, `apply`, `am`, ... (P166 r8B, Grok r7 MEDIUM 1). It gets
/// the ordinary FileWrite floor. Whether the other branch's tree holds a protected file is not knowable without
/// running git, so that residual stays outside a path-naming floor.
pub(crate) fn git_words_rewrite_worktree(words: &[String]) -> bool {
    let inner = peel_write_command(words).words;
    if inner.first().map(|word| shell_program_name(word).to_ascii_lowercase()).as_deref() != Some("git") {
        return false;
    }
    let Some(verb_at) = git_verb_index(inner) else {
        return false;
    };
    let args = &inner[verb_at + 1..];
    let has = |names: &[&str]| args.iter().any(|arg| names.contains(&arg.as_str()));
    match inner[verb_at].as_str() {
        "checkout" | "switch" | "merge" | "pull" | "rebase" | "cherry-pick" | "revert" | "am" | "checkout-index"
        | "clone" | "clean" | "rm" | "sparse-checkout" => true,
        "reset" => has(&["--hard", "--merge", "--keep"]),
        "restore" => !has(&["--staged", "-S"]) || has(&["--worktree", "-W"]),
        "stash" => !matches!(
            args.iter().find(|arg| !arg.starts_with('-')).map(String::as_str),
            Some("list" | "show" | "drop" | "clear" | "create" | "store")
        ),
        "apply" => !has(&["--check", "--stat", "--numstat", "--summary", "--cached"]) || has(&["--apply", "--index"]),
        "read-tree" => has(&["-u"]),
        "worktree" => args.first().map(String::as_str) == Some("add"),
        "submodule" => matches!(args.first().map(String::as_str), Some("update" | "add")),
        "bisect" => !matches!(args.first().map(String::as_str), Some("log" | "visualize" | "view" | "terms" | "help")),
        _ => false,
    }
}

/// The creation set, shared by the write-path classifier and the auto-allow so they can't drift.
pub(crate) fn is_creation_program(program: &str) -> bool {
    matches!(program, "mkdir" | "touch")
}

/// The `Create`-mode operands that [`command_words_write_paths`] omits.
pub(crate) fn command_words_creation_paths(words: &[String]) -> Vec<String> {
    let inner = peel_write_command(words).words;
    let Some(program) = inner.first().map(|w| shell_program_name(w)) else {
        return Vec::new();
    };
    shell_path_command_operands(&program.to_ascii_lowercase(), inner)
        .into_iter()
        .flatten()
        .filter(|(_, mode)| matches!(mode, ShellFileMode::Create))
        .map(|(path, _)| path.to_owned())
        .collect()
}

/// What a directory-destination operand of `cp`/`mv`/`ln`/`install` writes (P166/S5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DestinationKind {
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
}

/// One directory-destination write: the path, its kind and, for [`DestinationKind::CopiedTree`], the source operand.
type DestinationWrite = (String, DestinationKind, Option<String>);

/// GNU `cp` long options (coreutils 9.4), for abbreviated `--parents`.
const CP_LONG_OPTIONS: [&str; 30] = [
    "archive", "attributes-only", "backup", "context", "copy-contents", "debug", "dereference", "force",
    "interactive", "keep-directory-symlink", "link", "no-clobber", "no-dereference", "no-preserve",
    "no-target-directory", "one-file-system", "parents", "preserve", "recursive", "reflink",
    "remove-destination", "sparse", "strip-trailing-slashes", "suffix", "symbolic-link", "target-directory",
    "update", "verbose", "help", "version",
];

/// GNU `install` long options (coreutils 9.4), for abbreviated `--directory`.
const INSTALL_LONG_OPTIONS: [&str; 18] = [
    "backup", "compare", "context", "debug", "directory", "group", "mode", "no-target-directory", "owner",
    "preserve-context", "preserve-timestamps", "strip", "strip-program", "suffix", "target-directory", "verbose",
    "help", "version",
];

/// Whether the long option `name` (no `--`, no `=value`) is `want` by getopt's unique-prefix rule, or is an
/// ambiguous prefix that could be (fails closed).
fn long_option_may_be(name: &str, table: &[&'static str], want: &str) -> bool {
    match unique_long_option(name, table) {
        Some(found) => found == want,
        None => !name.is_empty() && want.starts_with(name),
    }
}

/// `cp --parents` (any unique prefix; an ambiguous prefix counts): sources keep their path under the directory.
fn cp_uses_parents(inner: &[String]) -> bool {
    inner.iter().skip(1).take_while(|w| *w != "--").any(|word| {
        word.strip_prefix("--")
            .is_some_and(|long| long_option_may_be(long.split_once('=').map_or(long, |(n, _)| n), &CP_LONG_OPTIONS, "parents"))
    })
}

/// `install -d` / `--directory` (any unique prefix; an ambiguous prefix counts): every operand is a directory made.
fn install_makes_directories(inner: &[String]) -> bool {
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
fn target_directory_operands<'a>(program: &str, inner: &'a [String]) -> Vec<&'a str> {
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
fn cp_follows_links(inner: &[String]) -> bool {
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
fn rsync_operands(inner: &[String]) -> (Vec<&str>, bool) {
    const LONG_WITH_VALUE: &[&str] = &[
        "rsh", "rsync-path", "exclude", "include", "exclude-from", "include-from", "files-from", "filter",
        "temp-dir", "partial-dir", "backup-dir", "suffix", "compare-dest", "copy-dest", "link-dest", "chmod",
        "chown", "usermap", "groupmap", "max-size", "min-size", "bwlimit", "timeout", "contimeout", "port",
        "block-size", "password-file", "log-file", "log-file-format", "out-format", "remote-option", "iconv",
        "skip-compress", "max-delete", "modify-window", "sockopts", "outbuf", "info", "debug", "stop-after",
        "stop-at", "checksum-choice", "compress-choice", "compress-level", "address", "write-batch",
        "only-write-batch", "read-batch", "protocol", "checksum-seed", "max-alloc",
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
fn split_host_path(operand: &str) -> Option<(&str, &str)> {
    // An optional `user@` prefix (no `:` or `/` inside) may precede a bracketed IPv6 host.
    let user_len = operand
        .split_once('@')
        .filter(|(user, _)| !user.contains([':', '/', '[']))
        .map_or(0, |(user, _)| user.len() + 1);
    if let Some(rest) = operand[user_len..].strip_prefix('[') {
        let (inside, path) = rest.split_once("]:")?;
        return (!inside.is_empty() && !inside.contains('/')).then_some((&operand[..user_len + inside.len() + 2], path));
    }
    operand.split_once(':').filter(|(host, _)| !host.is_empty() && !host.contains('/'))
}

/// What an scp/rsync operand is: not a host operand at all, or a host operand with the path judged (P166 r12 class
/// rule: the PATH part of EVERY destination is judged whatever the host; nothing resolves or classifies hosts).
enum Operand {
    Plain,
    Local(String),
}

/// The path to judge for the path part of a host operand: absolute stays; a relative one (or none) is relative to the
/// remote home, judged as `~/path`; a one-letter host is a drive letter (`c:.mcp.json`): a local path.
fn host_operand_path(host: &str, path: &str) -> String {
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
fn parse_uri_operand(operand: &str) -> Option<Operand> {
    let (scheme, rest) = operand.split_once("://")?;
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic()) || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return None;
    }
    let end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = if authority.starts_with('[') {
        &authority[..authority.find(']')? + 1]
    } else {
        &authority[..authority.find(':').unwrap_or(authority.len())]
    };
    // `scp://host/x` is home-relative (`scp://host//x` is absolute); every other scheme's path is absolute as given.
    let path = if scheme.eq_ignore_ascii_case("scp") { path.strip_prefix('/').unwrap_or(path) } else { path };
    Some(Operand::Local(host_operand_path(host, path)))
}

fn parse_operand(operand: &str) -> Operand {
    if operand.contains("://") {
        // A URI that does not parse is judged whole, as a local path.
        return parse_uri_operand(operand).unwrap_or_else(|| Operand::Local(operand.to_owned()));
    }
    match split_host_path(operand) {
        None => Operand::Plain,
        // rsync daemon `host::module/path`: the landing place is unknowable, judge the whole word.
        Some((_, path)) if path.starts_with(':') => Operand::Local(operand.to_owned()),
        Some((host, path)) => Operand::Local(host_operand_path(host.rsplit_once('@').map_or(host, |(_, h)| h), path)),
    }
}

/// `host:path` syntax, local or not (a source that lands unknown names, or one that is not a local file).
fn is_host_operand(operand: &str) -> bool {
    !matches!(parse_operand(operand), Operand::Plain)
}

/// The path to judge for an operand: the path part of a host operand, else the operand itself.
fn operand_local_path(operand: &str) -> String {
    match parse_operand(operand) {
        Operand::Local(path) => path,
        Operand::Plain => operand.to_owned(),
    }
}

/// P166 r11 rule 4(b): whether an undecodable word sits among the global options of a `git` command (after the `git`
/// word, before its subcommand). It could be the value of `-C`, `--git-dir`, `--work-tree` or `--exec-path`, so the
/// directory the command runs in is unknown.
fn git_global_option_untrusted(words: &[InvocationWord]) -> bool {
    let Some(at) = words
        .iter()
        .position(|word| matches!(word, InvocationWord::Literal(w) if shell_program_name(w) == "git"))
    else {
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
enum TildeWord<'a> {
    NotTilde,
    Home,
    Cwd(&'a str),
    Unknown,
}

fn tilde_word(word: &str) -> TildeWord<'_> {
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
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
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
            let name = Path::new(home.trim_end_matches('/')).file_name()?.to_str()?.to_owned();
            (!name.is_empty()).then_some(name)
        })
}

/// P166 r13 rule 3: a current-user `~name` / `~name/...` is spelled `~` / `~/...`, the form every later step
/// resolves (`resolve_model_path` expands only `~` and `~/`). Every other word is returned as given.
fn home_spelling(word: &str) -> String {
    if let Some(rest) = word.strip_prefix('~') {
        let (name, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        if !name.is_empty() && matches!(tilde_word(word), TildeWord::Home) {
            return format!("~{tail}");
        }
    }
    word.to_owned()
}

/// `ditto`'s operands (the last is the destination); `--arch`/`--bom` take a value.
fn ditto_operands(inner: &[String]) -> Vec<&str> {
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
fn command_words_destination_writes(words: &[String]) -> (Vec<DestinationWrite>, bool) {
    let inner = peel_write_command(words).words;
    let Some(program) = inner.first().map(|w| shell_program_name(w).to_ascii_lowercase()) else {
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
            operand_hosts = operands.iter().map(|operand| is_host_operand(operand)).collect();
            rsync_paths = operands.into_iter().map(operand_local_path).collect();
            (Vec::new(), rsync_paths.iter().map(String::as_str).collect(), follow)
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
                out.push((Path::new(dir).join(kept).to_string_lossy().into_owned(), via_kind(dir, from_host), None));
            }
        }
        if let Some(name) = Path::new(source.trim_end_matches('/')).file_name() {
            out.push((Path::new(dir).join(name).to_string_lossy().into_owned(), via_kind(dir, from_host), None));
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
                into(dest, source, operand_hosts.get(i).copied().unwrap_or(false), &mut out);
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
fn scp_destination_writes(inner: &[String]) -> Vec<DestinationWrite> {
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
fn pax_destination_writes(inner: &[String]) -> Vec<DestinationWrite> {
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
        out.push((landing.to_string_lossy().into_owned(), DestinationKind::ViaDirectory, None));
        let tree_dest = match Path::new(source).parent() {
            Some(parent) if relative && !parent.as_os_str().is_empty() => Path::new(dest).join(parent),
            _ => Path::new(dest).to_path_buf(),
        };
        out.push((
            tree_dest.to_string_lossy().into_owned(),
            DestinationKind::CopiedTree { follow_links: pax.follow },
            Some((*source).to_owned()),
        ));
    }
    out
}

/// One write target of a shell script and where it runs (P166/S5).
#[derive(Clone, Debug)]
struct ShellWriteTarget {
    path: String,
    at: usize,
    scope: ExecutionScope,
    /// `None` for a direct write (redirect, writer operand, `mkdir`/`touch`).
    destination: Option<DestinationKind>,
    /// The copied source of a [`DestinationKind::CopiedTree`].
    source: Option<String>,
}

/// A `cd`/`pushd`/`popd` and its literal target; `None` when the new cwd cannot be pinned (`cd -`, `cd "$X"`, `popd`).
#[derive(Clone, Debug)]
struct ShellCwdChange {
    at: usize,
    scope: ExecutionScope,
    target: Option<String>,
}

/// Every write target of a parsed script plus its cwd changes, for the protected-target floor (P166/S5).
#[derive(Clone, Debug, Default)]
pub(crate) struct ShellWriteFacts {
    targets: Vec<ShellWriteTarget>,
    cwd_changes: Vec<ShellCwdChange>,
    /// Literal `sh -c`/`bash -c` scripts (P166 Grok r5 sweep), judged in the cwds their invocation can run in.
    nested: Vec<NestedWriteFacts>,
    /// A write redirect whose target is an expansion (`> "$1"`): unknown, which counts only when the script runs with
    /// names `xargs`/`find -exec` supply.
    opaque_write: bool,
    /// Start byte of every `git` command, in script order (P175 part B: lets the branch-switch plan ask whether a
    /// write into the git directory came BEFORE the n-th git command).
    git_starts: Vec<usize>,
    /// Symbolic `ln` commands (P175 part B rounds 2-3): a link made earlier on the same line does not exist yet when
    /// the plan runs, so its target is judged by what it will point at.
    symlinks: Vec<SymlinkFact>,
}

#[derive(Clone, Debug)]
struct SymlinkFact {
    form: LnForm,
    at: usize,
    scope: ExecutionScope,
}

/// The git directory in both spellings: as found (lexically cleaned) and with symlinks resolved.
struct GitDirSpelling<'a> {
    lexical: &'a Path,
    real: &'a Path,
}

impl GitDirSpelling<'_> {
    /// Whether `path` is the git directory or inside it, by spelling or by what it physically is. A path that cannot
    /// be resolved (symlink loop, depth cap, unreadable link) counts: the check only ever adds a prompt to a switch
    /// that already follows a write, so failing closed cannot touch everyday commands.
    fn contains(&self, path: &Path) -> bool {
        lexical_clean(path).starts_with(self.lexical)
            || resolve_kernel_order(path).is_none_or(|real| real.starts_with(self.real))
    }
}

/// An unparsed symbolic `ln`: every word is a possible source and a possible destination (or destination directory),
/// so a word counts when it, or it read from the directory of any other word, is the git directory or inside it.
fn unparsed_ln_hits_git(
    base: &Path,
    words: &[String],
    git: &GitDirSpelling<'_>,
    join: &dyn Fn(&Path, &str) -> std::path::PathBuf,
) -> bool {
    let spelled: Vec<String> = words.iter().filter_map(|word| ln_word_path(word, base)).collect();
    let mut dirs = vec![base.to_path_buf()];
    for word in &spelled {
        let full = join(base, word.trim_end_matches('/'));
        dirs.extend(full.parent().map(Path::to_path_buf));
        dirs.push(full);
    }
    dirs.iter().any(|dir| spelled.iter().any(|word| git.contains(&join(dir, word))))
}

/// Resolve `path` the way the kernel does: each component is resolved (symlinks followed) BEFORE a following `..` is
/// applied, so `deep/../config` with `deep -> .git/objects` is `.git/config`. Folding the `..` lexically first would
/// give `config` in the cwd. `None` (loop, depth cap, unreadable link) is the caller's fail-closed case.
fn resolve_kernel_order(path: &Path) -> Option<std::path::PathBuf> {
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
const LN_LONG_OPTIONS: [&str; 15] = [
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
fn unique_long_option(name: &str, table: &[&'static str]) -> Option<&'static str> {
    if let Some(exact) = table.iter().find(|option| **option == name) {
        return Some(exact);
    }
    let mut matches = table.iter().filter(|option| !name.is_empty() && option.starts_with(name));
    let first = matches.next()?;
    matches.next().is_none().then_some(*first)
}

fn ln_long_option(name: &str) -> Option<&'static str> {
    unique_long_option(name, &LN_LONG_OPTIONS)
}

/// The GNU long options of `cp`, `mv`, `install` and `ln` that start with `t`: only `--target-directory` for each, so
/// every `--t...` prefix is that option. An ambiguous prefix would be treated as a target directory too (fail closed
/// for the write floor); everyday commands do not abbreviate long options, so no new prompt for them.
const T_LONG_OPTIONS: &[&str] = &["target-directory"];

/// Whether the long option `name` (without `--` and without `=value`) may be `--target-directory`.
fn may_be_target_directory(name: &str) -> bool {
    unique_long_option(name, T_LONG_OPTIONS).is_some()
        || (!name.is_empty() && T_LONG_OPTIONS.iter().any(|option| option.starts_with(name)))
}

/// A word of an unparsed `ln` as a path to resolve: `~+/x` is `./x`, `~/x` the home directory; another `~user` is
/// unknown (no path).
fn ln_word_path(word: &str, base: &Path) -> Option<String> {
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
enum LinkSite {
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
enum LnForm {
    Parsed { sources: Vec<String>, site: LinkSite, target_dir: Option<String> },
    /// Every non-flag word and every `--opt=value` value, each a possible source and a possible destination.
    Unparsed { words: Vec<String> },
}

fn names_git_component(word: &str) -> bool {
    Path::new(word).components().any(|part| part.as_os_str() == ".git")
}

/// Parse a symbolic `ln` (`-s`, `--symbolic`, or `s` in a short cluster); `None` for any other command.
fn symlink_operands(words: &[String]) -> Option<LnForm> {
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
                "force" | "no-dereference" | "interactive" | "verbose" | "directory" | "logical" | "physical"
                | "help" | "version" => ok &= value.is_none(),
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
        (None, [sources @ .., dest]) => (sources.to_vec(), LinkSite::Name { dest: dest.clone(), no_target_dir }),
    };
    // `-r` makes the link relative to its own directory: the sources are read from the cwd.
    let site = if relative { LinkSite::Cwd } else { site };
    Some(LnForm::Parsed { sources, site, target_dir: parsed_dir })
}

/// An inline script and where its shell runs.
#[derive(Clone, Debug)]
struct NestedWriteFacts {
    at: usize,
    scope: ExecutionScope,
    facts: ShellWriteFacts,
}

/// The write targets of one command before they are placed in a script: `(path, kind, copied source)`.
type CommandTarget = (String, Option<DestinationKind>, Option<String>);

#[derive(Default)]
struct CommandTargets {
    targets: Vec<CommandTarget>,
    nested: Vec<ShellWriteFacts>,
}

impl CommandTargets {
    fn has_writes(&self) -> bool {
        self.targets
            .iter()
            .any(|target| !matches!(target.1, Some(DestinationKind::Watch | DestinationKind::HookMetadata { .. })))
            || self.nested.iter().any(ShellWriteFacts::has_writes)
    }

    fn unpinned(&mut self) {
        self.targets
            .push((".".to_owned(), Some(DestinationKind::Unpinned), None));
    }
}

/// Every write target of one command (its literal words): redirect-free writer operands, creation operands,
/// directory destinations, the extra writers of [`tool_writes`], git worktree writes, awk's literal print redirects,
/// what `xargs`/`find -exec` run, and literal `sh -c` scripts (parsed, up to `depth` levels).
fn command_targets(words: &[String], depth: usize, extras: &CommandExtras) -> CommandTargets {
    let mut out = CommandTargets::default();
    let peel = peel_write_command(words);
    if peel.opaque {
        out.unpinned();
        return out;
    }
    let inner = peel.words;
    let Some(program) = inner.first().map(|word| shell_program_name(word).to_ascii_lowercase()) else {
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
    if words.iter().any(|word| git_env_assignment_redirects_config(word)) {
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
        out.targets.extend(git.paths.into_iter().map(|path| (path, None, None)));
        out.targets.extend(
            git.watch
                .into_iter()
                .map(|token| (token, Some(DestinationKind::Watch), None)),
        );
        if !git.moves.is_empty() {
            let mv: Vec<String> = std::iter::once("mv".to_owned()).chain(git.moves).collect();
            let (moves, _) = command_words_destination_writes(&mv);
            out.targets
                .extend(shell_file_candidates(&mv).last().map(|dest| ((*dest).to_owned(), None, None)));
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
            word == "--recursive" || (word.starts_with('-') && !word.starts_with("--") && word.contains('R'))
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
                let cluster = word.starts_with('-') && word[1..].chars().all(|c| c.is_ascii_alphabetic());
                if !cluster {
                    out.targets
                        .push((word.clone(), Some(DestinationKind::HookMetadata { recursive }), None));
                }
            }
        }
    }
    if matches!(program.as_str(), "awk" | "gawk" | "mawk" | "nawk") {
        out.targets
            .extend(awk_literal_redirects(inner).into_iter().map(|path| (path, None, None)));
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

    fn from_tree_depth(root: Node<'_>, src: &str, depth: usize) -> Self {
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
                facts.symlinks.push(SymlinkFact { form, at: invocation.start_byte, scope: invocation.scope });
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

    /// Whether the script writes anything (a target, an expansion redirect, or a nested script that does).
    fn has_writes(&self) -> bool {
        self.targets
            .iter()
            .any(|target| !matches!(target.destination, Some(DestinationKind::Watch | DestinationKind::HookMetadata { .. })))
            || self.opaque_write
            || self.nested.iter().any(|nested| nested.facts.has_writes())
    }

    /// The cwds a write at `at` in `scope` can run in: the session cwd and each prefix of the chain of literal `cd`
    /// targets that PRECEDE it in its scope (plus each such target alone, for `cd a || cd b`). A preceding unpinnable
    /// `cd` is `Err(Sensitive)`.
    fn bases(
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
        for change in self
            .cwd_changes
            .iter()
            .filter(|change| change.at <= at && (change.scope == scope || change.scope.contains(scope)))
        {
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
    pub(crate) fn writes_into_git_dir_before(&self, real_cwd: &Path, git_dir: &Path, git_ordinal: usize) -> bool {
        let limit = self.git_starts.get(git_ordinal).copied().unwrap_or(usize::MAX);
        // Both sides are compared physically (symlinks followed, on-disk spelling on a case-insensitive volume) AND
        // lexically. A git dir that cannot be resolved is compared by its lexical spelling only.
        let real_git = resolve_following_symlinks(git_dir).unwrap_or_else(|| git_dir.to_path_buf());
        self.writes_into(real_cwd, &GitDirSpelling { lexical: git_dir, real: &real_git }, limit)
    }

    /// Number of git commands this script has (the planner cross-checks it against its own count).
    pub(crate) fn git_start_count(&self) -> usize {
        self.git_starts.len()
    }

    fn writes_into(&self, real_cwd: &Path, git: &GitDirSpelling<'_>, limit: usize) -> bool {
        let join = |base: &Path, path: &str| {
            let p = Path::new(path);
            if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
        };
        let direct = self.targets.iter().any(|target| {
            if target.at >= limit
                || is_safe_write_sink(&target.path)
                || matches!(
                    target.destination,
                    Some(DestinationKind::Watch | DestinationKind::HookMetadata { .. } | DestinationKind::Unpinned)
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
                            Ok(bases) => bases.iter().any(|base| unparsed_ln_hits_git(base, words, git, &join)),
                        };
                    }
                    LnForm::Parsed { sources, site, target_dir } => (sources, site, target_dir),
                };
                match self.bases(real_cwd, link.at, link.scope, false, &join) {
                    Err(_) => true,
                    // A relative symlink source is read from the directory that holds the new link (never from the
                    // cwd): that is the link's parent, or the destination when it is an existing directory.
                    Ok(bases) => bases.iter().any(|base| {
                        // A link CREATED inside `.git` is a write into it, wherever its text points.
                        if target_dir.as_deref().is_some_and(|dir| {
                            ln_word_path(dir, base).is_some_and(|spelled| git.contains(&join(base, &spelled)))
                        }) {
                            return true;
                        }
                        let dirs: Vec<std::path::PathBuf> = match site {
                            LinkSite::Cwd => vec![base.clone()],
                            LinkSite::Dir(dir) => vec![join(base, dir)],
                            LinkSite::Name { dest, no_target_dir } => {
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
                                ln_word_path(source, base).is_some_and(|spelled| git.contains(&join(dir, &spelled)))
                            })
                        })
                    }),
                }
            })
            || self.nested.iter().any(|nested| {
                nested.at < limit
                    && match self.bases(real_cwd, nested.at, nested.scope, false, &join) {
                        Err(_) => true,
                        Ok(bases) => bases.iter().any(|base| nested.facts.writes_into(base, git, usize::MAX)),
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

    fn protection_in(
        &self,
        real_cwd: &Path,
        resolve: &dyn Fn(&Path, &str) -> std::path::PathBuf,
    ) -> Option<ProtectedEditReason> {
        let direct = self.targets.iter().find_map(|target| {
            if is_safe_write_sink(&target.path) {
                return None;
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
            bases.iter().find_map(|base| {
                let path = resolve(base, &spelled);
                match target.destination {
                    None | Some(DestinationKind::TargetDirectory | DestinationKind::Watch) => {
                        edit_target_protection(&path)
                    }
                    Some(DestinationKind::ViaDirectory) => via_directory_protection(&path),
                    Some(DestinationKind::ViaExistingDirectory) => via_existing_directory_protection(&path),
                    Some(DestinationKind::CopiedTree { follow_links }) => {
                        let source = resolve(base, &home_spelling(target.source.as_deref().unwrap_or_default()));
                        copied_tree_protection(&path, &source, follow_links)
                    }
                    Some(DestinationKind::Unpinned) => Some(ProtectedEditReason::Sensitive),
                    Some(DestinationKind::Pathspec) => pathspec_protection(&path),
                    Some(DestinationKind::HookMetadata { recursive }) => hook_metadata_protection(&path, recursive),
                    Some(DestinationKind::GeneratedNames) => {
                        generated_names_protection(&path, target.path.ends_with('/'))
                    }
                }
            })
        });
        direct.or_else(|| {
            self.nested.iter().find_map(|nested| {
                let bases = match self.bases(real_cwd, nested.at, nested.scope, false, resolve) {
                    Ok(bases) => bases,
                    Err(reason) => return Some(reason),
                };
                bases
                    .iter()
                    .find_map(|base| nested.facts.protection_in(base, resolve))
            })
        })
    }
}

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
fn pathspec_protection(path: &Path) -> Option<ProtectedEditReason> {
    edit_target_protection(path).or_else(|| {
        (!std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_dir()))
            .then_some(ProtectedEditReason::Sensitive)
    })
}

/// [`DestinationKind::HookMetadata`]: only a hook root or git hooks directory (or, recursively, a directory above one).
fn hook_metadata_protection(path: &Path, recursive: bool) -> Option<ProtectedEditReason> {
    let hook = |candidate: &Path| {
        edit_target_protection(candidate)
            .filter(|reason| matches!(reason, ProtectedEditReason::HookRoot | ProtectedEditReason::GitHooks))
    };
    let walk = |path: &Path| -> Option<ProtectedEditReason> {
        // P166 r9: `-R` on a directory inside a `.git` whose subtree can hold a `hooks` directory: `modules`,
        // `modules/<name>` (nested submodules repeat the pair), `worktrees`, `worktrees/<name>`. Lexical only: nothing is
        // walked, so an absent directory is judged the same as a present one.
        let names: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase()).collect();
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
        let inside: &[&str] = if container { &["hooks"] } else { &[".git/hooks", ".fuigo/hooks"] };
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
        walk(&fuigo_paths::normalize_lexically(path)).or_else(|| resolve_following_symlinks(path).and_then(|real| walk(&real)))
    })
}

/// [`DestinationKind::GeneratedNames`]: `spelled_as_dir` is a prefix ending in `/` (names are suffixes in that dir).
fn generated_names_protection(prefix: &Path, spelled_as_dir: bool) -> Option<ProtectedEditReason> {
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
struct GitWrites {
    pathspecs: Vec<String>,
    paths: Vec<String>,
    moves: Vec<String>,
    /// Text judged only by the tripwire (the shell text of a stored `!` alias).
    watch: Vec<String>,
    unpinned: bool,
}

/// A pathspec that names a file literally: no glob, no `:` magic, no escape.
fn literal_pathspec(spec: &str) -> bool {
    !spec.is_empty() && !spec.starts_with(':') && !spec.contains(['*', '?', '[', '\\'])
}

fn git_worktree_writes(inner: &[String]) -> GitWrites {
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
    if verb.is_empty() || !verb.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
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
        "switch" => &["-c", "-C", "--orphan", "--conflict", "--create", "--force-create"],
        "restore" => &["-s", "--source", "--conflict"],
        "stash" => &["-m", "--message"],
        "merge-file" => &["-L"],
        "config" => &["-f", "--file", "--blob", "--type"],
        "am" | "apply" => &["-p", "-C", "--directory", "--include", "--exclude", "--whitespace"],
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
    let has = |names: &[&str]| options.iter().any(|option| names.iter().any(|name| option == name || option.starts_with(&format!("{name}="))));
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
        let words: Vec<String> = std::iter::once("git".to_owned()).chain(inner[i..].iter().cloned()).collect();
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
                    if literal_pathspec(operand) && !matches!(*operand, "." | "..") && !operand.ends_with('/') {
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
            let read_only = has(&["--check", "--stat", "--numstat", "--summary"]) && !has(&["--apply"]);
            let index_only = has(&["--cached"]) && !has(&["--index"]);
            writes.unpinned = !(read_only || index_only);
        }
        "am" | "merge" | "cherry-pick" | "revert" | "rebase" | "clone" | "checkout-index" => {
            writes.unpinned = true;
        }
        "read-tree" => writes.unpinned = has(&["-u"]),
        "bisect" => {
            writes.unpinned =
                !matches!(before.first().copied(), Some("log" | "visualize" | "view" | "terms" | "help"));
        }
        "sparse-checkout" => writes.unpinned = !matches!(before.first().copied(), Some("list") | None),
        "submodule" => writes.unpinned = matches!(before.first().copied(), Some("update" | "add")),
        "worktree" => writes.unpinned = before.first() == Some(&"add"),
        "init" => writes.unpinned = template || has(&["--template"]),
        "mv" => writes.moves = before.iter().chain(&after).map(|operand| (*operand).to_owned()).collect(),
        "merge-file" if !has(&["-p", "--stdout"]) => {
            writes.paths.extend(before.first().map(|current| (*current).to_owned()));
        }
        "config" => {
            let sub = before.first().copied();
            let sub_read = matches!(sub, Some("get" | "list"));
            let reads = sub_read
                || has(&["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--get-color", "--get-colorbool"]);
            let sub_write = matches!(sub, Some("set" | "unset" | "edit" | "rename-section" | "remove-section"));
            let edit = sub == Some("edit") || has(&["-e", "--edit"]);
            let write_flag = has(&[
                "--add", "--unset", "--unset-all", "--replace-all", "--rename-section", "--remove-section", "-e", "--edit",
            ]);
            let file = options
                .windows(2)
                .find(|pair| matches!(pair[0], "-f" | "--file"))
                .map(|pair| pair[1])
                .or_else(|| options.iter().find_map(|option| option.strip_prefix("--file=")));
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
                        "--unset", "--unset-all", "--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
                        "--name-only", "--show-origin",
                    ]);
                if !sets_no_value
                    && let [key, value, ..] = keys
                    && ((key.to_ascii_lowercase().starts_with("alias.") && value.starts_with('!'))
                        || crate::permission::exec_risk::command_valued_config(key, Some(value)))
                {
                    let text: Vec<String> = std::iter::once("alias-text".to_owned())
                        .chain(value.split_whitespace().map(|word| word.trim_matches(['\'', '"', '`', ';']).to_owned()))
                        .collect();
                    writes.watch = tripwire::tripwire("alias-text", &text, &text, &CommandExtras::default()).tokens;
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
            writes.paths.extend(before.get(1).map(|file| (*file).to_owned()));
        }
        _ => {}
    }
    if verb == "clone" && template {
        writes.unpinned = true;
    }
    let glob_dir = moved_dirs.iter().any(|dir| dir.contains(['{', '}', '*', '?', '[', '\\', '$', '`']));
    if branch_switch && glob_dir {
        writes.unpinned = true;
    } else {
        // The directory git is moved into (`-C`, `--git-dir`, `--work-tree`) is itself judged for EVERY verb (P166 r10,
        // Grok r9 M6): `git -C .git/hooks init` is a protected write, `git -C ../other checkout main` is not.
        if moved
            && !branch_switch
            && (writes.unpinned || !writes.pathspecs.is_empty() || !writes.paths.is_empty() || !writes.moves.is_empty())
        {
            writes.unpinned = true;
        }
        writes.paths.extend(moved_dirs);
    }
    writes
}

/// A bare operand that reads as a branch name and could not be a protected file: no leading dot in any component
/// (`.mcp.json`, `.git/hooks`), no alphabetic extension (`mcp.json`, `settings.json`), no glob or revision syntax.
fn branch_like(operand: &str) -> bool {
    if operand.is_empty() || operand.starts_with('/') || operand.ends_with('/') {
        return false;
    }
    let plain = operand
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'));
    let dotted_component = operand.split('/').any(|part| part.is_empty() || part.starts_with('.'));
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
fn git_config_key_redirects_hooks(key: &str) -> bool {
    key.starts_with("core.hookspath") || config_key_pulls_in_include(key)
}

fn config_key_pulls_in_include(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.starts_with("include.") || key.starts_with("includeif.")
}

/// `GIT_CONFIG_*` assignment text (`NAME=value`) that redirects git config: a key or value naming `core.hooksPath`, or a
/// pointer at another global/system config file.
fn git_env_assignment_redirects_config(assignment: &str) -> bool {
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

/// P166 r9: whether any variable assignment in the script (prefix assignment, `export`, `declare`) sets a git
/// environment variable that retargets the repository or names a program git runs (`GIT_DIR=/tmp/evil git commit`).
pub(crate) fn tree_has_git_exec_env_assignment(root: Node<'_>, src: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_assignment"
            && node.utf8_text(src.as_bytes()).is_ok_and(is_git_exec_env_assignment)
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
fn git_config_assignments(root: Node<'_>, src: &str) -> Vec<(usize, ExecutionScope)> {
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
fn via_existing_directory_protection(path: &Path) -> Option<ProtectedEditReason> {
    let dir = path.parent()?;
    if std::fs::metadata(dir).is_ok_and(|metadata| metadata.is_dir()) {
        edit_target_protection(path)
    } else {
        None
    }
}

/// Whether a destination operand's spelling says it is a directory (`dir/`, `.`, `..`, `~`).
fn destination_spelled_as_directory(dest: &str) -> bool {
    dest.ends_with('/') || matches!(dest, "." | ".." | "~") || dest.ends_with("/.") || dest.ends_with("/..")
}

/// The kind of the `DEST/<name>` write of one source: a remote source into a destination not spelled as a directory is
/// judged only when `DEST` really is a directory.
fn via_kind(dest: &str, from_host: bool) -> DestinationKind {
    if from_host && !destination_spelled_as_directory(dest) {
        DestinationKind::ViaExistingDirectory
    } else {
        DestinationKind::ViaDirectory
    }
}

fn via_directory_protection(path: &Path) -> Option<ProtectedEditReason> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return None;
    };
    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => edit_target_protection(path),
        Ok(_) => None,
        // Not there yet (created earlier in the same script): judge the spelling.
        Err(_) => protected_edit_reason(&fuigo_paths::normalize_lexically(&Path::new(dir).join(name))),
    }
}

/// Entries walked in a copied source tree. Past it the copy still prompts (`Sensitive`): an unchecked tree is never
/// allowed silently, so `cp -R node_modules /tmp/bak` under `Bash(cp:*)` or an exact grant asks (receipt R166, round 4).
const MAX_COPIED_TREE_ENTRIES: usize = 10_000;

/// A directory `source` copied or moved to `dest` writes its tree at `dest/<rel>` (a contents copy: GNU `-T`, `SRC/.`,
/// BSD `SRC/`) or at `dest/<source name>/<rel>`. Both are judged for every entry, so a payload carrying `.mcp.json`,
/// `.claude/settings.json` or `.fuigo/` anywhere prompts while an ordinary tree copies freely. A symlinked directory in
/// the tree is copied as a link unless the copy dereferences (`follow_links`: `cp -L`, `rsync -L`), and then its
/// contents are walked too (a link back to an ancestor directory is a cycle and ends there). A file source is covered by the
/// `DEST/<name>` and destination checks; a source that is not there yet adds nothing. A directory that cannot be read
/// or resolved, or a tree over [`MAX_COPIED_TREE_ENTRIES`], prompts.
fn copied_tree_protection(
    dest: &Path,
    source: &Path,
    follow_links: bool,
) -> Option<ProtectedEditReason> {
    if !std::fs::metadata(source).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
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
                protected_edit_reason(&fuigo_paths::normalize_lexically(&prefix.join(&rel_entry)))
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
fn shell_cwd_changes(root: Node<'_>, src: &str) -> Vec<ShellCwdChange> {
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
fn literal_cwd_target(node: Node<'_>, src: &str) -> Option<String> {
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
        [target] if target != "-" && !matches!(tilde_word(target), TildeWord::Unknown) => Some(home_spelling(target)),
        _ => None,
    }
}

/// Safe write sinks that do not touch a real file. Exact match.
pub(crate) fn is_safe_write_sink(path: &str) -> bool {
    matches!(path, "/dev/null" | "/dev/stdout" | "/dev/stderr")
}

/// Why acceptEdits must still prompt for this edit target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedEditReason {
    HookRoot,
    GitHooks,
    Ssh,
    StartupFile,
    Etc,
    FuigoConfig,
    FuigoSandbox,
    ClaudeSettings,
    CursorHooks,
    /// MCP / LSP server config (`mcp.json`, `lsp.json`, `.mcp.json`, `.cursor/mcp.json`, `.claude.json`): names programs Fuigo starts.
    McpConfig,
    /// Fail-closed / unclassified sensitive path; no user copy yet.
    Sensitive,
}

impl ProtectedEditReason {
    pub fn kind(self) -> &'static str {
        match self {
            Self::HookRoot => "hook_root",
            Self::GitHooks => "git_hooks",
            Self::Ssh => "ssh",
            Self::StartupFile => "startup_file",
            Self::Etc => "etc",
            Self::FuigoConfig => "fuigo_config",
            Self::FuigoSandbox => "fuigo_sandbox",
            Self::ClaudeSettings => "claude_settings",
            Self::CursorHooks => "cursor_hooks",
            Self::McpConfig => "mcp_config",
            Self::Sensitive => "sensitive",
        }
    }

    pub fn description(self) -> Option<&'static str> {
        match self {
            Self::HookRoot => Some(
                "Note: This edit contains changes to hooks, which can be executed as code on later sessions without a separate execution approval.",
            ),
            Self::GitHooks => Some(
                "Note: This edit contains changes to Git hooks, which can run automatically on commit, push, or other Git actions without a separate execution approval.",
            ),
            Self::Ssh => Some(
                "Note: This edit contains changes under `.ssh`, which can affect credentials and authentication for future sessions.",
            ),
            Self::StartupFile => Some(
                "Note: This edit contains changes to a shell startup file, which can run automatically in future terminals without a separate execution approval.",
            ),
            Self::Etc => Some(
                "Note: This edit contains changes under `/etc`, which is system configuration and can affect this machine beyond the current project.",
            ),
            Self::FuigoConfig => Some(
                "Note: This edit contains changes to Fuigo config, which can alter permissions, tools, and other behavior in later sessions.",
            ),
            Self::FuigoSandbox => Some(
                "Note: This edit contains changes to the Fuigo sandbox config, which can loosen filesystem and network restrictions on commands.",
            ),
            Self::ClaudeSettings => Some(
                "Note: This edit contains changes to Claude-compatible settings, which can install hooks or change permission mode without a separate execution approval.",
            ),
            Self::CursorHooks => Some(
                "Note: This edit contains changes to Cursor hooks, which can run automatically in later sessions without a separate execution approval.",
            ),
            Self::McpConfig => Some(
                "Note: This edit contains changes to MCP or language-server config, which can start new programs in later sessions without a separate execution approval.",
            ),
            Self::Sensitive => None,
        }
    }
}

/// ACP `_meta` payload for protected-edit prompts (pager reads this for description).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedEditPermission {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ProtectedEditPermission {
    pub fn from_reason(reason: ProtectedEditReason) -> Self {
        Self {
            kind: reason.kind().to_owned(),
            description: reason.description().map(str::to_owned),
        }
    }
}

/// Whether an already-resolved direct edit target needs confirmation, and why.
///
/// The caller uses the edit tools' shared model-path resolver first.
/// This helper preserves its uncollapsed components for physical symlink and `..` resolution.
/// It also checks a separate lexical normalization for traversal aliases.
pub(crate) fn edit_target_protection(path: &Path) -> Option<ProtectedEditReason> {
    if !path.is_absolute() {
        return Some(ProtectedEditReason::Sensitive);
    }
    let lexical = fuigo_paths::normalize_lexically(path);
    if let Some(reason) = protected_edit_reason(&lexical) {
        return Some(reason);
    }
    let Some(resolved) = resolve_following_symlinks(path) else {
        return Some(ProtectedEditReason::Sensitive);
    };
    if let Some(reason) = protected_edit_reason(&resolved) {
        return Some(reason);
    }
    resolved_path_is_within_root(&resolved, Path::new("/etc"))
        .then_some(ProtectedEditReason::Sensitive)
}

/// Whether the (absolute) `path` is a protected edit target by its lexical form alone: no filesystem access, so a
/// large tree listing can be judged cheaply (P166 r13B).
pub(crate) fn lexical_path_is_protected(path: &Path) -> bool {
    protected_edit_reason(&fuigo_paths::normalize_lexically(path)).is_some()
}

fn protected_edit_reason(path: &Path) -> Option<ProtectedEditReason> {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let string_components: Vec<&str> = components.iter().map(String::as_str).collect();
    let file = string_components.last().copied().unwrap_or("");
    const STARTUP_FILES: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
        ".kshrc",
        ".cshrc",
        ".tcshrc",
        ".login",
        ".logout",
        ".inputrc",
        ".xprofile",
    ];

    if protected_fuigo_hook_root(path, &string_components) {
        return Some(ProtectedEditReason::HookRoot);
    }
    if string_components.ends_with(&[".claude", "settings.json"])
        || string_components.ends_with(&[".claude", "settings.local.json"])
    {
        return Some(ProtectedEditReason::ClaudeSettings);
    }
    if string_components.ends_with(&[".cursor", "hooks.json"]) {
        return Some(ProtectedEditReason::CursorHooks);
    }
    if protected_vendor_mcp_config(&string_components) {
        return Some(ProtectedEditReason::McpConfig);
    }
    if protected_git_hooks_path(&string_components) {
        return Some(ProtectedEditReason::GitHooks);
    }
    if string_components.contains(&".ssh") {
        return Some(ProtectedEditReason::Ssh);
    }
    if STARTUP_FILES.contains(&file) {
        return Some(ProtectedEditReason::StartupFile);
    }
    if let Some(reason) = protected_fuigo_config_file(path, &string_components) {
        return Some(reason);
    }
    if let Some(reason) = protected_container_dir(
        path,
        &string_components,
        fuigo_config::user_fuigo_home().as_deref(),
    ) {
        return Some(reason);
    }
    if path == Path::new("/etc") || path.starts_with(Path::new("/etc")) {
        return Some(ProtectedEditReason::Etc);
    }
    None
}

/// Fuigo config files that alter permissions or sandbox restrictions; a silent edit would let the agent loosen its own guardrails.
/// Matched directly inside any `.fuigo` dir (user-global default and workspace overlays) and directly under a custom `$FUIGO_HOME`.
/// A custom home has no `.fuigo` component, so the component match alone cannot see it.
fn protected_fuigo_config_file(path: &Path, components: &[&str]) -> Option<ProtectedEditReason> {
    protected_fuigo_config_file_with_home(
        path,
        components,
        fuigo_config::user_fuigo_home().as_deref(),
    )
}

fn protected_fuigo_config_file_with_home(
    path: &Path,
    components: &[&str],
    user_fuigo_home: Option<&Path>,
) -> Option<ProtectedEditReason> {
    let file = components.last().copied()?;
    let n = components.len();
    // Per-session grant store: `{home}/sessions/<scope>/permission.toml` or `permission_<client>.toml` (permission/state.rs).
    // Editing it grants the agent its own approvals.
    if (file == "permission.toml" || (file.starts_with("permission_") && file.ends_with(".toml")))
        && n >= 3
        && components.get(n - 3) == Some(&"sessions")
    {
        let in_dot_fuigo = n >= 4 && components.get(n - 4) == Some(&".fuigo");
        let in_fuigo_home = || {
            fuigo_home_matches(user_fuigo_home, |home| {
                path.parent()
                    .and_then(Path::parent)
                    .is_some_and(|sessions| sessions == home.join("sessions"))
            })
        };
        return (in_dot_fuigo || in_fuigo_home()).then_some(ProtectedEditReason::FuigoConfig);
    }
    let reason = match file {
        fuigo_config::USER_CONFIG_FILENAME
        | fuigo_config::MANAGED_CONFIG_FILENAME
        | fuigo_config::REQUIREMENTS_FILENAME => ProtectedEditReason::FuigoConfig,
        // Spawn configs: `lsp.json` starts language servers at the next load; `mcp.json` is the upstream daemon's MCP list.
        "mcp.json" | "lsp.json" => ProtectedEditReason::McpConfig,
        fuigo_config::SANDBOX_CONFIG_FILENAME => ProtectedEditReason::FuigoSandbox,
        _ => return None,
    };
    let in_dot_fuigo = n >= 2 && components.get(n - 2) == Some(&".fuigo");
    let in_fuigo_home = || fuigo_home_matches(user_fuigo_home, |home| path.parent() == Some(home));
    (in_dot_fuigo || in_fuigo_home()).then_some(reason)
}

/// P166/S5: directories that hold protected files, as a write TARGET (`cp -r x ~/.fuigo`, `mv cfg .cursor`, `mkdir .claude`).
/// A copy or move into one can create any protected file inside it, which no file-name check sees.
/// `.fuigo` and `$FUIGO_HOME` hold config, hooks, spawn configs and the grant stores (`sessions/<scope>/permission*.toml`);
/// `.cursor` holds `mcp.json` and `hooks.json`; `.claude` holds `settings*.json`.
fn protected_container_dir(
    path: &Path,
    components: &[&str],
    user_fuigo_home: Option<&Path>,
) -> Option<ProtectedEditReason> {
    let n = components.len();
    match components.last().copied()? {
        ".fuigo" => return Some(ProtectedEditReason::FuigoConfig),
        ".cursor" => return Some(ProtectedEditReason::McpConfig),
        ".claude" => return Some(ProtectedEditReason::ClaudeSettings),
        _ => {}
    }
    let at = |i: usize| n.checked_sub(i).and_then(|i| components.get(i)).copied();
    // `.fuigo/sessions` and `.fuigo/sessions/<scope>`.
    let dot_fuigo_sessions = (at(2) == Some(".fuigo") && at(1) == Some("sessions"))
        || (at(3) == Some(".fuigo") && at(2) == Some("sessions"));
    let fuigo_home_tree = || {
        fuigo_home_matches(user_fuigo_home, |home| {
            let sessions = home.join("sessions");
            path == home || path == sessions || path.parent() == Some(sessions.as_path())
        })
    };
    (dot_fuigo_sessions || fuigo_home_tree()).then_some(ProtectedEditReason::FuigoConfig)
}

/// Vendor MCP server lists Fuigo loads and hot-reloads: project `.mcp.json` (repo root to cwd), `.cursor/mcp.json`
/// (project and home), and `.claude.json` (the config watcher reloads MCP from it). A new entry starts a program.
fn protected_vendor_mcp_config(components: &[&str]) -> bool {
    matches!(components.last().copied(), Some(".mcp.json" | ".claude.json"))
        || components.ends_with(&[".cursor", "mcp.json"])
}

/// True when `pred` holds for the user fuigo home in either its lexical or physically-resolved form.
/// Both forms are checked because callers hold a lexical and a resolved candidate path, and the home itself may sit behind a symlink.
/// The comparison is byte-exact (no case folding), like every other resolved-path check in this module.
fn fuigo_home_matches(home: Option<&Path>, pred: impl Fn(&Path) -> bool) -> bool {
    home.is_some_and(|home| {
        let lexical = fuigo_paths::normalize_lexically(home);
        pred(&lexical)
            || resolve_following_symlinks(&lexical).is_some_and(|resolved| pred(&resolved))
    })
}

fn path_is_under_user_fuigo_hook_root(path: &Path, fuigo_home: &Path) -> bool {
    path.starts_with(fuigo_home.join("hooks")) || path == fuigo_home.join("hooks-paths")
}

fn protected_fuigo_hook_root(path: &Path, components: &[&str]) -> bool {
    components.windows(2).any(|pair| pair == [".fuigo", "hooks"])
        || components.ends_with(&[".fuigo", "hooks-paths"])
        || fuigo_home_matches(fuigo_config::user_fuigo_home().as_deref(), |home| {
            path_is_under_user_fuigo_hook_root(path, home)
        })
}

fn protected_git_hooks_path(components: &[&str]) -> bool {
    components.windows(2).any(|pair| pair == [".git", "hooks"])
        || components.iter().enumerate().any(|(git, component)| {
            *component == ".git"
                && components.get(git + 1) == Some(&"modules")
                && components[git + 2..]
                    .iter()
                    .skip(1)
                    .any(|component| *component == "hooks")
        })
}

/// `resolved_path` is already physical; resolve `root` so platform aliases such as macOS `/etc -> /private/etc` compare in the same namespace.
/// Resolution failure is conservative: the caller then requires confirmation.
fn resolved_path_is_within_root(resolved_path: &Path, root: &Path) -> bool {
    resolve_following_symlinks(root)
        .map(|resolved_root| resolved_path.starts_with(resolved_root))
        .unwrap_or(true)
}

#[derive(Clone, Copy)]
pub(crate) enum ShellFileMode {
    Read,
    Write,
    /// Empty dir/file creation (`mkdir`/`touch`): `Edit` for the inline-shell gate, not a content write.
    Create,
}

/// Tools that read/write a file named as an argument.
/// Not exhaustive; redirects are the robust catch-all (caught via the AST for any program).
fn shell_file_mode(program: &str) -> Option<ShellFileMode> {
    match program {
        "cat" | "tac" | "nl" | "head" | "tail" | "grep" | "egrep" | "fgrep" | "rg" | "sed"
        | "awk" | "less" | "more" | "bat" | "strings" | "xxd" | "od" | "hexdump" | "base64"
        | "base32" | "cut" | "sort" | "uniq" | "wc" | "type" | "get-content" | "gc" | "diff"
        | "comm" | "rev" | "jq" | "yq" | "select-string" | "sls" | "ag" | "ack" | "zcat"
        | "zless" | "zmore" | "zgrep" | "zegrep" | "zfgrep" | "bzcat" | "bzgrep" | "xzcat"
        | "xzgrep" | "zstdcat" | "lz4cat" => Some(ShellFileMode::Read),
        "tee" | "set-content" | "out-file" | "add-content" | "tee-object" | "truncate" => {
            Some(ShellFileMode::Write)
        }
        _ => None,
    }
}

fn shell_program_name(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutionScope {
    start: usize,
    end: usize,
}

impl ExecutionScope {
    fn contains(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

struct ShellRedirectTarget {
    path: Option<String>,
    /// Raw source text of the destination word (P166 r12: an undecodable one is scanned for protected names).
    raw: String,
    mode: ShellFileMode,
    ambiguous: bool,
    start_byte: usize,
    /// Where the redirect takes effect: bash opens a statement's redirects before running its body, so a redirect
    /// on `{ cd /etc; } > log` or `if cd /etc; then :; fi > log` writes in the cwd at the statement's start.
    opens_at: usize,
    scope: ExecutionScope,
}

fn execution_scope(node: Node<'_>) -> ExecutionScope {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if current
            .next_sibling()
            .is_some_and(|sibling| sibling.kind() == "&")
        {
            let component = if current.kind() == "list" {
                current
            } else {
                parent
            };
            return ExecutionScope {
                start: component.start_byte(),
                end: component.end_byte(),
            };
        }
        if matches!(
            parent.kind(),
            "subshell" | "command_substitution" | "process_substitution"
        ) {
            return ExecutionScope {
                start: parent.start_byte(),
                end: parent.end_byte(),
            };
        }
        if parent.kind() == "pipeline" {
            return ExecutionScope {
                start: current.start_byte(),
                end: current.end_byte(),
            };
        }
        current = parent;
    }
    ExecutionScope {
        start: 0,
        end: usize::MAX,
    }
}

struct CwdPoison {
    at: usize,
    scope: ExecutionScope,
}

/// In-scope `cd`/`pushd`/`popd` positions; relative later operands must Ask.
fn cwd_poison_positions(root: Node<'_>, src: &str) -> Vec<CwdPoison> {
    let mut positions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command"
            && node
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(src.as_bytes()).ok())
                .is_some_and(|program| {
                    matches!(shell_program_name(program), "cd" | "pushd" | "popd")
                })
        {
            positions.push(CwdPoison {
                at: node.start_byte(),
                scope: execution_scope(node),
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    positions
}

/// Whether an operand runs after a cwd change in its nearest execution scope.
fn cwd_unpinned_before(positions: &[CwdPoison], at: usize, scope: ExecutionScope) -> bool {
    positions
        .iter()
        .any(|poison| poison.at < at && (poison.scope == scope || poison.scope.contains(scope)))
}

/// A command operand or redirect destination extracted from the AST, with escape/quote folding already applied to literals.
#[derive(Clone)]
enum InvocationWord {
    Literal(String),
    Untrusted,
}

#[derive(Clone)]
struct ShellInvocation {
    start_byte: usize,
    scope: ExecutionScope,
    words: Vec<InvocationWord>,
    wrapper_words: Vec<String>,
    /// What the parser saw but did not decode (P166 r8 tripwire input).
    extras: CommandExtras,
}

#[derive(Clone, Copy)]
struct InvocationSlice<'a> {
    words: &'a [InvocationWord],
}

struct CheckedInvocationPeel<'a> {
    words: InvocationSlice<'a>,
    has_chdir: bool,
    has_split_string: bool,
    env_options_uncertain: bool,
    exhausted: bool,
    transparent_ambiguous: bool,
}

impl InvocationSlice<'_> {
    fn literal_words(&self) -> Vec<String> {
        self.words
            .iter()
            .filter_map(|word| match word {
                InvocationWord::Literal(word) => Some(word.clone()),
                InvocationWord::Untrusted => None,
            })
            .collect()
    }

    fn shell_words(&self) -> Vec<ShellWord<'_>> {
        self.words
            .iter()
            .map(|word| match word {
                InvocationWord::Literal(word) => ShellWord::Literal(word),
                InvocationWord::Untrusted => ShellWord::Untrusted,
            })
            .collect()
    }
}

fn unwrap_invocation_checked(invocation: &ShellInvocation) -> CheckedInvocationPeel<'_> {
    // Parallel String/`InvocationWord` slices stay index-aligned under normalize.
    let norm = normalize_command_words(&invocation.wrapper_words);
    let peeled_count = invocation.wrapper_words.len() - norm.words.len();
    CheckedInvocationPeel {
        words: InvocationSlice {
            words: invocation.words.get(peeled_count..).unwrap_or_default(),
        },
        has_chdir: norm.has_chdir,
        has_split_string: norm.has_split_string,
        env_options_uncertain: norm.env_options_uncertain,
        exhausted: norm.exhausted,
        transparent_ambiguous: norm.ambiguous,
    }
}

enum ArgText {
    /// Literal path/word, no runtime expansion.
    Literal(String),
    /// Runtime expansion; unpinnable, so callers prompt.
    Ambiguous,
}

/// True if any descendant expands at runtime (e.g. `$X` in `.e"$X"`), so the text isn't a literal path.
fn node_has_expansion(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        for i in 0..n.child_count() {
            let Some(child) = n.child(i) else { continue };
            if matches!(
                child.kind(),
                "expansion"
                    | "simple_expansion"
                    | "command_substitution"
                    | "arithmetic_expansion"
                    | "process_substitution"
            ) {
                return true;
            }
            stack.push(child);
        }
    }
    false
}

/// Drive-letter / UNC-looking text must keep separators for path normalize.
fn is_windows_path_like(raw: &str) -> bool {
    raw.starts_with("\\\\")
        || (raw
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic())
            && raw.as_bytes().get(1) == Some(&b':'))
}

/// Fold unquoted shell backslash escapes (`b\ash` becomes `bash`, `\-c` becomes `-c`).
fn decode_unquoted_word(raw: &str) -> Option<String> {
    if !raw.contains('\\') {
        return Some(raw.to_owned());
    }
    if is_windows_path_like(raw) {
        return Some(raw.to_owned());
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(chars.next()?);
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

/// Double-quote body: only `\$`, `` \` ``, `\"`, `\\`, and `\<newline>` fold.
fn decode_double_quoted_content(content: &str) -> Option<String> {
    if !content.contains('\\') {
        return Some(content.to_owned());
    }
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(n @ ('$' | '`' | '"' | '\\' | '\n')) => out.push(n),
            Some(n) => {
                out.push('\\');
                out.push(n);
            }
            None => return None,
        }
    }
    Some(out)
}

fn shell_node_arg(node: Node<'_>, src: &str) -> Option<ArgText> {
    shell_node_arg_with(node, src, false)
}

/// [`shell_node_arg`]; with `fold_home` a `$HOME`/`${HOME}`-only expansion is the literal `~` (the write floor expands
/// `~` like the edit tools; read rules keep treating the word as unpinnable).
fn shell_node_arg_with(node: Node<'_>, src: &str, fold_home: bool) -> Option<ArgText> {
    let home = |raw: String| if fold_home { replace_home_vars(&raw) } else { None };
    let text = || node.utf8_text(src.as_bytes()).ok().map(str::to_owned);
    match node.kind() {
        "variable_assignment" => None,
        "word" | "number" => match text().and_then(|raw| decode_unquoted_word(&raw)) {
            Some(literal) => Some(ArgText::Literal(literal)),
            None => Some(ArgText::Ambiguous),
        },
        "ansi_c_string" => {
            let raw = node.utf8_text(src.as_bytes()).ok()?;
            let body = raw.strip_prefix("$'").and_then(|s| s.strip_suffix('\''))?;
            Some(ArgText::Literal(tripwire::decode_ansi_c_body(body)))
        }
        "raw_string" => {
            let raw = node.utf8_text(src.as_bytes()).ok()?;
            let stripped = raw
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(raw);
            Some(ArgText::Literal(stripped.to_owned()))
        }
        "string" => {
            if node_has_expansion(node) {
                // `"$HOME/x"` is the literal `~/x` (P166 r7): the floor expands `~` like the edit tools do.
                let literal = text()
                    .and_then(home)
                    .and_then(|raw| {
                        let inner = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(&raw);
                        decode_double_quoted_content(inner)
                    });
                return Some(literal.map_or(ArgText::Ambiguous, ArgText::Literal));
            }
            let raw = node.utf8_text(src.as_bytes()).ok()?;
            let stripped = raw
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(raw);
            match decode_double_quoted_content(stripped) {
                Some(literal) => Some(ArgText::Literal(literal)),
                None => Some(ArgText::Ambiguous),
            }
        }
        "concatenation" => {
            if node_has_expansion(node) {
                let literal = text().and_then(home).and_then(|raw| decode_concatenation(&raw));
                Some(literal.map_or(ArgText::Ambiguous, ArgText::Literal))
            } else {
                match text().and_then(|raw| decode_concatenation(&raw)) {
                    Some(literal) => Some(ArgText::Literal(literal)),
                    None => Some(ArgText::Ambiguous),
                }
            }
        }
        "simple_expansion" | "expansion" => Some(
            text()
                .and_then(home)
                .map_or(ArgText::Ambiguous, ArgText::Literal),
        ),
        _ => Some(ArgText::Ambiguous),
    }
}

/// A concatenation word: when it holds a `$'...'` piece the ANSI-C decoding goes first (the plain spelling decoder
/// would read `$` and the quotes literally); otherwise the plain spelling decoder.
fn decode_concatenation(raw: &str) -> Option<String> {
    if raw.contains("$'") {
        decode_ansi_concatenation(raw).or_else(|| decode_shell_literal_spelling(raw))
    } else {
        decode_shell_literal_spelling(raw)
    }
}

/// A concatenation that contains `$'...'` pieces (P166 r8): quote removal with the ANSI-C escapes decoded; `None` when
/// an expansion remains.
fn decode_ansi_concatenation(raw: &str) -> Option<String> {
    if !raw.contains("$'") {
        return None;
    }
    let decoded = tripwire::decode_view(raw);
    (!decoded.contains(['$', '`'])).then_some(decoded)
}

/// `text` with every `$HOME` / `${HOME}` replaced by `~`, and (P166 r11 rule 4a) `$PWD` / `${PWD}` replaced by `~+`
/// (the tracked working directory) where a tilde word can stand: at the start of the word or right after `=`; `None`
/// when any other expansion remains, or a `$PWD` stands anywhere else.
fn replace_home_vars(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let name_ends = |tail: &str| !tail.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
        let tilde_position = || {
            let before = out.trim_end_matches(['"', '\'']);
            before.is_empty() || before.ends_with('=')
        };
        if let Some(tail) = after.strip_prefix("{HOME}") {
            out.push('~');
            rest = tail;
        } else if let Some(tail) = after.strip_prefix("HOME").filter(|tail| name_ends(tail)) {
            out.push('~');
            rest = tail;
        } else if let Some(tail) = after
            .strip_prefix("{PWD}")
            .or_else(|| after.strip_prefix("PWD").filter(|tail| name_ends(tail)))
            .filter(|_| tilde_position())
        {
            out.push_str("~+");
            rest = tail;
        } else {
            return None;
        }
    }
    out.push_str(rest);
    (!out.contains(['`', '$'])).then_some(out)
}

/// Here-string and here-document nodes that feed this command's stdin: those under the redirect, pipeline or negation
/// that wraps it, and a here-document body that follows it as a sibling.
fn stdin_bodies_around(command: Node<'_>, src: &str) -> Vec<String> {
    let mut top = command;
    while let Some(parent) = top.parent() {
        if matches!(parent.kind(), "redirected_statement" | "pipeline" | "negated_command") {
            top = parent;
        } else {
            break;
        }
    }
    let mut found = Vec::new();
    let mut stack = vec![top];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "heredoc_body" | "heredoc_redirect" | "herestring_redirect") {
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                found.push(text.to_owned());
            }
            continue;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    let mut sibling = top.next_sibling();
    while let Some(node) = sibling {
        if node.kind() != "heredoc_body" {
            break;
        }
        if let Ok(text) = node.utf8_text(src.as_bytes()) {
            found.push(text.to_owned());
        }
        sibling = node.next_sibling();
    }
    found
}

fn shell_command_invocations(root: Node<'_>, src: &str) -> Vec<ShellInvocation> {
    shell_command_invocations_with(root, src, false)
}

fn shell_command_invocations_with(root: Node<'_>, src: &str, fold_home: bool) -> Vec<ShellInvocation> {
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command" {
            let mut words = Vec::new();
            let mut extras = CommandExtras::default();
            for i in 0..node.named_child_count() {
                let Some(child) = node.named_child(i) else {
                    continue;
                };
                let child_text = child.utf8_text(src.as_bytes()).unwrap_or_default();
                match child.kind() {
                    "variable_assignment" => {
                        if let Some((_, value)) = child_text.split_once('=') {
                            extras.assignments.push(value.to_owned());
                        }
                    }
                    "herestring_redirect" | "heredoc_redirect" => extras.stdin_bodies.push(child_text.to_owned()),
                    _ => {}
                }
                let operand = if child.kind() == "command_name" {
                    child
                        .named_child(0)
                        .and_then(|inner| shell_node_arg_with(inner, src, fold_home))
                } else {
                    shell_node_arg_with(child, src, fold_home)
                };
                match operand {
                    Some(ArgText::Literal(word)) => {
                        // Brace expansion makes several words (P166 r8); an unquoted spelling only, write floor only.
                        let expandable = fold_home
                            && child.kind() != "command_name"
                            && word.contains('{')
                            && (word.contains(',') || word.contains(".."))
                            && !child_text.contains(['\'', '"', '\\', '$', '`']);
                        let mut budget = tripwire::BRACE_CAP;
                        match expandable.then(|| tripwire::brace_expand(&word, &mut budget)) {
                            Some(Ok(list)) => words.extend(list.into_iter().map(InvocationWord::Literal)),
                            Some(Err(())) => {
                                words.push(InvocationWord::Untrusted);
                                extras.raw_ambiguous.push(child_text.to_owned());
                            }
                            None => words.push(InvocationWord::Literal(word)),
                        }
                    }
                    Some(ArgText::Ambiguous) => {
                        words.push(InvocationWord::Untrusted);
                        if !matches!(
                            child.kind(),
                            "file_redirect" | "herestring_redirect" | "heredoc_redirect" | "heredoc_body"
                        ) {
                            extras.raw_ambiguous.push(child_text.to_owned());
                        }
                    }
                    None => {}
                }
            }
            extras.stdin_bodies.extend(stdin_bodies_around(node, src));
            extras.git_option_untrusted = git_global_option_untrusted(&words);
            // WHY: the placeholder preserves operand indexes while preventing wrapper matches.
            let wrapper_words = words
                .iter()
                .map(|word| match word {
                    InvocationWord::Literal(word) => word.clone(),
                    InvocationWord::Untrusted => "\0".to_owned(),
                })
                .collect();
            found.push(ShellInvocation {
                start_byte: node.start_byte(),
                scope: execution_scope(node),
                words,
                wrapper_words,
                extras,
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    found.sort_by_key(|invocation| invocation.start_byte);
    found
}

/// Auto-mode opaque-shell floor: a (potential) `-c` string reinterpretation (`bash|sh|dash|zsh|ksh -c …`) or a literal `eval` head.
/// The one classifier shared by the decomposable segment loop and the undecomposable tree walk so the two can't drift.
pub(crate) fn words_are_opaque_shell(words: &[ShellWord<'_>]) -> bool {
    shell_dash_c_script(words).is_potential_inline()
        || matches!(
            words.first(),
            Some(ShellWord::Literal(program)) if shell_program_name(program) == "eval"
        )
}

/// Undecomposable-path opaque-shell floor: word-only decomposition failed, so apply the canonical word predicate to each parsed invocation directly.
pub(crate) fn tree_has_opaque_shell(root: Node<'_>, src: &str) -> bool {
    shell_command_invocations(root, src)
        .iter()
        .any(|invocation| {
            let peeled = unwrap_invocation_checked(invocation);
            words_are_opaque_shell(&peeled.words.shell_words())
        })
}

fn shell_redirect_targets(root: Node<'_>, src: &str) -> Vec<ShellRedirectTarget> {
    shell_redirect_targets_with(root, src, false)
}

/// [`shell_redirect_targets`]; with `fold_home` (the write floor) `$HOME` / `$PWD` fold like on command words.
fn shell_redirect_targets_with(root: Node<'_>, src: &str, fold_home: bool) -> Vec<ShellRedirectTarget> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "file_redirect"
            && let Some((path, mode, ambiguous, raw)) = shell_redirect_one(node, src, fold_home)
        {
            out.push(ShellRedirectTarget {
                raw,
                start_byte: node.start_byte(),
                opens_at: redirect_opens_at(node),
                scope: execution_scope(node),
                path,
                mode,
                ambiguous,
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    out
}

/// Where a redirect takes effect (P166 Grok r4 LOW 6): bash opens a statement's redirects before its body runs, so
/// `{ cd /etc; } > log` and `if cd /etc; then :; fi > log` write `log` in the old cwd. tree-sitter-bash also hangs a
/// trailing redirect on a whole `list`/`pipeline` (`cd /etc && echo > log`), where bash gives it to the LAST element
/// only, so the body is followed down to that element.
fn redirect_opens_at(node: Node<'_>) -> usize {
    let Some(statement) = node
        .parent()
        .filter(|parent| parent.kind() == "redirected_statement")
    else {
        return node.start_byte();
    };
    let Some(mut body) = statement.child_by_field_name("body") else {
        return node.start_byte();
    };
    while matches!(body.kind(), "list" | "pipeline") {
        let Some(last) = body
            .named_child_count()
            .checked_sub(1)
            .and_then(|last| body.named_child(last))
        else {
            break;
        };
        body = last;
    }
    body.start_byte()
}

fn shell_redirect_one(
    node: Node<'_>,
    src: &str,
    fold_home: bool,
) -> Option<(Option<String>, ShellFileMode, bool, String)> {
    let mut redirect = None;
    for i in 0..node.child_count() {
        let kind = node.child(i)?.kind();
        // `<<`/`<<<` read from inline text, not a file.
        if kind.contains("<<") {
            return None;
        }
        if kind.contains('>') || kind.contains('<') {
            redirect = Some(kind);
            break;
        }
    }
    let redirect = redirect?;
    let mode = if redirect.contains('>') {
        ShellFileMode::Write
    } else {
        ShellFileMode::Read
    };
    let duplicates_fd = matches!(redirect, ">&" | "<&");
    let dest = node.child_by_field_name("destination")?;
    let raw = dest.utf8_text(src.as_bytes()).unwrap_or_default().to_owned();
    match shell_node_arg_with(dest, src, fold_home)? {
        ArgText::Literal(s) => {
            if s.is_empty()
                || s.starts_with('&')
                || (duplicates_fd && (s == "-" || s.bytes().all(|b| b.is_ascii_digit())))
            {
                None
            } else {
                let ambiguous = shell_arg_is_ambiguous(&s);
                Some((Some(s), mode, ambiguous, raw))
            }
        }
        ArgText::Ambiguous => Some((None, mode, true, raw)),
    }
}

fn shell_sed_in_place(words: &[String]) -> bool {
    words.iter().skip(1).any(|word| {
        word == "--in-place"
            || word.starts_with("--in-place=")
            // `i` is sed's only short flag with that letter, so any `-…i…` is in-place
            || (word.starts_with('-') && !word.starts_with("--") && word.contains('i'))
    })
}

/// How a program spells its output options: `-o`, long `--output`-style options, and short-option clusters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OutputFlagSyntax {
    clusters: ShortClusters,
    /// Long options whose value is written, matched in full or as any abbreviation down to 3 characters
    /// (`--out=f`, `--outp f`). An abbreviation that is ambiguous for the program still counts, so a match
    /// never under-reports a write.
    long_outputs: &'static [&'static str],
    /// Long options (exact spelling) whose value is a comma list of `TYPE=PATH` items, each PATH written
    /// (`rustc --emit link=out`).
    long_typed_outputs: &'static [&'static str],
    /// Long options (exact spelling) that take the NEXT word as their value, so that word is not rescanned as a flag
    /// (`git log --grep --out`). An abbreviation is not skipped, which can only over-report a write.
    long_valued: &'static [&'static str],
    /// Unclustered (`Exact`) programs only: short-option letters with a mandatory value. Walking a short cluster, the
    /// first such letter takes the rest of the word, or the next word when it ends the cluster (`git log -pS --out`).
    short_valued_letters: &'static str,
    /// Unclustered (`Exact`) programs only: letters with an optional attached value; one ends the walk without
    /// consuming the next word (`git status -uno`).
    short_optarg_letters: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShortClusters {
    /// Go's `flag` package: no clusters (`-json` is one flag), and `-o=FILE` means `-o FILE`.
    Go,
    /// No clusters and a literal value: only `-o`, `-o FILE` and `-oFILE` (`-o=f` writes `=f`).
    Exact,
    /// getopt-style clusters (`-no FILE` is `-n` plus `-o FILE`). Walking left to right, a letter in `arg_letters`
    /// takes the rest of the word, or the next word, as its own value; a letter in `optarg_letters` takes only the
    /// rest of the word (an optional argument never consumes the next word). Either way an `o` after it is not the
    /// output flag. Any other letter is treated as a plain flag, which over-reports a write rather than missing one.
    Getopt {
        arg_letters: &'static str,
        optarg_letters: &'static str,
    },
}

/// GNU `sort` (`-bcCdfghik:mMno:rRsS:t:T:uVy:z`): `-k`, `-S`, `-t`, `-T` and `-y` take a value.
const SORT_OUTPUT_SYNTAX: OutputFlagSyntax = OutputFlagSyntax {
    clusters: ShortClusters::Getopt {
        arg_letters: "kStTy",
        optarg_letters: "",
    },
    long_outputs: &["--output"],
    long_typed_outputs: &[],
    long_valued: &[
        "--key",
        "--field-separator",
        "--buffer-size",
        "--temporary-directory",
        "--compress-program",
        "--files0-from",
        "--random-source",
        "--sort",
        "--parallel",
        "--batch-size",
    ],
    short_valued_letters: "",
    short_optarg_letters: "",
};
const GO_OUTPUT_SYNTAX: OutputFlagSyntax = OutputFlagSyntax {
    clusters: ShortClusters::Go,
    long_outputs: &["--output"],
    long_typed_outputs: &[],
    long_valued: &[],
    short_valued_letters: "",
    short_optarg_letters: "",
};
/// `rustc` (getopts, which groups short options): `-C`, `-L`, `-l`, `-W`, `-A`, `-D`, `-F` and `-Z` take a value.
const RUSTC_OUTPUT_SYNTAX: OutputFlagSyntax = OutputFlagSyntax {
    clusters: ShortClusters::Getopt {
        arg_letters: "CLlWADFZ",
        optarg_letters: "",
    },
    long_outputs: &["--output", "--out-dir"],
    long_typed_outputs: &["--emit"],
    long_valued: &[
        "--cfg",
        "--check-cfg",
        "--crate-type",
        "--crate-name",
        "--edition",
        "--print",
        "--target",
        "--cap-lints",
        "--extern",
        "--sysroot",
        "--explain",
        "--error-format",
        "--json",
        "--color",
        "--remap-path-prefix",
    ],
    short_valued_letters: "",
    short_optarg_letters: "",
};
/// `git` long options that write a file or directory, for every verb.
const GIT_LONG_OUTPUTS: &[&str] = &["--output", "--output-directory"];
/// Free-text `git` options whose value may look like a flag.
const GIT_LONG_VALUED: &[&str] = &[
    "--grep",
    "--author",
    "--committer",
    "--format",
    "--message",
    "--since",
    "--until",
    "--before",
    "--after",
];
/// `git` short options with a mandatory value in the log/diff family and in `grep` (`-S`, `-G`, `-I`, `-O`, `-e`).
const GIT_SHORT_VALUED_LETTERS: &str = "SGIOe";
/// `git` short options with an optional attached value (`-M -C -B -U -X`, status `-u`).
const GIT_SHORT_OPTARG_LETTERS: &str = "MCBUXu";
/// Global `git` options that take the next word as their value (they come before the verb).
const GIT_GLOBALS_WITH_VALUE: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

/// Whether a global `git` option takes the next word as its value: an exact short or long name, or (like getopt_long)
/// a bare abbreviation of a long one (`--git-d /repo`). `--git-dir=/repo` carries its own value.
fn git_global_takes_next(token: &str) -> bool {
    GIT_GLOBALS_WITH_VALUE.contains(&token)
        || (!token.contains('=')
            && GIT_GLOBALS_WITH_VALUE.iter().any(|full| {
                full.starts_with("--") && is_accepted_long_option_prefix(token, full, 3)
            }))
}

/// Index of the verb of a `git` command: the first word after the global options and their values.
/// A `--` that is not a global option's value ends the globals and the next word is the verb. (git itself rejects
/// `--` and abbreviations here; reading past them can only over-report a write.)
fn git_verb_index(words: &[String]) -> Option<usize> {
    let mut i = 1;
    while let Some(token) = words.get(i) {
        if token == "--" {
            return words.get(i + 1).map(|_| i + 1);
        }
        if !token.starts_with('-') {
            return Some(i);
        }
        i += if git_global_takes_next(token) { 2 } else { 1 };
    }
    None
}

/// Output syntax for `git`, and the index its verb's arguments start at (global options are never rescanned).
/// `-o` is a write for every verb, and is clustered only for `archive` (every other short option is a plain flag)
/// and `format-patch`. There `-v` takes the next word even when it is `--` (git 2.50: `-v -- -o d` writes `d`); the
/// diff letters (`-U -M -C -B -l -S -G -O -X -I`) end the cluster but never take a following option word (git 2.50:
/// `-S -o d` and `-M -o d` write `d`). Other verbs keep exact `-o` so `git status -uno` stays a non-write.
/// A git alias is not resolved.
fn git_output_syntax(words: &[String]) -> (OutputFlagSyntax, usize) {
    let verb = git_verb_index(words);
    let clusters = match verb.and_then(|i| words.get(i)).map(String::as_str) {
        Some("archive") => ShortClusters::Getopt {
            arg_letters: "",
            optarg_letters: "",
        },
        Some("format-patch") => ShortClusters::Getopt {
            arg_letters: "v",
            optarg_letters: "UMCBlSGOXI",
        },
        _ => ShortClusters::Exact,
    };
    let syntax = OutputFlagSyntax {
        clusters,
        long_outputs: GIT_LONG_OUTPUTS,
        long_typed_outputs: &[],
        long_valued: GIT_LONG_VALUED,
        short_valued_letters: GIT_SHORT_VALUED_LETTERS,
        short_optarg_letters: GIT_SHORT_OPTARG_LETTERS,
    };
    (syntax, verb.map_or(1, |i| i + 1))
}

/// Write targets of a program's output options, scanning `words` from index `start`: `-o f`, `-of`, `--output=f`,
/// `--out f` (any abbreviation of a `long_outputs` entry), `TYPE=PATH` lists of `long_typed_outputs`, and, for
/// getopt-style programs, `-o` inside a short-option cluster (`-ro f`, `-rof`).
/// Scanning stops at `--`, and a word consumed as another option's value is skipped.
/// A missing value is an empty path, so the write is still seen.
fn shell_output_flag_values(words: &[String], syntax: OutputFlagSyntax, start: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = start;
    while let Some(token) = words.get(i) {
        let next = words.get(i + 1).map(String::as_str);
        // Default: move to the next word; an option that consumes the next word moves two.
        let mut step = 1;
        if token == "--" {
            // `--` ends the options only where it cannot be the previous option's value: right after the program or
            // git verb, after an operand, after an option carrying its own `=value`, or after a getopt short cluster
            // of plain flags. After a bare long option (possibly an abbreviation such as `sort --temp`), a Go flag
            // (`-tags`) or a cluster holding a value letter (`format-patch -S --`) it may be a value, so scanning
            // goes on.
            let ends_options = i == start
                || words.get(i - 1).is_none_or(|prev| {
                    !prev.starts_with('-')
                        || prev == "-"
                        || prev.contains('=')
                        || match syntax.clusters {
                            ShortClusters::Getopt {
                                arg_letters,
                                optarg_letters,
                            } => {
                                !prev.starts_with("--")
                                    && !prev.chars().skip(1).any(|letter| {
                                        arg_letters.contains(letter)
                                            || optarg_letters.contains(letter)
                                    })
                            }
                            ShortClusters::Go | ShortClusters::Exact => false,
                        }
                });
            if ends_options {
                break;
            }
            i += 1;
            continue;
        }
        if token.starts_with("--") {
            let (flag, attached) = match token.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (token.as_str(), None),
            };
            let value = || attached.unwrap_or_else(|| next.unwrap_or(""));
            let writes = syntax
                .long_outputs
                .iter()
                .any(|full| is_accepted_long_option_prefix(flag, full, 3));
            let typed = syntax.long_typed_outputs.contains(&flag);
            if writes {
                out.push(value());
            } else if typed {
                out.extend(
                    value()
                        .split(',')
                        .filter_map(|item| item.split_once('=').map(|(_, path)| path)),
                );
            }
            if attached.is_none() && (writes || typed || syntax.long_valued.contains(&flag)) {
                step = 2;
            }
        } else if token == "-o" {
            out.push(next.unwrap_or(""));
            step = 2;
        } else if let Some(value) = token.strip_prefix("-o").filter(|value| !value.is_empty()) {
            // Glued `-oFILE`; getopt takes the rest of the word even when it starts with `-`.
            out.push(match syntax.clusters {
                ShortClusters::Go => value.strip_prefix('=').unwrap_or(value),
                ShortClusters::Exact | ShortClusters::Getopt { .. } => value,
            });
        } else if let (ShortClusters::Exact, Some(letters)) =
            (syntax.clusters, token.strip_prefix('-'))
        {
            for (at, letter) in letters.char_indices() {
                if syntax.short_optarg_letters.contains(letter) {
                    break;
                }
                if syntax.short_valued_letters.contains(letter) {
                    if at + letter.len_utf8() == letters.len() {
                        step = 2;
                    }
                    break;
                }
            }
        } else if let (
            ShortClusters::Getopt {
                arg_letters,
                optarg_letters,
            },
            Some(letters),
        ) = (syntax.clusters, token.strip_prefix('-'))
        {
            for (at, letter) in letters.char_indices() {
                let optional = optarg_letters.contains(letter);
                if letter != 'o' && !optional && !arg_letters.contains(letter) {
                    continue;
                }
                let rest = letters.get(at + letter.len_utf8()..).unwrap_or("");
                if rest.is_empty() && !optional {
                    step = 2;
                }
                if letter == 'o' {
                    out.push(if rest.is_empty() {
                        next.unwrap_or("")
                    } else {
                        rest
                    });
                }
                break;
            }
        }
        i += step;
    }
    out
}

/// Flag-named file operands (not positionals). Empty for other programs.
fn special_file_operands(program: &str, words: &[String]) -> Vec<(String, ShellFileMode)> {
    match program {
        "dd" => words
            .iter()
            .skip(1)
            .filter_map(|token| {
                token
                    .strip_prefix("if=")
                    .map(|path| (path.to_owned(), ShellFileMode::Read))
                    .or_else(|| {
                        token
                            .strip_prefix("of=")
                            .map(|path| (path.to_owned(), ShellFileMode::Write))
                    })
            })
            .collect(),
        // `--output`/`-o` (and git's `--output-directory`) write the output file, in every spelling the program accepts.
        // (`git`'s `-O` is a READ order-file, NOT a write, so it is intentionally excluded.)
        "sort" | "go" | "git" => {
            let (syntax, start) = match program {
                "sort" => (SORT_OUTPUT_SYNTAX, 1),
                "git" => git_output_syntax(words),
                _ => (GO_OUTPUT_SYNTAX, 1),
            };
            shell_output_flag_values(words, syntax, start)
                .into_iter()
                .map(|output| (output.to_owned(), ShellFileMode::Write))
                .collect()
        }
        // `rustc` writes its compiled output via `-o`/`--out-dir`/`--emit TYPE=PATH` (mirrors `go`).
        "rustc" => shell_output_flag_values(words, RUSTC_OUTPUT_SYNTAX, 1)
            .into_iter()
            .map(|output| (output.to_owned(), ShellFileMode::Write))
            .collect(),
        // `rustfmt` rewrites each file operand in place (like an always-on `sed -i`), so its non-flag operands are writes
        "rustfmt" => shell_file_candidates(words)
            .into_iter()
            .map(|path| (path.to_owned(), ShellFileMode::Write))
            .collect(),
        _ => Vec::new(),
    }
}

fn shell_access(mode: ShellFileMode, path: String) -> AccessKind {
    match mode {
        ShellFileMode::Read => AccessKind::Read(Some(path)),
        ShellFileMode::Write | ShellFileMode::Create => AccessKind::Edit(path),
    }
}

/// Operands that may name a file.
/// After a bare `--`, tokens are positional even if `-`-prefixed (`rm -- -/../.env`).
/// `=`-names are kept (a real `VAR=value` is already dropped by the AST).
fn shell_file_candidates(words: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut end_of_options = false;
    for token in words.iter().skip(1) {
        if !end_of_options && token == "--" {
            end_of_options = true;
            continue;
        }
        if end_of_options || (token != "-" && !token.starts_with('-')) {
            out.push(token.as_str());
        }
    }
    out
}

/// File operands implied by path-moving commands.
/// `cp`/`mv`/`ln`/`install` read source(s) and write the destination; `rm`/`rmdir`/`mkdir`/`touch` write every operand; `None` otherwise.
/// (`chmod`/`chown` touch metadata, not content.)
fn shell_path_command_operands<'a>(
    program: &str,
    words: &'a [String],
) -> Option<Vec<(&'a str, ShellFileMode)>> {
    match program {
        "cp" | "mv" | "ln" | "install" => {
            // Last positional is the destination (Write), the rest sources (Read).
            // The rare `-t DIR` reorder isn't parsed; bounded since denies match by basename
            let operands = shell_file_candidates(words);
            // P175b r6: `install -d` makes every operand.
            if program == "install" && install_makes_directories(words) {
                return Some(operands.into_iter().map(|c| (c, ShellFileMode::Write)).collect());
            }
            let (dest, sources) = operands.split_last()?;
            Some(
                sources
                    .iter()
                    .map(|s| (*s, ShellFileMode::Read))
                    .chain(std::iter::once((*dest, ShellFileMode::Write)))
                    .collect(),
            )
        }
        "rm" | "rmdir" => Some(
            shell_file_candidates(words)
                .into_iter()
                .map(|c| (c, ShellFileMode::Write))
                .collect(),
        ),
        p if is_creation_program(p) => Some(
            shell_file_candidates(words)
                .into_iter()
                .map(|c| (c, ShellFileMode::Create))
                .collect(),
        ),
        // `uniq [INPUT [OUTPUT]]`: a 2nd positional is the output file (Write); the 1st is the input (Read)
        // Fewer operands use stdin/stdout
        "uniq" => match shell_file_candidates(words).as_slice() {
            [input, output, ..] => Some(vec![
                (*input, ShellFileMode::Read),
                (*output, ShellFileMode::Write),
            ]),
            _ => None,
        },
        _ => None,
    }
}

fn shell_arg_is_ambiguous(token: &str) -> bool {
    token.contains('*') || token.contains('?') || token.contains('[')
}

/// A recursive directory search can't pin its operands, so it must prompt.
/// `rg`/`ag`/`ack` recurse given no path or a directory operand (`candidates[0]` is the pattern); grep only with `-r`/`-R`.
fn shell_reader_can_recurse(program: &str, words: &[String], candidates: &[&str]) -> bool {
    let grep_recursive = matches!(program, "grep" | "egrep" | "fgrep")
        && words.iter().any(|word| {
            word == "--recursive"
                || word == "--dereference-recursive"
                || (word.starts_with('-')
                    && !word.starts_with("--")
                    && (word.contains('r') || word.contains('R')))
        });
    let searches_dir = matches!(program, "rg" | "ag" | "ack")
        && (candidates.len() <= 1 || candidates.iter().skip(1).any(|c| is_directory_operand(c)));
    grep_recursive || searches_dir
}

/// A path that syntactically names a directory (so a recursive reader descends it).
fn is_directory_operand(token: &str) -> bool {
    token == "." || token == ".." || token.ends_with('/')
}

fn is_absolute_shell_path(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with("~/")
        || path.as_bytes().get(1).is_some_and(|b| *b == b':')
}

fn normalize_shell_path(path: &str) -> String {
    lexical_normalize(&normalize_shell_path_raw(path))
}

/// Quote/backslash/`/c/` normalization WITHOUT collapsing `.`/`..`.
/// Symlink resolution can then follow `..` *physically* (after the link) rather than have it erased textually before the link is ever seen.
fn normalize_shell_path_raw(path: &str) -> String {
    let p = path.trim_matches(['\"', '\'']).replace('\\', "/");
    match p.strip_prefix("/c/") {
        Some(rest) => format!("C:/{rest}"),
        None => p,
    }
}

fn lexical_normalize(path: &str) -> String {
    let prefix_len = if path.as_bytes().get(1).is_some_and(|b| *b == b':') {
        2
    } else {
        0
    };
    let (prefix, rest) = path.split_at(prefix_len);
    let absolute = rest.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|s| *s != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            segment => out.push(segment),
        }
    }
    let body = out.join("/");
    match (prefix.is_empty(), absolute, body.is_empty()) {
        (false, true, false) => format!("{prefix}/{body}"),
        (false, true, true) => format!("{prefix}/"),
        (false, false, _) => format!("{prefix}{body}"),
        (true, true, false) => format!("/{body}"),
        (true, true, true) => "/".to_owned(),
        (true, false, _) => body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::bash_command_splitting::{
        MAX_INLINE_SHELL_DEPTH, MAX_TRANSPARENT_PREFIX_DEPTH, MAX_WRAPPER_DEPTH,
    };
    use crate::permission::types::{
        PatternMode, PermissionConfig, PermissionRule, RuleAction, ToolFilter,
    };

    fn file_rule(action: RuleAction, tool: ToolFilter, pattern: &str) -> PermissionRule {
        PermissionRule {
            action,
            tool,
            pattern: Some(pattern.to_owned()),
            pattern_mode: PatternMode::Glob,
        }
    }

    fn bash_rule(action: RuleAction, pattern: &str) -> PermissionRule {
        file_rule(action, ToolFilter::Bash, pattern)
    }

    fn compiled(rules: Vec<PermissionRule>) -> CompiledPolicy {
        CompiledPolicy::new(PermissionConfig::new(rules))
    }

    fn cwd() -> &'static std::path::Path {
        std::path::Path::new("/work")
    }

    #[test]
    fn shell_file_gate_distinguishes_ask_provenance() {
        let ask = compiled(vec![file_rule(
            RuleAction::Ask,
            ToolFilter::Read,
            "**/secrets/**",
        )]);
        // Rule match: an identified operand hits the ask rule.
        assert_eq!(
            ask.evaluate_shell_file_access_gate("cat secrets/token.txt", cwd()),
            Some(GateDecision::AskRuleMatch)
        );
        // Fail-closed: a recursive reader has no pinnable operands.
        assert_eq!(
            ask.evaluate_shell_file_access_gate("rg TODO", cwd()),
            Some(GateDecision::AskFailClosed)
        );
        // Fail-closed: a dynamic operand on a known reader is unpinnable.
        assert_eq!(
            ask.evaluate_shell_file_access_gate("cat \"$F\"", cwd()),
            Some(GateDecision::AskFailClosed)
        );
        // A rule match anywhere outranks a fail-closed floor in the same script.
        assert_eq!(
            ask.evaluate_shell_file_access_gate("rg TODO && cat secrets/token.txt", cwd()),
            Some(GateDecision::AskRuleMatch)
        );
        // Deny rules keep rejecting with provenance preserved.
        let deny = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        assert!(matches!(
            deny.evaluate_shell_file_access_gate("cat .env", cwd()),
            Some(GateDecision::Reject(_))
        ));
    }

    #[test]
    fn shell_gate_matches_cwd_relative_rules_on_absolute_operands() {
        let deny = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "src/**",
        )]);
        // A rooted relative rule keys on the same file spelled absolutely, matching the direct Read tool gate (which evaluates with the cwd)
        assert!(matches!(
            deny.evaluate_shell_file_access_gate("cat /work/src/secret.txt", cwd()),
            Some(GateDecision::Reject(_))
        ));
        // An absolute operand is cwd-independent, so it stays covered even after a `cd` unpins the working directory
        assert!(matches!(
            deny.evaluate_shell_file_access_gate("cd /tmp && cat /work/src/secret.txt", cwd()),
            Some(GateDecision::Reject(_))
        ));
        // Outside the working directory the rooted rule stays silent.
        assert_eq!(
            deny.evaluate_shell_file_access_gate("cat /elsewhere/src/secret.txt", cwd()),
            None
        );
    }

    #[test]
    fn sensitive_edit_targets_and_lexical_aliases_prompt() {
        for path in [
            "/home/user/.zshrc",
            "/etc",
            "/etc/fuigo-test",
            "/work/subdir/../.git/hooks/pre-commit",
            "/home/user/.fuigo/sandbox.toml",
            "/work/project/.fuigo/sandbox.toml",
        ] {
            assert!(
                edit_target_protection(Path::new(path)).is_some(),
                "protected edit target must prompt: {path}"
            );
        }
        for path in [
            "/work/src/main.rs",
            "/work/project/.fuigo/config.toml/backup",
            "/work/project/sandbox.toml",
            "/work/project/requirements.toml",
            "/work/project/managed_config.toml",
        ] {
            assert!(
                edit_target_protection(Path::new(path)).is_none(),
                "ordinary edit target should not prompt: {path}"
            );
        }
    }

    #[test]
    fn sensitive_edit_targets_include_submodule_hooks() {
        for path in [
            "/work/.git/modules/foo/hooks/pre-commit",
            "/work/.git/modules/submodules/sglang-private/hooks/pre-commit",
            "/work/.git/modules/outer/modules/inner/hooks/pre-commit",
            "/work/subdir/../.git/modules/foo/hooks/pre-commit",
        ] {
            assert!(
                edit_target_protection(Path::new(path)).is_some(),
                "submodule hook target must prompt: {path}"
            );
        }
        for path in [
            "/work/.git/modules/hooks/pre-commit",
            "/work/.git/module/foo/hooks/pre-commit",
            "/work/.git/modules/foo/hook/pre-commit",
            "/work/.git/modules/foo/hooks-disabled/pre-commit",
            "/work/src/modules/foo/hooks/pre-commit",
        ] {
            assert!(
                edit_target_protection(Path::new(path)).is_none(),
                "non-hook control must not prompt: {path}"
            );
        }
    }

    /// P166 r9 (MEDIUM 6): the `git config` SET classifier and the ambient config scan read ONE key table, so every
    /// table entry is both a SET redirect and an ambient exec entry (and a benign value is neither).
    #[test]
    fn p166_r9_config_key_table_is_shared_by_set_and_ambient_scan() {
        use crate::permission::exec_risk::{
            COMMAND_VALUED_CONFIG_KEYS, ConfigValue, local_git_config_entry_is_exec,
        };
        assert!(COMMAND_VALUED_CONFIG_KEYS.len() >= 30);
        for (pattern, rule) in COMMAND_VALUED_CONFIG_KEYS {
            let key = if *rule == ConfigValue::ExtBase {
                pattern.replace('*', "ext::sh -c evil")
            } else {
                pattern.replace('*', "x.y")
            };
            let (command, benign) = match rule {
                ConfigValue::Any => ("/tmp/evil", None),
                ConfigValue::NotBool => ("/tmp/evil", Some("false")),
                ConfigValue::ExtBase => ("x", None),
                ConfigValue::Bang => ("!/tmp/evil", Some("merge")),
                ConfigValue::PathLike => ("/tmp/evil", Some("smtp.example.com")),
                ConfigValue::NotNever => ("always", Some("never")),
                ConfigValue::Url => ("ext::sh -c evil", Some("https://github.com/a/b")),
            };
            assert!(local_git_config_entry_is_exec(&key, command), "ambient: {key}={command}");
            assert!(config_words_set_command_valued(&[key.as_str(), command]), "set (config): {key} {command}");
            if let Some(benign) = benign {
                assert!(!local_git_config_entry_is_exec(&key, benign), "ambient benign: {key}={benign}");
                assert!(!config_words_set_command_valued(&[key.as_str(), benign]), "set benign: {key} {benign}");
            }
        }
        for key in ["url.https://b/.insteadof", "url.https://b/.pushinsteadof"] {
            assert!(!local_git_config_entry_is_exec(key, "ext::sh -c evil"), "{key}");
            assert!(!config_words_set_command_valued(&[key, "ext::sh -c evil"]), "{key}");
        }
        for key in ["user.name", "pull.rebase", "color.ui", "core.autocrlf", "diff.tool"] {
            assert!(!local_git_config_entry_is_exec(key, "x"), "{key}");
            assert!(!config_words_set_command_valued(&[key, "x"]), "{key}");
        }
    }

    #[test]
    fn edit_target_protection_classifies_reasons() {
        let cases = [
            (
                "/home/user/.fuigo/hooks/evil.json",
                ProtectedEditReason::HookRoot,
            ),
            ("/work/.git/hooks/pre-commit", ProtectedEditReason::GitHooks),
            ("/home/user/.ssh/id_rsa", ProtectedEditReason::Ssh),
            ("/home/user/.zshrc", ProtectedEditReason::StartupFile),
            ("/etc/hosts", ProtectedEditReason::Etc),
            (
                "/home/user/.fuigo/config.toml",
                ProtectedEditReason::FuigoConfig,
            ),
            (
                "/home/user/.fuigo/sandbox.toml",
                ProtectedEditReason::FuigoSandbox,
            ),
            (
                "/work/project/.fuigo/sandbox.toml",
                ProtectedEditReason::FuigoSandbox,
            ),
            (
                "/home/user/.fuigo/managed_config.toml",
                ProtectedEditReason::FuigoConfig,
            ),
            (
                "/home/user/.fuigo/requirements.toml",
                ProtectedEditReason::FuigoConfig,
            ),
            (
                "/home/user/.claude/settings.json",
                ProtectedEditReason::ClaudeSettings,
            ),
            (
                "/home/user/.cursor/hooks.json",
                ProtectedEditReason::CursorHooks,
            ),
        ];
        for (path, reason) in cases {
            assert_eq!(
                edit_target_protection(Path::new(path)),
                Some(reason),
                "{path}"
            );
            assert!(reason.description().is_some(), "{path}");
        }
        assert_eq!(
            edit_target_protection(Path::new("/home/user/project/src/main.rs")),
            None
        );
        assert!(ProtectedEditReason::Sensitive.description().is_none());
    }

    #[test]
    fn sensitive_edit_targets_include_hook_roots() {
        for path in [
            "/home/user/.fuigo/hooks/evil.json",
            "/home/user/.fuigo/hooks/nested/deep.json",
            "/home/user/.fuigo/hooks-paths",
            "/home/user/.claude/settings.json",
            "/home/user/.claude/settings.local.json",
            "/home/user/.cursor/hooks.json",
            "/work/project/.fuigo/hooks/local.json",
            "/work/project/.fuigo/hooks-paths",
        ] {
            assert!(
                edit_target_protection(Path::new(path)).is_some(),
                "hook root edit target must prompt: {path}"
            );
        }
        for path in [
            "/home/user/.fuigo/hooks-disabled/note.json",
            "/home/user/.fuigo/hooks-evil/note.json",
            "/home/user/project/src/hooks.json",
            "/home/user/.claude/other.json",
            "/home/user/.cursor/settings.json",
        ] {
            assert!(
                edit_target_protection(Path::new(path)).is_none(),
                "ordinary edit target should not prompt: {path}"
            );
        }
    }

    #[test]
    fn path_is_under_user_fuigo_hook_root_matches_relocated_home() {
        let home = Path::new("/custom/fuigo-home");
        for path in [
            "/custom/fuigo-home/hooks/x.json",
            "/custom/fuigo-home/hooks/nested/deep.json",
            "/custom/fuigo-home/hooks",
            "/custom/fuigo-home/hooks-paths",
        ] {
            assert!(
                path_is_under_user_fuigo_hook_root(Path::new(path), home),
                "must match under custom fuigo home: {path}"
            );
        }
        for path in [
            "/custom/fuigo-home/hooks-disabled/note.json",
            "/custom/fuigo-home/hooks-evil/note.json",
            "/custom/fuigo-home/config.toml",
            "/custom/other/hooks/x.json",
            "/custom/fuigo-home-extra/hooks/x.json",
        ] {
            assert!(
                !path_is_under_user_fuigo_hook_root(Path::new(path), home),
                "must not match outside hook roots: {path}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn sensitive_edit_targets_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let startup = outside.path().join(".zshrc");
        std::fs::write(&startup, b"").unwrap();
        symlink(&startup, ws.path().join("file-link")).unwrap();
        std::fs::create_dir_all(outside.path().join(".git/hooks")).unwrap();
        symlink(
            outside.path().join(".git/hooks"),
            ws.path().join("hooks-link"),
        )
        .unwrap();
        std::fs::create_dir_all(outside.path().join(".git/modules/foo/hooks")).unwrap();
        symlink(
            outside.path().join(".git/modules/foo/hooks"),
            ws.path().join("module-hooks-link"),
        )
        .unwrap();
        let fuigo_hook = outside.path().join(".fuigo/hooks/evil.json");
        std::fs::create_dir_all(fuigo_hook.parent().unwrap()).unwrap();
        std::fs::write(&fuigo_hook, b"{}").unwrap();
        symlink(&fuigo_hook, ws.path().join("fuigo-hook-link")).unwrap();

        for path in [
            ws.path().join("file-link"),
            ws.path().join("hooks-link/new-hook"),
            ws.path().join("module-hooks-link/new-hook"),
            ws.path().join("fuigo-hook-link"),
        ] {
            assert!(
                edit_target_protection(&path).is_some(),
                "symlinked protected edit target must prompt: {}",
                path.display()
            );
        }
    }

    /// A custom `$FUIGO_HOME` has no `.fuigo` path component, so the live `config.toml` / `sandbox.toml` must be caught by the home-prefix branch.
    #[test]
    fn fuigo_config_files_under_custom_fuigo_home_are_protected() {
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path();
        for (file, reason) in [
            (
                fuigo_config::USER_CONFIG_FILENAME,
                ProtectedEditReason::FuigoConfig,
            ),
            (
                fuigo_config::MANAGED_CONFIG_FILENAME,
                ProtectedEditReason::FuigoConfig,
            ),
            (
                fuigo_config::REQUIREMENTS_FILENAME,
                ProtectedEditReason::FuigoConfig,
            ),
            (
                fuigo_config::SANDBOX_CONFIG_FILENAME,
                ProtectedEditReason::FuigoSandbox,
            ),
        ] {
            let path = home_path.join(file);
            let components = [file];
            assert_eq!(
                protected_fuigo_config_file_with_home(&path, &components, Some(home_path)),
                Some(reason),
                "{file} directly under $FUIGO_HOME must be protected"
            );
        }
        // Same file names elsewhere (or with no resolvable home) stay ordinary.
        let elsewhere = home_path
            .join("sub")
            .join(fuigo_config::SANDBOX_CONFIG_FILENAME);
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &elsewhere,
                &["sub", fuigo_config::SANDBOX_CONFIG_FILENAME],
                Some(home_path)
            ),
            None
        );
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &home_path.join(fuigo_config::SANDBOX_CONFIG_FILENAME),
                &[fuigo_config::SANDBOX_CONFIG_FILENAME],
                None
            ),
            None
        );
    }

    /// The resolved-symlink arm of the fuigo-home match must decide.
    /// `$FUIGO_HOME` points at a symlink while the edit targets the physical home directory, so the lexical parent-equality arm cannot fire.
    #[test]
    #[cfg(unix)]
    fn fuigo_config_under_symlinked_fuigo_home_is_protected() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let real_home = tmp.path().join("real-home");
        std::fs::create_dir(&real_home).unwrap();
        let link = tmp.path().join("home-link");
        symlink(&real_home, &link).unwrap();
        // Tempdir paths can themselves contain symlinks (macOS `/var -> /private/var`)
        // Compare against the physical home the production resolver will produce
        let physical_home = resolve_following_symlinks(&real_home).unwrap();
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &physical_home.join(fuigo_config::SANDBOX_CONFIG_FILENAME),
                &[fuigo_config::SANDBOX_CONFIG_FILENAME],
                Some(&link)
            ),
            Some(ProtectedEditReason::FuigoSandbox)
        );
    }

    /// P166/S5 (upstream 48271133): spawn configs and the per-session grant stores are protected edit targets.
    /// `mcp.json` / `lsp.json` start servers; `sessions/<scope>/permission*.toml` holds the agent's own approvals.
    #[cfg(unix)]
    #[test]
    fn spawn_configs_and_grant_stores_are_protected() {
        for (path, reason) in [
            ("/home/user/.fuigo/mcp.json", ProtectedEditReason::McpConfig),
            ("/home/user/.fuigo/lsp.json", ProtectedEditReason::McpConfig),
            ("/work/project/.fuigo/lsp.json", ProtectedEditReason::McpConfig),
            ("/work/project/.fuigo/mcp.json", ProtectedEditReason::McpConfig),
            ("/work/project/.mcp.json", ProtectedEditReason::McpConfig),
            ("/work/project/sub/.MCP.json", ProtectedEditReason::McpConfig),
            ("/work/project/.cursor/mcp.json", ProtectedEditReason::McpConfig),
            ("/home/user/.cursor/mcp.json", ProtectedEditReason::McpConfig),
            ("/home/user/.claude.json", ProtectedEditReason::McpConfig),
            (
                "/home/user/.fuigo/sessions/ws/permission.toml",
                ProtectedEditReason::FuigoConfig,
            ),
            (
                "/home/user/.fuigo/sessions/%2Fwork%2Fproject/permission_fuigo-pager.toml",
                ProtectedEditReason::FuigoConfig,
            ),
            (
                "/home/user/.fuigo/sessions/ws/../ws/permission_zed.toml",
                ProtectedEditReason::FuigoConfig,
            ),
        ] {
            assert_eq!(
                edit_target_protection(Path::new(path)),
                Some(reason),
                "{path}"
            );
            assert!(reason.description().is_some(), "{path}");
        }
        for path in [
            "/work/project/mcp.json",
            "/work/project/lsp.json",
            "/work/project/config/mcp.json.bak",
            "/work/project/.fuigo/sub/mcp.json",
            "/work/project/sessions/x/permission_fuigo-pager.toml",
            "/work/project/sessions/x/permission.toml",
            "/home/user/.fuigo/sessions/ws/permissions.toml",
            "/home/user/.fuigo/sessions/ws/permission_x.json",
            "/home/user/.fuigo/sessions/ws/sub/permission.toml",
        ] {
            assert_eq!(edit_target_protection(Path::new(path)), None, "{path}");
        }
    }

    /// P166/S5: a custom `$FUIGO_HOME` has no `.fuigo` component, so its spawn configs and grant stores need the home-prefix branch.
    #[test]
    fn spawn_configs_and_grant_stores_under_custom_fuigo_home_are_protected() {
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path();
        for file in ["mcp.json", "lsp.json"] {
            assert_eq!(
                protected_fuigo_config_file_with_home(&home_path.join(file), &[file], Some(home_path)),
                Some(ProtectedEditReason::McpConfig),
                "{file}"
            );
        }
        for file in ["permission.toml", "permission_fuigo-pager.toml"] {
            let grant = home_path.join("sessions").join("ws").join(file);
            assert_eq!(
                protected_fuigo_config_file_with_home(
                    &grant,
                    &["sessions", "ws", file],
                    Some(home_path)
                ),
                Some(ProtectedEditReason::FuigoConfig),
                "{file} under $FUIGO_HOME/sessions must be protected"
            );
        }
        // A `sessions/` tree elsewhere is ordinary.
        let elsewhere = home_path.join("sub").join("sessions").join("ws").join("permission.toml");
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &elsewhere,
                &["sub", "sessions", "ws", "permission.toml"],
                Some(home_path)
            ),
            None
        );
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &home_path.join("mcp.json"),
                &["mcp.json"],
                None
            ),
            None
        );
    }

    /// P166/S5: the grant store behind a symlinked `$FUIGO_HOME` is caught by the resolved arm.
    #[test]
    #[cfg(unix)]
    fn grant_store_under_symlinked_fuigo_home_is_protected() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let real_home = tmp.path().join("real-home");
        std::fs::create_dir(&real_home).unwrap();
        let link = tmp.path().join("home-link");
        symlink(&real_home, &link).unwrap();
        let physical_home = resolve_following_symlinks(&real_home).unwrap();
        let grant = physical_home.join("sessions").join("ws").join("permission.toml");
        assert_eq!(
            protected_fuigo_config_file_with_home(
                &grant,
                &["sessions", "ws", "permission.toml"],
                Some(&link)
            ),
            Some(ProtectedEditReason::FuigoConfig)
        );
    }

    /// `protected_edit_reason` lowercases path components before matching.
    /// The canonical filename constants must stay lowercase or the const patterns silently stop firing.
    #[test]
    fn protected_config_filename_constants_are_lowercase() {
        for name in [
            fuigo_config::USER_CONFIG_FILENAME,
            fuigo_config::MANAGED_CONFIG_FILENAME,
            fuigo_config::REQUIREMENTS_FILENAME,
        ] {
            assert_eq!(name, name.to_ascii_lowercase(), "{name}");
        }
    }

    #[test]
    fn resolved_root_alias_matches_physical_destination() {
        let resolved_root = resolve_following_symlinks(Path::new("/etc")).unwrap();
        assert!(resolved_path_is_within_root(
            &resolved_root.join("fuigo-test"),
            Path::new("/etc")
        ));
        assert!(!resolved_path_is_within_root(
            Path::new("/tmp/fuigo-test"),
            Path::new("/etc")
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn private_etc_alias_requires_prompt() {
        assert!(edit_target_protection(Path::new("/private/etc/hosts")).is_some());
    }

    #[test]
    #[cfg(unix)]
    fn resolved_symlink_target_hits_read_deny() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret_dir = outside.path().join("prohibited-zone");
        std::fs::create_dir(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("data.txt"), b"secret").unwrap();
        symlink(&secret_dir, ws.path().join("linked")).unwrap();

        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/prohibited-zone/**",
        )]);
        let decision = policy.evaluate_shell_file_access("cat linked/data.txt", ws.path());
        assert!(
            matches!(decision, Some(Decision::Reject(_))),
            "read via a symlink to a denied dir must be rejected, got {decision:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn dangling_symlink_write_hits_edit_deny() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret_dir = outside.path().join("prohibited-zone");
        std::fs::create_dir(&secret_dir).unwrap();
        // Dangling link: target doesn't exist yet.
        symlink(secret_dir.join("new.txt"), ws.path().join("out")).unwrap();

        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/prohibited-zone/**",
        )]);
        let decision = policy.evaluate_shell_file_access("echo hi > out", ws.path());
        assert!(
            matches!(decision, Some(Decision::Reject(_))),
            "write through a dangling symlink into a denied dir must be rejected, got {decision:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn resolved_symlink_to_allowed_target_not_blocked() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir(ws.path().join("real")).unwrap();
        std::fs::write(ws.path().join("real/data.txt"), b"ok").unwrap();
        symlink(ws.path().join("real"), ws.path().join("linked")).unwrap();

        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/prohibited-zone/**",
        )]);
        assert!(
            policy
                .evaluate_shell_file_access("cat linked/data.txt", ws.path())
                .is_none(),
            "a symlink to a non-denied path must not be blocked"
        );
    }

    /// `..` after a symlink must resolve physically: `link/../dir2/x` where `link -> <zone>/dir` lands in `<zone>/dir2/x`, not `<cwd>/dir2/x`.
    #[test]
    #[cfg(unix)]
    fn resolved_symlink_dotdot_hits_read_deny() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let zone = outside.path().join("prohibited-zone");
        std::fs::create_dir_all(zone.join("dir")).unwrap();
        std::fs::create_dir_all(zone.join("dir2")).unwrap();
        std::fs::write(zone.join("dir2/x"), b"secret").unwrap();
        symlink(zone.join("dir"), ws.path().join("link")).unwrap();

        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/prohibited-zone/**",
        )]);
        let decision = policy.evaluate_shell_file_access("cat link/../dir2/x", ws.path());
        assert!(
            matches!(decision, Some(Decision::Reject(_))),
            "`..` after a symlink must resolve into the denied tree, got {decision:?}"
        );
    }

    /// An unresolvable operand (symlink cycle) fails closed to Ask rather than silently passing the gate.
    #[test]
    #[cfg(unix)]
    fn unresolvable_symlink_operand_asks() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        symlink(ws.path().join("b"), ws.path().join("a")).unwrap();
        symlink(ws.path().join("a"), ws.path().join("b")).unwrap();

        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/prohibited-zone/**",
        )]);
        let decision = policy.evaluate_shell_file_access("cat a", ws.path());
        assert!(
            matches!(decision, Some(Decision::Ask)),
            "unresolvable symlink operand must escalate to Ask, got {decision:?}"
        );
    }

    /// A *mid-path* symlink chain that can't be resolved (non-symlink leaf) must still fail closed to Ask, not skip the check.
    #[test]
    #[cfg(unix)]
    fn unresolvable_midpath_symlink_operand_asks() {
        use std::os::unix::fs::symlink;
        let ws = tempfile::tempdir().unwrap();
        // Directory-component cycle: `linkdir -> linkdir2 -> linkdir`
        symlink(ws.path().join("linkdir2"), ws.path().join("linkdir")).unwrap();
        symlink(ws.path().join("linkdir"), ws.path().join("linkdir2")).unwrap();

        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/prohibited-zone/**",
        )]);
        // Leaf `file.txt` is not itself a symlink; the link is the `linkdir` component.
        let decision = policy.evaluate_shell_file_access("cat linkdir/file.txt", ws.path());
        assert!(
            matches!(decision, Some(Decision::Ask)),
            "unresolvable mid-path symlink chain must escalate to Ask, got {decision:?}"
        );
    }

    #[test]
    fn shell_readers_hit_read_deny() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            "cat .env",
            "grep . .env",
            "head -n 5 .env",
            "sed -n 1p .env",
            "dd if=.env",
            "base64 .env",
            "sort < .env",
            "sort <.env",
            "grep -f .env README.md",
            "sed -f .env README.md",
            "awk -f .env README.md",
            // additional readers: dumpers, jq, PS/grep-alts, compressed
            "diff .env /dev/null",
            "comm .env /dev/null",
            "rev .env",
            "jq . .env",
            "select-string FAKE .env",
            "ag FAKE .env",
            "zcat .env",
            "zgrep FAKE .env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "expected deny for {cmd}"
            );
        }
    }

    #[test]
    fn shell_writers_hit_edit_deny() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/.env",
        )]);
        for cmd in [
            "tee .env",
            "dd of=.env",
            "Set-Content .env secret",
            "Out-File .env",
            "echo secret > .env",
            "echo secret >.env",
            "echo secret >>.env",
            "sed -i.bak s/FAKE/HACKED/ .env",
            "sed -ni s/FAKE/HACKED/ .env",
            "sort README.md -o .env",
            // Abbreviated long options and short-option clusters (getopt spellings of `--output`/`-o`).
            "sort README.md --out=.env",
            "sort README.md --outp .env",
            "sort README.md --o=.env",
            "sort -no .env README.md",
            "sort -ro .env README.md",
            "sort -ro.env README.md",
            "go build -o=.env ./cmd",
            "go build --o=.env ./cmd",
            "rustc -go .env main.rs",
            "rustc --out .env main.rs",
            "git archive -vo .env HEAD",
            "git -C . archive -vo.env HEAD",
            "git format-patch -no .env HEAD~1",
            "git diff --out=.env",
            "git log --outp .env",
            "git format-patch --output-directory=.env -1 HEAD",
            "git format-patch --output-directory .env -1 HEAD",
            "rustc --emit=link=.env main.rs",
            "git format-patch -M -o .env -1 HEAD",
            "git --namespace -- archive -o .env HEAD",
            "sort --temp -- -o .env README.md",
            "go build -tags -- -o .env ./cmd",
            "git -C repo -- format-patch -o .env HEAD",
            "git --git-dir /repo -- archive -o .env",
            "git format-patch -S -- -o .env HEAD~1",
            "git format-patch -v -- -o .env HEAD~1",
            "truncate -s 0 .env",
            "Tee-Object .env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "expected deny for {cmd}"
            );
        }
    }

    /// Write targets that `special_file_operands` finds for one whitespace-split command.
    fn output_flag_writes(cmd: &str) -> Vec<String> {
        let words: Vec<String> = cmd.split_whitespace().map(str::to_owned).collect();
        let program = words.first().cloned().unwrap_or_default();
        special_file_operands(&program, &words)
            .into_iter()
            .filter(|(_, mode)| matches!(mode, ShellFileMode::Write))
            .map(|(path, _)| path)
            .collect()
    }

    /// A git pickaxe value that looks like an output flag is not a write, so an Edit deny on the path stays quiet.
    #[test]
    fn git_pickaxe_value_is_not_an_edit() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/Cargo.toml",
        )]);
        let cmd = "git log -1 -pS --out Cargo.toml";
        assert!(
            !matches!(
                policy.evaluate_shell_file_access(cmd, cwd()),
                Some(Decision::Reject(_))
            ),
            "`{cmd}` must not hit an Edit deny on Cargo.toml"
        );
    }

    /// Auto-mode write detection sees the same output spellings, so they are never auto-allowed as read-only.
    #[test]
    fn output_flag_spellings_reach_auto_mode_write_paths() {
        let words =
            |cmd: &str| -> Vec<String> { cmd.split_whitespace().map(str::to_owned).collect() };
        for (cmd, path) in [
            ("sort a --out=w.txt", "w.txt"),
            ("sort -ro w.txt a", "w.txt"),
            ("git format-patch --output-directory=w -1", "w"),
            ("git archive -vo w.tar HEAD", "w.tar"),
            ("rustc --emit=link=w main.rs", "w"),
            ("sort a -o", ""),
            ("git format-patch -M -o w -1", "w"),
            ("git --namespace -- archive -o w HEAD", "w"),
            ("sort --temp -- -o w a", "w"),
            ("go build -tags -- -o w ./cmd", "w"),
            ("git -C repo -- format-patch -o w HEAD", "w"),
            ("git --git-dir /repo -- archive -o w", "w"),
            ("git format-patch -S -- -o w HEAD~1", "w"),
            ("git format-patch -v -- -o w HEAD~1", "w"),
        ] {
            assert!(
                command_words_write_paths(&words(cmd))
                    .iter()
                    .any(|p| p == path),
                "`{cmd}` must report a write to {path:?}"
            );
        }
        assert!(command_words_write_paths(&words("git status -uno")).is_empty());
        assert!(command_words_write_paths(&words("git log -1 -pS --out Cargo.toml")).is_empty());
    }

    /// S6: every spelling getopt_long / getopt / getopts accept for the output flag is a write,
    /// and an option letter that takes its own value hides a later `o` (no false write).
    #[test]
    fn output_flag_spellings_are_writes() {
        let cases: &[(&str, &[&str])] = &[
            // Exact and attached forms (unchanged behaviour).
            ("sort a -o out", &["out"]),
            ("sort a -oout", &["out"]),
            ("sort a --output=out", &["out"]),
            ("sort a --output out", &["out"]),
            // Abbreviated long options; an ambiguous one (git `--outp`) still counts.
            ("sort a --out=out", &["out"]),
            ("sort a --outp out", &["out"]),
            ("sort a --o out", &["out"]),
            ("git diff --outp out", &["out"]),
            ("git log --out=out", &["out"]),
            // getopt clusters: `-o` after plain flags takes the rest of the word or the next word.
            ("sort -ro out a", &["out"]),
            ("sort -rno out a", &["out"]),
            ("sort -rout a", &["ut"]),
            ("sort -o-x a", &["-x"]),
            ("rustc -go out main.rs", &["out"]),
            ("rustc -Ogoout main.rs", &["out"]),
            ("git archive -vo out HEAD", &["out"]),
            ("git -C . archive -9vo out HEAD", &["out"]),
            ("git format-patch -kno out HEAD~1", &["out"]),
            // Go's flag package: `-o=FILE` and `--o=FILE` mean `-o FILE`.
            ("go build -o=out ./cmd", &["out"]),
            ("go build --o=out ./cmd", &["out"]),
            // rustc `--out-dir` and its abbreviations.
            ("rustc --out-dir=d main.rs", &["d"]),
            ("rustc --out-d d main.rs", &["d"]),
            // git `--output-directory` (format-patch) in full and abbreviated (Astra R1 HIGH).
            ("git format-patch --output-directory=out -1", &["out"]),
            ("git format-patch --output-directory out -1", &["out"]),
            ("git format-patch --output-dir out -1", &["out"]),
            // git keeps a literal `=`: only Go strips it (Astra R1 HIGH).
            ("git -c alias.a=archive a -o=blocked HEAD", &["=blocked"]),
            ("git archive -o=out HEAD", &["=out"]),
            ("sort a -o=out", &["=out"]),
            // rustc `--emit TYPE=PATH`.
            ("rustc --emit=link=out main.rs", &["out"]),
            ("rustc --emit obj=o1,link=o2 main.rs", &["o1", "o2"]),
            // An optional-argument letter never consumes the next word, and scanning starts after the git verb
            // (Astra R2 HIGH).
            ("git format-patch -M -o out -1", &["out"]),
            ("git format-patch -C -B -X -U -o out -1", &["out"]),
            ("git --namespace -- archive -o out HEAD", &["out"]),
            // A `--` that may be an option's value does not end the scan (Astra R3 HIGH).
            ("sort --temp -- -o out a", &["out"]),
            ("go build -tags -- -o out ./cmd", &["out"]),
            // Round 4 (Grok 4.7): a `--` among git's global options ends them; the next word is the verb.
            ("git -C repo -- format-patch -o out HEAD", &["out"]),
            ("git -- format-patch -o out", &["out"]),
            ("git -c x=y -- diff --output out", &["out"]),
            ("git --git-dir /repo -- archive -o out", &["out"]),
            ("git --git-dir=/repo -- archive -o out", &["out"]),
            ("git --git-d /repo -- archive -vo out", &["out"]),
            ("git --namespace foo -- archive -o out", &["out"]),
            // format-patch `-v` takes the next word even when it is `--` (git 2.50: `-v -- -o od` writes od).
            ("git format-patch -v -- -o out HEAD~1", &["out"]),
            // `-S` and the other diff letters do not take a following `-o` (git 2.50: `-S -o od` writes od), and a
            // `--` after a value letter may be its value, so the scan goes on.
            ("git format-patch -S -o out HEAD~1", &["out"]),
            ("git format-patch -S -- -o out HEAD~1", &["out"]),
            ("git format-patch -pS -- -o out HEAD~1", &["out"]),
            // A missing value is still a write (empty path), never silently dropped.
            ("sort a -o", &[""]),
            ("sort a --out", &[""]),
            ("sort a -ro", &[""]),
        ];
        for (cmd, expected) in cases {
            assert_eq!(output_flag_writes(cmd), *expected, "writes of `{cmd}`");
        }
        // Not writes: the `o` is a value of an earlier letter, or the program does not cluster.
        for cmd in [
            "sort -to a b",
            "sort -k1o a",
            "sort -So a",
            "rustc -Copt-level=3 main.rs",
            "rustc -Lnative=/opt/lib main.rs",
            "git status -uno",
            "git format-patch -vo HEAD~1",
            "go test -json ./...",
            "sort --check a",
            "git diff --output-indicator-new=x",
            // The verb is the first word after git's global options, not any word (Astra R1 MEDIUM).
            "git status -uno .env archive",
            "git -C archive status -uno",
            // Global-option values are never rescanned as the verb's options.
            "git --git-dir -o status",
            // `--` ends options, and a word consumed as another option's value is not a flag (Astra R1 MEDIUM).
            "sort -- -ro .env",
            "go build -- -o=out",
            "git log --grep --out -1",
            "sort -t -o out",
            "sort --key -o out",
            "rustc --emit=link main.rs",
            // Values of `-S` and `--remap-path-prefix` are not rescanned as flags (Astra R2 MEDIUM).
            "git log -1 -S --out Cargo.toml",
            "git log -G -o x",
            "rustc --remap-path-prefix --emit=link=.env --print=cfg",
            // A clustered git pickaxe takes the next word (Astra R3 MEDIUM).
            "git log -1 -pS --out Cargo.toml",
            // format-patch `-v` takes `-o` as its value (git 2.50: no write).
            "git format-patch -v -o x HEAD~1",
        ] {
            assert!(
                output_flag_writes(cmd).is_empty(),
                "`{cmd}` must not report an output write, got {:?}",
                output_flag_writes(cmd)
            );
        }
    }

    #[test]
    fn inline_shells_hit_read_and_edit_denies() {
        let read = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        let mut commands: Vec<String> = ["bash", "sh", "dash", "zsh", "ksh"]
            .into_iter()
            .map(|shell| format!("{shell} -c 'cat .env'"))
            .collect();
        commands.extend([
            r#"/bin/bash -c 'cat .env'"#.to_owned(),
            r#"bash -lc 'cat .env'"#.to_owned(),
            r#"bash -c -x 'cat .env'"#.to_owned(),
            r#"bash -c -- 'cat .env'"#.to_owned(),
            r#"bash -c -o pipefail 'cat .env'"#.to_owned(),
            r#"bash -c -O extglob 'cat .env'"#.to_owned(),
            r#"bash -c -Oextglob 'cat .env'"#.to_owned(),
            r#"bash -c +O extglob 'cat .env'"#.to_owned(),
            r#"bash -c +Oextglob 'cat .env'"#.to_owned(),
            r#"bash -c +o pipefail 'cat .env'"#.to_owned(),
            r#"timeout 5 bash -c 'cat .env'"#.to_owned(),
            r#"bash -c "sh -c 'cat .env'""#.to_owned(),
            r#"bash -c 'cat .env' "$IGNORED""#.to_owned(),
        ]);
        for cmd in commands {
            assert!(
                matches!(
                    read.evaluate_shell_file_access(&cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "inline read must be denied: {cmd}"
            );
        }
        for cmd in [
            r#"bash -- -c 'cat .env'"#,
            r#"bash script.sh -c 'cat .env'"#,
        ] {
            assert!(
                read.evaluate_shell_file_access(cmd, cwd()).is_none(),
                "non-inline shell form must stay unchanged: {cmd}"
            );
        }
        let edit = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/.env",
        )]);
        assert!(matches!(
            edit.evaluate_shell_file_access(r#"bash -c 'echo secret > .env'"#, cwd()),
            Some(Decision::Reject(_))
        ));
    }

    #[test]
    fn untrusted_inline_shells_ask() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            r#"bash -c "$SCRIPT" 'cat .env'"#,
            r#"env FOO=1 bash -c "$SCRIPT""#,
            "bash -c",
            "bash -c 'cat",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "untrusted inline script must ask: {cmd}"
            );
        }

        assert!(
            policy
                .evaluate_shell_file_access(r#"bash -c 'bash -c '\''cat README.md'\'''"#, cwd(),)
                .is_none(),
            "concatenated literal script operands remain recursively analyzable"
        );

        let malformed_control = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "/unrelated/secret",
        )]);
        assert!(
            malformed_control
                .evaluate_shell_file_access("echo 'unterminated", cwd())
                .is_none(),
            "top-level malformed non-inline command keeps legacy behavior"
        );

        let mut nested = "cat README.md".to_owned();
        for _ in 0..MAX_INLINE_SHELL_DEPTH {
            nested = format!("bash -c {}", shell_quote(&nested));
        }
        assert!(
            policy.evaluate_shell_file_access(&nested, cwd()).is_none(),
            "the maximum supported nesting remains analyzable"
        );
        nested = format!("bash -c {}", shell_quote(&nested));
        assert!(matches!(
            policy.evaluate_shell_file_access(&nested, cwd()),
            Some(Decision::Ask)
        ));

        let deny = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        let mut nested = "cat .env".to_owned();
        for _ in 0..=MAX_INLINE_SHELL_DEPTH {
            nested = format!("bash -c {}", shell_quote(&nested));
        }
        let cmd = format!("{nested}; cat .env");
        assert!(matches!(
            deny.evaluate_shell_file_access(&cmd, cwd()),
            Some(Decision::Reject(_))
        ));
    }

    fn shell_quote(script: &str) -> String {
        format!("'{}'", script.replace('\'', r#"'\''"#))
    }

    #[test]
    fn wrapper_depth_exhaustion_asks() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        let wrapped = |depth: usize| format!("{}bash -c 'cat README.md'", "env ".repeat(depth));
        assert!(
            policy
                .evaluate_shell_file_access(&wrapped(MAX_WRAPPER_DEPTH), cwd())
                .is_none(),
            "maximum canonical wrapper depth remains analyzable"
        );
        assert!(matches!(
            policy.evaluate_shell_file_access(&wrapped(MAX_WRAPPER_DEPTH + 1), cwd()),
            Some(Decision::Ask)
        ));
    }

    /// Opaque `env -S`, dynamic program `-c`, transparent prefixes, escape folding.
    #[test]
    fn inline_shell_opaque_and_transparent_forms_escalate() {
        let read = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        let must_escalate = |cmd: &str| {
            assert!(
                matches!(
                    read.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_)) | Some(Decision::Ask)
                ),
                "must not fail open: {cmd}"
            );
        };

        // env -S / --split-string is opaque (no packed reparse).
        for cmd in [
            "env -S 'cat .env'",
            r#"env -S 'bash -c "cat .env"'"#,
            "env --split-string 'cat .env'",
            "env --split-string=cat",
            "env -Scat",
            "/usr/bin/env -S 'cat .env'",
            "timeout 5 env -S 'cat .env'",
            "env -S",
        ] {
            must_escalate(cmd);
        }
        // Ordinary env assignment / peel still Rejects the reader.
        assert!(matches!(
            read.evaluate_shell_file_access("env FOO=1 cat .env", cwd()),
            Some(Decision::Reject(_))
        ));
        assert!(matches!(
            read.evaluate_shell_file_access("env cat .env", cwd()),
            Some(Decision::Reject(_))
        ));
        // Reject still wins over an opaque Ask floor.
        assert!(matches!(
            read.evaluate_shell_file_access("env -S 'cat README.md'; cat .env", cwd()),
            Some(Decision::Reject(_))
        ));

        // Untrusted program head with a supported `-c` shape escalates.
        for cmd in [
            r#"$SHELL -c 'cat .env'"#,
            r#"$(echo bash) -c 'cat .env'"#,
            r#"$SHELL -lc 'cat .env'"#,
            r#"timeout 5 $SHELL -c 'cat .env'"#,
        ] {
            must_escalate(cmd);
        }
        // Dynamic head without an inline `-c` shape is not a global Ask.
        assert!(
            read.evaluate_shell_file_access(r#"$CMD README.md"#, cwd())
                .is_none(),
            "dynamic non-inline program must stay inert"
        );

        // Transparent exec/command/builtin prefixes (outer and in-script)
        for cmd in [
            "bash -c 'exec cat .env'",
            "bash -c 'command cat .env'",
            "bash -c 'builtin cat .env'",
            "exec bash -c 'cat .env'",
            "command bash -c 'cat .env'",
            "command cat .env",
            "exec cat .env",
            "command -p cat .env",
            "exec -a name cat .env",
            "bash -c 'command -p cat .env'",
            "bash -c 'exec bash -c \"cat .env\"'",
        ] {
            must_escalate(cmd);
        }
        // Display forms of `command` are not peeled into readers.
        assert!(
            read.evaluate_shell_file_access("command -v cat", cwd())
                .is_none(),
            "command -v display form must not invent a read"
        );
        // Unknown prefix options fail closed.
        must_escalate("exec -u cat .env");
        must_escalate("command -Z cat .env");

        // Eight peels reach the reader; a ninth Asks.
        let nested_exec = |depth: usize| format!("{}cat .env", "exec ".repeat(depth));
        assert!(
            matches!(
                read.evaluate_shell_file_access(&nested_exec(MAX_TRANSPARENT_PREFIX_DEPTH), cwd()),
                Some(Decision::Reject(_))
            ),
            "maximum transparent prefix depth must still reach the denied reader"
        );
        assert!(
            matches!(
                read.evaluate_shell_file_access(
                    &nested_exec(MAX_TRANSPARENT_PREFIX_DEPTH + 1),
                    cwd()
                ),
                Some(Decision::Ask)
            ),
            "one extra transparent prefix must fail closed"
        );
        // Mixed / path-qualified prefixes at the supported budget still Reject.
        let mixed = format!(
            "{}cat .env",
            "exec command builtin /usr/bin/exec ".repeat(MAX_TRANSPARENT_PREFIX_DEPTH / 4)
        );
        assert!(
            matches!(
                read.evaluate_shell_file_access(&mixed, cwd()),
                Some(Decision::Reject(_))
            ),
            "mixed path-qualified transparent prefixes within budget must Reject"
        );
        // Reject still beats transparent-depth exhaustion Ask.
        let exhausted_then_deny = format!(
            "{}; cat .env",
            nested_exec(MAX_TRANSPARENT_PREFIX_DEPTH + 1).replace("cat .env", "cat README.md")
        );
        assert!(
            matches!(
                read.evaluate_shell_file_access(&exhausted_then_deny, cwd()),
                Some(Decision::Reject(_))
            ),
            "a later denied reader must beat transparent exhaustion Ask"
        );

        // Shell escapes fold before program/flag/path matching.
        for cmd in [
            r#"b\ash -c 'cat .env'"#,
            r#"bash \-c 'cat .env'"#,
            r#"bash -c "cat .en\\v""#,
            r#"bash -c "b\\ash -c 'cat .env'""#,
        ] {
            must_escalate(cmd);
        }
        // Single quotes stay literal (no escape fold).
        assert!(
            read.evaluate_shell_file_access(r#"cat '.en\v'"#, cwd())
                .is_none(),
            "single-quoted backslash must remain literal"
        );
    }

    #[test]
    fn shell_gate_merges_decisions_so_deny_beats_earlier_ask() {
        // The whole command runs once approved, so a later deny must beat an earlier ask.
        let policy = compiled(vec![
            file_rule(RuleAction::Ask, ToolFilter::Edit, "**/dump.txt"),
            file_rule(RuleAction::Ask, ToolFilter::Read, "**/notes.txt"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.env"),
        ]);
        for cmd in [
            // Redirect target (checked first) asks; the read operand denies.
            "cat .env > dump.txt",
            // First operand asks; the second denies.
            "cat notes.txt .env",
            // Outer read asks; recursively discovered inner read denies.
            "cat notes.txt; bash -c 'cat .env'",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "deny on a later path must win over an earlier ask for {cmd}"
            );
        }
    }

    #[test]
    fn shell_in_place_sed_enforces_read_deny() {
        // `sed -i` reads each operand before rewriting it, so a Read deny must block it.
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in ["sed -i s/FAKE/X/ .env", "sed -ni s/FAKE/X/ .env"] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "in-place sed must honor a Read deny for {cmd}"
            );
        }
    }

    #[test]
    fn powershell_and_windows_path_readers_hit_read_deny() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            "Get-Content .env",
            "gc .env",
            "type .env",
            "more .env",
            "Get-Content C:\\Users\\alice\\repo\\.env",
            "Get-Content /c/Users/alice/repo/.env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "expected deny for {cmd}"
            );
        }
    }

    /// A relative operand after any in-shell `cd`/`pushd`/`env -C` is unpinnable and must Ask.
    /// Only path-scoped rules are affected; basename denies still fire.
    #[test]
    fn shell_cwd_change_escalates_path_scoped_operands() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "/repo-b/.env", // path-scoped: matching would need the untracked cd target
        )]);
        let session = std::path::Path::new("/repo-a");
        for cmd in [
            "cd /repo-b && cat .env",                 // cd in the current shell
            "pushd /repo-b; cat .env",                // pushd is never folded
            "if true; then cd /repo-b; fi; cat .env", // conditional cd
            "env -C /repo-b cat .env",                // env chdir wrapper
            "env --chdir=/repo-b cat .env",
            "/usr/bin/env -C /repo-b cat .env", // path-qualified env
            "env FOO=1 -C /repo-b cat .env",    // chdir after an assignment
            "cd /repo-b && echo x > .env",      // redirect operand too
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, session),
                    Some(Decision::Ask)
                ),
                "an unpinnable cwd change must escalate: {cmd}"
            );
        }
    }

    #[test]
    fn inline_shell_cwd_uncertainty_preserves_rejects() {
        let exact = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "/repo-a/.env",
        )]);
        for cmd in [
            r#"cd /repo-b && bash -c 'cat .env'"#,
            r#"env -C /repo-b bash -c 'cat .env'"#,
            r#"(cd /repo-b; bash -c 'cat .env')"#,
            r#"bash -c 'cd /repo-b && cat .env'"#,
            r#"bash -c '(cd /repo-b; cat .env)'"#,
        ] {
            assert!(
                matches!(
                    exact.evaluate_shell_file_access(cmd, std::path::Path::new("/repo-a")),
                    Some(Decision::Ask)
                ),
                "relative inline path under an unpinned cwd must ask: {cmd}"
            );
        }

        let basename = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            r#"cd /repo-b && bash -c 'cat .env'"#,
            r#"(cd /repo-b; bash -c 'cat .env')"#,
            r#"bash -c 'cd /repo-b && cat .env'"#,
            r#"bash -c '(cd /repo-b; cat .env)'"#,
        ] {
            assert!(matches!(
                basename.evaluate_shell_file_access(cmd, std::path::Path::new("/repo-a")),
                Some(Decision::Reject(_))
            ));
        }

        let absolute = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "/repo-b/.env",
        )]);
        assert!(matches!(
            absolute.evaluate_shell_file_access(
                r#"env -C /elsewhere bash -c 'cat /repo-b/.env'"#,
                std::path::Path::new("/repo-a"),
            ),
            Some(Decision::Reject(_))
        ));
    }

    /// A `**/` basename deny matches regardless of cwd, so a `cd`/`env -C` can't smuggle a denied read past the gate.
    #[test]
    fn shell_basename_deny_survives_cwd_change() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        let session = std::path::Path::new("/repo-a");
        for cmd in [
            "cd /repo-b && cat .env",
            "env -C /repo-b cat .env",
            "pushd /repo-b; cat .env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, session),
                    Some(Decision::Reject(_))
                ),
                "a basename deny must still fire under a cwd change: {cmd}"
            );
        }
    }

    /// A `cd` in a pipeline/subshell/backgrounded `&` doesn't change a sibling's cwd.
    /// Their reads resolve against the original cwd, not the `cd` target.
    #[test]
    fn shell_cd_does_not_scope_across_pipe_subshell_or_background() {
        // Deny is scoped to the original cwd (`/work`), where the reader runs.
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "/work/secret.env",
        )]);
        for cmd in [
            "cd /elsewhere | cat secret.env",  // pipeline segment: own subshell
            "(cd /elsewhere); cat secret.env", // subshell ended with `;`
            "cd /elsewhere & cat secret.env",  // backgrounded cd
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "cd must not scope across boundary: {cmd}"
            );
        }
        // A deny scoped to the cd target must not fire; the reader never runs there
        let elsewhere = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "/elsewhere/secret.env",
        )]);
        assert!(
            elsewhere
                .evaluate_shell_file_access("cd /elsewhere | cat secret.env", cwd())
                .is_none(),
            "reader runs in the original cwd, so the cd-target deny must not match"
        );
    }

    /// After `--`, tokens are positional even when they start with `-`.
    /// A path like `-/../.env` must still be deny-checked (not skipped as a flag).
    #[test]
    fn shell_double_dash_end_of_options_extracts_paths() {
        let read = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        assert!(matches!(
            read.evaluate_shell_file_access("cat -- -/../.env", cwd()),
            Some(Decision::Reject(_))
        ));
        let edit = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/.env",
        )]);
        assert!(matches!(
            edit.evaluate_shell_file_access("rm -- -/../.env", cwd()),
            Some(Decision::Reject(_))
        ));
    }

    /// `cp`/`mv`/`ln`/`install`/`rm`/`touch` move/destroy files: sources are reads (exfil), destinations are writes.
    #[test]
    fn shell_path_commands_hit_deny() {
        // Reading a denied source (exfil via copy/move) is caught by a Read deny.
        let read = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            "cp .env /tmp/x",
            "mv .env /tmp/exfil",
            "install .env /tmp/x",
        ] {
            assert!(
                matches!(
                    read.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "source read must be denied: {cmd}"
            );
        }
        // Writing/deleting a denied path is caught by an Edit deny.
        let edit = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Edit,
            "**/.env",
        )]);
        for cmd in [
            "rm .env",
            "touch .env",
            "mkdir .env",
            "cp src .env",
            "ln -s src .env",
        ] {
            assert!(
                matches!(
                    edit.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "write/delete must be denied: {cmd}"
            );
        }
        // A copy source is a read, not an edit: an Edit-only deny must not fire.
        assert!(
            edit.evaluate_shell_file_access("cp .env /tmp/x", cwd())
                .is_none(),
            "copying a source only reads it, so an Edit-only deny must not match"
        );
    }

    /// A reader whose operand can't be pinned (glob, recursive search, expansion) prompts.
    #[test]
    fn ambiguous_known_reader_prompts_when_path_cannot_be_pinned() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in ["cat *.env", "grep -r secret .", "cat \"$HOME/.env\""] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "unpinnable reader must prompt: {cmd}"
            );
        }
    }

    /// A positional `=`-operand is a filename (deny-checked); only leading `VAR=value` assignments are dropped by the AST.
    #[test]
    fn shell_reader_checks_equals_containing_operand() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/data=*.env",
        )]);
        assert!(
            matches!(
                policy.evaluate_shell_file_access("cat data=v1.env", cwd()),
                Some(Decision::Reject(_))
            ),
            "operand containing = must be deny-checked"
        );
        // A leading assignment is not an operand, so it isn't treated as a file.
        assert!(
            policy
                .evaluate_shell_file_access("FOO=data=v1.env cat README.md", cwd())
                .is_none()
        );
    }

    /// An expansion nested in a quoted/concatenated operand (`.e"$X"`) is ambiguous and prompts, not treated as a literal.
    #[test]
    fn shell_nested_expansion_operand_prompts() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in ["cat .e\"$X\"", "cat .e\"$(echo nv)\"", "cat pre\"${X}\"suf"] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "nested expansion must be ambiguous and prompt: {cmd}"
            );
        }
    }

    /// `rg`/`ag`/`ack` recurse a directory (no path, `.`, or `dir/`), so a Read deny on a path they could reach must prompt.
    /// A single file operand scopes them.
    #[test]
    fn shell_recursive_readers_prompt_for_directory_search() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            "rg secret",      // no path: searches cwd
            "ack secret",     // no path
            "rg secret .",    // directory operand
            "rg secret src/", // directory operand
            "ag secret .",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "recursive directory search must prompt: {cmd}"
            );
        }
        assert!(
            policy
                .evaluate_shell_file_access("rg secret README.md", cwd())
                .is_none(),
            "a single file operand scopes the search"
        );
    }

    /// Arbitrary interpreters run code we don't parse, so reads inside them fall through.
    #[test]
    fn non_reader_is_not_covered_by_shell_gate() {
        let policy = compiled(vec![file_rule(
            RuleAction::Deny,
            ToolFilter::Read,
            "**/.env",
        )]);
        for cmd in [
            "python -c \"open('.env').read()\"",
            "node -e \"require('fs').readFileSync('.env')\"",
        ] {
            assert!(
                policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
                "expected no shell gate decision for {cmd}"
            );
        }
    }

    /// Representative enterprise deny/ask fixture for managed-policy tests `[permission]` tier.
    /// Tool mapping: `Read` to Read, `Write`/`Edit` to Edit, `Bash` to Bash.
    fn enterprise_requirements_policy() -> CompiledPolicy {
        compiled(vec![
            // ── ask = [...] ──
            bash_rule(RuleAction::Ask, "kubectl *"),
            bash_rule(RuleAction::Ask, "terraform apply *"),
            bash_rule(RuleAction::Ask, "aws *"),
            bash_rule(RuleAction::Ask, "gcloud *"),
            bash_rule(RuleAction::Ask, "az *"),
            bash_rule(RuleAction::Ask, "ssh *"),
            bash_rule(RuleAction::Ask, "security *"),
            bash_rule(RuleAction::Ask, "op *"),
            file_rule(RuleAction::Ask, ToolFilter::Read, "**/secrets/**"),
            file_rule(RuleAction::Ask, ToolFilter::Edit, "**/secrets/**"), // Write(..)
            file_rule(RuleAction::Ask, ToolFilter::Edit, "**/secrets/**"), // Edit(..)
            file_rule(RuleAction::Ask, ToolFilter::Read, "**/Library/Mail/**"),
            // ── deny = [...] ──
            bash_rule(RuleAction::Deny, "rm -rf *"),
            bash_rule(RuleAction::Deny, "sudo *"),
            bash_rule(RuleAction::Deny, "su *"),
            bash_rule(RuleAction::Deny, "ssh *.corp.example"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.env"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.env.*"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.pem"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.key"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.p12"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.pfx"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.jks"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/*.keystore"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.ssh/**"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.aws/**"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.config/gcloud/**"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.kube/**"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.internal-deploy/**"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/.git-credentials"),
            file_rule(RuleAction::Deny, ToolFilter::Read, "**/terraform.tfstate"),
            file_rule(
                RuleAction::Deny,
                ToolFilter::Read,
                "**/terraform.tfstate.backup",
            ),
            file_rule(
                RuleAction::Deny,
                ToolFilter::Read,
                "**/Library/Keychains/**",
            ),
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.env*"), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.ssh/**"), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/*.pem"), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/*.key"), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/*.p12"), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.internal-deploy/**"), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/terraform.tfstate"), // Write(..)
            file_rule(
                RuleAction::Deny,
                ToolFilter::Edit,
                "**/terraform.tfstate.backup",
            ), // Write(..)
            file_rule(
                RuleAction::Deny,
                ToolFilter::Edit,
                "**/Library/Keychains/**",
            ), // Write(..)
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.env"),
            file_rule(RuleAction::Deny, ToolFilter::Edit, "**/.env.*"),
        ])
    }

    /// fd-prefixed/glued READ redirects must still hit the Read deny via the AST walk.
    #[test]
    fn adversarial_fd_and_glued_read_redirects_denied() {
        let policy = enterprise_requirements_policy();
        for cmd in [
            "cat 0<.env",
            "cat 0< .env",
            "cat<.env",
            "grep secret 0<.env",
            "sort 0< .env",
            "head -n1 0<.env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "read redirect must be denied: {cmd}"
            );
        }
    }

    /// fd-prefixed / glued WRITE redirects (truncate, append, stderr, both-streams) must hit the Edit deny.
    #[test]
    fn adversarial_fd_and_glued_write_redirects_denied() {
        let policy = enterprise_requirements_policy();
        for cmd in [
            "echo x 1>.env",
            "echo x 1> .env",
            "echo x 2>.env",
            "echo x 2> .env",
            "echo x &>.env",
            "echo x &> .env",
            "echo x 1>>.env",
            "echo x>>.env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "write redirect must be denied: {cmd}"
            );
        }
    }

    #[test]
    fn adversarial_fd_duplication_and_numeric_filenames() {
        let parsed = |cmd: &str| {
            let tree = try_parse_shell(cmd).expect("shell parses");
            command_write_paths_in_tree(tree.root_node(), cmd)
        };
        assert!(parsed("cat payload 2>&1").is_empty());
        assert!(parsed("cat payload 1>&-").is_empty());
        assert!(parsed("cat payload 0<&3").is_empty());
        assert_eq!(parsed("cat payload > 3"), vec!["3"]);
    }

    /// An outer reader fed a substitution can't pin its operand (Ask); an inner literal read (incl. inside `<(…)`) is a hard deny.
    #[test]
    fn adversarial_substitution_readers_do_not_bypass() {
        let policy = enterprise_requirements_policy();
        for cmd in [
            "cat $(echo .env)",
            "xxd `echo .env`",
            "cut -d= -f2 $(echo .env)",
            "tac $(printf .env)",
            "nl $(echo .env)",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "substitution reader must prompt: {cmd}"
            );
        }
        for cmd in [
            "echo $(cat .env)",
            "echo `cat .env`",
            "echo $(base64 key.pem)",
            "diff <(cat .env) x",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "inner literal read must be denied: {cmd}"
            );
        }
    }

    /// Enterprise-policy coverage beyond the single-rule tests.
    #[test]
    fn adversarial_enterprise_matrix_denies_and_asks() {
        let policy = enterprise_requirements_policy();
        for cmd in [
            // readers only covered here
            "tail -n1 .env",
            "strings .env",
            "wc -c .env",
            "od -An .env",
            "xxd .env",
            "hexdump -C .env",
            "tac .env",
            "nl .env",
            // non-.env deny globs (*.pem, .ssh/**, .aws/**, .kube/**)
            "cat key.pem",
            "cat .ssh/id_rsa",
            "cat .aws/credentials",
            "cat .kube/config",
            // wrapper stripping / program basename
            "/bin/cat .env",
            "env FOO=1 cat .env",
            "timeout 5 cat .env",
            // path normalization and `..` traversal
            "cat ./.env",
            "cat subdir/../.env",
            // chaining / pipeline, checked per segment
            "ls && cat .env",
            "cat README.md; cat .env",
            "cat .env | head -n1",
            // case-insensitive command match
            "GET-CONTENT .env",
        ] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Reject(_))
                ),
                "must deny: {cmd}"
            );
        }
        // Ask rules reached through the shell gate (Read and Edit on **/secrets/**)
        for cmd in ["cat secrets/value.txt", "echo x > secrets/new.txt"] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "must ask: {cmd}"
            );
        }
    }

    /// Decision-level mirror of the managed-config e2e.
    /// Asserts the `Decision` the manager computes on the real sentinel paths, no inference.
    /// Covers all four entry points: read tool, write/edit tools, bash rules, shell gate.
    #[test]
    fn live_enterprise_e2e_matrix_decision_parity() {
        // What the model can do and the manager function that decides it
        #[derive(Clone, Copy)]
        enum Vector {
            /// File-read tool / list_dir: `evaluate(AccessKind::Read(..))`.
            ReadTool(&'static str),
            /// write / search_replace / apply_patch: `evaluate(AccessKind::Edit(..))`.
            EditTool(&'static str),
            /// Bash command rules: `evaluate(AccessKind::Bash(..))`.
            Bash(&'static str),
            /// Shell file args: `evaluate_shell_file_access(cmd, cwd)`.
            Shell(&'static str),
        }
        #[derive(Clone, Copy)]
        enum Expect {
            /// Managed deny means `Reject(_)` (the live SENTINEL must never leak).
            Deny,
            /// Managed ask means `Ask` (the live model is prompted).
            Ask,
            /// Not denied/asked means `None` (the live file stays readable / command runs).
            Allowed,
        }
        use Expect::{Allowed, Ask, Deny};
        use Vector::{Bash, EditTool, ReadTool, Shell};

        let policy = enterprise_requirements_policy();
        let matrix: &[(&str, Vector, Expect)] = &[
            // ── file-read tool: real sentinel files (setup.sh) ──
            ("read .env", ReadTool(".env"), Deny),
            ("read .env.staging", ReadTool(".env.staging"), Deny), // **/.env.*
            ("read src/server.pem", ReadTool("src/server.pem"), Deny), // **/*.pem
            (
                "read terraform.tfstate",
                ReadTool("terraform.tfstate"),
                Deny,
            ),
            (
                "read secrets/api_key.txt",
                ReadTool("secrets/api_key.txt"),
                Ask,
            ), // **/secrets/**
            ("read README.md (neg)", ReadTool("README.md"), Allowed),
            ("read src/main.py (neg)", ReadTool("src/main.py"), Allowed),
            // ── file-read tool: every remaining deny/ask glob in the policy ──
            ("read *.key", ReadTool("config/id_rsa.key"), Deny),
            ("read *.p12", ReadTool("cert.p12"), Deny),
            ("read *.pfx", ReadTool("cert.pfx"), Deny),
            ("read *.jks", ReadTool("keystore.jks"), Deny),
            ("read *.keystore", ReadTool("app.keystore"), Deny),
            ("read .ssh/**", ReadTool(".ssh/id_rsa"), Deny),
            ("read .aws/**", ReadTool(".aws/credentials"), Deny),
            (
                "read .config/gcloud/**",
                ReadTool(".config/gcloud/access_tokens.db"),
                Deny,
            ),
            ("read .kube/**", ReadTool(".kube/config"), Deny),
            (
                "read .internal-deploy/**",
                ReadTool(".internal-deploy/config"),
                Deny,
            ),
            ("read .git-credentials", ReadTool(".git-credentials"), Deny),
            (
                "read terraform.tfstate.backup",
                ReadTool("terraform.tfstate.backup"),
                Deny,
            ),
            (
                "read Library/Keychains/**",
                ReadTool("Library/Keychains/login.keychain-db"),
                Deny,
            ),
            (
                "read Library/Mail/** (ask)",
                ReadTool("Library/Mail/Inbox.mbox"),
                Ask,
            ),
            // ── file-read tool: lookalike negatives (must NOT match) ──
            ("read key.pem.txt (neg)", ReadTool("key.pem.txt"), Allowed),
            (
                "read my.env.example (neg)",
                ReadTool("my.env.example"),
                Allowed,
            ),
            // ── write/edit tool: Write(..)/Edit(..) denies + secrets ask ──
            ("edit .env", EditTool(".env"), Deny),
            ("edit .env.local", EditTool(".env.local"), Deny), // **/.env* and **/.env.*
            ("edit src/server.pem", EditTool("src/server.pem"), Deny), // Write(**/*.pem)
            ("edit *.key", EditTool("config/id_rsa.key"), Deny),
            ("edit *.p12", EditTool("cert.p12"), Deny),
            (
                "edit terraform.tfstate",
                EditTool("terraform.tfstate"),
                Deny,
            ),
            ("edit .ssh/**", EditTool(".ssh/authorized_keys"), Deny),
            (
                "edit .internal-deploy/**",
                EditTool(".internal-deploy/config"),
                Deny,
            ),
            (
                "edit Library/Keychains/**",
                EditTool("Library/Keychains/login.keychain-db"),
                Deny,
            ),
            (
                "edit secrets/** (ask)",
                EditTool("secrets/api_key.txt"),
                Ask,
            ),
            // Real-policy asymmetry: *.pfx/*.jks/*.keystore are Read-denied but have NO Write rule, so editing them is allowed (faithful to deploy)
            ("edit *.pfx (no write rule)", EditTool("cert.pfx"), Allowed),
            ("edit README.md (neg)", EditTool("README.md"), Allowed),
            ("edit src/main.py (neg)", EditTool("src/main.py"), Allowed),
            // ── bash command rules: deny set ──
            ("bash rm -rf", Bash("rm -rf /tmp/x"), Deny),
            ("bash sudo", Bash("sudo apt-get update"), Deny),
            ("bash su", Bash("su - root"), Deny),
            // ssh to *.corp.example is deny even though `ssh *` is ask (deny wins).
            ("bash ssh corp-example", Bash("ssh prod.corp.example"), Deny),
            // ── bash command rules: ask set ──
            ("bash kubectl", Bash("kubectl get pods -A"), Ask),
            (
                "bash terraform apply",
                Bash("terraform apply -auto-approve"),
                Ask,
            ),
            ("bash aws", Bash("aws s3 ls"), Ask),
            ("bash gcloud", Bash("gcloud auth list"), Ask),
            ("bash az", Bash("az account show"), Ask),
            ("bash ssh (non-corp-example)", Bash("ssh user@host"), Ask),
            (
                "bash security",
                Bash("security find-generic-password -s x"),
                Ask,
            ),
            ("bash op", Bash("op read op://vault/item"), Ask),
            // ── bash command rules: negatives ──
            ("bash ls (neg)", Bash("ls -la"), Allowed),
            ("bash git status (neg)", Bash("git status"), Allowed),
            // ── shell file-access gate: readers / redirects / substitutions ──
            ("sh cat .env", Shell("cat .env"), Deny),
            ("sh cat .env.staging", Shell("cat .env.staging"), Deny),
            ("sh cat src/server.pem", Shell("cat src/server.pem"), Deny),
            (
                "sh cat terraform.tfstate",
                Shell("cat terraform.tfstate"),
                Deny,
            ),
            ("sh grep FAKE .env", Shell("grep FAKE .env"), Deny),
            ("sh base64 .env", Shell("base64 .env"), Deny),
            ("sh cat 0<.env", Shell("cat 0<.env"), Deny), // fd-prefixed read redirect
            ("sh cat<.env", Shell("cat<.env"), Deny),     // glued read redirect
            ("sh cat $(echo .env)", Shell("cat $(echo .env)"), Ask), // unpinnable substitution
            (
                "sh diff <(cat .env)",
                Shell("diff <(cat .env) /dev/null"),
                Deny,
            ), // process sub
            ("sh cat subdir/../.env", Shell("cat subdir/../.env"), Deny), // `..` traversal
            ("sh cat .ssh/id_rsa", Shell("cat .ssh/id_rsa"), Deny),
            // ── shell file-access gate: writers (file must stay unchanged) ──
            ("sh echo > .env", Shell("echo HACKED > .env"), Deny), // write redirect
            (
                "sh sed -ni .env",
                Shell("sed -ni s/FAKE/HACKED/ .env"),
                Deny,
            ), // in-place sed
            ("sh tee .env", Shell("printf HACKED | tee .env"), Deny), // pipe into tee
            (
                "sh echo > tfstate",
                Shell("echo x > terraform.tfstate"),
                Deny,
            ),
            // ── shell file-access gate: secrets ask + negatives ──
            (
                "sh cat secrets/api_key.txt",
                Shell("cat secrets/api_key.txt"),
                Ask,
            ),
            (
                "sh echo > secrets/new.txt",
                Shell("echo x > secrets/new.txt"),
                Ask,
            ),
            ("sh cat README.md (neg)", Shell("cat README.md"), Allowed),
            (
                "sh cat src/main.py (neg)",
                Shell("cat src/main.py"),
                Allowed,
            ),
        ];

        for &(label, vector, expect) in matrix {
            let decision = match vector {
                ReadTool(path) => policy.evaluate(&AccessKind::Read(Some(path.to_string()))),
                EditTool(path) => policy.evaluate(&AccessKind::Edit(path.to_string())),
                Bash(cmd) => policy.evaluate(&AccessKind::Bash(cmd.to_string())),
                Shell(cmd) => policy.evaluate_shell_file_access(cmd, cwd()),
            };
            match expect {
                Deny => assert!(
                    matches!(decision, Some(Decision::Reject(_))),
                    "[{label}] expected Deny (Reject), got {decision:?}"
                ),
                Ask => assert!(
                    matches!(decision, Some(Decision::Ask)),
                    "[{label}] expected Ask, got {decision:?}"
                ),
                Allowed => assert!(
                    decision.is_none(),
                    "[{label}] expected allowed (None), got {decision:?}"
                ),
            }
        }
    }

    /// Negative controls: legit reads/writes and lookalike names aren't blocked.
    #[test]
    fn adversarial_legitimate_commands_not_overblocked() {
        let policy = enterprise_requirements_policy();
        for cmd in [
            "cat README.md",
            "head -n 5 README.md",
            "tail -n 5 README.md",
            "grep hello README.md",
            "sed -n 1p README.md",
            "wc -c README.md",
            "cut -d: -f1 README.md",
            "sort README.md",
            "uniq README.md",
            "pwd",
            "date",
            "whoami",
            "git status --short",
            "ls && cat README.md",
            "cat my.env.example",
            "cat env.txt",
            "cat key.pem.txt",
            "cat env.dir/README.md",
            "echo ok > scratch.txt",
            "echo x 2>/dev/null",
            "cat README.md 2>&1",
            // Path-moving commands on non-restricted files stay inert.
            "cp README.md backup.md",
            "mv old.txt new.txt",
            "rm scratch.txt",
            "touch newfile.txt",
            "mkdir build",
        ] {
            assert!(
                policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
                "must not over-block: {cmd}"
            );
        }
    }

    /// No Read/Edit/Any rules: skip the shell gate entirely, even for known readers.
    #[test]
    fn adversarial_no_file_rules_means_no_shell_gate() {
        let policy = compiled(vec![bash_rule(RuleAction::Deny, "rm*")]);
        assert!(
            policy
                .evaluate_shell_file_access("cat .env", cwd())
                .is_none()
        );
    }

    /// Local mirror of the grep tool's read-exclude derivation: `Deny` rules on `Read`/`Any`.
    /// Proves a no-restriction policy derives zero read-excludes.
    fn read_deny_globs(config: &PermissionConfig) -> Vec<String> {
        config
            .rules
            .iter()
            .filter(|r| {
                r.action == RuleAction::Deny && matches!(r.tool, ToolFilter::Read | ToolFilter::Any)
            })
            .filter_map(|r| r.pattern.clone())
            .collect()
    }

    /// Read/exfil vectors the shell gate classifies under a policy; reused to prove a no-restriction policy gates none of them.
    const BYPASS_VECTORS: &[&str] = &[
        "cat .env",
        "grep FAKE .env",
        "base64 .env",
        "cat 0<.env",
        "cat<.env",
        "cat $(echo .env)",
        "diff <(cat .env) /dev/null",
        "echo X > .env",
        "sed -ni s/// .env",
    ];

    /// No-restriction policies (empty / Bash-only / Allow-only-file) must be inert.
    /// The gate stays off, every bypass vector is declined, and the policy derives zero read-excludes.
    #[test]
    fn h1_no_restriction_policies_are_inert() {
        let policies: [(&str, Vec<PermissionRule>); 3] = [
            ("empty", vec![]),
            (
                "bash-only",
                vec![
                    bash_rule(RuleAction::Deny, "rm -rf *"),
                    bash_rule(RuleAction::Ask, "kubectl *"),
                ],
            ),
            (
                "allow-only-file",
                vec![
                    file_rule(RuleAction::Allow, ToolFilter::Read, "**"),
                    file_rule(RuleAction::Allow, ToolFilter::Edit, "**"),
                ],
            ),
        ];
        for (label, rules) in policies {
            let config = PermissionConfig::new(rules.clone());
            let policy = compiled(rules);
            assert!(
                !policy.has_file_restrictions,
                "[{label}] no-restriction policy must not arm the file gate"
            );
            for cmd in BYPASS_VECTORS {
                assert!(
                    policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
                    "[{label}] inert policy must not gate `{cmd}`"
                );
            }
            assert!(
                read_deny_globs(&config).is_empty(),
                "[{label}] inert policy must derive zero recursive-grep read-excludes"
            );
        }
    }

    /// The policy must not over-match legit look-alikes (direct read or shell gate).
    /// It targets dotfile `.env`/`.env.<x>` and real cert globs, not any `env`/`pem`.
    #[test]
    fn h2_enterprise_policy_does_not_over_match_legit_paths() {
        let policy = enterprise_requirements_policy();
        for path in [
            "environment.txt",
            "foo.env",
            "my.env.example",
            "src/env.rs",
            "environments/config.yaml",
            "README.md",
            "src/main.py",
            "prevent.pem.md",
            ".environment/app.conf",
        ] {
            let direct = policy.evaluate(&AccessKind::Read(Some(path.to_string())));
            assert!(
                !matches!(direct, Some(Decision::Reject(_))),
                "[read {path}] legit look-alike must not be denied, got {direct:?}"
            );
            let shell = policy.evaluate_shell_file_access(&format!("cat {path}"), cwd());
            assert!(
                !matches!(shell, Some(Decision::Reject(_))),
                "[cat {path}] legit look-alike must not be denied, got {shell:?}"
            );
        }
        // Nuance: `**/.env.*` DOES catch a dotfile `.env.<suffix>` (both vectors)…
        for path in [".env.example", ".env.staging"] {
            assert!(
                matches!(
                    policy.evaluate(&AccessKind::Read(Some(path.to_string()))),
                    Some(Decision::Reject(_))
                ),
                "[read {path}] must be denied by **/.env.*"
            );
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(&format!("cat {path}"), cwd()),
                    Some(Decision::Reject(_))
                ),
                "[cat {path}] must be denied by **/.env.*"
            );
        }
        // …but `my.env.example` (not a dotfile) is NOT caught.
        assert!(
            policy
                .evaluate(&AccessKind::Read(Some("my.env.example".to_string())))
                .is_none(),
            "my.env.example must not match **/.env.*"
        );
    }

    /// The shell gate never hard-blocks legit reads; fail-closed cases (glob, recursion, unpinnable substitution) `Ask`, not `Reject`.
    #[test]
    fn h3_enterprise_gate_never_false_blocks_legit() {
        let policy = enterprise_requirements_policy();
        for cmd in ["cat README.md", "grep foo src/main.py", "wc -l src/main.py"] {
            assert!(
                policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
                "legit read must not be gated: {cmd}"
            );
        }
        for cmd in ["cat *.md", "grep -r foo .", "cat $(echo README.md)"] {
            assert!(
                matches!(
                    policy.evaluate_shell_file_access(cmd, cwd()),
                    Some(Decision::Ask)
                ),
                "fail-closed case must ask, never reject: {cmd}"
            );
        }
    }

    /// A deployment that ships managed config with no `[permission]` rules must see zero gating (no secrets embedded, only the empty rule set).
    #[test]
    fn unrestricted_enterprise_has_no_file_restrictions() {
        let policy = compiled(vec![]);
        assert!(
            !policy.has_file_restrictions,
            "a deployment with no [permission] rules must not arm the file gate"
        );
        for cmd in BYPASS_VECTORS {
            assert!(
                policy.evaluate_shell_file_access(cmd, cwd()).is_none(),
                "no-restriction enterprise policy must not gate `{cmd}`"
            );
        }
    }
}
