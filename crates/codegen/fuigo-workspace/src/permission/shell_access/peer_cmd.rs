//! Peer scope only (S6.4, round 3): command-level rules for a peer-influenced session's shell command. Called from
//! `command_targets` only while the extended set is active; the ordinary floor never reaches it.

use super::{
    CommandTargets, DestinationKind, launched_commands, peel_write_command, shell_program_name,
    shell_sed_in_place,
};

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh", "busybox"];

/// Whether a command launched by `xargs` / `find -exec` writes or deletes (or runs shell text).
fn launched_writer(command: &[String]) -> bool {
    let peel = peel_write_command(command);
    let Some(program) = peel.words.first().map(|w| shell_program_name(w).to_ascii_lowercase()) else {
        return false;
    };
    matches!(
        program.as_str(),
        "rm" | "rmdir" | "unlink" | "shred" | "mv" | "cp" | "tee" | "chmod" | "chown" | "chgrp" | "chattr"
            | "truncate" | "dd" | "install" | "ln" | "touch" | "rsync" | "eval" | "source" | "."
    ) || SHELLS.contains(&program.as_str())
        || (program == "sed" && shell_sed_in_place(peel.words))
        || (program == "perl" && peel.words.iter().skip(1).any(|w| w.starts_with('-') && w.contains('i')))
}

/// Positional operands of a command (`--` ends options); `-t`/`--target-directory` values are returned separately.
fn operands(inner: &[String]) -> (Vec<&String>, bool) {
    let (mut out, mut target_dir, mut end, mut skip) = (Vec::new(), false, false, false);
    for word in inner.iter().skip(1) {
        if std::mem::take(&mut skip) {
            continue;
        }
        if !end && word == "--" {
            end = true;
        } else if !end && word.starts_with("--") {
            if word == "--target-directory" {
                target_dir = true;
                skip = true;
            } else if word.starts_with("--target-directory=") {
                target_dir = true;
            }
        } else if !end && word.starts_with('-') && word.len() > 1 {
            if word[1..].chars().all(|c| c.is_ascii_alphabetic()) && word.ends_with('t') {
                target_dir = true;
                skip = true;
            }
        } else {
            out.push(word);
        }
    }
    (out, target_dir)
}

/// A `-c` / `--config-env` key that makes git run a program of the caller's choosing.
fn risky_git_key(kv: &str) -> bool {
    let key = kv.split('=').next().unwrap_or_default().to_ascii_lowercase();
    matches!(
        key.as_str(),
        "core.hookspath" | "core.sshcommand" | "core.fsmonitor" | "core.editor"
    )
}

/// Git subcommand and its arguments, skipping global options; flags `--exec-path` and risky `-c` keys.
/// Attached spellings (`-ckey=v`, `--config-env=key=ENV`) and option-name abbreviations (`--exec-p=`) count too.
fn git_parts(inner: &[String]) -> (Option<&str>, &[String], bool) {
    let mut risky = false;
    let mut i = 1;
    while let Some(word) = inner.get(i) {
        i += 1;
        if word == "-c" || word == "--config-env" {
            risky |= inner.get(i).is_some_and(|kv| risky_git_key(kv));
            i += 1;
        } else if let Some(kv) = word.strip_prefix("--config-env=") {
            risky |= risky_git_key(kv);
        } else if word.starts_with("--exec-p") {
            risky = true;
        } else if matches!(word.as_str(), "-C" | "--git-dir" | "--work-tree" | "--namespace") {
            i += 1;
        } else if let Some(kv) = word.strip_prefix("-c").filter(|_| !word.starts_with("--")) {
            risky |= risky_git_key(kv);
        } else if word.starts_with('-') {
            continue;
        } else {
            return (Some(word.as_str()), &inner[i..], risky);
        }
    }
    (None, &[], risky)
}

fn git_config_write(inner: &[String]) -> bool {
    let (sub, args, risky) = git_parts(inner);
    if risky {
        return true;
    }
    let first = args.iter().find(|a| !a.starts_with('-')).map(String::as_str);
    let has = |f: &[&str]| args.iter().any(|a| f.iter().any(|x| a == x || a.starts_with(&format!("{x}="))));
    match sub {
        Some("remote") => matches!(
            first,
            Some("add" | "set-url" | "rename" | "remove" | "rm" | "set-head" | "set-branches")
        ),
        Some("submodule") => matches!(
            first,
            Some("add" | "init" | "update" | "set-url" | "set-branch" | "sync" | "deinit")
        ),
        // `-uorigin/main` (attached) and abbreviated long options (`--set-up=`) write the upstream too.
        Some("branch") => {
            has(&["-u", "--set-upstream-to", "--unset-upstream", "--edit-description"])
                || args.iter().any(|a| {
                    (a.starts_with('-') && !a.starts_with("--") && a.contains('u'))
                        // Git accepts any unique prefix of a long option: `--u`, `--unset`, `--e`, `--edit`, `--set-up`.
                        || a.starts_with("--u")
                        || a.starts_with("--e")
                        || a.starts_with("--set")
                })
        }
        Some("init" | "clone") => true,
        Some("worktree") => first == Some("add"),
        Some("lfs") => first == Some("install"),
        _ => false,
    }
}

pub(super) fn peer_command_targets(program: &str, inner: &[String], out: &mut CommandTargets) {
    match program {
        // Shell text nothing here can read.
        "source" | "." | "eval" => out.unpinned(),
        "xargs" | "find" => {
            if launched_commands(program, inner).into_iter().any(launched_writer)
                || (program == "find" && inner.iter().any(|w| w == "-delete" || w == "-rm"))
            {
                out.unpinned();
            }
        }
        "rm" | "rmdir" | "unlink" | "shred" | "truncate" | "mv" => {
            let (ops, target_dir) = operands(inner);
            let skip_last = program == "mv" && !target_dir;
            let n = ops.len().saturating_sub(usize::from(skip_last));
            out.targets.extend(
                ops.into_iter()
                    .take(n)
                    .map(|op| (op.clone(), Some(DestinationKind::Container), None)),
            );
        }
        "chmod" | "chown" | "chgrp" | "chattr" | "touch" => {
            let (ops, _) = operands(inner);
            out.targets.extend(ops.into_iter().map(|op| (op.clone(), None, None)));
        }
        "git" if git_config_write(inner) => out.unpinned(),
        _ => {}
    }
}
