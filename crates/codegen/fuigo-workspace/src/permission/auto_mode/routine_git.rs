//! Fail-closed `git` arm of the routine-bash heuristic: any shape not recognized here goes to the model.
//! Callers pass wrapper-peeled words with `words[0]` literally `git`; a case-variant or path-qualified spelling may resolve to a different binary.

use crate::permission::exec_risk::{
    git_words_are_read_only_query, git_words_have_unsafe_query_option,
};

pub(super) fn git_words_are_routine(words: &[String]) -> bool {
    if words.first().map(String::as_str) != Some("git") {
        return false;
    }
    if git_words_are_read_only_query(words) {
        return true;
    }
    if git_words_have_unsafe_query_option(words) {
        return false;
    }
    let Some(verb) = words.get(1).map(String::as_str) else {
        return false;
    };
    let args = &words[2..];
    match verb {
        "add" | "fetch" => true,
        "commit" => !commit_reads_message_file(args),
        "pull" => !pull_uses_custom_strategy(args),
        "worktree" => args.first().map(String::as_str) == Some("list"),
        "checkout" | "switch" => is_routine_branch_switch(args),
        "stash" => is_routine_stash(args),
        _ => false,
    }
}

/// u35 g3: `commit -F FILE`/`--file`, `-t FILE`/`--template` read the message from a file the command does not show
/// (it lands in the commit); `-` (stdin) is visible. Long options may be abbreviated (`--fil`, `--te`).
fn commit_reads_message_file(args: &[String]) -> bool {
    use crate::permission::exec_risk::is_accepted_long_option_prefix;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        if word.starts_with("--") {
            let (name, value) = word.split_once('=').map_or((word.as_str(), None), |(n, v)| (n, Some(v)));
            if (is_accepted_long_option_prefix(name, "--file", 5) || is_accepted_long_option_prefix(name, "--template", 4))
                && value.or(args.get(i).map(String::as_str)) != Some("-")
            {
                return true;
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for (at, letter) in cluster.char_indices() {
            let rest = &cluster[at + letter.len_utf8()..];
            match letter {
                'F' | 't' => {
                    let value = if rest.is_empty() { args.get(i).map(String::as_str) } else { Some(rest) };
                    if value != Some("-") {
                        return true;
                    }
                    break;
                }
                'm' | 'c' | 'C' | 'S' => break,
                _ => {}
            }
        }
    }
    false
}

/// u35 g3: `pull -s NAME`/`--strategy` other than a built-in strategy runs `git-merge-NAME` from PATH.
fn pull_uses_custom_strategy(args: &[String]) -> bool {
    const BUILTIN: &[&str] = &["ort", "recursive", "resolve", "octopus", "ours", "subtree"];
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        let value = if let Some(value) = word.strip_prefix("--strategy=") {
            Some(value)
        } else if word == "--strategy" || word == "-s" {
            args.get(i).map(String::as_str)
        } else if let Some(value) = word.strip_prefix("-s") {
            Some(value)
        } else {
            continue;
        };
        if !value.is_some_and(|v| BUILTIN.contains(&v)) {
            return true;
        }
    }
    false
}

/// Exact spellings only, so clusters (`-qf`) and abbreviations (`--fo`) fail closed.
const BRANCH_SWITCH_BENIGN_FLAGS: &[&str] = &[
    "-q",
    "--quiet",
    "-d",
    "--detach",
    "-t",
    "--track",
    "--no-track",
    "--guess",
    "--no-guess",
    "--progress",
    "--no-progress",
    "--recurse-submodules",
    "--no-recurse-submodules",
];

/// An unlisted option or a second operand means path mode or a discard, so both fail closed.
fn is_routine_branch_switch(args: &[String]) -> bool {
    let mut operands = 0;
    let mut it = args.iter().map(String::as_str);
    while let Some(word) = it.next() {
        match word {
            "-b" | "-B" | "-c" | "-C" | "--orphan" => {
                it.next();
            }
            // Bare `-` is the previous branch
            "-" => operands += 1,
            _ if BRANCH_SWITCH_BENIGN_FLAGS.contains(&word) => {}
            _ if word.starts_with('-') => return false,
            _ => {
                if operand_reads_as_path(word) {
                    return false;
                }
                operands += 1;
            }
        }
    }
    operands <= 1
}

/// `drop` and `clear` throw away a stash, so only the recoverable subcommands are listed.
fn is_routine_stash(args: &[String]) -> bool {
    let mut it = args.iter().map(String::as_str);
    let subcommand = loop {
        match it.next() {
            Some("-m" | "--message") => {
                it.next();
            }
            Some("-q" | "--quiet") => {}
            Some(word) if word.starts_with('-') => return false,
            other => break other,
        }
    };
    matches!(
        subcommand,
        None | Some("push" | "save" | "pop" | "apply" | "list" | "show" | "branch")
    )
}

/// A dotless bare name (`Makefile`, `src`) is indistinguishable from a branch without a repo lookup and stays routine.
fn operand_reads_as_path(op: &str) -> bool {
    // git-check-ref-format rejects these in a branch name, so the operand is a pathspec or a revision expression like `HEAD~1`
    if op
        .split('/')
        .any(|c| c.starts_with('.') || c.ends_with(".lock"))
        || op.ends_with('/')
        || op.ends_with('.')
        || op.contains("..")
        || op.contains("@{")
        || op.contains(['~', '^', ':', '\\'])
        || op.contains(char::is_whitespace)
    {
        return true;
    }
    if op.starts_with('/') || op.contains(['*', '?', '[']) {
        return true;
    }
    let Some((stem, ext)) = op.rsplit_once('.') else {
        return false;
    };
    // `2.x` / `release/1.2.x` are maintenance branches, not a one-letter file extension
    let stem_leaf = stem.rsplit('/').next().unwrap_or(stem);
    if ext == "x"
        && stem_leaf.bytes().any(|b| b.is_ascii_digit())
        && stem_leaf.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return false;
    }
    (1..=5).contains(&ext.len())
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
        && ext.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
#[path = "routine_git_tests.rs"]
mod tests;
