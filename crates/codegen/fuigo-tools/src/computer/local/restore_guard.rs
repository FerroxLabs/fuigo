//! u35: make the replayed shell state deterministic for permission checks.
//!
//! The persistent and static shell wrappers replay a snapshot of shell options, functions and aliases before every
//! command. The permission layer approves some plain commands by program name alone, so two things a snapshot can
//! carry would make the command it approved differ from the command that runs:
//!
//! - an option that changes how plain words are read (bash `set -k`, zsh `EQUALS`, ...), and
//! - a user function or alias named after a safe-listed program (or after a builtin the wrapper itself calls).
//!
//! After the snapshot is evaluated, [`bash_guarded`] / [`zsh_guarded`] remove both before anything else runs, and run
//! the rest of the wrapper only when the removal provably succeeded; otherwise the shell exits without running the
//! user command.
//!
//! Neither guard can be intercepted by a user function named after the command it uses:
//!
//! - bash: the guard first assigns `POSIXLY_CORRECT` (a variable assignment, which no function or alias can hook) and
//!   checks `[[ -o posix ]]` (a reserved word). In POSIX mode bash finds POSIX special builtins (`unset`, `return`,
//!   ...) before functions, so its `unset -f` is the real builtin even when a function named `unset` exists. That one
//!   call removes every function with an identifier name that is named after a wrapper builtin (`builtin`, `command`,
//!   `local`, `shopt`, ...) or a safe-listed program; only then does the guard call `builtin`, leave POSIX mode and
//!   remove the non-identifier names (`[`, `.`, ...), which bash 3.2 refuses in POSIX mode. A read-only function
//!   cannot be unset, so a failed `unset -f` refuses the command instead of running it. The guard's own text was
//!   parsed before the snapshot ran
//!   (the wrapper is one line, and bash and zsh read a whole line before running any of it), so a replayed alias
//!   cannot rewrite it either.
//! - zsh: zsh has no lookup mode that puts a builtin ahead of a function, so the guard calls no command at all. It
//!   works only through assignments to the `zsh/parameter` special hashes: assigning `dis_functions[name]` replaces
//!   the enabled function with a disabled one (disabled functions are skipped by command lookup and are not dumped),
//!   and likewise `dis_aliases`, `dis_galiases`, `dis_saliases`; options are set through `options[name]`. It then
//!   re-checks with pure parameter expansion that no matching function or alias is still enabled, and refuses
//!   otherwise (including when a snapshot unset or replaced one of those hashes).
//!
//! The replay before the guard calls nothing a replayed definition can intercept (`ShellState::replay_script`, and
//! the static wrapper's capture order): options first, then aliases with alias expansion off, then function
//! definitions, and nothing after them. Zsh `TRAP*` and hook functions, which act as soon as they are defined, are
//! left out of every state dump and capture, and the guard disables any that are still there.
//!
//! Fuigo's own shadows are installed after the guard and are the only exceptions: the embedded-search `find` (bfs)
//! and `grep` (ugrep) functions from `embedded_search_tools.rs`, and the `sudo='sudo -A'` alias when
//! `SUDO_ASKPASS` is configured.

/// Programs the permission layer may approve by name alone: the Ask-mode read-only lists (`ALWAYS_SAFE_COMMANDS`,
/// `SAFE_COMMAND_PREFIXES`), the Auto-mode routine list (`ROUTINE_PREFIXES`) and its named special cases (git, gh,
/// find, kubectl, package managers), and the creation programs (`mkdir`, `touch`). A replayed user function or alias
/// with one of these names is dropped before the command runs, so the name resolves to the real program or builtin.
/// The permission layer's lists must stay a subset of this one.
pub const PERMISSION_SAFE_PROGRAMS: &[&str] = &[
    "basename", "bazel", "bin/explorer", "cargo", "cat", "cd", "clippy", "cmake", "cut", "date", "df", "diff",
    "dirname", "du", "echo", "false", "file", "find", "gh", "git", "go", "grep", "head", "hostname", "htop", "jq",
    "just", "kubectl", "ls", "make", "mkdir", "node", "nodejs", "npm", "npx", "nproc", "perl", "php", "pnpm",
    "popd", "printenv", "printf", "ps", "pushd", "pwd", "pytest", "python", "python3", "readlink", "realpath", "rg",
    "ruby", "rustc", "rustfmt", "rustup", "set", "sleep", "sort", "stat", "strings", "tail", "test", "top", "touch",
    "tr", "tree", "true", "type", "uname", "uniq", "uptime", "uv", "uvx", "wc", "which", "whoami", "yarn",
];

/// Interpreter families with versioned spellings (`python3.13`, `node22`): the name followed by a digit.
pub const PERMISSION_SAFE_PROGRAM_FAMILIES: &[&str] = &["lua", "node", "perl", "php", "python", "ruby"];

/// Builtins (and hook functions) the wrappers call after the snapshot is replayed, plus the shell's
/// command-not-found hooks, which would run user code for a safe-listed program that is not installed.
const WRAPPER_BUILTINS: &[&str] = &[
    ".", ":", "[", "alias", "base64", "builtin", "command", "command_not_found_handle", "command_not_found_handler",
    "declare", "disable", "emulate", "enable", "eval", "exec", "exit", "export", "local", "print", "read",
    "readonly", "return", "setopt", "shopt", "source", "trap", "typeset", "unalias", "unfunction", "unset",
    "unsetopt", "zmodload",
];

/// Every fixed name the guards clear, deduplicated.
fn fixed_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = WRAPPER_BUILTINS.iter().chain(PERMISSION_SAFE_PROGRAMS).copied().collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// A `case` pattern list (`'a'|'b'|'python'[0-9]*`) matching every guarded name. Each fixed name is single-quoted, so
/// `[`, `.` and `/` are literal.
fn case_pattern(extra: &[&str]) -> String {
    fixed_names()
        .into_iter()
        .map(|n| format!("'{n}'"))
        .chain(PERMISSION_SAFE_PROGRAM_FAMILIES.iter().map(|f| format!("'{f}'[0-9]*")))
        .chain(extra.iter().map(|e| (*e).to_owned()))
        .collect::<Vec<_>>()
        .join("|")
}

/// The message a refused command prints (through a `${var:?message}` expansion, which needs no command).
const REFUSED: &str = "fuigo: refusing to run: the replayed shell state keeps a function or alias named after a \
                       safe-listed program or shell builtin that cannot be removed";

/// Whether bash accepts `name` in `unset -f` in POSIX mode: bash 3.2 (stock macOS `/bin/bash`) rejects any other
/// name there as "not a valid identifier", even when no such function exists.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Space-separated single-quoted names.
fn quoted(names: impl Iterator<Item = &'static str>) -> String {
    names.map(|n| format!("'{n}'")).collect::<Vec<_>>().join(" ")
}

/// Bash: the guard, then `rest` only when it succeeded. `rest` must be a `;`-terminated command list.
///
/// The guard function runs in POSIX mode, where `unset` is found before a function of that name. Its first `unset -f`
/// takes only identifier names (bash 3.2 refuses any other name there), which removes every function named after a
/// builtin the guard calls next (`builtin`, `set`, `local`, `read`, `trap`, ...). It then leaves POSIX mode and
/// removes the non-identifier names (`[`, `.`, `:`, `bin/explorer`) with `builtin unset -f`, which accepts any name
/// outside POSIX mode on bash 3.2 through 5.x, and the rest of the loop-matched functions and aliases.
/// Every builtin it calls after leaving POSIX mode goes through `builtin` (`builtin continue` included: a multiline
/// alias prints continuation lines the loop skips, and a replayed `continue` function would run there).
///
/// Hooks: it clears the `DEBUG`, `RETURN`, `ERR` and `EXIT` traps and unsets `PROMPT_COMMAND`, and resets `PS4`,
/// which bash expands (command substitutions included) before every traced command.
///
/// Forced options after the guard: `keyword` off (`set -k` turns any later `NAME=value` argument into an environment
/// assignment), `posix` off (it changes command lookup and was only borrowed for the guard), `histexpand` off (`!` in
/// a word), `xtrace` off (each traced command expands `PS4`), `functrace` and `errtrace` off (they carry traps into
/// functions), and `interactive_comments` on (a word starting with `#` stays a comment). Leaving POSIX mode resets
/// `expand_aliases` to the non-interactive default (off), so it is turned back on: both wrappers run with it on.
pub(crate) fn bash_guarded(rest: &str) -> String {
    let names = fixed_names();
    let posix_names = quoted(names.iter().copied().filter(|n| is_identifier(n)));
    let other_names = quoted(names.iter().copied().filter(|n| !is_identifier(n)));
    let pattern = case_pattern(&[]);
    format!(
        "POSIXLY_CORRECT=y; \
         __fuigo_restore_guard() {{ \
           unset -f -- {posix_names} || return 1; \
           unset POSIXLY_CORRECT || return 1; builtin set +o posix || return 1; \
           builtin unset -f -- {other_names} || return 1; \
           local __fuigo_n __fuigo_x || return 1; \
           while IFS=' ' builtin read -r __fuigo_x __fuigo_x __fuigo_n; do \
             case $__fuigo_n in ({pattern}) builtin unset -f -- \"$__fuigo_n\" || return 1;; esac; \
           done <<< \"$(builtin declare -F)\"; \
           while IFS= builtin read -r __fuigo_n; do \
             [[ $__fuigo_n == 'alias '* ]] || builtin continue; \
             __fuigo_n=${{__fuigo_n#alias }}; __fuigo_n=${{__fuigo_n%%=*}}; \
             case $__fuigo_n in ({pattern}) builtin unalias -- \"$__fuigo_n\" 2>/dev/null;; esac; \
           done <<< \"$(builtin alias -p)\"; \
           builtin trap - DEBUG RETURN ERR EXIT || return 1; \
           builtin unset PROMPT_COMMAND 2>/dev/null; PS4='+ ' || return 1; \
         }}; \
         if [[ -o posix ]] && __fuigo_restore_guard; then \
           builtin unset -f __fuigo_restore_guard; \
           builtin set +o keyword +o histexpand +o xtrace +o functrace +o errtrace; \
           builtin shopt -s interactive_comments expand_aliases; \
           {rest} \
         else [[ ${{__fuigo_guard_refused:?{REFUSED}}} ]]; fi; "
    )
}

/// The `zsh/parameter` hashes the zsh guard works through; each must still be the module's special parameter.
const ZSH_SPECIAL_HASHES: &[&str] = &[
    "functions", "dis_functions", "aliases", "dis_aliases", "galiases", "dis_galiases", "saliases", "dis_saliases",
    "options",
];

/// Zsh hook functions: `chpwd` runs on every `cd` and `zshexit` when the shell exits, both in a non-interactive
/// shell; the others run around prompts and history. Each also has a `<name>_functions` array.
pub(crate) const ZSH_HOOK_FUNCTIONS: &[&str] = &["chpwd", "periodic", "precmd", "preexec", "zshaddhistory", "zshexit"];

/// A `case` pattern list for the zsh functions a state dump or capture leaves out: `TRAP*` functions install their
/// trap as soon as they are defined (a `TRAPDEBUG` would run before the restore guard), and the hook functions.
pub(crate) fn zsh_unreplayed_functions() -> String {
    std::iter::once("TRAP*").chain(ZSH_HOOK_FUNCTIONS.iter().copied()).collect::<Vec<_>>().join("|")
}

/// Zsh: the guard, then `rest` only when it succeeded. `rest` must be a `;`-terminated command list.
///
/// Besides the named functions and aliases, it disables every `TRAP*` function (`TRAPZERR`, `TRAPDEBUG`, ... run user
/// code around a plain command), the hook functions and their `*_functions` arrays ([`ZSH_HOOK_FUNCTIONS`]), every
/// global alias (expanded in any word position, so it rewrites plain arguments) and every suffix alias (a program word
/// ending `.ext` runs the alias). Forced options: `EQUALS` off (`=name` expands to a path), `MAGIC_EQUAL_SUBST` off
/// (expansion after `=` in `a=b` arguments), `AUTO_CD` off (a directory name in command position runs `cd`),
/// `XTRACE` off and `PS4` reset (a traced command expands `PS4`), `PROMPT_SUBST` off (it lets that expansion run
/// command substitutions). zsh has no `keyword` option.
pub(crate) fn zsh_guarded(rest: &str) -> String {
    let hooks: Vec<String> = ZSH_HOOK_FUNCTIONS.iter().map(|h| format!("'{h}'")).collect();
    let pattern = case_pattern(&std::iter::once("TRAP*").chain(hooks.iter().map(String::as_str)).collect::<Vec<_>>());
    let clear_hook_arrays = ZSH_HOOK_FUNCTIONS
        .iter()
        .map(|h| format!("{h}_functions=()"))
        .collect::<Vec<_>>()
        .join(" ");
    let hook_arrays_empty = ZSH_HOOK_FUNCTIONS
        .iter()
        .map(|h| format!("${{#{h}_functions}} -eq 0"))
        .collect::<Vec<_>>()
        .join(" && ");
    let special = ZSH_SPECIAL_HASHES
        .iter()
        .map(|h| format!("${{(t){h}}} == *special*"))
        .collect::<Vec<_>>()
        .join(" && ");
    format!(
        "if [[ {special} ]]; then \
           for __fuigo_n in \"${{(@k)functions[@]}}\"; do \
             case $__fuigo_n in ({pattern}) dis_functions[$__fuigo_n]=$functions[$__fuigo_n];; esac; \
           done; \
           for __fuigo_n in \"${{(@k)aliases[@]}}\"; do \
             case $__fuigo_n in ({pattern}) dis_aliases[$__fuigo_n]=$aliases[$__fuigo_n];; esac; \
           done; \
           for __fuigo_n in \"${{(@k)galiases[@]}}\"; do dis_galiases[$__fuigo_n]=$galiases[$__fuigo_n]; done; \
           for __fuigo_n in \"${{(@k)saliases[@]}}\"; do dis_saliases[$__fuigo_n]=$saliases[$__fuigo_n]; done; \
           {clear_hook_arrays}; \
         fi; \
         if [[ {special} \
               && -z ${{(M)${{(@k)functions[@]}}:#({pattern})}} \
               && -z ${{(M)${{(@k)aliases[@]}}:#({pattern})}} \
               && ${{#galiases}} -eq 0 && ${{#saliases}} -eq 0 && {hook_arrays_empty} ]]; then \
           options[equals]=off; options[magicequalsubst]=off; options[autocd]=off; \
           options[xtrace]=off; options[promptsubst]=off; PS4='+%N:%i> '; \
           builtin unset __fuigo_n 2>/dev/null; \
           {rest} \
         else [[ ${{__fuigo_guard_refused:?{REFUSED}}} ]]; fi; "
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_guard_names_are_quoted_and_cover_families() {
        let p = case_pattern(&[]);
        assert!(p.contains("'ls'") && p.contains("'['") && p.contains("'builtin'"));
        assert!(p.contains("'python'[0-9]*"));
        assert!(!p.contains("TRAP"));
        assert!(fixed_names().iter().all(|n| !n.contains('\'')));
    }

    /// g5a: bash 3.2 (stock macOS `/bin/bash`) refuses a non-identifier name in a POSIX-mode `unset -f`, so the guard
    /// must pass only identifier names there, and the other names in the later, non-POSIX `builtin unset -f`.
    #[test]
    fn restore_guard_posix_unset_names_are_identifiers() {
        let text = bash_guarded("");
        let posix = text.split("unset -f -- ").nth(1).and_then(|t| t.split(" || return 1").next()).unwrap();
        let names: Vec<&str> = posix.split(' ').map(|n| n.trim_matches('\'')).collect();
        assert!(names.contains(&"builtin") && names.contains(&"ls"), "{posix}");
        assert!(names.iter().all(|n| is_identifier(n)), "non-identifier in the POSIX-mode unset: {posix}");
        let later = text.split("builtin unset -f -- ").nth(1).and_then(|t| t.split(" || return 1").next()).unwrap();
        for name in ["'.'", "':'", "'['", "'bin/explorer'"] {
            assert!(later.split(' ').any(|n| n == name), "{name} missing from {later}");
        }
        // The non-identifier names are removed only after POSIX mode is left.
        let leave = text.find("builtin set +o posix").unwrap();
        assert!(leave < text.find("builtin unset -f -- ").unwrap());
    }
}
