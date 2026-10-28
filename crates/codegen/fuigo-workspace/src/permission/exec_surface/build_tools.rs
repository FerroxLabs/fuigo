//! u35 g3: options of the Auto mode build tools (and `gh`) that run a program the command does not name as its own
//! job: an inline makefile or cmake script, a replacement shell, compiler, linker or test runner, a cargo config
//! override, a debugger fed from stdin, a browser. A hit is an exec-surface finding, so it floors every broad grant
//! and is never routine. Ordinary build and test runs carry none. Forms that only write outside the project, change
//! other state or read a file the command does not show ask through `permission::safe_forms` instead.

use super::{is_unresolved, jq_reads_environment, long_option_is, names_stdin_stream};

/// The value of an option given as `--name=value` (attached) or as the next word.
fn long_value<'a>(word: &'a str, next: Option<&'a String>) -> Option<&'a str> {
    match word.split_once('=') {
        Some((_, value)) => Some(value),
        None => next.map(String::as_str),
    }
}

/// The value of a short option `-X`: the rest of its word, else the next word.
fn short_value<'a>(rest: &'a str, next: Option<&'a String>) -> Option<&'a str> {
    if rest.is_empty() {
        next.map(String::as_str)
    } else {
        Some(rest)
    }
}

// ---- make ----

/// How a GNU make option takes its value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MakeValue {
    None,
    /// The rest of the word or the next word.
    Required,
    /// Attached only (`--debug=a`); `jobs`/`load-average` also take a next word that is a number.
    Optional,
}

/// GNU make 4.4 long options (getopt: any unique prefix is accepted) and how each takes a value.
const MAKE_LONG: &[(&str, MakeValue)] = &[
    ("always-make", MakeValue::None),
    ("assume-new", MakeValue::Required),
    ("assume-old", MakeValue::Required),
    ("check-symlink-times", MakeValue::None),
    ("debug", MakeValue::Optional),
    ("directory", MakeValue::Required),
    ("dry-run", MakeValue::None),
    ("environment-overrides", MakeValue::None),
    ("eval", MakeValue::Required),
    ("file", MakeValue::Required),
    ("help", MakeValue::None),
    ("ignore-errors", MakeValue::None),
    ("include-dir", MakeValue::Required),
    ("jobs", MakeValue::Optional),
    ("jobserver-auth", MakeValue::Required),
    ("jobserver-style", MakeValue::Required),
    ("just-print", MakeValue::None),
    ("keep-going", MakeValue::None),
    ("load-average", MakeValue::Optional),
    ("makefile", MakeValue::Required),
    ("max-load", MakeValue::Optional),
    ("new-file", MakeValue::Required),
    ("no-builtin-rules", MakeValue::None),
    ("no-builtin-variables", MakeValue::None),
    ("no-keep-going", MakeValue::None),
    ("no-print-directory", MakeValue::None),
    ("no-silent", MakeValue::None),
    ("old-file", MakeValue::Required),
    ("output-sync", MakeValue::Optional),
    ("print-data-base", MakeValue::None),
    ("print-directory", MakeValue::None),
    ("question", MakeValue::None),
    ("quiet", MakeValue::None),
    ("recon", MakeValue::None),
    ("shuffle", MakeValue::Optional),
    ("silent", MakeValue::None),
    ("stop", MakeValue::None),
    ("touch", MakeValue::None),
    ("trace", MakeValue::None),
    ("version", MakeValue::None),
    ("warn-undefined-variables", MakeValue::None),
    ("what-if", MakeValue::Required),
];

/// GNU make short options with a value, mapped to their long names (`j`, `l`, `O` take an optional one).
const MAKE_SHORT_VALUED: &[(char, &str, MakeValue)] = &[
    ('C', "directory", MakeValue::Required),
    ('E', "eval", MakeValue::Required),
    ('f', "file", MakeValue::Required),
    ('I', "include-dir", MakeValue::Required),
    ('o', "old-file", MakeValue::Required),
    ('W', "what-if", MakeValue::Required),
    ('j', "jobs", MakeValue::Optional),
    ('l', "load-average", MakeValue::Optional),
    ('O', "output-sync", MakeValue::Optional),
];

/// GNU make short options without a value (`p` is `--print-data-base`).
const MAKE_SHORT_FLAGS: &str = "bBdehikLnpqrRsStvw";

/// One parsed `make` argument.
pub(crate) enum MakeArg<'a> {
    /// An option by its long name (`file`, `eval`, `print-data-base`, ...) and its value.
    Option { name: &'static str, value: Option<&'a str> },
    /// A command-line variable definition (`NAME=value`, `NAME:=value`, `NAME+=value`, ...).
    Assign { name: &'a str, value: &'a str },
    /// A goal (target name).
    Goal,
    /// An option make does not know or an ambiguous prefix (make refuses to run).
    Unknown,
}

fn is_number(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit())
}

/// Parse a `make` argument list as GNU make 4.4 does (options anywhere, unique long prefixes, short clusters).
pub(crate) fn make_args(args: &[String]) -> Vec<MakeArg<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut options_done = false;
    while let Some(word) = args.get(i) {
        i += 1;
        let next = args.get(i);
        if !options_done && word == "--" {
            options_done = true;
            continue;
        }
        if options_done || !word.starts_with('-') || word == "-" {
            match word.split_once('=') {
                Some((name, value)) => {
                    let name = name.trim_end_matches([':', '+', '?', '!']);
                    out.push(MakeArg::Assign { name, value });
                }
                None => out.push(MakeArg::Goal),
            }
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (typed, attached) = match long.split_once('=') {
                Some((typed, value)) => (typed, Some(value)),
                None => (long, None),
            };
            let exact = MAKE_LONG.iter().find(|(name, _)| *name == typed);
            let mut prefixed = MAKE_LONG.iter().filter(|(name, _)| !typed.is_empty() && name.starts_with(typed));
            let found = exact.or_else(|| match (prefixed.next(), prefixed.next()) {
                (Some(only), None) => Some(only),
                _ => None,
            });
            let Some(&(name, kind)) = found else {
                out.push(MakeArg::Unknown);
                continue;
            };
            let value = match (kind, attached) {
                (_, Some(value)) => Some(value),
                (MakeValue::Required, None) => {
                    i += 1;
                    next.map(String::as_str)
                }
                (MakeValue::Optional, None) if next.is_some_and(|n| is_number(n)) => {
                    i += 1;
                    next.map(String::as_str)
                }
                _ => None,
            };
            out.push(MakeArg::Option { name, value });
            continue;
        }
        let cluster = &word[1..];
        for (at, letter) in cluster.char_indices() {
            if MAKE_SHORT_FLAGS.contains(letter) {
                out.push(MakeArg::Option {
                    name: if letter == 'p' { "print-data-base" } else { "flag" },
                    value: None,
                });
                continue;
            }
            let Some(&(_, name, kind)) = MAKE_SHORT_VALUED.iter().find(|(short, _, _)| *short == letter) else {
                out.push(MakeArg::Unknown);
                break;
            };
            let rest = &cluster[at + letter.len_utf8()..];
            let value = if !rest.is_empty() {
                Some(rest)
            } else if kind == MakeValue::Required || next.is_some_and(|n| is_number(n)) {
                i += 1;
                next.map(String::as_str)
            } else {
                None
            };
            out.push(MakeArg::Option { name, value });
            break;
        }
    }
    out
}

/// Variables whose command-line value changes how make runs recipes or reads its own options.
const MAKE_EXEC_VARIABLES: &[&str] = &[
    "SHELL",
    "MAKESHELL",
    ".SHELLFLAGS",
    "MAKEFLAGS",
    "MFLAGS",
    "GNUMAKEFLAGS",
    "MAKEFILES",
    "MAKE",
    "MAKEOVERRIDES",
    ".RECIPEPREFIX",
];

/// `make --eval`/`-E` (inline makefile text), a makefile from stdin, `-p` (prints every variable, the environment
/// included), a variable that replaces the recipe shell or make's own options, or a variable value holding a make
/// function call (`$(shell ...)` runs when the variable is expanded).
pub(super) fn make_runs_program(args: &[String]) -> bool {
    make_args(args).iter().any(|arg| match arg {
        MakeArg::Option { name: "eval" | "print-data-base", .. } => true,
        MakeArg::Option { name: "file" | "makefile", value } => {
            value.is_none_or(|path| path == "-" || names_stdin_stream(path) || is_unresolved(path))
        }
        MakeArg::Assign { name, value } => {
            MAKE_EXEC_VARIABLES.contains(name) || value.contains(['$', '`']) || is_unresolved(value) || is_unresolved(name)
        }
        _ => false,
    })
}

// ---- cmake ----

/// `-D` cache variables that name a program cmake or the build runs, or a script it includes.
fn cmake_definition_runs_program(definition: &str) -> bool {
    let name = definition.split(['=', ':']).next().unwrap_or(definition).to_ascii_uppercase();
    is_unresolved(definition)
        || (name.starts_with("CMAKE_")
            && ["COMPILER", "LAUNCHER", "INCLUDE", "TOOLCHAIN", "MAKE_PROGRAM", "LINKER", "RULES_OVERRIDE", "COMMAND"]
                .iter()
                .any(|part| name.contains(part)))
        || ["_EXECUTABLE", "_COMMAND", "_PROGRAM"].iter().any(|suffix| name.ends_with(suffix))
        || matches!(name.as_str(), "CMAKE_AR" | "CMAKE_RANLIB" | "CMAKE_NM" | "CMAKE_OBJCOPY" | "CMAKE_OBJDUMP" | "CMAKE_STRIP")
}

/// `cmake -E` (command mode: `env`, `copy`, `rm`, ...), `-P` (script mode), `-C` (an initial-cache script),
/// `--toolchain`, `--open` (runs the IDE), a `-D` that names a compiler, launcher or included script, and native build
/// tool options after `--build DIR --` (judged as make's).
pub(super) fn cmake_runs_program(args: &[String]) -> bool {
    let mut build = false;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if build && word == "--" {
            return make_runs_program(&args[i..]);
        }
        match word.as_str() {
            "-E" | "-P" => return true,
            "--build" => build = true,
            _ => {}
        }
        if word.starts_with("-C") || word.starts_with("--toolchain") || word.starts_with("--open") {
            return true;
        }
        if let Some(definition) = word.strip_prefix("-D") {
            let definition = if definition.is_empty() {
                i += 1;
                args.get(i - 1).map_or("", String::as_str)
            } else {
                definition
            };
            if cmake_definition_runs_program(definition) {
                return true;
            }
        }
    }
    false
}

// ---- cargo, rustc ----

/// `cargo --config` (sets any config key: `build.rustc-wrapper`, `target.*.runner`, aliases), `-Z` (unstable flags,
/// some load config or host tools) and `cargo doc --open` (runs the browser). Words after `--` belong to the program
/// or test binary.
pub(super) fn cargo_runs_program(args: &[String]) -> bool {
    let options = args.iter().take_while(|w| *w != "--");
    let mut doc = false;
    for word in options {
        if word == "--config" || word.starts_with("--config=") || word.starts_with("-Z") {
            return true;
        }
        if !word.starts_with('-') && !word.starts_with('+') && matches!(word.as_str(), "doc" | "d") {
            doc = true;
        }
        if doc && word == "--open" {
            return true;
        }
    }
    false
}

/// `rustc` codegen options that run a program (`-C linker=`, `-C link-arg=` / `link-args=` can pass `-fuse-ld=PATH`
/// or `-B`, `-C dlltool=`), `-Z` (unstable, e.g. `codegen-backend=` loads a library), `--extern` of anything but an
/// rlib/rmeta (a proc-macro library runs at compile time), and `@file` (options read from a file).
pub(super) fn rustc_runs_program(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        let next = args.get(i);
        if word.starts_with('@') || word.starts_with("-Z") || is_unresolved(word) {
            return true;
        }
        let codegen = if let Some(rest) = word.strip_prefix("--codegen") {
            rest.strip_prefix('=').or_else(|| rest.is_empty().then(|| next.map_or("", String::as_str)))
        } else {
            word.strip_prefix("-C").map(|rest| if rest.is_empty() { next.map_or("", String::as_str) } else { rest })
        };
        if let Some(setting) = codegen {
            let key = setting.split('=').next().unwrap_or(setting);
            if matches!(key, "linker" | "link-arg" | "link-args" | "dlltool") {
                return true;
            }
        }
        if word == "--extern" || word.starts_with("--extern=") {
            let value = long_value(word, next).unwrap_or("");
            let path = value.split_once('=').map_or("", |(_, path)| path);
            if !(path.ends_with(".rlib") || path.ends_with(".rmeta")) {
                return true;
            }
        }
    }
    false
}

// ---- pytest ----

/// pytest's debugger (`--pdb`, `--trace`, `--pdbcls`) takes commands from stdin, `-p NAME` imports a plugin module
/// (`-p no:NAME` only disables one), and `-o`/`--override-ini` can set `addopts` and so add any option.
pub(super) fn pytest_runs_program(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        let next = args.get(i);
        if let Some(long) = word.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if matches!(name, "pdb" | "trace" | "pdbcls" | "override-ini") {
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
                'o' => return true,
                'p' => {
                    if !short_value(rest, next).is_some_and(|plugin| plugin.starts_with("no:")) {
                        return true;
                    }
                    break;
                }
                'k' | 'm' | 'c' | 'r' | 'W' | 'n' => break,
                _ => {}
            }
        }
    }
    false
}

// ---- just ----

/// `just --shell`/`--shell-arg`/`--shell-command` replace the recipe shell, `-c`/`--command` runs a command,
/// `--chooser`/`--choose` run a chooser, and `-e`/`--edit` runs the editor. Options end at the first recipe name.
pub(super) fn just_runs_program(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if !word.starts_with('-') || word == "--" {
            // A variable override (`NAME=value`) may come before the recipe.
            if word.contains('=') {
                continue;
            }
            return false;
        }
        if let Some(long) = word.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if matches!(name, "shell" | "shell-arg" | "shell-command" | "command" | "chooser" | "choose" | "edit") {
                return true;
            }
            if !long.contains('=')
                && matches!(name, "justfile" | "working-directory" | "dotenv-filename" | "dotenv-path" | "tempdir" | "color" | "dump-format" | "list-heading" | "list-prefix" | "show" | "completions" | "request" | "usage")
            {
                i += 1;
            }
            if name == "set" {
                i += 2;
            }
            continue;
        }
        for letter in word[1..].chars() {
            match letter {
                'c' | 'e' => return true,
                'd' | 'E' | 'f' | 's' => {
                    i += usize::from(word.ends_with(letter));
                    break;
                }
                _ => {}
            }
        }
    }
    false
}

// ---- bazel ----

/// Bazel options that run a program of the caller's choosing (`--run_under`, `--workspace_status_command`,
/// `--credential_helper`) or load an rc file that can set them (`--bazelrc`, a startup option).
pub(super) fn bazel_runs_program(args: &[String]) -> bool {
    args.iter().take_while(|w| *w != "--").any(|word| {
        word.strip_prefix("--").is_some_and(|long| {
            let name = long.split('=').next().unwrap_or(long);
            matches!(name, "run_under" | "workspace_status_command" | "credential_helper" | "bazelrc")
        })
    })
}

// ---- npm, pnpm, yarn ----

/// npm config keys that name a program npm runs: the script shell, node's own options (`--require`), the git and
/// node-gyp binaries, the editor/browser/viewer/shell commands, and the init module. npm accepts abbreviations, so
/// each is matched from the shortest prefix that no other common key shares.
const NPM_PROGRAM_KEYS: &[(&str, usize)] = &[
    ("--script-shell", 3),
    ("--node-options", 6),
    ("--node-gyp", 6),
    ("--editor", 2),
    ("--browser", 2),
    ("--viewer", 2),
    ("--shell", 3),
    ("--onload-script", 2),
    ("--init-module", 6),
];

/// An npm-family option naming a program npm runs. Words after `--` belong to the script.
pub(super) fn npm_runs_program(args: &[String]) -> bool {
    args.iter().take_while(|w| *w != "--").any(|word| {
        let name = word.split('=').next().unwrap_or(word);
        name == "--git"
            || NPM_PROGRAM_KEYS
                .iter()
                .any(|(full, min)| name.len() >= *min + 2 && long_option_is(word, full, *min))
    })
}

// ---- uv, rustup ----

/// `uv --python PATH` / `-p PATH` runs that interpreter to query it; a version request (`3.12`) does not.
pub(super) fn uv_runs_program(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        let value = if word == "--python" || word.starts_with("--python=") {
            long_value(word, args.get(i))
        } else if let Some(rest) = word.strip_prefix("-p") {
            short_value(rest, args.get(i))
        } else {
            continue;
        };
        if value.is_none_or(|value| value.contains(['/', '\\']) || is_unresolved(value)) {
            return true;
        }
    }
    false
}

/// `rustup doc` opens the browser unless it only prints the path (`--path`).
pub(super) fn rustup_runs_program(args: &[String]) -> bool {
    args.iter().find(|w| !w.starts_with('-') && !w.starts_with('+')).is_some_and(|sub| sub == "doc")
        && !args.iter().any(|w| w == "--path")
}

// ---- gh ----

/// `gh --web`/`-w` opens the browser, `gh auth status --show-token`/`-t` prints the token, and a `--jq`/`-q` filter
/// can read the environment (`env`, `$ENV`).
pub(super) fn gh_runs_program(args: &[String]) -> bool {
    let auth_status = args.first().is_some_and(|w| w == "auth") && args.get(1).is_some_and(|w| w == "status");
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if name == "web" || (auth_status && name == "show-token") {
                return true;
            }
            if name == "jq"
                && long_value(word, args.get(i))
                    .is_none_or(|filter| is_unresolved(filter) || jq_reads_environment(&[filter.to_owned()]))
            {
                return true;
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for (at, letter) in cluster.char_indices() {
            match letter {
                'w' => return true,
                't' if auth_status => return true,
                'q' => {
                    let filter = short_value(&cluster[at + 1..], args.get(i));
                    if filter.is_none_or(|filter| is_unresolved(filter) || jq_reads_environment(&[filter.to_owned()])) {
                        return true;
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    false
}
