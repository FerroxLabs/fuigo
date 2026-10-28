//! u35 g3: forms of the programs on the built-in approval lists (the Ask-mode read-only lists and the Auto mode
//! routine list) that write a file the write model does not see, change machine, repository, registry or toolchain
//! state, or read a file whose name the read model does not see (and print what is in it). Such a form gets no
//! approval from a list: it asks, or in Auto mode goes to the model. A user grant still covers it.
//!
//! Options that run another program are exec-surface findings instead (`exec_surface`, `exec_risk`), which also floor
//! broad grants. Every program on both lists was audited for both kinds (u35-classify BUILD-LOG, packet g3); a program
//! with no arm here has no option of either kind that the other models miss. When an option's meaning was in doubt,
//! the form asks.

use crate::permission::exec_surface::{MakeArg, is_unresolved, long_option_is, make_args};

/// Whether the list-approved program in `words` (canonical wrappers peeled, program word already plain) is used in a
/// form that must not be approved by the list alone.
pub(crate) fn listed_form_needs_approval(words: &[String]) -> bool {
    let Some(head) = words.first() else {
        return false;
    };
    let args = &words[1..];
    match head.as_str() {
        "date" => !date_only_prints(args),
        "hostname" => !hostname_only_prints(args),
        "wc" | "du" => options(args).any(|w| long_option_is(w, "--files0-from", 1)),
        "sort" => sort_needs_approval(args),
        "diff" => options(args).any(|w| long_option_is(w, "--from-file", 1) || long_option_is(w, "--to-file", 2)),
        "file" => file_needs_approval(args),
        "tree" => tree_needs_approval(args),
        "strings" => args.iter().any(|w| w.starts_with('@')),
        "jq" => args.iter().any(|w| matches!(w.as_str(), "--rawfile" | "--slurpfile" | "--argfile")),
        // Interactive process viewers take keys from stdin (kill, renice, show a process environment); procps
        // `top -b` and macOS `top -l N` only print.
        "htop" => true,
        "top" => !args.iter().any(|w| {
            w.strip_prefix('-').is_some_and(|cluster| !cluster.starts_with('-') && cluster.contains('b'))
                || w.starts_with("-l")
        }),
        "kubectl" => kubectl_needs_approval(args),
        "cargo" => cargo_needs_approval(args),
        "rustc" | "clippy" => rustc_needs_approval(args),
        "pytest" => pytest_needs_approval(args),
        "make" => make_needs_approval(args),
        "cmake" => !cmake_is_routine(args),
        "go" => go_needs_approval(args),
        "bazel" => bazel_needs_approval(args),
        "just" => just_needs_approval(args),
        "npm" | "pnpm" | "yarn" => npm_needs_approval(args),
        "uv" => uv_needs_approval(args),
        "rustup" => rustup_needs_approval(args),
        _ => false,
    }
}

/// The words before a bare `--`.
fn options(args: &[String]) -> impl Iterator<Item = &String> {
    args.iter().take_while(|w| *w != "--")
}

/// A path that leaves the project: absolute, home-relative, through `..`, a drive or URL form, or unresolved.
fn leaves_project(path: &str) -> bool {
    path.starts_with(['/', '\\', '~'])
        || path.contains(':')
        || path.split(['/', '\\']).any(|part| part == "..")
        || is_unresolved(path)
}

/// The value of `--name=value` / `--name value` or `-Xvalue` / `-X value` at `args[at]`.
fn value_at<'a>(args: &'a [String], at: usize, attached: Option<&'a str>) -> Option<&'a str> {
    match attached {
        Some(value) if !value.is_empty() => Some(value),
        _ => args.get(at + 1).map(String::as_str),
    }
}

/// `date` printing the time: `+FORMAT`, `-u`, `-R`, `-I`, `-d STRING`, `-r FILE` (its time only), BSD `-j`/`-n`/
/// `-v`/`-z`. Anything else asks: an operand sets the clock (GNU and BSD), `-s`/`--set` sets it, GNU `-f FILE` prints
/// each line of FILE in its error messages, and BSD `-f` parses an operand.
fn date_only_prints(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word.starts_with('+') {
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = long.split_once('=').map_or((long, false), |(name, _)| (name, true));
            match name {
                "utc" | "universal" | "rfc-2822" | "rfc-email" | "iso-8601" | "rfc-3339" | "debug" | "help" | "version" => {}
                "date" | "reference" => i += usize::from(!attached),
                _ => return false,
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) else {
            return false;
        };
        for (at, letter) in cluster.char_indices() {
            match letter {
                'u' | 'R' | 'j' | 'n' => {}
                'I' => break,
                'd' | 'r' | 'v' | 'z' => {
                    i += usize::from(at + 1 == cluster.len());
                    break;
                }
                _ => return false,
            }
        }
    }
    true
}

/// `hostname` printing names: no operand (one sets the host name, or with `-y`/`-d` the NIS/DNS domain) and none of
/// `-F`/`--file` (sets it from a file) or `-b`/`--boot`.
fn hostname_only_prints(args: &[String]) -> bool {
    const LONG: &[&str] = &[
        "--alias", "--all-fqdns", "--domain", "--fqdn", "--long", "--ip-address", "--all-ip-addresses", "--short", "--yp",
        "--nis", "--version", "--help", "--verbose",
    ];
    args.iter().all(|word| {
        if word.starts_with("--") {
            return LONG.contains(&word.as_str());
        }
        word.strip_prefix('-')
            .is_some_and(|cluster| !cluster.is_empty() && cluster.chars().all(|c| "aAdfiIsyVhv".contains(c)))
    })
}

/// GNU sort `--files0-from` (sorts files named in a file), `--random-source` (reads a file the read model does not
/// see) and `-T`/`--temporary-directory` (writes temporary files there). `--compress-program` is an exec-risk floor.
fn sort_needs_approval(args: &[String]) -> bool {
    options(args).any(|word| {
        if word.starts_with("--") {
            return long_option_is(word, "--files0-from", 3)
                || long_option_is(word, "--random-source", 8)
                || long_option_is(word, "--temporary-directory", 2);
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        for letter in cluster.chars() {
            match letter {
                'T' => return true,
                'k' | 'o' | 'S' | 't' => return false,
                _ => {}
            }
        }
        false
    })
}

/// file(1) `-f`/`--files-from` (names read from a file, printed), `-m`/`--magic-file` and macOS `-M` (a magic file
/// the read model does not see; parse errors quote it), `-C`/`--compile` (writes a compiled magic file).
fn file_needs_approval(args: &[String]) -> bool {
    options(args).any(|word| {
        if word.starts_with("--") {
            return long_option_is(word, "--files-from", 3)
                || long_option_is(word, "--magic-file", 1)
                || long_option_is(word, "--compile", 3);
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        for letter in cluster.chars() {
            match letter {
                'C' | 'f' | 'm' | 'M' => return true,
                'e' | 'F' | 'P' => return false,
                _ => {}
            }
        }
        false
    })
}

/// tree `--fromfile`/`--fromtabfile` (prints a listing read from a file), `--infofile` (prints comments from a file)
/// and `-R` (runs tree again in every directory, writing `00Tree.html`). `-o` is checked by the routine list.
fn tree_needs_approval(args: &[String]) -> bool {
    options(args).any(|word| {
        let name = word.split('=').next().unwrap_or(word);
        matches!(name, "--fromfile" | "--fromtabfile" | "--infofile")
            || (word.starts_with('-') && !word.starts_with("--") && word.contains('R'))
    })
}

/// kubectl `--cache-dir` (writes the HTTP cache there), `--log-file`/`--log-dir`, `--profile-output` (writes a
/// profile), and a template read from a file (`-o go-template-file=`, `jsonpath-file=`, `--template`). Resource
/// selection by `-f`/`-k` is an exec-surface floor (it can name a Secret).
fn kubectl_needs_approval(args: &[String]) -> bool {
    args.iter().any(|word| {
        long_option_is(word, "--cache-dir", 3)
            || long_option_is(word, "--log-file", 5)
            || long_option_is(word, "--log-dir", 5)
            || long_option_is(word, "--profile-output", 9)
            || long_option_is(word, "--template", 3)
            || ["template-file", "templatefile", "jsonpath-file", "custom-columns-file"].iter().any(|form| word.contains(form))
    })
}

/// cargo subcommands that build, test, run or manage the project. `install`/`uninstall` (build a remote crate and
/// install it outside the project), `publish`/`login`/`logout`/`owner`/`yank` (registry state), `config`, and any
/// other external subcommand (`cargo-NAME` from PATH) ask. A listed subcommand cargo does not build in (`fmt`,
/// `clippy`, `nextest`) can be replaced by an `[alias]` in a Cargo config file of the project, and one that does not
/// build can run a `[build] rustc`/`rustc-wrapper` of it; that is not judged here but by the bash request's
/// configuration scan ([`repository_tool_config_runs`], u35 g13/g14), which asks for it.
const CARGO_ROUTINE_SUBCOMMANDS: &[&str] = &[
    "build", "b", "check", "c", "test", "t", "bench", "run", "r", "clippy", "fmt", "doc", "d", "tree", "metadata", "fetch",
    "update", "clean", "fix", "new", "init", "add", "remove", "rm", "generate-lockfile", "locate-project", "pkgid",
    "read-manifest", "verify-project", "version", "help", "search", "info", "vendor", "package", "nextest",
];

/// cargo options whose value is the next word when not attached with `=`.
const CARGO_VALUED: &[&str] = &[
    "--color", "--config", "-Z", "-C", "--directory", "--explain", "--manifest-path", "--target-dir", "--artifact-dir", "--out-dir",
    "--lockfile-path", "-p", "--package", "--exclude", "--target", "--features", "-F", "-j", "--jobs", "--bin", "--example",
    "--test", "--bench", "--profile", "--message-format", "--registry", "--index", "--vers", "--git",
    "--branch", "--tag", "--rev", "--path", "--name", "--edition", "--vcs", "--rename",
];

/// A routine cargo invocation: a listed subcommand, no output or manifest path outside the project, no other
/// registry. Words after `--` belong to the program or test binary.
fn cargo_needs_approval(args: &[String]) -> bool {
    let mut subcommand: Option<&str> = None;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        let at = i;
        i += 1;
        if word == "--" {
            break;
        }
        if at == 0 && word.starts_with('+') {
            continue;
        }
        if word.starts_with('-') {
            let (name, attached) = match word.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None if word.starts_with("-C") && word.len() > 2 => ("-C", Some(&word[2..])),
                None => (word.as_str(), None),
            };
            if matches!(name, "--registry" | "--index") {
                return true;
            }
            if matches!(
                name,
                "--target-dir" | "--artifact-dir" | "--out-dir" | "--manifest-path" | "--lockfile-path" | "-C" | "--directory"
            )
                && value_at(args, at, attached).is_none_or(leaves_project)
            {
                return true;
            }
            if attached.is_none() && CARGO_VALUED.contains(&name) {
                i += 1;
            }
            continue;
        }
        match subcommand {
            None => {
                if !CARGO_ROUTINE_SUBCOMMANDS.contains(&word.as_str()) {
                    return true;
                }
                subcommand = Some(word.as_str());
            }
            // `cargo new PATH` / `cargo init PATH` create the package there.
            Some("new" | "init") if leaves_project(word) => return true,
            Some(_) => {}
        }
    }
    false
}

/// rustc `--sysroot` (another standard library and its proc macros), `-C incremental=`/`profile-generate=`/
/// `profile-use=` (write or read a directory the models do not see). Codegen options that run a program are an
/// exec-surface floor.
fn rustc_needs_approval(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--sysroot" || word.starts_with("--sysroot=") {
            return true;
        }
        let setting = if let Some(rest) = word.strip_prefix("--codegen") {
            rest.strip_prefix('=').or_else(|| rest.is_empty().then(|| args.get(i).map_or("", String::as_str)))
        } else {
            word.strip_prefix("-C").map(|rest| if rest.is_empty() { args.get(i).map_or("", String::as_str) } else { rest })
        };
        if setting.is_some_and(|s| {
            matches!(s.split('=').next().unwrap_or(s), "incremental" | "profile-generate" | "profile-use")
        }) {
            return true;
        }
    }
    false
}

/// pytest options that write a report or temporary tree (`--junitxml`, `--basetemp` (also deleted), `--log-file`,
/// `--debug`, `--report-log`, `--resultlog`, `--html`, a `--cov-report` with a path), choose another config or root
/// (`-c`, `--config-file`, `--rootdir`, `--confcutdir`), or upload the session (`--pastebin`). pytest does not accept
/// abbreviated long options. The debugger, plugins and ini overrides are an exec-surface floor.
fn pytest_needs_approval(args: &[String]) -> bool {
    args.iter().any(|word| {
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = long.split_once('=').map_or((long, ""), |(name, value)| (name, value));
            return matches!(
                name,
                "junitxml" | "junit-xml" | "basetemp" | "log-file" | "debug" | "report-log" | "resultlog" | "result-log"
                    | "html" | "config-file" | "rootdir" | "confcutdir" | "pastebin" | "inifile"
            ) || (name == "cov-report" && value.contains(':'));
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        for letter in cluster.chars() {
            match letter {
                'c' => return true,
                'k' | 'm' | 'p' | 'o' | 'r' | 'W' | 'n' => return false,
                _ => {}
            }
        }
        false
    })
}

/// make `-C DIR`, `-f FILE` and `-I DIR` outside the project (another project's makefile runs) and a variable whose
/// value is a path (it can name the compiler or another program a recipe runs). Inline makefiles, stdin makefiles,
/// `-p` and shell-replacing variables are an exec-surface floor.
fn make_needs_approval(args: &[String]) -> bool {
    make_args(args).iter().any(|arg| match arg {
        MakeArg::Option { name: "directory" | "file" | "makefile" | "include-dir", value } => value.is_none_or(leaves_project),
        MakeArg::Assign { value, .. } => value.contains(['/', '\\', '~']),
        MakeArg::Unknown => true,
        _ => false,
    })
}

/// The cmake forms that configure or build a project: `-S`/`-B` (the build tree inside the project), `-G`/`-A`/`-T`,
/// `-D` (a plain value; one that names a compiler or script is an exec-surface floor), `-U`, `-W…`, presets, log and
/// trace options, a source directory operand, and `--build DIR` with its build options. Everything else asks:
/// `--install`, `--open`, `-E`, `-P`, `-C`, `--graphviz`, `--trace-redirect`, `--profiling-output`,
/// `--system-information`, `--help-*` with a file, `--workflow`, the debugger, and native build tool options after
/// `--`.
fn cmake_is_routine(args: &[String]) -> bool {
    const FLAGS: &[&str] = &[
        "--fresh", "--version", "-h", "--help", "-N", "-L", "-LA", "-LH", "-LAH", "--debug-output", "--debug-find",
        "--trace", "--trace-expand", "--warn-uninitialized", "--no-warn-unused-cli", "--check-system-vars",
        "--compile-no-warning-as-error", "--list-presets", "--clean-first", "-v", "--verbose", "--log-context",
    ];
    let mut build = false;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        let at = i;
        i += 1;
        if !word.starts_with('-') {
            continue;
        }
        if FLAGS.contains(&word.as_str()) || word.starts_with("-W") {
            continue;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = long.split_once('=').map_or((long, None), |(name, value)| (name, Some(value)));
            match name {
                "build" => {
                    build = true;
                    i += 1;
                }
                "preset" | "log-level" | "loglevel" | "trace-source" | "list-presets" | "parallel" => {
                    i += usize::from(attached.is_none() && name == "preset");
                }
                "target" | "config" | "resolve-package-references" if build => i += usize::from(attached.is_none()),
                _ => return false,
            }
            continue;
        }
        let Some(letter) = word[1..].chars().next() else {
            return false;
        };
        let attached = Some(&word[1 + letter.len_utf8()..]).filter(|rest| !rest.is_empty());
        match letter {
            'B' => {
                if value_at(args, at, attached).is_none_or(leaves_project) {
                    return false;
                }
                i += usize::from(attached.is_none());
            }
            'S' | 'G' | 'A' | 'T' | 'U' => i += usize::from(attached.is_none()),
            'D' => {
                let definition = value_at(args, at, attached).unwrap_or("");
                let value = definition.split_once('=').map_or("", |(_, value)| value);
                if value.contains(['/', '\\', '~']) || is_unresolved(definition) {
                    return false;
                }
                i += usize::from(attached.is_none());
            }
            't' if build => i += usize::from(attached.is_none()),
            'j' if build => {
                if attached.is_none() && args.get(i).is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) {
                    i += 1;
                }
            }
            _ => return false,
        }
    }
    true
}

/// go flags that write a profile, trace, cover or output directory the write model does not see, read an overlay or
/// alternate go.mod, or a package dir; `go env -w`/`-u` (rewrites the user's go env file, e.g. `GOFLAGS`), `go clean`
/// of the shared caches or installed binaries, `go telemetry` with a mode (writes its config). Flags that run a
/// program are an exec-surface floor.
fn go_needs_approval(args: &[String]) -> bool {
    const WRITE_FLAGS: &[&str] = &[
        "coverprofile", "cpuprofile", "memprofile", "blockprofile", "mutexprofile", "trace", "outputdir", "overlay",
        "pkgdir", "modfile", "fuzzcachedir",
    ];
    let mut subcommand: Option<&str> = None;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if let Some(flag) = word.strip_prefix("--").or_else(|| word.strip_prefix('-')) {
            let name = flag.split('=').next().unwrap_or(flag);
            let name = name.strip_prefix("test.").unwrap_or(name);
            if WRITE_FLAGS.contains(&name) {
                return true;
            }
            match (subcommand, name) {
                (Some("env"), "w" | "u") => return true,
                (Some("clean"), "cache" | "modcache" | "testcache" | "fuzzcache" | "i") => return true,
                (None, "C") if !flag.contains('=') => i += 1,
                _ => {}
            }
            continue;
        }
        match subcommand {
            None => subcommand = Some(word.as_str()),
            Some("telemetry") => return true,
            Some(_) => {}
        }
    }
    false
}

/// bazel: startup options (before the command: `--output_base`, `--output_user_root`, `--host_jvm_args`, ...), a
/// command outside build/test/query/run and the other read or build commands, options that change the toolchain,
/// the action environment or a repository, write a cache, log or profile elsewhere, talk to a remote service, or are
/// experimental, and a copt/linkopt naming a path or another linker (`-B`, `-fuse-ld`).
fn bazel_needs_approval(args: &[String]) -> bool {
    const COMMANDS: &[&str] = &[
        "build", "test", "query", "cquery", "aquery", "info", "version", "help", "run", "coverage", "fetch", "mod", "clean",
        "shutdown", "sync", "print_action",
    ];
    const RISKY_PREFIXES: &[&str] = &[
        "crosstool_top", "host_crosstool_top", "extra_toolchains", "extra_execution_platforms", "platforms",
        "host_platform", "override_", "registry", "action_env", "host_action_env", "repo_env", "test_env",
        "disk_cache", "repository_cache", "remote_", "bes_", "experimental_", "build_event_", "execution_log",
        "profile", "explain", "java_", "host_java", "tool_java", "javabase", "host_javabase", "jvmopt", "host_jvmopt",
        "script_path", "output_base", "output_user_root", "install_base", "distdir", "google_credentials",
        "grpc_log", "memory_profile",
    ];
    let mut command: Option<&str> = None;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        let Some(long) = word.strip_prefix("--") else {
            if word.starts_with('-') {
                // A short option (`-c opt`, `-k`, `-s`) after the command; none before it.
                if command.is_none() {
                    return true;
                }
                continue;
            }
            if command.is_none() {
                if !COMMANDS.contains(&word.as_str()) {
                    return true;
                }
                command = Some(word.as_str());
            }
            continue;
        };
        if command.is_none() {
            return true;
        }
        let (name, value) = long.split_once('=').map_or((long, ""), |(name, value)| (name, value));
        let name = name.strip_prefix("no").filter(|rest| !rest.is_empty()).unwrap_or(name);
        if RISKY_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
            return true;
        }
        if matches!(name, "copt" | "cxxopt" | "conlyopt" | "linkopt" | "host_copt" | "host_cxxopt" | "host_linkopt")
            && (value.is_empty() || value.contains(['/', '\\']) || value.contains("-B") || value.contains("fuse-ld"))
        {
            return true;
        }
    }
    false
}

/// just `-f`/`--justfile` and `-d`/`--working-directory` outside the project, `--dotenv-filename`/`--dotenv-path`/
/// `-E` (loads variables from a file), `--tempdir`, `--init` (writes a justfile), `--set` and `NAME=value` overrides
/// naming a path (a recipe can run it). The shell, command, chooser and editor options are an exec-surface floor.
fn just_needs_approval(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        let at = i;
        i += 1;
        if !word.starts_with('-') {
            if let Some((_, value)) = word.split_once('=') {
                if value.contains(['/', '\\', '~']) || is_unresolved(value) {
                    return true;
                }
                continue;
            }
            // The first recipe name ends the options.
            return false;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = long.split_once('=').map_or((long, None), |(name, value)| (name, Some(value)));
            match name {
                "dotenv-filename" | "dotenv-path" | "tempdir" | "init" | "set" => return true,
                "justfile" | "working-directory" => {
                    if value_at(args, at, attached).is_none_or(leaves_project) {
                        return true;
                    }
                    i += usize::from(attached.is_none());
                }
                _ => {}
            }
            continue;
        }
        for (pos, letter) in word[1..].char_indices() {
            let rest = &word[1 + pos + letter.len_utf8()..];
            match letter {
                'E' => return true,
                'f' | 'd' => {
                    let attached = Some(rest).filter(|r| !r.is_empty());
                    if value_at(args, at, attached).is_none_or(leaves_project) {
                        return true;
                    }
                    i += usize::from(attached.is_none());
                    break;
                }
                's' => {
                    i += usize::from(rest.is_empty());
                    break;
                }
                _ => {}
            }
        }
    }
    false
}

/// npm/pnpm/yarn: `config` (sets or prints registry tokens and program keys), `link`/`unlink` (global symlinks),
/// `store` other than `path`/`status` (pnpm's shared store), `version` with a bump (commits and tags), and (u35 g5b,
/// Astra r4) any option word before `--` that is not exactly one of [`NPM_EXACT_OPTIONS`]. npm accepts unique
/// abbreviations (`--prefi=/tmp/out`), combined shorthands (`-gq` is `--global --quiet`) and shorthands with a value
/// (`-L global`), so its options are approved by exact spelling only: a global install, another prefix, registry,
/// config file or cache directory, and every form not listed, ask. Options that name a program npm runs are an
/// exec-surface floor.
fn npm_needs_approval(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("config" | "c" | "link" | "ln" | "unlink") => return true,
        Some("store") if !matches!(args.get(1).map(String::as_str), Some("path" | "status")) => return true,
        Some("version") if args[1..].iter().any(|w| !w.starts_with('-')) => return true,
        _ => {}
    }
    options(args).any(|word| word.starts_with('-') && !npm_option_is_listed(word))
}

/// u35 g5b: the npm/pnpm/yarn options an approved form may carry, spelled exactly. Each changes only how the
/// project's own dependencies are recorded or installed, or how output looks.
const NPM_EXACT_OPTIONS: &[&str] = &[
    "--save", "-S", "--save-dev", "-D", "--save-exact", "-E", "--save-optional", "-O", "--save-peer", "--save-prod",
    "-P", "--no-save", "--dev", "--production", "--prod", "--frozen-lockfile", "--no-frozen-lockfile", "--immutable",
    "--prefer-offline", "--offline", "--no-audit", "--no-fund", "--no-package-lock", "--legacy-peer-deps",
    "--strict-peer-deps", "--ignore-scripts", "--if-present", "--no-optional", "--silent", "-s", "--quiet", "--json",
    "--long", "--parseable", "--all", "--verbose", "--version", "-v", "--help", "-h", "--recursive", "-r",
    "--workspaces", "--include-workspace-root", "--color", "--no-color", "--foreground-scripts", "--dry-run",
    "--non-interactive", "--check-files",
];

fn npm_option_is_listed(word: &str) -> bool {
    if NPM_EXACT_OPTIONS.contains(&word) {
        return true;
    }
    match word.split_once('=') {
        Some(("--omit", value)) => matches!(value, "dev" | "optional" | "peer"),
        Some(("--include", value)) => matches!(value, "dev" | "optional" | "peer" | "prod"),
        Some(("--loglevel", value)) => {
            matches!(value, "silent" | "error" | "warn" | "notice" | "http" | "info" | "verbose" | "silly")
        }
        Some(("--depth", value)) => !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        _ => false,
    }
}

/// uv: `self` (replaces the uv binary), `cache clean`/`prune` (the shared cache), installs outside the project
/// environment (`--system`, `--break-system-packages`, `--target`, `--prefix`), output files and directories
/// (`-o`/`--output-file`, `--out-dir`), another config file or index, and `--directory`/`--project` or a `venv`/
/// `init` path outside the project.
fn uv_needs_approval(args: &[String]) -> bool {
    match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
        (Some("self"), _) | (Some("cache"), Some("clean" | "prune")) => return true,
        _ => {}
    }
    let subcommand = args.first().map(String::as_str);
    // `uv run [OPTIONS] COMMAND ...`: the launched command's own options are judged as that command.
    let own = if subcommand == Some("run") {
        args.iter().skip(1).position(|w| !w.starts_with('-')).map_or(args.len(), |at| at + 1)
    } else {
        args.len()
    };
    let options: Vec<&String> = options(&args[..own]).collect();
    options.iter().enumerate().any(|(at, word)| {
        let (name, attached) = word.split_once('=').map_or((word.as_str(), None), |(name, value)| (name, Some(value)));
        match name {
            "--system" | "--break-system-packages" | "--target" | "--prefix" | "-o" | "--output-file" | "--out-dir"
            | "--config-file" | "--index-url" | "-i" | "--extra-index-url" | "--index" | "--default-index"
            | "--find-links" | "-f" => true,
            "--directory" | "--project" => attached
                .or_else(|| options.get(at + 1).map(|w| w.as_str()))
                .is_none_or(leaves_project),
            _ => at > 0 && matches!(subcommand, Some("venv" | "init")) && !word.starts_with('-') && leaves_project(word),
        }
    })
}

/// rustup `self` (updates or uninstalls rustup itself) and `toolchain link` (a directory whose binaries later builds
/// run). `rustup doc` opening a browser is an exec-surface floor.
fn rustup_needs_approval(args: &[String]) -> bool {
    let words: Vec<&str> = args.iter().map(String::as_str).filter(|w| !w.starts_with('-') && !w.starts_with('+')).collect();
    matches!(words.as_slice(), ["self", ..] | ["toolchain", "link", ..])
}

// ---- u35 g13/g14: configuration files of the project that a routine tool loads ----

/// u35 g14: one command of a bash request as the configuration scan sees it ([`repository_tool_config_runs`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolSegment {
    /// A command whose program the normaliser pinned: its normalised words. `moved`: a wrapper moved its directory
    /// (`env -C`, `sudo -D`), so where it runs is not known.
    Command { words: Vec<String>, moved: bool },
    /// An opaque shell script (`sh -c 'cd sub && npm ls'`): its words split into commands
    /// ([`crate::permission::exec_surface::split_script_text`]), judged from the directory the script starts in.
    Nested(Vec<Vec<String>>),
}

/// u35 g14: the programs whose project configuration the scan reads.
const CONFIG_TOOLS: &[&str] = &["npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg", "cargo", "bazel", "bazelisk"];

/// u35 g14: the program name of `word` (basename, lowercased, `.exe` stripped) when it is one whose project
/// configuration the scan reads.
pub(crate) fn is_config_tool(word: &str) -> bool {
    CONFIG_TOOLS.contains(&crate::permission::exec_surface::program_name(word).as_str())
}

/// u35 g13 (Grok r12 High), g14 (Astra/Grok r13 High, Fable r13 Medium): whether a command of `segments` loads a
/// configuration file of the project that can make it run a program no command-line check sees, in the folder the
/// command runs in or one above it (up to, not including, the home folder): the npm family's `.npmrc` (`onload-script`
/// and the other keys naming a program), yarn's `.yarnrc.yml` (`yarnPath`, `plugins`) and classic `.yarnrc`
/// (`yarn-path`); a Cargo config file's alias for the subcommand, `[build]` `rustc`/`rustc-wrapper`/
/// `rustc-workspace-wrapper`/`rustdoc` naming a file, `[env]`, a credential provider or an `include`; for bazel, a
/// `.bazelrc` with a `startup`, `import` or `try-import` line or an option [`bazel_needs_approval`] rejects,
/// bazelisk's `tools/bazel` wrapper, and a `.bazelversion` or `.bazeliskrc` naming a fork or download URL.
///
/// Owner decision 2: a routine build, test, run or install already runs repository code, so the scan judges only the
/// subcommands that do not ([`tool_scan_applies`]). The folder is followed as the shell and the tool change it: a
/// literal `cd`/`pushd` (every folder the script has been in is judged, so a subshell or `popd` cannot hide one),
/// `cargo -C`/`--directory`, npm `--prefix`/`-C`, pnpm `--dir`/`-C`, yarn `--cwd`. A change that cannot be pinned (a
/// `cd "$X"`, `env -C`) is a hit for a command the scan judges. A plain text scan, not a parser, so it fails closed: a
/// file that is there but cannot be read counts, and so does a Cargo config line it cannot classify.
pub(crate) fn repository_tool_config_runs(segments: &[ToolSegment], dir: &std::path::Path) -> bool {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(std::path::PathBuf::from);
    tool_config_runs_with_home(segments, dir, home.as_deref())
}

/// [`repository_tool_config_runs`] with the home folder given (tests).
pub(crate) fn tool_config_runs_with_home(
    segments: &[ToolSegment],
    dir: &std::path::Path,
    home: Option<&std::path::Path>,
) -> bool {
    let mut cwds = Some(vec![dir.to_path_buf()]);
    for segment in segments {
        let hit = match segment {
            ToolSegment::Command { words, moved } => command_config_runs(words, *moved, &mut cwds, home),
            ToolSegment::Nested(commands) => {
                let mut nested = cwds.clone();
                commands.iter().any(|words| command_config_runs(words, false, &mut nested, home))
            }
        };
        if hit {
            return true;
        }
    }
    false
}

/// One command: a `cd`/`pushd` adds the folder it moves to (`None`: the folder is no longer known); a configuration
/// tool is judged in every folder the script can be in.
fn command_config_runs(
    words: &[String],
    moved: bool,
    cwds: &mut Option<Vec<std::path::PathBuf>>,
    home: Option<&std::path::Path>,
) -> bool {
    let Some(head) = words.first() else {
        return false;
    };
    let name = crate::permission::exec_surface::program_name(head);
    if matches!(name.as_str(), "cd" | "pushd") {
        *cwds = cwds.take().and_then(|mut dirs| {
            let next: Option<Vec<std::path::PathBuf>> =
                dirs.iter().map(|dir| crate::permission::exec_risk::apply_literal_chdir(dir, words)).collect();
            next.map(|next| {
                dirs.extend(next);
                dirs
            })
        });
        return false;
    }
    if !CONFIG_TOOLS.contains(&name.as_str()) {
        return false;
    }
    let args = &words[1..];
    if !tool_scan_applies(&name, args) {
        return false;
    }
    let Some(dirs) = cwds.as_ref().filter(|_| !moved) else {
        return true;
    };
    dirs.iter().any(|dir| match tool_run_dir(&name, args, dir) {
        Some(run) => dirs_below_home(&run, home).iter().any(|d| tool_config_in(&name, args, d)),
        None => true,
    })
}

/// The folders `dir` and above it up to, not including, the home folder (compared as written and resolved, so a
/// symlinked home or a Git Bash spelling of it still ends the walk).
fn dirs_below_home<'a>(dir: &'a std::path::Path, home: Option<&std::path::Path>) -> Vec<&'a std::path::Path> {
    let home_real = home.and_then(|home| dunce::canonicalize(home).ok());
    dir.ancestors()
        .take_while(|d| {
            home != Some(*d) && home_real.as_ref().is_none_or(|real| dunce::canonicalize(d).ok().as_ref() != Some(real))
        })
        .collect()
}

/// cargo subcommands that build or run the project's code (owner decision 2: no configuration scan). Every other
/// one, an alias or external one included, is scanned.
const CARGO_BUILDING: &[&str] = &[
    "build", "b", "check", "c", "test", "t", "bench", "run", "r", "clippy", "doc", "d", "fix", "nextest", "package",
    "install", "publish", "rustc", "rustdoc", "miri",
];

/// bazel commands that build or run the project's code (owner decision 2: no configuration scan).
const BAZEL_BUILDING: &[&str] = &["build", "test", "run", "coverage", "fetch", "sync", "mobile-install", "vendor"];

/// npm family subcommands that print or query and run no script of the project: the configuration scan applies to
/// these only (an install, a run, a test or a build runs the project's scripts: owner decision 2).
const NPM_QUERY_SUBCOMMANDS: &[&str] = &[
    "ls", "list", "ll", "la", "outdated", "why", "explain", "view", "info", "show", "v", "version", "audit", "config",
    "c", "get", "set", "prefix", "root", "bin", "search", "s", "se", "find", "help", "help-search", "doctor", "fund",
    "query", "owner", "whoami", "ping", "dist-tag", "completion", "licenses", "store", "cache", "npm",
];

/// npm family options whose value is the next word when not attached with `=`.
const NPM_VALUED: &[&str] = &[
    "-C", "--prefix", "--dir", "--cwd", "--userconfig", "--globalconfig", "--workspace", "-w", "--filter", "-F",
    "--loglevel", "--registry", "--cache",
];

/// Owner decision 2: whether the configuration scan judges this invocation of `tool` (one that does not already run
/// the project's code). An option before the npm subcommand that is not known is judged too (fail closed).
fn tool_scan_applies(tool: &str, args: &[String]) -> bool {
    match tool {
        "cargo" => cargo_subcommand(args).is_none_or(|sub| !CARGO_BUILDING.contains(&sub)),
        "bazel" | "bazelisk" => {
            let command = args.iter().take_while(|w| *w != "--").find(|w| !w.starts_with('-'));
            command.is_none_or(|command| !BAZEL_BUILDING.contains(&command.as_str()))
        }
        _ => {
            let mut i = 0;
            while let Some(word) = args.get(i) {
                i += 1;
                if word == "--" {
                    break;
                }
                if !word.starts_with('-') {
                    return NPM_QUERY_SUBCOMMANDS.contains(&word.as_str());
                }
                let name = word.split('=').next().unwrap_or(word);
                if NPM_VALUED.contains(&name) || npm_prefix_option(name) {
                    i += usize::from(!word.contains('='));
                } else if !NPM_EXACT_OPTIONS.contains(&word.as_str()) && !npm_option_is_listed(word) {
                    return true;
                }
            }
            // No subcommand: `yarn` alone installs; npm, pnpm and a `--version`/`--help` print.
            !matches!(tool, "yarn" | "yarnpkg")
                || args.iter().any(|w| matches!(w.as_str(), "-v" | "--version" | "-h" | "--help"))
        }
    }
}

/// npm's `--prefix` or an abbreviation of it npm can expand (`--pref`).
fn npm_prefix_option(name: &str) -> bool {
    name.len() >= "--pref".len() && "--prefix".starts_with(name)
}

/// The folder `tool` reads its configuration from when the shell is in `cwd`: moved by `cargo -C`/`--directory`, npm
/// `--prefix`/`-C`, pnpm `--dir`/`-C`, yarn `--cwd`. `None`: a move to a folder that cannot be pinned.
pub(crate) fn tool_run_dir(tool: &str, args: &[String], cwd: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dir = cwd.to_path_buf();
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        let (name, attached) = match word.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None if word.starts_with("-C") && word.len() > 2 => ("-C", Some(&word[2..])),
            None => (word.as_str(), None),
        };
        let moves = match tool {
            "cargo" => matches!(name, "-C" | "--directory"),
            "bazel" | "bazelisk" => false,
            _ => matches!(name, "-C" | "--dir" | "--cwd") || npm_prefix_option(name),
        };
        if !moves {
            continue;
        }
        let value = match attached {
            Some(value) => value,
            None => {
                i += 1;
                args.get(i - 1)?.as_str()
            }
        };
        dir = crate::permission::exec_risk::literal_dir(&dir, value)?;
    }
    Some(dir)
}

/// Whether `tool`'s configuration in `dir` can make it run a program.
fn tool_config_in(tool: &str, args: &[String], dir: &std::path::Path) -> bool {
    match tool {
        "cargo" => cargo_config_runs(dir, cargo_subcommand(args)),
        "bazel" | "bazelisk" => bazel_config_runs(dir),
        "yarn" | "yarnpkg" => npmrc_runs(dir) || yarnrc_runs(dir),
        _ => npmrc_runs(dir),
    }
}

/// Whether the file at `path` matches `hit`; absent is no match, present but unreadable is one (fail closed).
fn config_file_matches(path: &std::path::Path, hit: impl Fn(&str) -> bool) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => hit(&String::from_utf8_lossy(&bytes)),
        Err(e) => !matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory),
    }
}

/// `.npmrc` keys that name a program npm (or yarn classic, which reads `.npmrc` too) runs.
const NPMRC_PROGRAM_KEYS: &[&str] = &[
    "onload-script", "script-shell", "node-options", "node-gyp", "git", "editor", "browser", "viewer", "shell",
    "init-module",
];

/// The project's `.npmrc` names a program (keys as npm reads them: case, `_`/`-` and a leading `--` ignored); a key
/// with an expansion counts (fail closed).
fn npmrc_runs(dir: &std::path::Path) -> bool {
    config_file_matches(&dir.join(".npmrc"), |text| {
        text.lines().any(|line| {
            let Some((key, _)) = line.split_once('=') else {
                return false;
            };
            let key = key.trim().trim_matches(['"', '\'']).trim_start_matches('-').to_ascii_lowercase().replace('_', "-");
            !key.starts_with([';', '#']) && (key.contains('$') || NPMRC_PROGRAM_KEYS.contains(&key.as_str()))
        })
    })
}

/// yarn's `.yarnrc.yml` `yarnPath`/`plugins` or classic `.yarnrc` `yarn-path`, matched as the key a line starts with
/// (quoted or not). A YAML line the scan cannot read as a plain key (a flow mapping, a complex key, a tag, an escape
/// in a quoted key) counts (fail closed).
fn yarnrc_runs(dir: &std::path::Path) -> bool {
    let key_starts = |line: &str, keys: &[&str]| {
        let line = line.trim();
        let key = line.trim_start_matches(['"', '\'']);
        keys.iter().any(|k| key.starts_with(k)) || (line.starts_with('"') && line.split(':').next().unwrap_or("").contains('\\'))
    };
    config_file_matches(&dir.join(".yarnrc.yml"), |text| {
        text.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(['{', '?', '!', '&', '*']) || trimmed.starts_with("<<") || key_starts(line, &["yarnPath", "plugins"])
        })
    }) || config_file_matches(&dir.join(".yarnrc"), |text| text.lines().any(|line| key_starts(line, &["yarn-path"])))
}

/// The cargo subcommand of `args` (after `+toolchain` and global options).
fn cargo_subcommand(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        let at = i;
        i += 1;
        if word == "--" {
            return None;
        }
        if at == 0 && word.starts_with('+') {
            continue;
        }
        if word.starts_with('-') {
            if !word.contains('=') && CARGO_VALUED.contains(&word.as_str()) {
                i += 1;
            }
            continue;
        }
        return Some(word.as_str());
    }
    None
}

/// u35 g14 (Fable/Astra r13 High): whether a Cargo config file in `dir` (`.cargo/config.toml` or `.cargo/config`) can
/// make cargo run a program for `sub`, a subcommand that does not build: an alias for `sub` (an `[alias]` table in any
/// TOML key spelling, a dotted `alias.sub`, an inline `alias = { … }`), a `[build]` `rustc`, `rustc-wrapper`,
/// `rustc-workspace-wrapper` or `rustdoc` naming anything but a bare program name (a path is relative to the config
/// file), an `[env]` entry, a credential provider, or an `include`. Read line by line with TOML's key rules; a header
/// or key line the scan cannot classify (an escape, a multi-line string) counts (fail closed).
fn cargo_config_runs(dir: &std::path::Path, sub: Option<&str>) -> bool {
    ["config.toml", "config"].iter().any(|file| config_file_matches(&dir.join(".cargo").join(file), |text| cargo_config_text_runs(text, sub)))
}

pub(crate) fn cargo_config_text_runs(text: &str, sub: Option<&str>) -> bool {
    let mut table: Vec<String> = Vec::new();
    let mut depth = 0i32;
    for line in text.lines() {
        if line.contains("\"\"\"") || line.contains("'''") {
            return true;
        }
        if depth > 0 {
            depth += toml_bracket_balance(line);
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let (array, header) = header.strip_prefix('[').map_or((false, header), |rest| (true, rest));
            let Some((key, rest)) = toml_key(header) else {
                return true;
            };
            let rest = if array { rest.strip_prefix("]]") } else { rest.strip_prefix(']') };
            if rest.is_none_or(|rest| !(rest.trim().is_empty() || rest.trim_start().starts_with('#'))) {
                return true;
            }
            table = key;
            continue;
        }
        let Some((key, rest)) = toml_key(line) else {
            return true;
        };
        let Some(value) = rest.strip_prefix('=') else {
            return true;
        };
        depth = toml_bracket_balance(value);
        let path: Vec<&str> = table.iter().chain(&key).map(String::as_str).collect();
        if cargo_key_runs(&path, value, sub) {
            return true;
        }
    }
    false
}

/// Whether the Cargo config entry at `path` with `value` can run a program for the non-building subcommand `sub`.
fn cargo_key_runs(path: &[&str], value: &str, sub: Option<&str>) -> bool {
    match path {
        ["alias"] | ["build"] | ["env", ..] | ["include"] => true,
        ["alias", name, ..] => Some(*name) == sub,
        ["build", key, ..] => {
            matches!(*key, "rustc" | "rustc-wrapper" | "rustc-workspace-wrapper" | "rustdoc") && !toml_bare_program(value)
        }
        _ => path.iter().any(|segment| matches!(*segment, "credential-provider" | "global-credential-providers")),
    }
}

/// A TOML string value that is a bare program name (looked up on `PATH`, not a file of the project), optionally
/// followed by a comment.
fn toml_bare_program(value: &str) -> bool {
    let value = value.trim();
    let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
        return false;
    };
    let Some((name, rest)) = value[1..].split_once(quote) else {
        return false;
    };
    let rest = rest.trim();
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && (rest.is_empty() || rest.starts_with('#'))
}

/// A TOML dotted key at the start of `text` (bare and quoted parts joined by dots) and the text after it; `None` for
/// a key the scan does not read (an escape in a quoted part, an unterminated quote, no key).
fn toml_key(text: &str) -> Option<(Vec<String>, &str)> {
    let mut parts = Vec::new();
    let mut rest = text.trim_start();
    loop {
        let (part, after) = if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"')?;
            if quoted[..end].contains('\\') {
                return None;
            }
            (quoted[..end].to_owned(), &quoted[end + 1..])
        } else if let Some(quoted) = rest.strip_prefix('\'') {
            let end = quoted.find('\'')?;
            (quoted[..end].to_owned(), &quoted[end + 1..])
        } else {
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))).unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            (rest[..end].to_owned(), &rest[end..])
        };
        parts.push(part);
        let after = after.trim_start();
        match after.strip_prefix('.') {
            Some(next) => rest = next.trim_start(),
            None => return Some((parts, after)),
        }
    }
}

/// Opening minus closing `[`/`{` brackets of a TOML value line outside strings and comments (a multi-line array).
fn toml_bracket_balance(text: &str) -> i32 {
    let mut balance = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => break,
                '[' | '{' => balance += 1,
                ']' | '}' => balance -= 1,
                _ => {}
            },
        }
    }
    balance
}

fn bazel_config_runs(dir: &std::path::Path) -> bool {
    let bazelrc_runs = |text: &str| {
        text.lines().any(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return false;
            }
            let mut words = line.split_whitespace();
            let command = words.next().unwrap_or_default();
            let command = command.split(':').next().unwrap_or(command);
            match command {
                "startup" | "import" | "try-import" => true,
                _ => {
                    let command = if matches!(command, "common" | "always") { "build" } else { command };
                    let argv: Vec<String> = std::iter::once(command.to_owned()).chain(words.map(str::to_owned)).collect();
                    bazel_needs_approval(&argv)
                }
            }
        })
    };
    let names_fork = |text: &str| text.contains('/') || text.contains("URL");
    // u35 g14 (Grok r13 Low): a `tools/bazel` that cannot be checked counts (fail closed), as an unreadable file does.
    let wrapper = match std::fs::metadata(dir.join("tools").join("bazel")) {
        Ok(meta) => meta.is_file(),
        Err(e) => !matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory),
    };
    config_file_matches(&dir.join(".bazelrc"), bazelrc_runs)
        || wrapper
        || config_file_matches(&dir.join(".bazelversion"), names_fork)
        || config_file_matches(&dir.join(".bazeliskrc"), names_fork)
}

#[cfg(test)]
mod u35_g14_tests {
    use super::*;

    fn cmd(text: &str) -> ToolSegment {
        ToolSegment::Command { words: text.split_whitespace().map(str::to_owned).collect(), moved: false }
    }

    fn runs(segments: &[ToolSegment], dir: &std::path::Path, home: Option<&std::path::Path>) -> bool {
        tool_config_runs_with_home(segments, dir, home)
    }

    #[test]
    fn u35_g14_cargo_config_lines_are_classified_or_fail_closed() {
        let fmt = Some("fmt");
        for text in [
            "[alias]\nfmt = \"run --bin pwn\"",
            "[\"alias\"]\nfmt = \"run\"",
            "['alias']\nfmt = \"run\"",
            "[ alias ]\nfmt = \"run\"",
            "alias.fmt = \"run\"",
            "alias = { fmt = \"run\" }",
            "[build]\nrustc = \"../pwn\"",
            "build.rustc-wrapper = \"./w\"",
            "[build]\nrustc-workspace-wrapper = '/tmp/x'",
            "build = { rustc = \"x\" }",
            "[env]\nLD_PRELOAD = \"./x.so\"",
            "[registry]\ncredential-provider = \"./p\"",
            "include = \"other.toml\"",
            "[\"al\\u0069as\"]\nfmt = \"run\"",
            "x = \"\"\"\n[package]\n\"\"\"",
            "%%% not toml",
        ] {
            assert!(cargo_config_text_runs(text, fmt), "{text}");
        }
        for text in [
            "[alias]\nxtask = \"run -p xtask\"",
            "[build]\nrustc-wrapper = \"sccache\" # cache",
            "[build]\nrustflags = [\n  \"-C\", \"link-arg=-fuse-ld=lld\",\n]\ntarget-dir = \"t\"",
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"./ld\"",
            "# alias.fmt = 1\n[net]\ngit-fetch-with-cli = true",
        ] {
            assert!(!cargo_config_text_runs(text, fmt), "{text}");
        }
    }

    #[test]
    fn u35_g14_scan_follows_the_directory_and_stops_at_home() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("p");
        let sub = project.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        // The user's own configuration (in the home folder) is not the project's.
        std::fs::write(home.path().join(".npmrc"), "script-shell=/bin/zsh\n").unwrap();
        assert!(!runs(&[cmd("npm ls")], &project, Some(home.path())));
        // A parent folder of the run directory counts.
        std::fs::write(project.join(".npmrc"), "onload-script=./x.js\n").unwrap();
        assert!(runs(&[cmd("npm ls")], &sub, Some(home.path())));
        std::fs::remove_file(project.join(".npmrc")).unwrap();
        // Only the folder the tool runs in shows it: cd, -C, --prefix, --cwd, --dir.
        std::fs::write(sub.join(".npmrc"), "onload-script=./x.js\n").unwrap();
        std::fs::write(sub.join(".yarnrc.yml"), "yarnPath: ./x.cjs\n").unwrap();
        assert!(!runs(&[cmd("npm ls")], &project, Some(home.path())));
        for script in [
            vec![cmd("cd sub"), cmd("npm ls")],
            vec![cmd("pushd sub"), cmd("popd"), cmd("npm ls")],
            vec![cmd("npm --prefix sub ls")],
            vec![cmd("npm --prefix=sub ls")],
            vec![cmd("npm -C sub outdated")],
            vec![cmd("pnpm --dir sub ls")],
            vec![cmd("yarn --cwd sub info")],
            vec![cmd("cd \"$X\""), cmd("npm ls")],
            vec![ToolSegment::Command { words: vec!["npm".into(), "ls".into()], moved: true }],
            vec![ToolSegment::Nested(vec![vec!["cd".into(), "sub".into()], vec!["yarn".into(), "info".into()]])],
        ] {
            assert!(runs(&script, &project, Some(home.path())), "{script:?}");
        }
        // Owner decision 2: a build or install follows the model; yarn reads .yarnrc.yml, npm does not.
        for script in [vec![cmd("cd sub"), cmd("yarn build")], vec![cmd("cd sub"), cmd("npm install")]] {
            assert!(!runs(&script, &project, Some(home.path())), "{script:?}");
        }
        std::fs::remove_file(sub.join(".npmrc")).unwrap();
        assert!(!runs(&[cmd("cd sub"), cmd("npm ls")], &project, Some(home.path())));
        assert!(runs(&[cmd("cd sub"), cmd("yarn ls")], &project, Some(home.path())));
        // cargo -C / --directory; a building subcommand follows the model.
        std::fs::create_dir_all(sub.join(".cargo")).unwrap();
        std::fs::write(sub.join(".cargo/config.toml"), "[build]\nrustc = \"../pwn\"\n").unwrap();
        for script in [cmd("cargo -C sub metadata"), cmd("cargo --directory=sub tree"), cmd("cargo --directory sub fetch")] {
            assert!(runs(std::slice::from_ref(&script), &project, Some(home.path())), "{script:?}");
        }
        assert!(!runs(&[cmd("cargo -C sub build")], &project, Some(home.path())));
    }

    #[test]
    fn u35_g14_yarnrc_keys_are_line_leading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".yarnrc.yml"), "# plugins are not used\nnodeLinker: node-modules # yarnPath\n").unwrap();
        assert!(!yarnrc_runs(dir.path()));
        std::fs::write(dir.path().join(".yarnrc.yml"), "\"yarnPath\": ./x.cjs\n").unwrap();
        assert!(yarnrc_runs(dir.path()));
        std::fs::write(dir.path().join(".yarnrc.yml"), "{yarnPath: ./x.cjs}\n").unwrap();
        assert!(yarnrc_runs(dir.path()));
    }

    #[test]
    fn u35_g14_unparseable_text_is_scanned_for_configuration_options() {
        use crate::permission::exec_surface::{split_script_text, text_may_load_config_file};
        assert_eq!(
            split_script_text(&["sh".into(), "-c".into(), "cd sub && npm ls".into()]),
            vec![vec!["sh".to_owned()], vec!["-c".to_owned()], vec!["cd".to_owned(), "sub".to_owned()], vec!["npm".to_owned(), "ls".to_owned()]],
        );
        for text in ["x; time kubectl --kubeconfig=./k get pods", "(cargo --config c.toml build", "npm --userc=./x ls |"] {
            assert!(text_may_load_config_file(text), "{text}");
        }
        assert!(!text_may_load_config_file("(kubectl get pods; npm ls"));
    }

    #[test]
    fn u35_g14_bazel_wrapper_stat_error_counts() {
        let dir = tempfile::tempdir().unwrap();
        // `tools` is a file, so `tools/bazel` is not a directory entry: no wrapper.
        std::fs::write(dir.path().join("tools"), "").unwrap();
        assert!(!bazel_config_runs(dir.path()));
        std::fs::remove_file(dir.path().join("tools")).unwrap();
        std::fs::create_dir_all(dir.path().join("tools")).unwrap();
        std::fs::write(dir.path().join("tools/bazel"), "#!/bin/sh\n").unwrap();
        assert!(bazel_config_runs(dir.path()));
    }

    #[cfg(unix)]
    #[test]
    fn u35_g14_unreadable_configuration_counts() {
        use std::os::unix::fs::PermissionsExt;
        // Root reads any file, so the case cannot be built there.
        if std::process::Command::new("id").arg("-u").output().is_ok_and(|o| o.stdout.starts_with(b"0")) {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".npmrc");
        std::fs::write(&rc, "registry=https://r\n").unwrap();
        std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(npmrc_runs(dir.path()));
        std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!npmrc_runs(dir.path()));
    }
}
