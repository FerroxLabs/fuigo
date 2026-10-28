//! u35: tools that are read-only in ordinary use but run another program or script in some mode.
//!
//! [`segment_has_exec_surface`] is the one per-segment check. `evaluate_bash` (both its decomposed and its recovered
//! loop) records a hit as `SpecialExecSurface`, which floors every broad grant, and the auto-mode heuristic treats a
//! hit as not routine, so the decision paths agree. Ordinary use (a `sed` substitution to stdout, `awk` field printing,
//! `python3 script.py`, an `rsync` without a remote shell) carries no finding. An interpreter is floored only for code
//! the command does not show (inline code, stdin); a script file or module run is visible and left to the grants.
//!
//! The same check covers the commands whose output is a secret or whose effect is on the shell itself rather than on
//! files: a full environment dump (`env`, `printenv`, `set`, `export -p`, `declare -p`, `jq env`), a kubectl secret
//! read, and `printf -v`, which assigns a shell variable (`PATH` included) that later words in the script resolve
//! through.

use crate::permission::shell_access::{awk_runs_code, sed_runs_code};

mod build_tools;
mod interpreters;
mod search_shadows;

pub(crate) use build_tools::{MakeArg, make_args};

/// Programs whose job is to run another command given as arguments (or read from stdin), which the classifier never
/// sees as its own segment.
const EXEC_VEHICLES: &[&str] = &[
    "xargs", "parallel", "sudo", "sudoedit", "doas", "run0", "pkexec", "su", "flock", "watch", "setsid", "nohup",
    "nsenter", "unshare", "chroot", "systemd-run", "firejail", "bwrap",
];

/// Whether `head` names an [`EXEC_VEHICLES`] program (basename, case-insensitive).
pub(crate) fn is_exec_vehicle(head: &str) -> bool {
    EXEC_VEHICLES.contains(&program_name(head).as_str())
}

/// Shells; with no script operand (or `-s`) they read the program from stdin (`curl … | sh`).
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];

/// Whether this segment (canonical wrappers already peeled) runs code the classifier cannot see.
pub(crate) fn segment_has_exec_surface(words: &[String]) -> bool {
    let Some(head) = words.first() else {
        return false;
    };
    let name = program_name(head);
    let name = name.as_str();
    let args = &words[1..];
    if EXEC_VEHICLES.contains(&name) {
        return true;
    }
    if SHELLS.contains(&name) {
        return shell_reads_stdin(args);
    }
    // u35 r2: any operand naming a process environment file (`/proc/self/environ`) reads the environment.
    if args.iter().any(|word| names_environ_file(word)) {
        return true;
    }
    if is_interpreter(name) {
        return interpreter_runs_code(name, args);
    }
    match name {
        "sed" | "gsed" => sed_runs_code(words),
        "awk" | "gawk" | "mawk" | "nawk" => awk_runs_code(words),
        // u35: a plain `find` runs Fuigo's bfs shadow and a plain `grep` its ugrep shadow, so their own options count.
        "find" => {
            args.iter()
                .any(|w| matches!(w.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
                || search_shadows::bfs_option_floors(args)
        }
        "grep" => search_shadows::ugrep_option_floors(args),
        "fd" | "fdfind" => args.iter().any(|w| {
            long_option_is(w, "--exec", 1)
                || long_option_is(w, "--exec-batch", 1)
                || (w.starts_with('-') && !w.starts_with("--") && w.contains(['x', 'X']))
        }),
        "rsync" => rsync_runs_program(args),
        "scp" | "ssh" => ssh_runs_local_program(name, args),
        // u35 r2: sftp runs a local program for `-S`/`-D`, and a batch file (`-b`) or a command list on stdin can hold
        // `!command` local shell escapes, so no sftp invocation is vouched for.
        "sftp" => true,
        "tar" | "gtar" | "bsdtar" => tar_runs_program(args),
        "man" => man_runs_program(args),
        "printf" => printf_is_special(args),
        "env" | "printenv" => true,
        // With no operand, `set` prints every shell variable.
        "set" => args.is_empty(),
        // u35 r2: options only (`export`, `declare -x`) print variables, and so does `-p` with or without names
        // (`declare -p TOKEN` prints TOKEN's value): names never exempt it.
        "export" | "declare" | "typeset" | "readonly" | "local" => {
            args.iter().all(|w| w.starts_with('-'))
                || args.iter().take_while(|w| *w != "--").any(|w| {
                    w.strip_prefix('-').is_some_and(|cluster| !cluster.starts_with('-') && cluster.contains('p'))
                })
        }
        "jq" | "gojq" | "jaq" => jq_reads_environment(args),
        "kubectl" => kubectl_reads_secrets(args),
        "go" => go_runs_program(args),
        // u35 g3: build tools and `gh` in a mode that runs a program the command does not name (`build_tools`).
        "make" | "gmake" => build_tools::make_runs_program(args),
        "cmake" => build_tools::cmake_runs_program(args),
        "cargo" => build_tools::cargo_runs_program(args),
        "rustc" | "clippy" | "clippy-driver" => build_tools::rustc_runs_program(args),
        "pytest" | "py.test" => build_tools::pytest_runs_program(args),
        "just" => build_tools::just_runs_program(args),
        "bazel" | "bazelisk" => build_tools::bazel_runs_program(args),
        "npm" | "pnpm" | "yarn" => build_tools::npm_runs_program(args),
        "uv" => build_tools::uv_runs_program(args),
        "rustup" => build_tools::rustup_runs_program(args),
        "gh" => build_tools::gh_runs_program(args),
        "wget" | "wget2" => wget_runs_program(args),
        _ => false,
    }
}

/// u35 g13 (Astra r12 High): whether this segment (canonical wrappers peeled) makes a program load a configuration
/// file whose content the command does not show and which can make it run a program: ugrep's `--config`/`---FILE` (a
/// `.ugrep` in the working directory can set `filter=`), `cargo --config`, `bazel --bazelrc`, `wget --config`,
/// `ssh`/`scp`/`sftp -F` and `rustc @file`. Each is also an exec surface ([`segment_has_exec_surface`]); this is the
/// part of it that is content the repository controls rather than command text, so an Auto mode model allow of it
/// asks the user. The other exec surfaces run what the command itself shows (an inline program, a named script, an
/// option naming a program), which the model reads.
///
/// u35 g14 (Astra r13 High 4, Grok r13 High 3): also `kubectl`/`helm --kubeconfig` (a kubeconfig `users[].exec`
/// plugin), `docker --config` (its `cli-plugins` and credential helpers), the npm family's `--userconfig`/
/// `--globalconfig` and npm's unique abbreviations of them (an npmrc `onload-script`), and `node --env-file` (a
/// `NODE_OPTIONS=--require`). Audit of the other sources: the rest select a script the command names (`make -f`,
/// `gradle -I`), configuration that runs nothing (`curl -K`, `pip --config`), or the user's own configuration (`aws
/// --profile`, `gcloud --configuration`).
pub(crate) fn segment_loads_config_file(words: &[String]) -> bool {
    let Some(head) = words.first() else {
        return false;
    };
    let args = &words[1..];
    let mut options = args.iter().take_while(|word| *word != "--");
    match program_name(head).as_str() {
        "grep" => search_shadows::ugrep_loads_config(args),
        "cargo" => options.any(|word| word == "--config" || word.starts_with("--config=")),
        "bazel" | "bazelisk" => {
            options.any(|word| word.strip_prefix("--").is_some_and(|long| long.split('=').next() == Some("bazelrc")))
        }
        "wget" | "wget2" => options.any(|word| long_option_is(word, "--config", 1)),
        // `-F` alone or in a short cluster (ssh scans every word, as `ssh_runs_local_program` does).
        "ssh" | "scp" | "sftp" => args
            .iter()
            .any(|word| word.strip_prefix('-').is_some_and(|cluster| !cluster.starts_with('-') && cluster.contains('F'))),
        "rustc" | "clippy" | "clippy-driver" => args.iter().any(|word| word.starts_with('@')),
        "kubectl" | "helm" => {
            options.any(|word| crate::permission::exec_risk::long_option_abbreviates(word, "--kubeconfig"))
        }
        "docker" | "podman" => options.any(|word| word == "--config" || word.starts_with("--config=")),
        "npm" | "npx" | "pnpm" | "pnpx" | "yarn" | "yarnpkg" => options.any(|word| npm_selects_config_file(word)),
        "node" | "nodejs" => options.any(|word| {
            let name = word.split('=').next().unwrap_or(word);
            name == "--env-file" || name == "--env-file-if-exists"
        }),
        _ => false,
    }
}

/// u35 g14: an npm family option naming the user or global npmrc: `--userconfig`/`--globalconfig`, or an abbreviation
/// npm expands to one of them (`--userc`, `--globalc`; shorter ones are shared with another key).
fn npm_selects_config_file(word: &str) -> bool {
    let name = word.split('=').next().unwrap_or(word);
    (name.len() >= "--userc".len() && "--userconfig".starts_with(name))
        || (name.len() >= "--globalc".len() && "--globalconfig".starts_with(name))
}

/// u35 g14: the commands of a script text the parser could not decompose, or of an opaque shell's words
/// (`sh -c 'cd sub && npm ls'`), split as plainly as possible: each word starts a command, `;`, `&`, `|`, `(`, `)`,
/// a backquote and a newline end one, whitespace separates words, and quotes are dropped. A probe, not a parser: the
/// configuration checks run on every command it yields, so a command it splits wrongly is judged more, not less.
pub(crate) fn split_script_text(words: &[String]) -> Vec<Vec<String>> {
    let mut commands: Vec<Vec<String>> = Vec::new();
    for word in words {
        let mut command: Vec<String> = Vec::new();
        let mut token = String::new();
        for c in word.chars() {
            match c {
                ';' | '&' | '|' | '(' | ')' | '`' | '\n' | '{' | '}' => {
                    if !token.is_empty() {
                        command.push(std::mem::take(&mut token));
                    }
                    if !command.is_empty() {
                        commands.push(std::mem::take(&mut command));
                    }
                }
                '\'' | '"' => {}
                c if c.is_whitespace() => {
                    if !token.is_empty() {
                        command.push(std::mem::take(&mut token));
                    }
                }
                c => token.push(c),
            }
        }
        if !token.is_empty() {
            command.push(token);
        }
        if !command.is_empty() {
            commands.push(command);
        }
    }
    commands
}

/// u35 g14 (Grok r13 Low): [`segment_loads_config_file`] for a script the parser could not decompose: every command
/// [`split_script_text`] finds, from each of its words on (the program may follow a wrapper).
pub(crate) fn text_may_load_config_file(cmd: &str) -> bool {
    split_script_text(&[cmd.to_owned()])
        .iter()
        .any(|command| (0..command.len()).any(|at| segment_loads_config_file(&command[at..])))
}

/// u35 r3 (Astra r2 H2): whether this segment changes how bash reads the words of later commands, which the
/// classifier modelled with bash's defaults: `set` turning off brace expansion or globbing or turning on keyword
/// assignments (`set +B`, `set -f`, `set -k`, `set -o posix`, ...), any `shopt`, an alias, a disabled builtin, or a
/// remembered program path (`hash -p`). Common `set -euo pipefail` style options are left alone.
pub(crate) fn changes_shell_parsing(words: &[String]) -> bool {
    /// `set` letters and `-o` names that do not change expansion, parsing or command lookup.
    const SAFE_SET_LETTERS: &str = "euxvETbmhaCn";
    const SAFE_SET_NAMES: &[&str] = &[
        "errexit", "nounset", "pipefail", "xtrace", "verbose", "errtrace", "functrace", "notify", "monitor", "hashall",
        "allexport", "ignoreeof", "noclobber", "nolog",
    ];
    let Some(head) = words.first() else {
        return false;
    };
    let args = &words[1..];
    match program_name(head).as_str() {
        "set" => {
            let mut i = 0;
            while let Some(word) = args.get(i) {
                i += 1;
                if word == "--" || word == "-" || !(word.starts_with('-') || word.starts_with('+')) {
                    break;
                }
                let cluster = &word[1..];
                // `-o NAME` may end a cluster (`set -euo pipefail`).
                let (letters, takes_name) = match cluster.strip_suffix('o') {
                    Some(letters) => (letters, true),
                    None => (cluster, false),
                };
                if cluster.is_empty() || !letters.chars().all(|c| SAFE_SET_LETTERS.contains(c)) {
                    return true;
                }
                if takes_name {
                    match args.get(i) {
                        Some(name) if SAFE_SET_NAMES.contains(&name.as_str()) => i += 1,
                        // `set -o` alone prints the options.
                        None => {}
                        Some(_) => return true,
                    }
                }
            }
            false
        }
        "shopt" | "alias" | "unalias" | "enable" => true,
        "hash" => !args.is_empty(),
        _ => false,
    }
}

/// u35 r2: a word the normaliser could not pin (an expansion, a glob, an over-cap brace group) is handed to this check
/// as [`UNRESOLVED_WORD`], so a script, program or format position holding one fails closed.
pub(crate) const UNRESOLVED_WORD: &str = "\0";

pub(crate) fn is_unresolved(word: &str) -> bool {
    word.contains('\0')
}

/// u35 r2: a path (or an option's `=value`) that reads a process environment: one whose last component is `environ`
/// (`/proc/self/environ`, `/proc/<pid>/task/<tid>/environ`, `./environ`), or any path into a process directory
/// (`/proc/self`, `/proc/thread-self`, `/proc/<pid>`, lexically normalised; u35 r3 (Grok r2 M) also relative,
/// `proc/self`, since a repository can hold a `proc` symlink), so a recursive read or a `cd` there followed by a bare
/// `environ` is covered by the `cd` operand. u35 r3 (Astra r2 H9):
/// a component holding a glob character is judged by what it could match (`/proc/s*/envi*`). u35 g3 (Astra r3): a
/// glob that can match a process directory counts, wildcard-only components included (`/pr?c/????/???????`,
/// `/*/*`). Over-asks only for an ordinary file named `environ`, a directory named `proc`, or a two-level wildcard.
pub(crate) fn names_environ_file(word: &str) -> bool {
    let value = word.rsplit_once('=').map_or(word, |(_, value)| value);
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    // A last component of wildcards only (`dir/*`) is caught below only when what precedes it can be a process
    // directory; on its own it names nothing in particular.
    if value.contains('/')
        && parts.last().is_some_and(|last| !is_wildcard_only(last) && component_may_be(last, "environ"))
    {
        return true;
    }
    parts.windows(2).any(|pair| {
        component_may_be(pair[0], "proc")
            && (["self", "thread-self"].iter().any(|dir| component_may_be(pair[1], dir))
                || (has_glob_char(pair[1]) && pair[0] == "proc")
                || component_may_be_pid(pair[1]))
    })
}

fn has_glob_char(text: &str) -> bool {
    text.contains(['*', '?', '['])
}

/// A component made of glob characters only (`*`, `????`, `[a-z]`).
fn is_wildcard_only(component: &str) -> bool {
    has_glob_char(component) && component.chars().all(|c| matches!(c, '*' | '?' | '[' | ']'))
}

/// Whether one path component equals `name` or, holding a glob character, could match it (`*`, `?` and a bracket
/// set are treated as matching anything at their position).
fn component_may_be(component: &str, name: &str) -> bool {
    if !has_glob_char(component) {
        return component == name;
    }
    let pattern: Vec<char> = component.chars().collect();
    let name: Vec<char> = name.chars().collect();
    glob_may_match(&pattern, &name)
}

/// Whether a component is, or as a glob could match, a process id (a run of digits).
fn component_may_be_pid(component: &str) -> bool {
    if !has_glob_char(component) {
        return !component.is_empty() && component.bytes().all(|b| b.is_ascii_digit());
    }
    // A bracket set may hold digits; outside sets only digits and wildcards can match one.
    let mut in_set = false;
    component.chars().all(|c| match c {
        '[' => {
            in_set = true;
            true
        }
        ']' => {
            in_set = false;
            true
        }
        _ => in_set || c == '*' || c == '?' || c.is_ascii_digit(),
    })
}

/// u35 g3 (Astra r3): the most matcher steps (pattern tokens times name positions) one component may take. Past it
/// the component is taken as matching, which floors the command.
const GLOB_STEP_LIMIT: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum GlobToken {
    Literal(char),
    /// `?` or a closed bracket set: any one character.
    One,
    /// A run of `*`.
    Star,
}

/// Whether `pattern` could match `name`, in bounded work: a single pass over the pattern tokens keeping the set of
/// name positions reached (no recursion, no backtracking). A pattern too long for [`GLOB_STEP_LIMIT`] may match.
fn glob_may_match(pattern: &[char], name: &[char]) -> bool {
    let mut tokens: Vec<GlobToken> = Vec::new();
    let mut i = 0;
    while let Some(&c) = pattern.get(i) {
        i += 1;
        let token = match c {
            '*' => GlobToken::Star,
            '?' => GlobToken::One,
            '[' => match pattern[i..].iter().position(|c| *c == ']') {
                Some(close) => {
                    i += close + 1;
                    GlobToken::One
                }
                None => GlobToken::Literal('['),
            },
            c => GlobToken::Literal(c),
        };
        if !(token == GlobToken::Star && tokens.last() == Some(&GlobToken::Star)) {
            tokens.push(token);
        }
        if tokens.len().saturating_mul(name.len() + 1) > GLOB_STEP_LIMIT {
            return true;
        }
    }
    let mut reach = vec![false; name.len() + 1];
    reach[0] = true;
    for token in tokens {
        let mut next = vec![false; name.len() + 1];
        match token {
            GlobToken::Star => {
                let mut reached = false;
                for (at, slot) in next.iter_mut().enumerate() {
                    reached |= reach[at];
                    *slot = reached;
                }
            }
            GlobToken::One | GlobToken::Literal(_) => {
                for at in 0..name.len() {
                    let fits = match token {
                        GlobToken::Literal(c) => name[at] == c,
                        _ => true,
                    };
                    if reach[at] && fits {
                        next[at + 1] = true;
                    }
                }
            }
        }
        reach = next;
    }
    reach[name.len()]
}

/// u35 r2: interpreters (`python`/`python3.12`/`pypy3`, `perl`, `ruby`/`irb`, `node`/`deno`/`bun`, `php`, `lua`,
/// `tclsh`/`wish`), by basename with an optional version suffix.
fn is_interpreter(name: &str) -> bool {
    const STEMS: &[&str] = &[
        "python", "pypy", "perl", "ruby", "irb", "node", "nodejs", "deno", "bun", "php", "lua", "luajit", "tclsh", "wish",
    ];
    STEMS.iter().any(|stem| {
        name.strip_prefix(stem)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// Only a lone version or help query is vouched for as harmless; `tclsh` has neither. u35 r3 (Fable r2 M1): each
/// interpreter's own short version flag counts too (`node -v`, `perl -v`/`-V`, `ruby -v`, `lua -v`, `php -v`,
/// `deno -V`, `bun -v`); `python -v` is verbose mode with a REPL and does not.
///
/// u35 g9 (Grok r8 High, probed on CPython 3.12): `python3 --version`, `-V`, `-VV` and `--help` exit while parsing the
/// command line, before `site` runs: no `sitecustomize`, `usercustomize` or `.pth` file is imported, from the working
/// directory or from `PYTHONPATH`. PyPy's entry point is itself Python code that was not probed, so its version and
/// help forms are not vouched for.
fn interpreter_query(name: &str, args: &[String]) -> bool {
    let [only] = args else {
        return false;
    };
    let stem = |prefix: &str| name.starts_with(prefix);
    if stem("tclsh") || stem("wish") || stem("pypy") {
        return false;
    }
    match only.as_str() {
        "--version" | "--help" => true,
        "-V" => stem("python") || stem("perl") || stem("deno"),
        "-v" => stem("node") || stem("perl") || stem("ruby") || stem("irb") || stem("lua") || stem("php") || stem("bun"),
        _ => false,
    }
}

/// u35 (lead decision after r2): an interpreter floors only code the command does not show: inline code (`-c`, `-e`,
/// `--eval`, `-r`, also inside a cluster) or a program from stdin, a heredoc, a here-string or a REPL. A script file
/// or module run (`python3 path.py`, `python3 -m mod`, `node build.js`) is visible code execution, governed by the
/// user's grants and the sandbox; it is still never read-only (see [`interpreter_is_not_query`]).
fn interpreter_runs_code(name: &str, args: &[String]) -> bool {
    // u35 r3: a script operand (or any argument) naming stdin or a descriptor is a program from a pipe.
    !interpreter_query(name, args)
        && (args.iter().any(|word| names_stdin_stream(word)) || interpreters::runs_hidden_code(name, args))
}

/// Whether `words` (canonical wrappers peeled) run an interpreter for anything but a lone version or help query. Such
/// a command never gets read-only or Auto mode routine approval, whether or not its code is visible.
pub(crate) fn interpreter_is_not_query(words: &[String]) -> bool {
    let Some(head) = words.first() else {
        return false;
    };
    let name = program_name(head);
    is_interpreter(&name) && !interpreter_query(&name, &words[1..])
}

/// u35 r2: `printf -v NAME` assigns a shell variable; a format holding `%n` (a conversion that assigns, applied again
/// each time the format is reused for more arguments) or one the normaliser could not pin may do the same.
fn printf_is_special(args: &[String]) -> bool {
    let format = match args {
        [first, ..] if first.starts_with("-v") => return true,
        [dashes, rest @ ..] if dashes == "--" => rest.first(),
        _ => args.first(),
    };
    format.is_some_and(|format| is_unresolved(format) || format_has_percent_n(format))
}

/// Whether a printf format holds a `%n` conversion, with any flags, width, precision or argument index.
fn format_has_percent_n(format: &str) -> bool {
    let chars: Vec<char> = format.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '%' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if chars.get(j) == Some(&'%') {
            i = j + 1;
            continue;
        }
        while chars.get(j).is_some_and(|c| c.is_ascii_digit() || "-+ #0'*.$hlLqjzt".contains(*c)) {
            j += 1;
        }
        if chars.get(j) == Some(&'n') {
            return true;
        }
        i = j.max(i + 1);
    }
    false
}

/// u35 r2: `wget --use-askpass=PROGRAM` runs PROGRAM; `-e`/`--execute` and `--config` apply wgetrc commands (which can
/// set `use_askpass`). Any short cluster holding `e` counts (over-asks only for an attached value with an `e`).
fn wget_runs_program(args: &[String]) -> bool {
    args.iter().take_while(|w| *w != "--").any(|word| {
        if word.starts_with("--") {
            return ["--use-askpass", "--execute", "--config"].iter().any(|option| long_option_is(word, option, 1));
        }
        word.strip_prefix('-').is_some_and(|cluster| cluster.contains('e'))
    })
}

/// Basename, lowercased, `.exe` stripped: `/usr/bin/sed` and `SED.exe` are `sed`.
pub(crate) fn program_name(head: &str) -> String {
    let base = head.rsplit(['/', '\\']).next().unwrap_or(head);
    let name = base.to_ascii_lowercase();
    name.strip_suffix(".exe").map(str::to_owned).unwrap_or(name)
}

fn shell_reads_stdin(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        // u35 g3 (Astra r3): the word after the end of options is the script operand, so a stream there is stdin.
        if word == "--" || word == "-" {
            return args.get(i).is_none_or(|script| script_is_hidden(script));
        }
        if word == "--version" || word == "--help" {
            return false;
        }
        if word.starts_with("--") {
            // A startup file is sourced code too.
            if long_option_is(word, "--rcfile", 1) || long_option_is(word, "--init-file", 1) {
                return true;
            }
            continue;
        }
        if let Some(cluster) = word.strip_prefix('-').or_else(|| word.strip_prefix('+')) {
            if cluster.contains(['s', 'c']) {
                return true;
            }
            // `-o OPT` / `-O OPT` take the next word.
            if cluster.ends_with(['o', 'O']) {
                i += 1;
            }
            continue;
        }
        // A script file operand; a standard-stream pseudo-path is the program read from stdin.
        return script_is_hidden(word);
    }
    true
}

/// A shell script operand whose program the command does not show: a standard stream or descriptor path, `-`, or a
/// word the normaliser could not pin.
fn script_is_hidden(script: &str) -> bool {
    script == "-" || names_stdin_stream(script) || is_unresolved(script)
}

/// u35 r3 (Astra r2 H8): a path naming a standard stream or an open descriptor (`/dev/stdin`, `/dev/fd/0`,
/// `/proc/self/fd/0`, `/dev/tty`), so a "script file" there is a program read from a pipe or the terminal. Matched on the
/// lexically normalised trailing components, so `/dev/./stdin` and `x/../dev/fd/3` count.
pub(crate) fn names_stdin_stream(word: &str) -> bool {
    let mut parts: Vec<&str> = Vec::new();
    for part in word.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    match parts.as_slice() {
        [.., "dev", "stdin" | "tty" | "stdout" | "stderr"] => true,
        [.., "fd", fd] => digits(fd),
        _ => false,
    }
}

/// `-e`/`--rsh` and `--rsync-path`/`-M`/`--remote-option` name a program rsync runs.
fn rsync_runs_program(args: &[String]) -> bool {
    for word in args {
        if word == "--" {
            break;
        }
        if word.starts_with("--") {
            if ["--rsh", "--rsync-path", "--remote-option"].iter().any(|option| long_option_is(word, option, 1)) {
                return true;
            }
            continue;
        }
        if let Some(cluster) = word.strip_prefix('-') {
            for option in cluster.chars() {
                if matches!(option, 'e' | 'M') {
                    return true;
                }
                // Short options whose value is the rest of the cluster.
                if matches!(option, 'B' | 'f' | 'T' | '@') {
                    break;
                }
            }
        }
    }
    false
}

/// Whether a long option `word` (`--name` or `--name=value`) names `option`, in full or abbreviated to at least
/// `min` characters (getopt accepts any unambiguous prefix). u35 r1: an ambiguous prefix of a floored option counts as
/// that option, so `min` is 1 unless a shorter spelling is another real option in full (`tar --checkpoint`).
pub(crate) fn long_option_is(word: &str, option: &str, min: usize) -> bool {
    word.strip_prefix("--").is_some_and(|long| {
        let name = long.split_once('=').map_or(long, |(name, _)| name);
        name.len() >= min && option.trim_start_matches('-').starts_with(name)
    })
}

/// `scp -S PROGRAM` runs PROGRAM as the transport; `-o ProxyCommand=…` (and `LocalCommand`, `PermitLocalCommand`,
/// `KnownHostsCommand`, every other `…Command` key, a PKCS#11 / security-key provider library, `Include`, `Match`) and
/// `-F CONFIG` (a config file can set them) run a program too. u35 r2: the same for `ssh` (`-S` is its control socket,
/// floored as well; `-I` loads a PKCS#11 library). Keys match in any case, `=`- or blank-separated, attached to `-o`
/// or not.
fn ssh_runs_local_program(name: &str, args: &[String]) -> bool {
    let command_option = |value: &str| {
        let key = value.trim_start().split(['=', ' ', '\t']).next().unwrap_or(value).to_ascii_lowercase();
        key.ends_with("command")
            || matches!(key.as_str(), "pkcs11provider" | "securitykeyprovider" | "include" | "match")
    };
    // Options whose value is the rest of the cluster or the next word.
    let takes_value: &[char] = if name == "ssh" {
        &['B', 'b', 'c', 'D', 'E', 'e', 'i', 'J', 'L', 'l', 'm', 'O', 'o', 'P', 'p', 'Q', 'R', 'W', 'w']
    } else {
        &['o', 'c', 'D', 'i', 'J', 'l', 'P', 'X']
    };
    // A word the normaliser could not pin may be any option.
    if args.iter().any(|word| is_unresolved(word)) {
        return true;
    }
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        // ssh also parses options after the destination, so every word is scanned (a remote command's own option
        // cluster can over-ask, never under-ask).
        let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty() && !c.starts_with('-')) else {
            continue;
        };
        for (at, option) in cluster.char_indices() {
            match option {
                'S' | 'F' => return true,
                'I' if name == "ssh" => return true,
                _ if takes_value.contains(&option) => {
                    let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
                    let value = if rest.is_empty() {
                        i += 1;
                        args.get(i - 1).map_or("", String::as_str)
                    } else {
                        rest
                    };
                    if option == 'o' && command_option(value) {
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

/// tar runs a program for `-I`/`--use-compress-program`, `--to-command`, `--checkpoint-action=exec=…`,
/// `-F`/`--info-script`/`--new-volume-script` and `--rsh-command`/`--rmt-command`. The first operand may be an
/// old-style dashless option cluster (`tar xIf prog a.tar`).
fn tar_runs_program(args: &[String]) -> bool {
    /// Short options whose value is the rest of the cluster or the next word.
    const SHORT_VALUE: &[char] = &['b', 'C', 'f', 'g', 'H', 'K', 'L', 'N', 'T', 'V', 'X'];
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        if word.starts_with("--") {
            if long_option_is(word, "--use-compress-program", 1)
                || long_option_is(word, "--to-command", 1)
                || long_option_is(word, "--info-script", 1)
                || long_option_is(word, "--new-volume-script", 1)
                || long_option_is(word, "--rsh-command", 1)
                || long_option_is(word, "--rmt-command", 1)
            {
                return true;
            }
            if long_option_is(word, "--checkpoint-action", 11) {
                let value = match word.split_once('=') {
                    Some((_, value)) => value,
                    None => args.get(i).map_or("", String::as_str),
                };
                if value.starts_with("exec") {
                    return true;
                }
            }
            continue;
        }
        let dashless_first = i == 1 && !word.starts_with('-');
        let Some(cluster) = word.strip_prefix('-').or(dashless_first.then_some(word.as_str())) else {
            continue;
        };
        for option in cluster.chars() {
            if matches!(option, 'I' | 'F') {
                return true;
            }
            // Dashless clusters take each value from the following words, so every letter is an option.
            if !dashless_first && SHORT_VALUE.contains(&option) {
                break;
            }
        }
    }
    false
}

/// `man -P PAGER` / `--pager` runs PAGER; `-H`/`--html` runs a browser.
fn man_runs_program(args: &[String]) -> bool {
    /// Short options whose value is the rest of the cluster or the next word.
    const SHORT_VALUE: &[char] = &['C', 'e', 'E', 'L', 'm', 'M', 'p', 'r', 'R', 's', 'S'];
    for word in args {
        if word == "--" {
            break;
        }
        if word.starts_with("--") {
            if long_option_is(word, "--pager", 1) || long_option_is(word, "--html", 1) {
                return true;
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for option in cluster.chars() {
            if matches!(option, 'P' | 'H') {
                return true;
            }
            if SHORT_VALUE.contains(&option) {
                break;
            }
        }
    }
    false
}

/// jq's `env` builtin and `$ENV` expose the whole environment; a filter read from a file (`-f`, also inside a
/// short-option cluster such as `-nf`, u35 r3 Astra r2 H10) or pulled in by `import`/`include` is not visible.
fn jq_reads_environment(args: &[String]) -> bool {
    args.iter().any(|word| {
        word.strip_prefix('-').is_some_and(|cluster| !cluster.starts_with('-') && cluster.contains('f'))
            || long_option_is(word, "--from-file", 1)
            || word.contains("$ENV")
            || word_has_identifier(word, "env")
            || word_has_identifier(word, "import")
            || word_has_identifier(word, "include")
    })
}

/// Whether `text` uses `ident` as a bare identifier: not part of a longer name, a `.field` access or a `$variable`.
fn word_has_identifier(text: &str, ident: &str) -> bool {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(ident).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + ident.len()..].chars().next();
        !before.is_some_and(|c| is_name(c) || c == '.' || c == '$') && !after.is_some_and(is_name)
    })
}

/// kubectl reads that return Secret objects (`get secrets`, `get pods,secret/db`, `describe secret`), or any raw API
/// path (`get --raw /api/v1/…/secrets`). A namespace or label value spelled `secrets` also counts (over-asks only).
fn kubectl_reads_secrets(args: &[String]) -> bool {
    // u35 g3 (Astra r3): `get`/`describe` with `-f`/`--filename` or `-k`/`--kustomize` take the resource kind from a
    // file the command does not show, which can name a Secret.
    let reads_resources = args.iter().any(|word| matches!(word.as_str(), "get" | "describe"));
    if reads_resources && args.iter().any(|word| kubectl_selects_from_file(word)) {
        return true;
    }
    args.iter().any(|word| {
        if word.starts_with('-') {
            return word == "--raw" || word.starts_with("--raw=");
        }
        word.split(',').any(|resource| {
            let kind = resource.split('/').next().unwrap_or(resource);
            let kind = kind.split('.').next().unwrap_or(kind).to_ascii_lowercase();
            matches!(kind.as_str(), "secret" | "secrets")
        })
    })
}

/// `-f`/`--filename` or `-k`/`--kustomize`, alone, attached or inside a pflag cluster after boolean shorthands
/// (`-Rf`); a pflag prefix of the long names counts too.
fn kubectl_selects_from_file(word: &str) -> bool {
    if word.starts_with("--") {
        return long_option_is(word, "--filename", 1) || long_option_is(word, "--kustomize", 1);
    }
    let Some(cluster) = word.strip_prefix('-') else {
        return false;
    };
    for option in cluster.chars() {
        match option {
            'f' | 'k' => return true,
            'A' | 'w' | 'R' | 'h' => {}
            _ => return false,
        }
    }
    false
}

/// `go run`/`go install`/`go generate`/`go tool` build and run (or install) a program, possibly a remote module;
/// `-exec`, `-toolexec` and (u35 r2) `go vet -vettool` run a program of the caller's choosing.
fn go_runs_program(args: &[String]) -> bool {
    if args.iter().any(|w| {
        let name = w.trim_start_matches('-');
        w.starts_with('-') && matches!(name.split_once('=').map_or(name, |(n, _)| n), "exec" | "toolexec" | "vettool")
    }) {
        return true;
    }
    // u35 g3: `-ldflags` naming an external linker (`-extld`, `-extldflags` can pass `-fuse-ld=PATH`), and
    // `-gccgoflags` (gccgo runs what `-B` names).
    for (at, w) in args.iter().enumerate() {
        let Some(flag) = w.strip_prefix("--").or_else(|| w.strip_prefix('-')) else {
            continue;
        };
        let (name, value) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (flag, args.get(at + 1).map(String::as_str)),
        };
        match name {
            "gccgoflags" => return true,
            "ldflags" if value.is_some_and(|v| v.contains("extld") || is_unresolved(v)) => return true,
            _ => {}
        }
    }
    // u35 r3 (Fable r2 L): `go -C dir run …`: the value of `-C` is not the subcommand.
    let mut i = 0;
    while let Some(word) = args.get(i) {
        if word == "-C" {
            i += 2;
            continue;
        }
        if word.starts_with('-') {
            i += 1;
            continue;
        }
        // u35 g3: `go bug` and `go doc -http` open a browser.
        if word == "doc" {
            return args[i..].iter().any(|w| w.trim_start_matches('-').split('=').next() == Some("http"));
        }
        return matches!(word.as_str(), "run" | "install" | "generate" | "tool" | "bug");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::segment_has_exec_surface;

    fn hit(cmd: &str) -> bool {
        let words: Vec<String> = cmd.split_whitespace().map(str::to_owned).collect();
        segment_has_exec_surface(&words)
    }

    #[test]
    fn exec_surface_ordinary_use_is_clear() {
        for cmd in [
            "sed -n 1,5p f",
            "awk -F: {print}",
            "python3 --version",
            "python3 -V",
            "node --version",
            "ruby --help",
            // u35: a script file or module run is visible code, left to the grants.
            "python3 script.py",
            "python3 -m pytest -q",
            "python3 -Bm pytest",
            "python3 -v script.py",
            "python3 -W ignore -X dev s.py",
            "python3 script.py -c x",
            "node build.js",
            "node --require ./x.js app.js",
            "node --no-warnings --title t app.js",
            "node --test",
            "perl script.pl",
            "perl -I lib script.pl",
            "perl -l012 -n script.pl",
            "perl -0777 -Mstrict script.pl",
            "ruby -v app.rb",
            "ruby -rjson -W0 app.rb",
            "php artisan",
            "php -l index.php",
            "php -f index.php",
            "deno run -A x.ts",
            "deno task build",
            "bun x.js",
            "bun run build",
            "lua5.4 x.lua",
            "lua -l mod x.lua",
            "tclsh8.6 x.tcl",
            "rsync -avz src host:/dst",
            "rsync -avzB 1024 src dst",
            "go build ./...",
            "go test ./...",
            "find . -name x",
            "fd -H foo",
            "bash script.sh",
            "bash --version",
        ] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_modes_are_flagged() {
        for cmd in [
            "python3 -Ic x",
            "python3",
            "node -pe 1",
            "perl -lne x",
            "ruby -ne x",
            "php -r x",
            // u35: inline code (also in a cluster or swallowed by a digit option), stdin, a REPL, an unvouched value.
            "python3 -v",
            "python3 -",
            "python3 -i script.py",
            "python3 --version -c x",
            "python3 -- -",
            "perl -l012e x",
            "perl -0x1e script.pl",
            "perl -MO=x script.pl",
            "perl -d script.pl",
            "perl",
            "ruby -W2e x",
            "ruby",
            "irb",
            "node",
            "node --ev 1",
            "node -i",
            "node --import data:text/javascript,x app.js",
            "node -rdata:x app.js",
            "deno",
            "deno eval x",
            "deno run -",
            "bun -e x",
            "bun repl",
            "bun exec x",
            "php",
            "php -B x -F f.php",
            "lua -e x",
            "lua5.4",
            "tclsh",
            "tclsh8.6 --version",
            "wish -display d x.tcl",
            "rsync -avze ssh a b",
            "go test -exec=id ./...",
            "fd -x rm",
            "bash",
            "sh -s",
            "xargs -0 cat",
        ] {
            assert!(hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_scp_transport_program() {
        for cmd in ["scp -S ./payload f host:", "scp -rS./payload f host:", "scp -o ProxyCommand=id f host:", "scp -F cfg f host:"] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in ["scp f host:/dst", "scp -P 2222 -r src host:", "scp -i key.pem -o Port=22 f host:"] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_tar_program_options() {
        for cmd in [
            "tar -I ./payload -xf a.tar",
            "tar -xIpayload -f a.tar",
            "tar xIf ./payload a.tar",
            "tar --use-compress-program=./payload -xf a.tar",
            "tar --use-compress ./payload -xf a.tar",
            "tar -xf a.tar --to-command=./payload",
            "tar -cf a.tar --checkpoint=1 --checkpoint-action=exec=./payload .",
            "tar -cf a.tar --checkpoint-action exec=./payload .",
        ] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in [
            "tar -czf a.tgz dir",
            "tar xzf a.tgz",
            "tar -xf a.tar -C out",
            "tar --checkpoint=100 --checkpoint-action=dot -cf a.tar .",
            "tar -tvf a.tar",
        ] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_man_pager_and_browser() {
        for cmd in ["man -P ./payload ls", "man -P./payload ls", "man --pager=./payload ls", "man -H ls", "man --html=firefox ls"] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in ["man ls", "man -k printf", "man -s 3 printf", "man 5 crontab"] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_environment_dumps_and_shell_state() {
        for cmd in [
            "env",
            "printenv",
            "printenv HOME",
            "set",
            "export",
            "export -p",
            "declare -p",
            "declare -p FOO",
            "typeset -p FOO BAR",
            "export -p FOO",
            "local -p",
            "typeset -x",
            "jq -n env",
            "jq -n $ENV",
            "jq -n env.HOME",
            "jq -f prog.jq data.json",
            "printf -v PATH ./bin",
            "printf -vPATH ./bin",
        ] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in [
            "set -e",
            "export FOO=1",
            "declare -r FOO=1",
            "jq .name package.json",
            "jq .environment f",
            "jq .env f",
            "printf %s\\n a",
            "printf -- -v",
        ] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_kubectl_secret_reads() {
        for cmd in [
            "kubectl get secrets",
            "kubectl get secret db -o yaml",
            "kubectl get pods,secrets",
            "kubectl get secret/db",
            "kubectl get secrets.v1",
            "kubectl describe Secret db",
            "kubectl get --raw /api/v1/namespaces/default/secrets",
        ] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in ["kubectl get pods -n kube-system -o wide", "kubectl logs secret-rotator-0", "kubectl get configmaps"] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_r2_ssh_family_local_programs() {
        for cmd in [
            "ssh -o ProxyCommand=id host",
            "ssh -oproxycommand=id host",
            "ssh -vo LocalCommand=id host",
            "ssh -o PermitLocalCommand=yes host",
            "ssh -o KnownHostsCommand=id host",
            "ssh host -o ProxyCommand=id",
            "ssh -F cfg host",
            "ssh -S ctl host",
            "ssh -I lib.so host",
            "scp -o PKCS11Provider=lib.so f host:",
            "sftp host",
            "sftp -b batch host",
        ] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in ["ssh host", "ssh -p 2222 host uptime", "ssh -i key.pem -o Port=22 host", "ssh -J jump host"] {
            assert!(!hit(cmd), "{cmd}");
        }
    }

    #[test]
    fn exec_surface_r2_printf_environ_go_wget() {
        for cmd in [
            "printf %n x",
            "printf %s%5n a b",
            "printf -- %1$n x",
            "printf \0 x",
            "cat /proc/self/environ",
            "xxd /proc/1/environ",
            "head /proc/thread-self/environ",
            "cat /proc/./self/../self/task/7/environ",
            "cd /proc/self",
            "grep -r PATH /proc/self",
            "go vet -vettool=./payload ./...",
            "go tool x",
            "wget --use-askpass=./payload https://example.test",
            "wget -e use_askpass=./payload https://example.test",
            "wget --config=rc https://example.test",
        ] {
            assert!(hit(cmd), "{cmd}");
        }
        for cmd in ["printf %s\\n a", "printf 100%% x", "cat /proc/cpuinfo", "rg environ src", "go vet ./...", "wget -q -O out https://example.test"] {
            assert!(!hit(cmd), "{cmd}");
        }
    }
}
