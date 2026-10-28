//! u35 (lead decision after r2): which interpreter invocations run code the user cannot see in the command.
//!
//! Inline code (`python3 -c`, `perl -e`/`-E` also inside a cluster, `node --eval`, `ruby -e`, `php -r`, `lua -e`,
//! `deno eval`, `bun -e`) and a program read from stdin, a heredoc, a here-string or a REPL are hidden from the user's
//! grant intent, so they floor every broad grant. A script file or module run (`python3 path.py`, `python3 -m mod`,
//! `node build.js`, `perl script.pl`) is visible code execution and carries no floor: the user's grants and the
//! sandbox govern it. Neither is read-only (see [`super::interpreter_is_not_query`]).
//!
//! Each scanner walks the options before the script operand. An option it does not know, a word the normaliser could
//! not pin, or a value it cannot vouch for counts as hidden code, so only a recognised script or module clears it.

use super::{is_unresolved, long_option_is};

/// Whether `args` (after the interpreter `name`, a known [`super::is_interpreter`] spelling) run inline or stdin code.
pub(super) fn runs_hidden_code(name: &str, args: &[String]) -> bool {
    let stem = |prefix: &str| name.starts_with(prefix);
    if stem("python") || stem("pypy") {
        python(args)
    } else if stem("perl") {
        perl(args)
    } else if stem("ruby") {
        ruby(args)
    } else if stem("node") {
        node(args)
    } else if stem("deno") {
        deno(args)
    } else if stem("bun") {
        bun(args)
    } else if stem("php") {
        php(args)
    } else if stem("lua") {
        lua(args)
    } else if stem("tclsh") || stem("wish") {
        tcl(name, args)
    } else {
        // `irb` and anything else: a REPL reading stdin.
        true
    }
}

/// Skip the separate value of an option at `args[*i]`; hidden if it is missing or unpinned.
fn skip_value(args: &[String], i: &mut usize) -> bool {
    let hidden = args.get(*i).is_none_or(|w| is_unresolved(w));
    *i += 1;
    hidden
}

/// After `--`, the next word is the script; none, `-` or an unpinned word is stdin or unknown.
fn script_after_double_dash(args: &[String], i: usize) -> bool {
    args.get(i).is_none_or(|w| w == "-" || is_unresolved(w))
}

fn long_name(word: &str) -> Option<(&str, bool)> {
    let long = word.strip_prefix("--")?;
    Some(long.split_once('=').map_or((long, false), |(name, _)| (name, true)))
}

/// `python [opts] (-c code | -m module | script | -) [args]`.
fn python(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" {
            return true;
        }
        if word == "--" {
            return script_after_double_dash(args, i);
        }
        if let Some((name, attached)) = long_name(word) {
            match name {
                "check-hash-based-pycs" => {
                    if !attached && skip_value(args, &mut i) {
                        return true;
                    }
                }
                "help" | "version" | "help-env" | "help-xoptions" | "help-all" => {}
                _ => return true,
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        for (at, option) in cluster.char_indices() {
            let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
            match option {
                // Inline code; `-i` reads a program from stdin after the script.
                'c' | 'i' => return true,
                'm' => return if rest.is_empty() { skip_value(args, &mut i) } else { false },
                'W' | 'X' => {
                    if rest.is_empty() && skip_value(args, &mut i) {
                        return true;
                    }
                    break;
                }
                'b' | 'B' | 'd' | 'E' | 'h' | 'I' | 'O' | 'P' | 'q' | 's' | 'S' | 'u' | 'v' | 'V' | 'x' | 'R' | '?' => {}
                _ => return true,
            }
        }
    }
    true
}

/// A `-M`/`-m` value perl pastes into `use …;` verbatim: only a plain module name is vouched for.
fn perl_module_is_plain(value: &str) -> bool {
    let name = value.strip_prefix('-').unwrap_or(value);
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// `perl [switches] [--] [programfile] [args]`.
fn perl(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" {
            return true;
        }
        if word == "--" {
            return script_after_double_dash(args, i);
        }
        if let Some((name, _)) = long_name(word) {
            if matches!(name, "help" | "version") {
                continue;
            }
            return true;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        let mut chars = cluster.char_indices().peekable();
        while let Some((at, option)) = chars.next() {
            let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
            match option {
                // Inline code; `-F` pastes a split pattern into the program; `-d` runs the debugger on stdin.
                'e' | 'E' | 'F' | 'd' => return true,
                'M' | 'm' => {
                    if !perl_module_is_plain(rest) {
                        return true;
                    }
                    break;
                }
                'I' => {
                    if rest.is_empty() && skip_value(args, &mut i) {
                        return true;
                    }
                    break;
                }
                // The rest of the cluster is this option's value.
                'i' | 'x' | 'C' | 'D' | 'V' => break,
                // Optional octal digits (`-l012`).
                'l' => {
                    while chars.peek().is_some_and(|(_, c)| c.is_digit(8)) {
                        chars.next();
                    }
                }
                // `-0777`, or `-0xHH…` whose hex digits may swallow an `e`: an `e` there is not vouched for.
                '0' => {
                    if chars.peek().is_some_and(|(_, c)| matches!(c, 'x' | 'X')) {
                        chars.next();
                        let mut hex = String::new();
                        while let Some((_, c)) = chars.peek().filter(|(_, c)| c.is_ascii_hexdigit()) {
                            hex.push(*c);
                            chars.next();
                        }
                        if hex.contains(['e', 'E']) {
                            return true;
                        }
                    } else {
                        while chars.peek().is_some_and(|(_, c)| c.is_digit(8)) {
                            chars.next();
                        }
                    }
                }
                'a' | 'c' | 'n' | 'p' | 's' | 'S' | 't' | 'T' | 'u' | 'U' | 'w' | 'W' | 'X' | 'v' | 'h' => {}
                _ => return true,
            }
        }
    }
    true
}

/// `ruby [switches] [--] [programfile] [args]`.
fn ruby(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" {
            return true;
        }
        if word == "--" {
            return script_after_double_dash(args, i);
        }
        if let Some((name, attached)) = long_name(word) {
            match name {
                "version" | "help" | "copyright" | "verbose" | "yjit" | "jit" | "rjit" => {}
                "encoding" | "external-encoding" | "internal-encoding" | "dump" | "backtrace-limit"
                | "crash-report" | "parser" | "disable" | "enable" => {
                    if !attached && skip_value(args, &mut i) {
                        return true;
                    }
                }
                _ if ["disable-", "enable-", "yjit-", "rjit-"].iter().any(|p| name.starts_with(p)) => {}
                _ => return true,
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        let mut chars = cluster.char_indices().peekable();
        while let Some((at, option)) = chars.next() {
            let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
            match option {
                'e' => return true,
                'r' | 'I' | 'E' | 'C' => {
                    if rest.is_empty() && skip_value(args, &mut i) {
                        return true;
                    }
                    break;
                }
                // The rest of the cluster is this option's value.
                'x' | 'i' | 'F' => break,
                // Optional octal level, then the cluster continues (`-W2e` is `-W2 -e`).
                '0' | 'W' | 'T' => {
                    if option == 'W' && rest.starts_with(':') {
                        break;
                    }
                    while chars.peek().is_some_and(|(_, c)| c.is_digit(8)) {
                        chars.next();
                    }
                }
                // One code character, then the cluster continues.
                'K' => {
                    chars.next();
                }
                'a' | 'c' | 'd' | 'l' | 'n' | 'p' | 's' | 'S' | 'v' | 'w' | 'y' | 'h' | 'U' => {}
                _ => return true,
            }
        }
    }
    true
}

/// Node long options that take a separate value; any other long option is a flag.
const NODE_LONG_VALUE: &[&str] = &[
    "require", "import", "loader", "experimental-loader", "conditions", "title", "inspect-port", "debug-port",
    "env-file", "env-file-if-exists", "input-type", "stack-size", "redirect-warnings", "diagnostic-dir",
    "report-dir", "report-directory", "report-filename", "report-signal", "heapsnapshot-signal",
    "heapsnapshot-near-heap-limit", "icu-data-dir", "openssl-config", "tls-cipher-list", "tls-keylog",
    "use-largepages", "secure-heap", "secure-heap-min", "unhandled-rejections", "dns-result-order", "disable-proto",
    "experimental-policy", "policy-integrity", "watch-path", "watch-kill-signal", "test-name-pattern",
    "test-skip-pattern", "test-reporter", "test-reporter-destination", "test-concurrency", "test-shard",
    "test-timeout", "test-coverage-include", "test-coverage-exclude", "cpu-prof-dir", "cpu-prof-name",
    "cpu-prof-interval", "heap-prof-dir", "heap-prof-name", "heap-prof-interval", "max-http-header-size",
    "experimental-config-file", "localstorage-file", "trace-event-categories", "trace-event-file-pattern",
    "snapshot-blob", "experimental-sea-config", "disable-warning", "max-old-space-size", "max-semi-space-size",
    "run",
];

/// A preload (`-r`, `--require`, `--import`, `--loader`) is a module file unless it is a `data:` URL (inline code).
fn node_preload_hidden(value: &str) -> bool {
    is_unresolved(value) || value.get(..5).is_some_and(|scheme| scheme.eq_ignore_ascii_case("data:"))
}

fn node_value(args: &[String], i: &mut usize, attached: Option<&str>, preload: bool) -> bool {
    let value = match attached {
        Some(value) => value,
        None => {
            let Some(value) = args.get(*i) else {
                return true;
            };
            *i += 1;
            value.as_str()
        }
    };
    is_unresolved(value) || (preload && node_preload_hidden(value))
}

/// `node [options] [script | -] [args]`; `--test` and `--run` run project files with no script operand.
fn node(args: &[String]) -> bool {
    let mut i = 0;
    let mut project_mode = false;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" {
            return true;
        }
        if word == "--" {
            return script_after_double_dash(args, i);
        }
        if let Some(long) = word.strip_prefix("--") {
            if long_option_is(word, "--eval", 1)
                || long_option_is(word, "--print", 1)
                || long_option_is(word, "--interactive", 1)
            {
                return true;
            }
            let (name, value) = long.split_once('=').map_or((long, None), |(name, value)| (name, Some(value)));
            if matches!(name, "test" | "run") {
                project_mode = true;
            }
            if NODE_LONG_VALUE.contains(&name) {
                let preload = matches!(name, "require" | "import" | "loader" | "experimental-loader");
                if node_value(args, &mut i, value, preload) {
                    return true;
                }
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        for (at, option) in cluster.char_indices() {
            let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
            let attached = (!rest.is_empty()).then_some(rest);
            match option {
                'e' | 'p' | 'i' => return true,
                'r' | 'C' => {
                    if node_value(args, &mut i, attached, option == 'r') {
                        return true;
                    }
                    break;
                }
                'c' | 'v' | 'h' => {}
                _ => return true,
            }
        }
    }
    !project_mode
}

/// Deno flags that take a separate value.
const DENO_VALUE: &[&str] = &["-c", "--config", "--import-map", "--location", "--seed", "--cert", "--ext", "--preload"];

/// `deno [subcommand] [flags] [script]`: `eval`, `repl` and a bare `deno` (a REPL) run hidden code, so does `-` (stdin).
fn deno(args: &[String]) -> bool {
    if args.iter().any(|w| is_unresolved(w) || w == "-" || w.starts_with("--eval")) {
        return true;
    }
    let mut i = 0;
    let mut run = false;
    while let Some(word) = args.get(i) {
        i += 1;
        if DENO_VALUE.contains(&word.as_str()) {
            i += 1;
            continue;
        }
        if word.starts_with('-') {
            continue;
        }
        // `deno x.ts` runs the file; after `run`/`serve` the first operand is the script.
        if run || word.contains(['.', '/']) {
            return false;
        }
        match word.as_str() {
            "run" | "serve" => run = true,
            "eval" | "repl" | "jupyter" => return true,
            _ => return false,
        }
    }
    // A bare `deno`, or `run`/`serve` with no script.
    true
}

/// Bun flags that take a separate value.
const BUN_VALUE: &[&str] = &[
    "-r", "--preload", "--require", "--import", "--cwd", "--env-file", "-c", "--config", "--tsconfig-override", "-d",
    "--define", "-l", "--loader", "--main-fields", "--extension-order", "--jsx-factory", "--jsx-fragment",
    "--jsx-import-source", "--jsx-runtime", "--port", "--conditions", "-F", "--filter", "--shell", "--elide-lines",
];

/// `bun [flags] (file | subcommand) [args]`: `-e`/`--eval`, `-p`/`--print`, `repl`, `exec` and stdin run hidden code.
fn bun(args: &[String]) -> bool {
    let mut i = 0;
    let mut run = false;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" {
            return true;
        }
        if let Some((name, attached)) = long_name(word) {
            if matches!(name, "eval" | "print") {
                return true;
            }
            if !attached && BUN_VALUE.contains(&word.as_str()) {
                let preload = matches!(name, "preload" | "require" | "import");
                if node_value(args, &mut i, None, preload) {
                    return true;
                }
            }
            continue;
        }
        if let Some(cluster) = word.strip_prefix('-') {
            if cluster.contains(['e', 'p']) {
                return true;
            }
            if BUN_VALUE.contains(&word.as_str()) && node_value(args, &mut i, None, word == "-r") {
                return true;
            }
            continue;
        }
        match word.as_str() {
            "repl" | "exec" => return true,
            "run" if !run => run = true,
            _ => return false,
        }
    }
    true
}

/// `php [options] [-f] file [args]`: `-r`, `-R`/`-B`/`-E`, `-a` and stdin run hidden code.
fn php(args: &[String]) -> bool {
    let mut i = 0;
    let mut no_stdin = false;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" || word == "--" {
            return true;
        }
        if let Some((name, attached)) = long_name(word) {
            match name {
                "run" | "process-code" | "process-begin" | "process-end" | "interactive" => return true,
                "file" => return !attached && skip_value(args, &mut i),
                "php-ini" | "define" | "zend-extension" | "docroot" | "process-file" => {
                    if !attached && skip_value(args, &mut i) {
                        return true;
                    }
                    no_stdin |= name == "process-file";
                }
                "rf" | "rc" | "re" | "rz" | "ri" => {
                    if !attached && skip_value(args, &mut i) {
                        return true;
                    }
                    no_stdin = true;
                }
                "info" | "modules" | "version" | "help" | "ini" | "syntax-check" | "syntax-highlight" | "strip" => {
                    no_stdin = true;
                }
                "no-php-ini" | "no-header" | "hide-args" | "no-chdir" => {}
                _ => return true,
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        for (at, option) in cluster.char_indices() {
            let rest = &cluster[crate::permission::shell_words::after_char(cluster, at)..];
            match option {
                'r' | 'R' | 'B' | 'E' | 'a' => return true,
                'f' => return rest.is_empty() && skip_value(args, &mut i),
                // Per-line file, lint, highlight and strip run no code from stdin.
                'F' | 'l' | 's' | 'w' | 'i' | 'm' | 'v' | 'h' | '?' => {
                    no_stdin = true;
                    if option == 'F' {
                        if rest.is_empty() && skip_value(args, &mut i) {
                            return true;
                        }
                        break;
                    }
                }
                // The built-in web server serves files from the docroot.
                'S' | 't' | 'c' | 'd' | 'z' => {
                    no_stdin |= matches!(option, 'S' | 't');
                    if rest.is_empty() && skip_value(args, &mut i) {
                        return true;
                    }
                    break;
                }
                'q' | 'H' | 'n' | 'e' | 'C' => {}
                _ => return true,
            }
        }
    }
    !no_stdin
}

/// `lua [options] [script [args]]`: `-e`, `-i`, `-` and no script run hidden code.
fn lua(args: &[String]) -> bool {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if is_unresolved(word) || word == "-" {
            return true;
        }
        if word == "--" {
            return script_after_double_dash(args, i);
        }
        let Some(cluster) = word.strip_prefix('-') else {
            return false;
        };
        let rest = cluster.get(1..).unwrap_or_default();
        match cluster.chars().next() {
            Some('l' | 'j' | 'O') => {
                if rest.is_empty() && cluster != "O" && skip_value(args, &mut i) {
                    return true;
                }
            }
            Some('v' | 'E' | 'W') if rest.is_empty() => {}
            // `luajit -b` compiles a file to bytecode.
            Some('b') => return false,
            _ => return true,
        }
    }
    true
}

/// `tclsh ?-encoding name? ?file args?`; `wish` options are not modelled.
fn tcl(name: &str, args: &[String]) -> bool {
    let mut rest = args;
    if name.starts_with("tclsh") && rest.first().is_some_and(|w| w == "-encoding") {
        if rest.get(1).is_none_or(|w| is_unresolved(w)) {
            return true;
        }
        rest = &rest[2..];
    }
    rest.first().is_none_or(|script| script.starts_with('-') || is_unresolved(script))
}
