//! u35: Fuigo's own `grep` and `find`.
//!
//! The agent shell defines `grep` as a function running the bundled ugrep (7.7.0) and `find` as one running the
//! bundled bfs (4.1) (`fuigo-tools` `embedded_search_tools.rs`). These are the only shadows of a safe-listed name that
//! the runner's restore guard leaves in place, so a plain `grep`/`find` is judged here by the options of the engine
//! that runs, not by GNU grep's or GNU find's. A hit is an exec-surface finding: it floors every broad grant and is
//! never read-only or Auto mode routine.
//!
//! Neither engine accepts abbreviated long options: ugrep compares each long name exactly (`--filter=` and `--pager`
//! are spelled out), and bfs looks primaries up by exact name (only `-D`, `-O`, `-S`, `-j` and `-newerXY` take a glued
//! suffix). So no prefix matching is needed.

/// Short options of ugrep whose value is the rest of the cluster or the next word.
const UGREP_SHORT_VALUE: &str = "ABCDdefgJKMmNOt";

/// Long options of ugrep that also accept their value as the next word (the legacy `--opt VALUE` form).
const UGREP_LONG_SEPARATE_VALUE: &[&str] = &[
    "after-context", "before-context", "binary-files", "context", "depth", "devices", "directories", "exclude",
    "exclude-dir", "exclude-from", "file", "from", "include", "include-dir", "include-from", "label", "regexp",
];

/// ugrep long options that run another program, write a file, or search files the command line does not name.
/// `filter` runs a filter command per file; `pager` pipes output into a command; `view` and `query` (the `-Q` TUI)
/// run a viewer or editor; `save-config` writes a configuration file; `from` reads the paths to search from a file.
const UGREP_FLOORED_LONG: &[&str] = &["filter", "pager", "view", "query", "save-config", "from"];

/// ugrep pre-scans every argument before the first `--`, whatever position it is in (an `-e` value included), for
/// `--config[=FILE]` and `---FILE`. Either loads a configuration file from the working directory or the home
/// directory, which can set `filter=` or `pager=`.
pub(super) fn ugrep_loads_config(args: &[String]) -> bool {
    args.iter().take_while(|word| *word != "--").any(|word| word.starts_with("---") || word.starts_with("--config"))
}

/// Whether a `grep` run as ugrep runs another program, writes a file, or reads beyond the paths it names.
pub(super) fn ugrep_option_floors(args: &[String]) -> bool {
    if ugrep_loads_config(args) {
        return true;
    }
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            if UGREP_FLOORED_LONG.contains(&name) {
                return true;
            }
            if !glued && UGREP_LONG_SEPARATE_VALUE.contains(&name) {
                i += 1;
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            continue;
        };
        let chars: Vec<char> = cluster.chars().collect();
        for (at, option) in chars.iter().enumerate() {
            let rest = &chars[at + 1..];
            if *option == 'Q' {
                return true;
            }
            if UGREP_SHORT_VALUE.contains(*option) {
                if rest.is_empty() {
                    i += 1;
                }
                break;
            }
            // `-Z` (fuzzy) takes an optional glued value.
            let fuzzy_value = rest.starts_with(&['b', 'e', 's', 't'])
                || rest.first().is_some_and(|c| *c == '=' || c.is_ascii_digit() || "+-~".contains(*c));
            if *option == 'Z' && fuzzy_value {
                break;
            }
        }
    }
    false
}

/// bfs primaries and options that take one argument.
const BFS_ONE_ARG: &[&str] = &[
    "-amin", "-anewer", "-asince", "-atime", "-Bmin", "-Bnewer", "-Bsince", "-Btime", "-cmin", "-cnewer", "-context",
    "-csince", "-ctime", "-flags", "-fls", "-fprint", "-fprint0", "-fstype", "-gid", "-group", "-ilname", "-iname",
    "-inum", "-ipath", "-iregex", "-iwholename", "-limit", "-links", "-lname", "-maxdepth", "-mindepth", "-mmin",
    "-mnewer", "-msince", "-mtime", "-name", "-path", "-perm", "-printf", "-regex", "-regextype", "-samefile",
    "-since", "-size", "-type", "-uid", "-used", "-user", "-wholename", "-xattrname", "-xtype",
];

/// bfs flags (`-H`, `-L`, ...): they may appear anywhere and are not part of the expression.
const BFS_FLAG_LETTERS: &str = "HLPEXdsx";

/// Whether a `find` run as bfs deletes, runs another program, or searches a path GNU find would not.
///
/// - `-rm` is bfs's alias of `-delete`.
/// - `-f PATH` (also at the end of a flag group such as `-Lf`) names a starting path as an option value.
/// - `-files0-from FILE` reads the starting paths from a file.
/// - `-help`/`--help` runs `$PAGER` when the output is a terminal.
/// - bfs takes paths anywhere: a bare word after the expression has started is another starting path
///   (`find . -name x /etc` searches `/etc`), where GNU find refuses to run.
///
/// `-exec`/`-ok` and friends are handled by the caller.
pub(super) fn bfs_option_floors(args: &[String]) -> bool {
    let mut in_expression = false;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        let word = word.as_str();
        match word {
            "-rm" | "-f" | "-files0-from" | "-help" | "--help" => return true,
            "--" => {}
            "(" | ")" | "!" | "," | "-not" | "-a" | "-and" | "-o" | "-or" | "-exclude" => in_expression = true,
            "-fprintf" => {
                i += 2;
                in_expression = true;
            }
            // `-exit [STATUS]` and `-depth [N]` take an optional numeric argument.
            "-exit" | "-depth" => {
                if args.get(i).is_some_and(|next| bfs_is_number(next)) {
                    i += 1;
                }
                in_expression = true;
            }
            // `-D FLAG` and `-S STRATEGY` take a glued or separate value; they are flags, not expression.
            "-D" | "-S" => i += 1,
            _ if BFS_ONE_ARG.contains(&word) || word.starts_with("-newer") => {
                i += 1;
                in_expression = true;
            }
            _ if word.starts_with('-') && word.len() > 1 => {
                if bfs_flag_group_has_f(word) {
                    return true;
                }
                if !bfs_is_flag(word) {
                    in_expression = true;
                }
            }
            // A bare word (or `-`) once the expression has started is another starting path.
            _ => {
                if in_expression {
                    return true;
                }
            }
        }
    }
    false
}

/// `N`, `+N` or `-N`.
fn bfs_is_number(word: &str) -> bool {
    let digits = word.strip_prefix(['+', '-']).unwrap_or(word);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// A flag word: a single flag letter, or a glued `-D…`/`-O…`/`-S…`/`-j…`, or a group of flag letters.
fn bfs_is_flag(word: &str) -> bool {
    let body = &word[1..];
    if body.starts_with(['D', 'O', 'S', 'j']) {
        return true;
    }
    body.chars().all(|c| BFS_FLAG_LETTERS.contains(c))
}

/// A flag group that ends in `-f` (`-Lf`, `-HEf`): its PATH is the next word. bfs reads a word as a flag group only
/// when every letter is a flag, one of them is upper case, and the `f` (which takes an argument) comes last.
fn bfs_flag_group_has_f(word: &str) -> bool {
    word[1..].strip_suffix('f').is_some_and(|group| {
        !group.is_empty()
            && group.chars().all(|c| BFS_FLAG_LETTERS.contains(c))
            && group.chars().any(|c| c.is_ascii_uppercase())
    })
}
