//! u35 r3: the strict plain-text gate for approving a shell command without any user grant.
//!
//! Every review round found another spelling that the classifier modelled one way and bash ran another way. Rather
//! than chase each spelling, a command approved on the strength of a built-in list alone (the Ask-mode read-only
//! lists, the Auto-mode routine heuristic) must first be plain text, where what the classifier reads is exactly what
//! bash runs. Anything richer asks. The quote-aware normaliser and the floors stay in place for user grants (prefix,
//! glob, the session "allow all", sandbox auto-allow), which are the user's own authority.

/// Programs that run, retarget or delay another command (wrappers), and shell builtins or reserved words that change
/// how later words, directories or options are read. None of them is a plain program word.
const NOT_PLAIN_PROGRAMS: &[&str] = &[
    // Wrappers and launchers.
    "env", "command", "builtin", "exec", "timeout", "nice", "nohup", "stdbuf", "xargs", "parallel", "sudo", "sudoedit",
    "doas", "run0", "pkexec", "su", "runuser", "time", "ionice", "chrt", "taskset", "setsid", "flock", "watch",
    "unbuffer", "script", "nsenter", "unshare", "chroot", "strace", "ltrace", "caffeinate", "systemd-run", "firejail",
    "bwrap",
    // Builtins that change shell state, the directory, or how later words are parsed.
    "set", "shopt", "cd", "pushd", "popd", "eval", "source", ".", "alias", "unalias", "export", "unset", "declare",
    "typeset", "local", "readonly", "enable", "hash", "trap", "let", "read", "mapfile", "readarray", "fc", "bind",
    // Reserved words.
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do", "done", "in",
    "function", "coproc",
];

/// One unquoted word character: `[A-Za-z0-9._/:=@%+,-]`.
fn is_plain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | ':' | '=' | '@' | '%' | '+' | ',' | '-')
}

/// Whether a word may end before `c`: a blank, a newline, a connector character, or the end of the command.
fn ends_word(c: Option<&char>) -> bool {
    c.is_none_or(|c| matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|'))
}

/// Whether `cmd` passes the plain-text gate. Only then may a built-in list approve it without a user grant; otherwise
/// the answer is Ask. The rule, all of which must hold:
///
/// - Structure: plain simple commands joined only by `&&`, `||`, `;`, `|` or a newline. No subshell, group,
///   background `&`, heredoc, here-string, process substitution or comment.
/// - Words: each word is either unquoted plain text using only `[A-Za-z0-9._/:=@%+,-]`, or exactly one quoted
///   segment that is the whole word: single quotes holding anything but a newline, or double quotes holding none of
///   `$`, backtick, `\`, `!` or a newline. No empty quotes, no joined or partly quoted words, no escapes, expansions,
///   globs (`*?[`), braces or leading tilde (none of those characters is plain text).
/// - Program: the first word of each command is unquoted, has no `/` and no `=` (no assignment), and is not a wrapper
///   (`env`, `command`, `builtin`, `exec`, `timeout`, `nice`, `nohup`, `stdbuf`, `xargs`, `sudo`, `time`, ...), not a
///   builtin that changes shell state or the directory (`set`, `shopt`, `cd`, `pushd`, `popd`, `eval`, `source`, `.`,
///   `alias`, `export`, `unset`, ...) and not a reserved word.
/// - Redirects: none, or to `/dev/null` only (`>`, `>>`, `<`, `&>`, `&>>`, an optional single-digit fd before `>`/`<`).
///
/// The caller still applies its own list and per-program argument checks after this gate.
pub(crate) fn is_plain_text_command(cmd: &str) -> bool {
    plain_commands(cmd).is_some()
}

/// One word and whether it was a quoted segment.
struct Word {
    text: String,
    quoted: bool,
}

/// The argv of each command, if `cmd` passes the gate (see [`is_plain_text_command`]).
fn plain_commands(cmd: &str) -> Option<Vec<Vec<String>>> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut commands: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<Word> = Vec::new();
    let mut redirected = false;
    // After `&&`, `||` or `|` a command must follow (newlines may come between).
    let mut need_command = false;
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        match c {
            ' ' | '\t' => i += 1,
            '\n' => {
                if !current.is_empty() || redirected {
                    commands.push(close_command(&mut current, &mut redirected)?);
                }
                i += 1;
            }
            ';' => {
                if next == Some(';') || next == Some('&') {
                    return None;
                }
                commands.push(close_command(&mut current, &mut redirected)?);
                i += 1;
            }
            '&' if next == Some('&') => {
                commands.push(close_command(&mut current, &mut redirected)?);
                need_command = true;
                i += 2;
            }
            '|' if next == Some('|') => {
                commands.push(close_command(&mut current, &mut redirected)?);
                need_command = true;
                i += 2;
            }
            '|' if next != Some('&') => {
                commands.push(close_command(&mut current, &mut redirected)?);
                need_command = true;
                i += 1;
            }
            '>' | '<' | '&' => {
                i = dev_null_redirect(&chars, i)?;
                redirected = true;
            }
            '0'..='9' if matches!(next, Some('>' | '<')) => {
                i = dev_null_redirect(&chars, i + 1)?;
                redirected = true;
            }
            '\'' | '"' => {
                let close = chars[i + 1..].iter().position(|&q| q == c)? + i + 1;
                let body = &chars[i + 1..close];
                let forbidden: &[char] = if c == '\'' { &['\n'] } else { &['\n', '$', '`', '\\', '!'] };
                if body.is_empty() || body.iter().any(|ch| forbidden.contains(ch)) || !ends_word(chars.get(close + 1)) {
                    return None;
                }
                current.push(Word {
                    text: body.iter().collect(),
                    quoted: true,
                });
                need_command = false;
                i = close + 1;
            }
            c if is_plain_char(c) => {
                let len = chars[i..].iter().take_while(|&&ch| is_plain_char(ch)).count();
                if !ends_word(chars.get(i + len)) {
                    return None;
                }
                current.push(Word {
                    text: chars[i..i + len].iter().collect(),
                    quoted: false,
                });
                need_command = false;
                i += len;
            }
            _ => return None,
        }
    }
    if need_command {
        return None;
    }
    if !current.is_empty() || redirected {
        commands.push(close_command(&mut current, &mut redirected)?);
    }
    (!commands.is_empty()).then_some(commands)
}

/// Finish one command: it must have a plain program word (see [`is_plain_text_command`]).
fn close_command(current: &mut Vec<Word>, redirected: &mut bool) -> Option<Vec<String>> {
    *redirected = false;
    let words = std::mem::take(current);
    let program = words.first()?;
    if program.quoted
        || program.text.contains(['/', '='])
        || NOT_PLAIN_PROGRAMS.contains(&program.text.as_str())
    {
        return None;
    }
    Some(words.into_iter().map(|word| word.text).collect())
}

/// Parse a redirect operator at `chars[at]` (`>`, `>>`, `<`, `&>`, `&>>`) and its target, which must be the unquoted
/// word `/dev/null`. Returns the index after the target.
fn dev_null_redirect(chars: &[char], at: usize) -> Option<usize> {
    let rest: String = chars[at..].iter().take(3).collect();
    let op_len = if rest.starts_with("&>>") {
        3
    } else if rest.starts_with(">>") || rest.starts_with("&>") {
        2
    } else if rest.starts_with('>') || rest.starts_with('<') {
        1
    } else {
        return None;
    };
    let mut i = at + op_len;
    // `>&`, `>|`, `<>`, `<<`, `<(`, `>(` and the like are not plain redirects.
    if chars.get(i).is_some_and(|c| !matches!(c, ' ' | '\t' | '/')) {
        return None;
    }
    while chars.get(i).is_some_and(|c| matches!(c, ' ' | '\t')) {
        i += 1;
    }
    const TARGET: &str = "/dev/null";
    let len = chars[i..].iter().take_while(|&&ch| is_plain_char(ch)).count();
    let target: String = chars[i..i + len].iter().collect();
    (target == TARGET && ends_word(chars.get(i + len))).then_some(i + len)
}

#[cfg(test)]
mod tests {
    use super::{is_plain_text_command, plain_commands};

    #[test]
    fn plain_text_gate_accepts_plain_commands() {
        for cmd in [
            "ls",
            "ls -la src",
            "git log --oneline -5",
            "cat 'my file.txt'",
            "grep -rn \"foo bar\" src",
            "rg -n 'fn main' src",
            "ls -la && git status",
            "git status || true",
            "ls | head -5",
            "ls; pwd",
            "ls;\npwd",
            "ls\n\npwd\n",
            "ls 2>/dev/null",
            "ls > /dev/null 2>/dev/null",
            "ls &>/dev/null",
            "cat < /dev/null",
            "echo a=b user@host 50% +x a,b c:d",
            "grep -rn foo src '--include=*.rs'",
            "git status &&\n git diff",
            // g4 (Fable r3 L1): every redirect form the gate accepts, and a tab separator.
            "ls &>>/dev/null",
            "ls 2</dev/null",
            "2>/dev/null ls",
            "ls >/dev/null",
            "ls\t-la",
        ] {
            assert!(is_plain_text_command(cmd), "{cmd:?} must pass the gate");
        }
        assert_eq!(
            plain_commands("cat 'a b' | wc -l"),
            Some(vec![vec!["cat".to_owned(), "a b".to_owned()], vec!["wc".to_owned(), "-l".to_owned()]])
        );
    }

    #[test]
    fn plain_text_gate_rejects_rich_forms() {
        for cmd in [
            "",
            "   ",
            "ls ~/x",
            "ls ~",
            "cat *.md",
            "ls src/?",
            "ls [ab]",
            "ls {a,b}",
            "ls $HOME",
            "ls \"$HOME\"",
            "echo `id`",
            "ls \"a\"b",
            "ls a'b'",
            "ls ''",
            "ls \"\"",
            "ls ''~",
            "ls \\x",
            "echo \"a!b\"",
            "echo \"a\\b\"",
            "echo 'a\nb'",
            "(ls)",
            "{ ls; }",
            "ls &",
            "ls & pwd",
            "ls # note",
            "ls > out",
            "ls 2>&1",
            "ls >&2",
            "ls >| /dev/null",
            "ls>/dev/null",
            "ls 12>/dev/null",
            "cat <<< x",
            "cat <<EOF\nx\nEOF",
            "cat <(ls)",
            "ls |& cat",
            "ls &&",
            "&& ls",
            "ls ||",
            "ls |",
            "; ls",
            "ls ;; pwd",
            "FOO=1 ls",
            "./ls",
            "/bin/ls",
            "'ls' -la",
            "env ls",
            "command ls",
            "builtin echo x",
            "exec ls",
            "time ls",
            "timeout 5 ls",
            "nice ls",
            "nohup ls",
            "stdbuf -o0 ls",
            "xargs ls",
            "sudo ls",
            "set +B",
            "shopt -s extglob",
            "cd src && git status",
            "pushd src",
            "popd",
            "eval ls",
            "source x",
            ". x",
            "alias ls=rm",
            "export A=1",
            "unset PATH",
            "for f in a; do ls; done",
            "if true; then ls; fi",
            "! ls",
            "ls é",
            "ls\r",
            "> /dev/null",
            "ls \\\n -la",
            // g4 (Fable r3 L1): unterminated quotes, case terminators, a newline in double quotes, and redirect
            // targets that only look like `/dev/null`.
            "ls 'abc",
            "ls \"abc",
            "ls ;& pwd",
            "ls ;;& pwd",
            "echo \"a\nb\"",
            "ls 2>/dev/null/",
            "ls >'/dev/null'",
            "ls >\"/dev/null\"",
            "ls > /dev/nullx",
        ] {
            assert!(!is_plain_text_command(cmd), "{cmd:?} must not pass the gate");
        }
    }
}
