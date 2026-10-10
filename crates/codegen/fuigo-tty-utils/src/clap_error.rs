//! One rendering of a clap error for the terminal, shared by the main binary and the workspace server.

use clap::error::{ContextValue, ErrorKind};

/// Backstop that does not depend on matching a value: of the rendered lines after the first, only those clap itself
/// emits keep their line break: an empty line, a line starting with two spaces (`  tip:`, a listed argument), `Usage:`,
/// and `For more information`. Any other line is joined to the previous one with one space.
fn join_foreign_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i == 0 {
            out.push_str(line);
        } else if line.is_empty() || line.starts_with("  ") || line.starts_with("Usage:") || line.starts_with("For more information") {
            out.push('\n');
            out.push_str(line);
        } else {
            out.push(' ');
            out.push_str(line);
        }
    }
    out
}

/// A clap error as plain (unstyled) text for the terminal. For every kind except help and version, each argv-derived
/// context value clap echoes (`ContextValue::String` / `Strings`) that holds LF, CR or TAB is flattened (each of those
/// becomes one space) inside the render. clap strips ANSI sequences from the values it echoes, so the value is looked
/// for in BOTH its raw form and the form `anstream::adapter::strip_str` leaves (the stripper clap's own `StyledStr`
/// display uses). A form with a visible character is replaced wherever it occurs;
/// a form that is only white space (a value such as `ESC[2J LF`) would match clap's own newlines, so it is replaced
/// only where clap echoes it, between its single quotes. Help and version keep their layout (env values are hidden by
/// the callers' `hide_env_values`). The whole text then goes through the terminal line filter, so no escape byte
/// survives. The caller keeps clap's exit code and stream (`use_stderr`, `exit_code`).
pub fn render_clap_error(e: &clap::Error) -> String {
    let mut text = e.render().to_string();
    let help = matches!(
        e.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
    if !help {
        let flat = |v: &str| v.replace(['\n', '\r', '\t'], " ");
        for (_, value) in e.context() {
            let values: Vec<&String> = match value {
                ContextValue::String(s) => vec![s],
                ContextValue::Strings(list) => list.iter().collect(),
                _ => Vec::new(),
            };
            for v in values.into_iter().filter(|v| v.contains(['\n', '\r', '\t'])) {
                for candidate in [v.clone(), anstream::adapter::strip_str(v).to_string()] {
                    if candidate.chars().any(|c| !c.is_whitespace()) {
                        text = text.replace(candidate.as_str(), &flat(&candidate));
                    } else {
                        text = text.replace(&format!("'{candidate}'"), &format!("'{}'", flat(&candidate)));
                    }
                }
            }
        }
        text = text.replace('\t', " ");
        text = join_foreign_lines(&text);
    }
    crate::scrub_terminal_text(&text).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd() -> clap::Command {
        clap::Command::new("t").subcommand(clap::Command::new("go")).arg(clap::Arg::new("n").long("n").value_parser(clap::value_parser!(u32)))
    }

    #[test]
    fn a_value_with_an_escape_and_a_line_break_renders_like_its_flat_twin() {
        for (hostile, flat) in [
            ("bogus\x1b[31m\nfuigo: granted", "bogus fuigo: granted"),
            ("bogus\r\nfuigo: granted", "bogus  fuigo: granted"),
            ("bogus\tfuigo: granted", "bogus fuigo: granted"),
            ("bogus\x1b]0;t\x07\nfuigo: granted", "bogus fuigo: granted"),
        ] {
            let e = cmd().try_get_matches_from(["t", hostile]).expect_err("unknown subcommand");
            let w = cmd().try_get_matches_from(["t", flat]).expect_err("unknown subcommand");
            assert_eq!(render_clap_error(&e), render_clap_error(&w), "{hostile:?}");
            assert_eq!(e.exit_code(), w.exit_code());
        }
        let e = cmd().try_get_matches_from(["t", "--n=\x1b[2J\n"]).expect_err("bad value");
        let w = cmd().try_get_matches_from(["t", "--n= "]).expect_err("bad value");
        assert_eq!(render_clap_error(&e), render_clap_error(&w));
    }

    /// Round S7 (M1): the shared renderer for a bare ESC, an unterminated CSI, OSC, DCS, a trailing ESC.
    #[test]
    fn a_bare_escape_before_a_line_break_renders_like_its_flat_twin() {
        for (hostile, flat) in [
            ("bogus\x1b\nfuigo: granted", Some("bogus fuigo: granted")),
            ("bogus\x1b[\nfuigo: granted", Some("bogus fuigo: granted")),
            ("bogus\x1b]0;t\x07\nfuigo: granted", Some("bogus fuigo: granted")),
            ("bogus\x1bP\nq", None),
            ("bogus\x1b", Some("bogus")),
            ("\x1b\n", Some(" ")),
        ] {
            let e = cmd().try_get_matches_from(["t", hostile]).expect_err("unknown subcommand");
            let shown = render_clap_error(&e);
            assert!(!shown.contains(['\x1b', '\r', '\t']), "{shown:?}");
            assert_eq!(shown.lines().filter(|l| l.starts_with("error:")).count(), 1, "{shown:?}");
            assert!(!shown.lines().any(|l| l.starts_with("fuigo:")), "{hostile:?}: {shown:?}");
            if let Some(flat) = flat {
                let w = cmd().try_get_matches_from(["t", flat]).expect_err("unknown subcommand");
                assert_eq!(shown, render_clap_error(&w), "{hostile:?}");
                assert_eq!(e.exit_code(), w.exit_code());
            }
        }
    }

    /// Round S7 (M1 backstop): a value whose flattened form is not found still cannot start a line of its own.
    #[test]
    fn join_foreign_lines_keeps_exactly_clap_s_own_line_starts() {
        let clap = "error: x\n\n  tip: y\n\nUsage: t\n\nFor more information, try '--help'.\n";
        assert_eq!(join_foreign_lines(clap), clap);
        assert_eq!(join_foreign_lines("error: x\nfuigo: granted\n"), "error: x fuigo: granted\n");
        assert_eq!(join_foreign_lines("error: x\n\nfuigo: granted"), "error: x\n fuigo: granted");
    }

    /// Round S7: ordinary clap errors are exactly clap's own plain text.
    #[test]
    fn ordinary_errors_are_clap_s_own_text() {
        let strict = || {
            clap::Command::new("t")
                .subcommand(clap::Command::new("go"))
                .arg(clap::Arg::new("n").long("n").value_parser(clap::value_parser!(u32)))
                .arg(clap::Arg::new("req").long("req").required(true))
        };
        for argv in [vec!["t", "--req", "a", "--zzz"], vec!["t"], vec!["t", "--req", "a", "--n", "x"], vec!["t", "--req", "a", "nope"]] {
            let e = strict().try_get_matches_from(argv.clone()).expect_err("error");
            let text = render_clap_error(&e);
            assert_eq!(text, e.render().to_string(), "{argv:?}");
            assert!(text.starts_with("error:"), "{text:?}");
            assert!(text.contains("Usage:") || text.contains("For more information"), "{text:?}");
        }
        let e = strict().try_get_matches_from(["t", "--req", "a", "--zzz"]).expect_err("error");
        assert_eq!(
            render_clap_error(&e),
            "error: unexpected argument '--zzz' found\n\nUsage: t --req <req>\n\nFor more information, try '--help'.\n"
        );
    }

    #[test]
    fn help_keeps_its_own_newlines() {
        let e = cmd().try_get_matches_from(["t", "--help"]).expect_err("help");
        assert!(render_clap_error(&e).lines().count() > 1);
        assert_eq!(e.exit_code(), 0);
    }
}
