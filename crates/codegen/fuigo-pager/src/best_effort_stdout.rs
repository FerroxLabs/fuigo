//! Stdout for the CLI subcommands: re-exports [`fuigo_tty_utils::best_effort_stdout`] and pins
//! that every CLI print site in this crate and the composition-root binary goes through it.
//!
//! `println!` panics when stdout's reader is gone and `panic = "abort"` makes that a SIGABRT;
//! the shipped 1.0.19 crash reports are `fuigo models`' first `println!`. The macros are
//! `fuigo_tty_utils::cli_println!` / `fuigo_tty_utils::cli_print!`; see the module docs there
//! for the policy (gone reader dropped, hard failures reported and turned into a non-zero exit).

pub use fuigo_tty_utils::best_effort_stdout::*;

#[cfg(test)]
mod tests {
    /// Source pin: every CLI subcommand prints through the best-effort macros. A raw
    /// `println!`/`print!` (qualified or not) in these files is the exact shape that aborted
    /// the shipped binary. Files in sibling crates are pinned when the layout ships them.
    #[test]
    fn cli_subcommands_do_not_use_raw_stdout_macros() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let own = [
            "src/models.rs",
            "src/plugin_cmd.rs",
            "src/mcp_cmd.rs",
            "src/sessions_cmd.rs",
            "src/memory_cmd.rs",
            "src/trace_cmd.rs",
            "src/worktree_cmd/mod.rs",
            "src/completions_cmd.rs",
            "src/app/session_startup.rs",
        ];
        // The composition-root binary dispatches the subcommands and prints too; the shell owns
        // the subscription CLI printers (`fuigo login --provider … --status`, `fuigo models
        // --provider …`). A layout that does not ship a sibling (packaged sources) skips it.
        let siblings = [
            "../fuigo-pager-bin/src/main.rs",
            "../fuigo-shell/src/auth/subscription/mod.rs",
            "../fuigo-shell/src/auth/subscription/inference.rs",
            "../fuigo-shell/src/mcp_doctor.rs",
        ];
        let mut offenders = Vec::new();
        for rel in own {
            let path = root.join(rel);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            offenders.extend(raw_stdout_macro_lines(&text).map(|(n, l)| format!("{rel}:{n}: {l}")));
        }
        for rel in siblings {
            if let Ok(text) = std::fs::read_to_string(root.join(rel)) {
                offenders
                    .extend(raw_stdout_macro_lines(&text).map(|(n, l)| format!("{rel}:{n}: {l}")));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw println!/print! in CLI code panics when stdout's reader is gone (SIGABRT under \
             panic=abort); use fuigo_tty_utils::cli_println!/cli_print!:\n{}",
            offenders.join("\n")
        );
    }

    /// Lines invoking `println!(` / `print!(` directly: bare or path-qualified (`std::println!`),
    /// but not `eprintln!`/`eprint!`, not the `cli_` macros, not comments.
    fn raw_stdout_macro_lines(text: &str) -> impl Iterator<Item = (usize, String)> + '_ {
        text.lines().enumerate().filter_map(|(i, line)| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                return None;
            }
            let hit = ["println!(", "print!("].iter().any(|needle| {
                line.match_indices(needle).any(|(at, _)| {
                    // The identifier (or path) the macro name belongs to.
                    let head = &line[..at];
                    let ident_start = head
                        .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                        .map_or(0, |p| p + 1);
                    let token = &line[ident_start..at + needle.len()];
                    let name = token.rsplit("::").next().unwrap_or(token);
                    name == *needle
                })
            });
            hit.then(|| (i + 1, trimmed.to_owned()))
        })
    }

    #[test]
    fn raw_stdout_macro_scan_distinguishes_the_shapes() {
        let text = "println!(\"x\");\neprintln!(\"y\");\nfuigo_tty_utils::cli_println!(\"z\");\n// println!(\"c\")\n  print!(\"p\");\ncrate::cli_print!(\"q\");\nstd::println!(\"s\");\n    ::std::print!(\"t\");\nwriteln!(out, \"w\");\n";
        let hits: Vec<usize> = raw_stdout_macro_lines(text).map(|(n, _)| n).collect();
        assert_eq!(hits, vec![1, 5, 7, 8]);
    }
}
