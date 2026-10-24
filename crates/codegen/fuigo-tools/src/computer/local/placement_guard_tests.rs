//! P189 guard: a spawn site added later must not silently escape the session
//! cgroup. Source-level (grep style) like the symbol tests of packet A1.

fn production(src: &str) -> &str {
    let cut = src.find("\n#[cfg(test)]\nmod tests").unwrap_or(src.len());
    &src[..cut]
}

/// Every raw `.spawn()` in production code must carry a `P189-unplaced:` reason
/// within the 8 lines above it; placed sites use `spawn_placed` instead.
fn assert_no_unmarked_raw_spawn(name: &str, src: &str) {
    let lines: Vec<&str> = production(src).lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let code = l.split("//").next().unwrap_or("");
        if !code.contains(".spawn()") {
            continue;
        }
        let from = i.saturating_sub(8);
        assert!(
            lines[from..i].iter().any(|p| p.contains("P189-unplaced:")),
            "{name}:{}: raw `.spawn()` without `P189-unplaced: <reason>`; session tool processes \
             must go through ProcessScope::spawn_placed (placement first)",
            i + 1
        );
    }
}

/// Every production `Command::new(` / `std::process::Command` in the scanned
/// directories must be on a `spawn_placed(` line, or carry `P189-placed:` or
/// `P189-unplaced: <reason>` on the same line or within the 8 lines above.
fn assert_no_unmarked_command(name: &str, src: &str) {
    let lines: Vec<&str> = production(src).lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let code = l.split("//").next().unwrap_or("");
        if !(code.contains("Command::new(") || code.contains("std::process::Command")) {
            continue;
        }
        let from = i.saturating_sub(8);
        let marked = |p: &&str| p.contains("P189-unplaced:") || p.contains("P189-placed:") || p.contains("spawn_placed(");
        assert!(
            lines[from..=i].iter().any(marked),
            "{name}:{}: `Command::new(`/`std::process::Command` without placement (`spawn_placed`) or \
             `P189-unplaced: <reason>`",
            i + 1
        );
    }
}

/// The body of `fn <name>(` up to the next function at the same nesting.
fn body<'a>(src: &'a str, sig: &str) -> &'a str {
    let start = src.find(sig).unwrap_or_else(|| panic!("missing `{sig}`"));
    let rest = &src[start + sig.len()..];
    let end = ["\n    async fn ", "\n    fn ", "\n    pub async fn ", "\nfn ", "\npub fn ", "\nasync fn "]
        .iter()
        .filter_map(|m| rest.find(m))
        .min()
        .unwrap_or(rest.len());
    &rest[..end]
}

/// `spawn_placed` is used with a bare-`Command` constructor, and the site holds
/// no placement call of its own: the entry registers the placement right after
/// `new_command` returns, before `configure` (and so before any other
/// `pre_exec`), whatever the caller writes.
fn assert_placed_first(what: &str, text: &str) {
    assert!(text.contains("spawn_placed("), "{what}: not spawned through spawn_placed");
    assert!(!text.contains("hook.place(") && !text.contains(".place(&mut"), "{what}: caller-side placement");
}

#[test]
fn terminal_backend_has_no_unmarked_raw_spawn() {
    assert_no_unmarked_raw_spawn("terminal.rs", include_str!("terminal.rs"));
    assert_no_unmarked_raw_spawn("shell_state.rs", include_str!("shell_state.rs"));
    assert_no_unmarked_raw_spawn("static_shell.rs", include_str!("static_shell.rs"));
}

#[test]
fn terminal_backend_and_hooks_have_no_unmarked_command_new() {
    for (name, src) in [
        ("terminal.rs", include_str!("terminal.rs")),
        ("shell_state.rs", include_str!("shell_state.rs")),
        ("static_shell.rs", include_str!("static_shell.rs")),
        ("embedded_search_tools.rs", include_str!("embedded_search_tools.rs")),
        ("lifecycle.rs", include_str!("lifecycle.rs")),
        ("file_system.rs", include_str!("file_system.rs")),
        ("cgroup.rs", include_str!("cgroup.rs")),
        ("mod.rs", include_str!("mod.rs")),
        ("hooks/runner/command.rs", include_str!("../../../../fuigo-hooks/src/runner/command.rs")),
        ("hooks/runner/http.rs", include_str!("../../../../fuigo-hooks/src/runner/http.rs")),
        ("hooks/runner/mod.rs", include_str!("../../../../fuigo-hooks/src/runner/mod.rs")),
    ] {
        assert_no_unmarked_command(name, src);
    }
}

#[test]
fn command_guard_detects_an_unmarked_command() {
    let bad = std::panic::catch_unwind(|| {
        assert_no_unmarked_command("x.rs", "fn f() {\n    let c = tokio::process::Command::new(\"x\");\n}\n");
    });
    assert!(bad.is_err());
    assert_no_unmarked_command("x.rs", "fn f() {\n    // P189-unplaced: helper\n    let c = std::process::Command::new(\"x\");\n}\n");
}

#[test]
fn placed_sites_place_first() {
    let t = include_str!("terminal.rs");
    assert_placed_first("spawn_static_command", body(t, "fn spawn_static_command("));
    assert_placed_first("spawn_persistent_command", body(t, "fn spawn_persistent_command("));
    assert_placed_first("spawn_shell_command", body(t, "fn spawn_shell_command("));
    assert_placed_first("ShellState::init", body(include_str!("shell_state.rs"), "pub async fn init("));
}

#[test]
fn guard_detects_a_raw_spawn() {
    let bad = std::panic::catch_unwind(|| {
        assert_no_unmarked_raw_spawn("x.rs", "fn f() {\n    let c = cmd.spawn();\n}\n");
    });
    assert!(bad.is_err(), "the guard must reject an unmarked raw spawn");
    assert_no_unmarked_raw_spawn(
        "x.rs",
        "fn f() {\n    // P189-unplaced: helper\n    let c = cmd.spawn();\n}\n",
    );
}

/// Item 8: the `new_command` argument of every `spawn_placed` site is a single
/// bare `Command::new(..)` expression, so a caller cannot register a `pre_exec`
/// before the entry registers the placement. Mechanism: this guard (the entry
/// takes a closure, so it cannot build the `Command` itself).
fn new_command_lines(src: &str) -> Vec<String> {
    production(src)
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| {
            l.contains("|| tokio::process::Command::new(")
                || l.contains("let new_command = ||")
                || l.contains("|| parts.new_command()")
        })
        .map(str::to_string)
        .collect()
}

fn assert_bare_new_command(line: &str) {
    // A site that rebuilds the command the sandbox hook rewrote constructs it from the captured
    // parts: `CommandParts::new_command` must itself be exactly one bare `Command::new(..)`.
    if line.contains("|| parts.new_command()") {
        let launch = include_str!("../../sandbox_launch.rs");
        let sig = "pub fn new_command(&self) -> tokio::process::Command {";
        let start = launch.find(sig).expect("CommandParts::new_command") + sig.len();
        let end = start + launch[start..].find("\n    }").expect("end of new_command");
        let body = launch[start..end].trim();
        assert_eq!(
            "tokio::process::Command::new(&self.program)", body,
            "CommandParts::new_command is not a bare Command::new"
        );
        return;
    }
    let at = line.find("|| tokio::process::Command::new(").expect("closure start");
    let expr = &line[at + 3..];
    // balanced parens: the expression ends where `Command::new(` closes, followed only by `,`/`;`/` ,`
    let open = expr.find('(').unwrap();
    let mut depth = 0i32;
    let mut end = None;
    for (i, c) in expr[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open + i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.expect("unbalanced");
    assert!(!expr[..end].contains("pre_exec") && !expr[..end].contains('{'), "new_command is not a bare Command::new: {line}");
    let tail = expr[end..].trim_start();
    assert!(tail.starts_with(',') || tail.starts_with(';') || tail.is_empty(), "extra code after Command::new(..): {line}");
}

#[test]
fn new_command_closures_are_bare_command_new() {
    let mut n = 0;
    for src in [
        include_str!("terminal.rs"),
        include_str!("shell_state.rs"),
        include_str!("../../../../fuigo-hooks/src/runner/command.rs"),
    ] {
        for l in new_command_lines(src) {
            assert_bare_new_command(&l);
            n += 1;
        }
    }
    assert_eq!(n, 5, "the five spawn_placed sites; a new one needs this guard updated");
    let bad = std::panic::catch_unwind(|| assert_bare_new_command("x(|| tokio::process::Command::new(p).pre_exec(f), c)"));
    assert!(bad.is_err());
}
