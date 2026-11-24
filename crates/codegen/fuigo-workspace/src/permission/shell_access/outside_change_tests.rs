//! S1 (1.0.47, DS-04) guard: the extractor, the exemptions and the cost, against injected boundary roots.

use super::*;
use std::os::unix::fs::symlink;

/// `T/work` (the workspace), `T/fuigo` and `T/tmp` are the roots; `T/srv/data/app.db` and `T/home` are outside.
struct Fx {
    _t: tempfile::TempDir,
    t: PathBuf,
    work: PathBuf,
    dir: PathBuf,
    db: PathBuf,
    home: PathBuf,
    guard: OutsideGuard,
}

impl Fx {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let t = dunce::canonicalize(tmp.path()).unwrap();
        let (work, dir, home, fuigo) = (
            t.join("work"),
            t.join("srv/data"),
            t.join("home"),
            t.join("fuigo"),
        );
        for d in [
            &work,
            &dir,
            &home,
            &fuigo,
            &t.join("tmp"),
            &home.join(".claude"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let db = dir.join("app.db");
        std::fs::write(&db, b"precious").unwrap();
        let guard = OutsideGuard::default();
        guard.install_env(GuardEnv::with_roots(
            vec![work.clone(), fuigo.clone(), t.join("tmp")],
            Some(home.clone()),
            Some(fuigo),
        ));
        guard.set_rules_once(Vec::new());
        Self {
            _t: tmp,
            t,
            work,
            dir,
            db,
            home,
            guard,
        }
    }

    fn effects(&self, cmd: &str) -> Vec<S1Effect> {
        s1_effects(cmd, &self.work, Some(&self.home))
    }

    fn verdict(&self, cmd: &str) -> OutsideVerdict {
        self.guard.evaluate(&self.effects(cmd), true)
    }

    fn hits(&self, cmd: &str) -> bool {
        self.verdict(cmd).change.is_some()
    }

    fn sub(&self, cmd: &str) -> String {
        cmd.replace("{P}", &self.db.to_string_lossy())
            .replace("{D}", &self.dir.to_string_lossy())
            .replace("{W}", &self.work.to_string_lossy())
            .replace("{H}", &self.home.to_string_lossy())
            .replace("{T}", &self.t.to_string_lossy())
    }

    fn type_text(&self, text: &str) {
        self.guard.note_user_text(&self.sub(text), &self.work, None);
    }
}

fn assert_hits(fx: &Fx, cmds: &[&str]) {
    for cmd in cmds {
        let cmd = fx.sub(cmd);
        assert!(
            fx.hits(&cmd),
            "expected an S1 hit: {cmd}\neffects: {:?}",
            fx.effects(&cmd)
        );
    }
}

fn assert_clear(fx: &Fx, cmds: &[&str]) {
    for cmd in cmds {
        let cmd = fx.sub(cmd);
        assert!(
            !fx.hits(&cmd),
            "expected no S1 hit: {cmd}\neffects: {:?}",
            fx.effects(&cmd)
        );
    }
}

#[test]
fn ds04_and_the_destructive_forms_hit() {
    let fx = Fx::new();
    symlink(&fx.db, fx.work.join("db-link")).unwrap();
    symlink(&fx.dir, fx.work.join("dirlink")).unwrap();
    std::fs::write(fx.dir.join("f"), b"x").unwrap();
    std::fs::write(fx.work.join("f"), b"y").unwrap();
    assert_hits(
        &fx,
        &[
            "rm -f {P}",
            "rm -f \"{P}\"",
            "rm -f '{D}'/app.db",
            "rm -f {P} && printf 'x' > migrations/002_add_email.sql",
            "cd {D} && rm app.db",
            // Fable r3 H1 / Astra / Grok r2 #1: a same-line assignment in `cd`.
            "D={D}; cd \"$D\" && rm -f app.db",
            "cd {D} && F=app.db; rm -f \"$F\"",
            "D={D}; rm \"$D/app.db\"",
            "find {D} -delete",
            "find {D} -name '*.db' -exec rm {} +",
            "echo {P} | xargs rm",
            "printf '%s\\n' {P} | xargs rm",
            "mv {P} /dev/null",
            ": > {P}",
            "cp /dev/null {P}",
            "truncate -s0 {P}",
            "dd if=/dev/zero of={P}",
            "shred {W}/db-link",
            // Fable r3 H2: `cp` writes through an existing link.
            "cp /dev/null {W}/db-link",
            "cp {W}/f {W}/db-link",
            "mv {W}/f {W}/dirlink",
            "sed -i --follow-symlinks s/a/b/ {W}/db-link",
            "rm -rf {D}/*",
            "rm -rf {W}/dirlink/",
            "sh -c 'rm -f {P}'",
            "bash -c \"cd {D} && rm app.db\"",
            "ln -s {D} {W}/data2 && : > {W}/data2/app.db",
            "ln {P} {W}/hard && : > {W}/hard",
            "sudo rm -f {P}",
            "/bin/rm -f {P}",
            "command rm -f {P}",
            "env X=1 rm -f {P}",
            "timeout 5 rm -f {P}",
            "nohup rm -f {P}",
            "bash <<'EOF'\nrm -f {P}\nEOF",
            "for f in {P}; do rm -f \"$f\"; done",
            "cd {W} || cd {D}; rm -f app.db",
            "if cd {D}; then rm app.db; fi",
            "rsync -a --delete {W}/ {D}",
            "tee {P} < /dev/null",
            "perl -pi -e 's/a/b/' {P}",
        ],
    );
}

#[test]
fn normal_and_ci_commands_do_not_hit() {
    let fx = Fx::new();
    symlink(&fx.db, fx.work.join("db-link")).unwrap();
    for f in ["app.db", "stale", "f"] {
        std::fs::write(fx.work.join(f), b"w").unwrap();
    }
    std::fs::create_dir_all(fx.work.join("target")).unwrap();
    std::fs::create_dir_all(fx.t.join("fuigo/worktrees/a")).unwrap();
    std::fs::write(fx.t.join("tmp/x"), b"t").unwrap();
    std::fs::create_dir_all(fx.home.join("bin")).unwrap();
    std::fs::write(fx.home.join(".bashrc"), b"rc").unwrap();
    assert_clear(
        &fx,
        &[
            "rm -rf target/",
            "rm -rf target",
            "cargo clean",
            "rm -rf build && cargo test",
            "rm -rf {T}/tmp/x",
            "rm -rf {T}/fuigo/worktrees/a",
            "cat {P}",
            "ls {D}",
            "touch {H}/new-file",
            "mkdir -p {H}/x",
            "cp f {H}/bin/",
            "echo x >> {H}/.bashrc",
            "cd {D} && cd {W} && rm app.db",
            "find {D} -maxdepth 0 -exec rm -f {W}/stale \\;",
            "ln -sf {W}/f {W}/db-link",
            "rm {W}/db-link",
            "sed -i s/a/b/ {W}/db-link",
            "cat {D}/list | xargs rm",
            ". /opt/venv/bin/activate && pytest > \"$OUT\"",
            "rm -rf \"$BUILD/obj\"",
            "git ls-files | xargs rm",
            "echo hi 2>/dev/tty",
            "cd \"$DATA_DIR\" && rm app.db",
            "rm -f {T}/nowhere/app.db",
            "tar -xzf a.tgz -C {H}/tools",
        ],
    );
}

#[test]
fn typed_paths_exempt_only_what_they_still_hold() {
    let fx = Fx::new();
    fx.type_text("Please delete {P}.");
    assert_clear(&fx, &["rm -f {P}", "rm -f '{P}'"]);

    let fx = Fx::new();
    fx.type_text("clean out `{D}` please");
    assert_clear(&fx, &["rm -f {P}", "find {D} -delete"]);

    // Sean 11-21 (1): a typed path that crosses a link stays exempt (`data/old` with `data` a link outside).
    let fx = Fx::new();
    symlink(&fx.dir, fx.work.join("data")).unwrap();
    std::fs::write(fx.dir.join("old"), b"o").unwrap();
    fx.type_text("remove data/old");
    assert_clear(&fx, &["rm -f data/old", "rm -f {W}/data/old"]);

    // Grok r3 #2: `~` and `$HOME` expand as the shell does.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.home.join("Documents")).unwrap();
    std::fs::write(fx.home.join("Documents/notes.md"), b"n").unwrap();
    std::fs::write(fx.home.join("b.md"), b"n").unwrap();
    fx.type_text("rewrite ~/Documents/notes.md and $HOME/b.md");
    assert_clear(
        &fx,
        &[
            "rm -f ~/Documents/notes.md",
            ": > \"$HOME/b.md\"",
            "rm {H}/b.md",
        ],
    );

    // A quoted path with a space; the sibling with a longer name still hits (no fragment rule).
    let fx = Fx::new();
    std::fs::write(fx.dir.join("my file"), b"m").unwrap();
    std::fs::write(fx.dir.join("app.db backup"), b"b").unwrap();
    fx.type_text("drop \"{D}/my file\" and {P}");
    assert_clear(&fx, &["rm \"{D}/my file\""]);
    assert_hits(&fx, &["rm -f '{D}/app.db backup'"]);

    // Astra r2 N4: no word cap.
    let fx = Fx::new();
    fx.type_text(&format!("{} {{P}}", "word ".repeat(5000)));
    assert_clear(&fx, &["rm -f {P}"]);
}

#[test]
fn typed_paths_never_lend_authority_to_links_words_or_dotdot() {
    // Fable r3 H3: backticked plain words of the DS-04 prompt are not tokens, even with repo links named after them.
    let fx = Fx::new();
    for word in [
        "users",
        "email",
        "TEXT",
        "Add",
        "migration",
        "file",
        "README.md",
    ] {
        symlink(&fx.dir, fx.work.join(word)).unwrap();
    }
    fx.type_text(
        "Add a migration file migrations/002_add_email.sql that adds a nullable `email` TEXT column to the \
         `users` table. Follow migrations/README.md.",
    );
    assert_hits(
        &fx,
        &[
            "rm -f users/app.db",
            "rm -f email/app.db",
            "rm -f TEXT/app.db",
        ],
    );

    // Fable r3 H4 (a): a link planted under a typed folder; (b) `..` out of it.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.work.join("migrations")).unwrap();
    symlink(&fx.dir, fx.work.join("migrations/devdb")).unwrap();
    fx.type_text("look in migrations/");
    assert_hits(
        &fx,
        &[
            "rm -f migrations/devdb/app.db",
            "rm -f migrations/../../srv/data/app.db",
        ],
    );

    // Astra r3 N1: `..` after a link must not collapse onto a typed spelling.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.dir.join("sub")).unwrap();
    std::fs::write(fx.dir.join("notes.txt"), b"n").unwrap();
    symlink(fx.dir.join("sub"), fx.work.join("jump")).unwrap();
    fx.type_text("edit {W}/notes.txt");
    assert_hits(&fx, &["rm {W}/jump/../notes.txt"]);
}

#[test]
fn an_approval_is_remembered_by_resolved_path_for_the_session() {
    let fx = Fx::new();
    let first = fx.verdict(&fx.sub("rm -f {P}"));
    assert!(first.change.is_some());
    fx.guard.after_decision(&first, true);
    assert_clear(&fx, &["truncate -s0 {P}", ": > {P}"]);
    std::fs::write(fx.dir.join("other.db"), b"o").unwrap();
    assert_hits(&fx, &["rm -f {D}/other.db"]);

    // A workspace link to an outside directory asks once.
    let fx = Fx::new();
    let fast = fx.t.join("fast/build");
    std::fs::create_dir_all(&fast).unwrap();
    std::fs::write(fast.join("x"), b"x").unwrap();
    std::fs::write(fast.join("log"), b"l").unwrap();
    symlink(&fast, fx.work.join("build")).unwrap();
    let first = fx.verdict("rm -rf build/x");
    assert!(first.change.is_some());
    fx.guard.after_decision(&first, true);
    assert_clear(&fx, &["rm -rf build/x"]);
    // Fable M (Sean 11-21): only that exact path, not the rest of the linked directory.
    assert_hits(&fx, &[": > build/log"]);

    // A denied ask remembers nothing.
    let fx = Fx::new();
    let first = fx.verdict(&fx.sub("rm -f {P}"));
    fx.guard.after_decision(&first, false);
    assert_hits(&fx, &["rm -f {P}"]);
}

#[test]
fn agent_created_files_are_recorded_from_what_happened() {
    let fx = Fx::new();
    let notes = fx.home.join("Documents/notes.md");
    std::fs::create_dir_all(notes.parent().unwrap()).unwrap();
    // Created by an allowed command (the file did not exist when it was decided, and exists after).
    let create = fx.verdict(&fx.sub("printf 'n' > {H}/Documents/notes.md"));
    assert!(create.change.is_none());
    fx.guard.after_decision(&create, true);
    std::fs::write(&notes, b"n").unwrap();
    assert_clear(
        &fx,
        &[": > {H}/Documents/notes.md", "rm {H}/Documents/notes.md"],
    );

    // Grok r3 M5: replaced by a link to the database afterwards: still a hit.
    std::fs::remove_file(&notes).unwrap();
    symlink(&fx.db, &notes).unwrap();
    assert_hits(&fx, &[": > {H}/Documents/notes.md"]);

    // Fable r3 H9: a hard link is never recorded; an agent-made link to an outside dir covers only the link itself.
    let fx = Fx::new();
    std::fs::hard_link(&fx.db, fx.home.join("h")).unwrap();
    assert_hits(&fx, &[": > {H}/h"]);
    let fx = Fx::new();
    let v = fx.verdict(&fx.sub("ln -s {D} {H}/l"));
    fx.guard.after_decision(&v, true);
    symlink(&fx.dir, fx.home.join("l")).unwrap();
    assert_hits(&fx, &["rm -rf {H}/l/", "rm -f {H}/l/app.db"]);
}

#[test]
fn authority_files_count_on_any_write_and_by_identity() {
    // Rev3 §1, Fable r3 M6, Grok r3 H3: any write to a user-tier settings file, a creation included.
    let fx = Fx::new();
    assert_hits(
        &fx,
        &[
            "printf '{\"permissions\":{\"allow\":[\"Bash(rm -f {P})\"]}}' > ~/.claude/settings.json",
            "echo x >> {H}/.claude/settings.local.json",
            "touch {H}/.claude/settings.json",
        ],
    );
    // Astra r3 N2: a hard-link alias inside the workspace is the authority file itself.
    std::fs::write(fx.home.join(".claude/settings.json"), b"{}").unwrap();
    std::fs::hard_link(
        fx.home.join(".claude/settings.json"),
        fx.work.join("alias.json"),
    )
    .unwrap();
    assert!(
        GuardEnv::with_roots(vec![], Some(fx.home.clone()), None)
            .authority_identity(&fx.work.join("alias.json"))
    );
    assert_hits(&fx, &["ln {H}/.claude/settings.json {W}/alias2.json"]);
}

#[test]
fn pre_allow_rules_must_match_the_segment_and_spell_the_path() {
    let rule = |pattern: &str| PermissionRule {
        action: RuleAction::Allow,
        tool: ToolFilter::Bash,
        pattern: Some(pattern.to_owned()),
        pattern_mode: Default::default(),
    };
    let fx = Fx::new();
    let guard = OutsideGuard::default();
    guard.install_env(GuardEnv::with_roots(
        vec![fx.work.clone()],
        Some(fx.home.clone()),
        None,
    ));
    guard.set_rules_once(vec![
        rule(&fx.sub("rm -f {P}")),
        rule("rm *"),
        rule(&fx.sub("cat {D}/*")),
    ]);
    let hit = |cmd: &str| {
        guard
            .evaluate(&fx.effects(&fx.sub(cmd)), true)
            .change
            .is_some()
    };
    assert!(!hit("rm -f {P}"));
    std::fs::write(fx.dir.join("b.db"), b"b").unwrap();
    assert!(hit("rm -f {D}/b.db"), "a broad rule exempts nothing");
    assert!(
        hit("cat {D}/b.db && rm -f {D}/b.db"),
        "the rule must match the deleting segment"
    );
    // Rules are sealed at session start: later ones never exempt (Grok r3 H3).
    guard.set_rules_once(vec![rule(&fx.sub("rm -f {D}/b.db"))]);
    assert!(hit("rm -f {D}/b.db"));
}

#[test]
fn exec_dir_and_effect_semantics() {
    let fx = Fx::new();
    // `find -exec` fixed operands do not inherit START points; `{}` operands do.
    let e = fx.effects(&fx.sub("find {D} -exec rm -f {} \\;"));
    assert!(
        e.iter()
            .any(|e| e.path == fx.dir && e.kind == EffectKind::Remove)
    );
    // `ln -sf` replaces only the entry.
    let e = fx.effects(&fx.sub("ln -sf {W}/new {W}/db-link"));
    assert!(
        e.iter()
            .all(|e| e.fin == Final::Entry || e.kind == EffectKind::Alias)
    );
    // An unpinned cwd drops later relative effects but keeps absolute ones.
    let e = fx.effects(&fx.sub("cd \"$X\" && rm a && rm {P}"));
    assert_eq!(
        e.iter().map(|e| e.path.clone()).collect::<Vec<_>>(),
        vec![fx.db.clone()]
    );
}

/// The shared extractor and its consumers are untouched by S1: the same facts with and without S1 work (and a
/// populated exemption set) in between, over the CI and S1 corpus.
#[test]
fn differential_shared_extractor_is_unchanged_by_s1() {
    let fx = Fx::new();
    fx.type_text("{P} {D}");
    let v = fx.verdict(&fx.sub("rm -f {P}"));
    fx.guard.after_decision(&v, true);
    let corpus = [
        "rm -rf target",
        "cd /srv/data && rm app.db",
        "D=/srv/data; cd \"$D\" && rm -f app.db",
        "find . -delete",
        "echo a | xargs rm",
        ": > .claude/settings.json",
        "cp x ~/.fuigo/config.toml",
        "sh -c 'rm -f /etc/x'",
        "git ls-files | xargs rm",
        "ln -s /etc .fuigo && echo > .fuigo/x",
        "tar -xzf a.tgz -C ~/tools",
    ];
    for cmd in corpus {
        let tree = try_parse_shell(cmd).unwrap();
        let before = format!("{:?}", ShellWriteFacts::from_tree(tree.root_node(), cmd));
        let unresolved = ShellWriteFacts::from_tree(tree.root_node(), cmd).has_unresolved();
        let _ = fx.guard.evaluate(&fx.effects(cmd), true);
        let after = ShellWriteFacts::from_tree(tree.root_node(), cmd);
        assert_eq!(before, format!("{after:?}"), "{cmd}");
        assert_eq!(unresolved, after.has_unresolved(), "{cmd}");
    }
}

/// Rev3 §7: p99 added time per Bash request at most 1 ms over a 1,000-command corpus.
#[test]
fn perf_budget_p99_under_one_millisecond() {
    let fx = Fx::new();
    let base = [
        "cargo test -p fuigo-workspace --lib",
        "git status --porcelain",
        "rm -rf target/debug/incremental",
        "ls -la src",
        "cd crates && cargo build",
        "grep -rn foo src | head -20",
        "echo done > out.txt",
        "rm -f {P}",
        "find . -name '*.o' -delete",
        "python -m pytest -q > log.txt 2>&1",
        "mkdir -p build && cd build",
        "D=/x; cd \"$D\" && rm -f a",
        "cp a b && mv b c",
        "sed -i s/a/b/ file.txt",
        "npm ci && npm test",
    ];
    let mut times = Vec::with_capacity(1000);
    for i in 0..1000 {
        let cmd = format!("{} # {i}", fx.sub(base[i % base.len()]));
        let start = std::time::Instant::now();
        let v = fx
            .guard
            .evaluate(&s1_effects(&cmd, &fx.work, Some(&fx.home)), true);
        times.push(start.elapsed());
        std::hint::black_box(v);
    }
    times.sort();
    let p50 = times[times.len() / 2];
    let p99 = times[times.len() * 99 / 100];
    eprintln!(
        "S1 perf: p50={p50:?} p99={p99:?} max={:?}",
        times.last().unwrap()
    );
    assert!(p99 <= std::time::Duration::from_millis(1), "p99 {p99:?}");
}

/// Fable H1: commands inside `$(...)`, backticks, `<(...)` and `>(...)` are judged like any other; a script that does
/// not parse asks (fail safe).
#[test]
fn substitutions_are_walked_and_unparsable_scripts_ask() {
    let fx = Fx::new();
    assert_hits(
        &fx,
        &[
            "out=$(rm -f {P} 2>&1)",
            "echo \"$(rm -f {P})\"",
            "cat <(rm -f {P})",
            "echo `rm -f {P}`",
            "X=$(rm -f {P}) true",
            "local v=$(rm -f {P})",
            "tee >(rm -f {P}) < /dev/null",
            ": > \"$(rm -f {P}; echo /dev/null)\"",
            "for f in $(rm -f {P}); do :; done",
            "cat <<EOF\n$(rm -f {P})\nEOF",
            "if [ -n \"$(rm -f {P})\" ]; then :; fi",
        ],
    );
    let v = fx.verdict("echo \"unterminated");
    let change = v.change.expect("an unparsable script asks");
    assert!(change.unparsed && change.paths.is_empty());
    assert!(change.deny_text().contains("could not be parsed"));
    assert_clear(
        &fx,
        &[
            "out=$(ls {D})",
            "echo \"$(date)\" > {W}/stamp",
            "diff <(cat {P}) {W}/f",
        ],
    );
}

/// Fable H2: the created-file record is the resolved path, so a `..` across a link cannot forge an existing outside
/// file as agent-created.
#[test]
fn a_dotdot_across_a_link_cannot_forge_an_agent_created_file() {
    let fx = Fx::new();
    let far = fx.t.join("other/a/b/c");
    std::fs::create_dir_all(&far).unwrap();
    symlink(&far, fx.work.join("l")).unwrap();
    let step1 = fx.verdict(&fx.sub("echo x > {W}/l/../../srv/data/app.db"));
    assert!(step1.change.is_none(), "creating a new file never asks");
    fx.guard.after_decision(&step1, true);
    // What the kernel really created.
    std::fs::create_dir_all(fx.t.join("other/a/srv/data")).unwrap();
    std::fs::write(fx.t.join("other/a/srv/data/app.db"), b"x").unwrap();
    assert_hits(&fx, &["rm -f {P}"]);
    // The file it did create is the agent's, by the same spelling.
    assert_clear(&fx, &["rm -f {W}/l/../../srv/data/app.db"]);
}

/// Fable H3: only the authority files under `$FUIGO_HOME` count; sessions (a `/goal` plan), memory and the rest are
/// inside the workspace.
#[test]
fn fuigo_session_files_are_inside_and_only_authority_files_count() {
    let fx = Fx::new();
    let fuigo = fx.home.join(".fuigo");
    std::fs::create_dir_all(fuigo.join("sessions/ws/s1/goal")).unwrap();
    let guard = OutsideGuard::default();
    guard.install_env(GuardEnv::with_roots(
        vec![fx.work.clone(), fuigo.clone()],
        Some(fx.home.clone()),
        Some(fuigo.clone()),
    ));
    guard.set_rules_once(Vec::new());
    let edit = |path: PathBuf| {
        guard.evaluate(
            &[S1Effect {
                path,
                kind: EffectKind::Overwrite,
                fin: Final::Follow,
                segment: String::new(),
                links: Vec::new(),
                wide: false,
            }],
            false,
        )
    };
    let plan = fuigo.join("sessions/ws/s1/goal/plan.md");
    assert!(edit(plan.clone()).change.is_none(), "create the /goal plan");
    std::fs::write(&plan, b"# plan").unwrap();
    assert!(edit(plan).change.is_none(), "edit the /goal plan");
    assert!(edit(fuigo.join("memory/notes.md")).change.is_none());
    assert!(
        edit(fuigo.join("sessions/ws/s1/transcript.jsonl"))
            .change
            .is_none()
    );
    assert!(
        edit(fuigo.join("sessions/ws/permission.toml"))
            .change
            .is_some(),
        "a grant store"
    );
    assert!(edit(fx.home.join(".claude/settings.json")).change.is_some());
}

/// Fable M4: an approval covers its exact resolved path; a glob's parent, `$HOME` and a link outside the roots are
/// never remembered as a prefix.
#[test]
fn an_approval_never_widens_to_a_glob_parent_or_a_system_link() {
    let fx = Fx::new();
    std::fs::write(fx.home.join("a.tmp"), b"t").unwrap();
    let v = fx.verdict(&fx.sub("rm {H}/*.tmp"));
    assert!(v.change.is_some());
    fx.guard.after_decision(&v, true);
    assert_hits(&fx, &["rm -rf {H}", "rm -f {H}/a.tmp"]);

    let fx = Fx::new();
    std::fs::create_dir_all(fx.dir.join("cache")).unwrap();
    let v = fx.verdict(&fx.sub("rm -rf {D}/cache/*"));
    fx.guard.after_decision(&v, true);
    assert_hits(&fx, &["rm -rf {D}/cache", "rm -rf {D}"]);

    // A link that is not itself in a root (macOS `/etc -> /private/etc`) lends no directory approval.
    let fx = Fx::new();
    symlink(fx.t.join("srv"), fx.t.join("sys")).unwrap();
    std::fs::write(fx.dir.join("other.db"), b"o").unwrap();
    let v = fx.verdict(&fx.sub("rm -f {T}/sys/data/app.db"));
    assert!(v.change.is_some());
    fx.guard.after_decision(&v, true);
    assert_clear(&fx, &["rm -f {P}"]);
    assert_hits(&fx, &["rm -f {D}/other.db"]);

    // Grok H2: a workspace link to `/` or `$HOME` lends no directory approval.
    for (name, to) in [("root", PathBuf::from("/")), ("homelink", fx.home.clone())] {
        let fx = Fx::new();
        std::fs::write(fx.dir.join("other.db"), b"o").unwrap();
        std::fs::write(fx.home.join("h.txt"), b"h").unwrap();
        let to = if name == "root" { to } else { fx.home.clone() };
        symlink(&to, fx.work.join(name)).unwrap();
        let through = if name == "root" {
            format!("rm -f {}/{name}{}", fx.work.display(), fx.db.display())
        } else {
            format!("rm -f {}/{name}/h.txt", fx.work.display())
        };
        let v = fx.verdict(&through);
        assert!(v.change.is_some(), "{through}");
        fx.guard.after_decision(&v, true);
        assert_hits(
            &fx,
            &["rm -f {D}/other.db", "printf x > {H}/.claude/settings.json"],
        );
    }
    // Grok M3: an absolute `ln -s` is applied after a cwd alternative too.
    let fx = Fx::new();
    assert_hits(
        &fx,
        &["cd {W} || cd {T}; ln -s {D} {W}/l2 && : > {W}/l2/app.db"],
    );
    // Grok M4: a typed directory that resolves to `$HOME` covers only itself.
    let fx = Fx::new();
    symlink(&fx.home, fx.work.join("hl")).unwrap();
    std::fs::write(fx.home.join("keep.txt"), b"k").unwrap();
    fx.type_text("look in {W}/hl/ please");
    assert_hits(&fx, &["rm -f {W}/hl/keep.txt"]);
}

/// Astra H1-H7 and Fable M8: fail-open paths found in the code review.
#[test]
fn code_review_fail_open_paths_hit() {
    let fx = Fx::new();
    symlink(&fx.db, fx.work.join("db-link")).unwrap();
    std::fs::create_dir_all(fx.work.join("w")).unwrap();
    let long = "x".repeat(300);
    assert_hits(
        &fx,
        &[
            // Grok H1: a prefix assignment.
            "D={D} rm -f \"$D/app.db\"",
            "D={D} cd \"$D\" && rm -f app.db",
            // H2: `ln -s` without `-f` fails on an existing name and leaves the old link in place.
            "ln -s {T}/nonexistent {W}/db-link; : > {W}/db-link",
            // H3: the directory stack, and branches each from the same entry state.
            "cd {D}; pushd {W}; popd; rm -f app.db",
            "cd {D}; pushd {W} && popd && rm -f app.db",
            "cd {D}; if false; then cd {W}; else rm -f app.db; fi",
            "cd {D}; case x in a) cd {W};; *) rm -f app.db;; esac",
            // H4: `-execdir` runs in the match's directory.
            "find {D} -maxdepth 0 -execdir rm -f data/app.db \\;",
            "find {D} -name '*.log' -execdir rm -f stale \\;",
            // H5: only NotFound is absent (here ENAMETOOLONG on the final component).
            &format!("rm -f {{D}}/{long}"),
        ],
    );
    assert_clear(
        &fx,
        &[
            "cd {D}; pushd {W}; rm -f f",
            "cd {D}; if true; then cd {W}; fi; cd {W} && rm -f f",
            "find {W} -maxdepth 0 -execdir rm -f w/x \\;",
        ],
    );

    // H6: a quoted path's space-separated pieces are not typed paths of their own.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.dir.join("report")).unwrap();
    std::fs::write(fx.dir.join("report/app.db"), b"r").unwrap();
    std::fs::write(fx.dir.join("report final.txt"), b"f").unwrap();
    fx.type_text("edit \"{D}/report final.txt\" and don't touch the rest");
    assert_clear(&fx, &["rm -f \"{D}/report final.txt\""]);
    assert_hits(&fx, &["rm -f {D}/report/app.db"]);

    // H7: the exact spelling with a link-sensitive `..` the user typed is exempt.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.dir.join("sub")).unwrap();
    std::fs::write(fx.dir.join("notes.txt"), b"n").unwrap();
    symlink(fx.dir.join("sub"), fx.work.join("jump")).unwrap();
    fx.type_text("remove {W}/jump/../notes.txt");
    assert_clear(&fx, &["rm {W}/jump/../notes.txt"]);

    // Fable M8: `mkdir` and `touch` record what the agent made.
    let fx = Fx::new();
    let v = fx.verdict(&fx.sub("mkdir -p {H}/scratch-x && touch {H}/scratch-y"));
    assert!(v.change.is_none());
    fx.guard.after_decision(&v, true);
    std::fs::create_dir_all(fx.home.join("scratch-x")).unwrap();
    std::fs::write(fx.home.join("scratch-y"), b"").unwrap();
    assert_clear(&fx, &["rm -rf {H}/scratch-x", "rm -f {H}/scratch-y"]);
}

/// The capped-review fixes (Grok H1/H2/M3, Astra H1/H5/H7, Fable M): each was silent before.
#[test]
fn capped_review_fail_open_paths_hit() {
    let fx = Fx::new();
    std::fs::write(fx.work.join("l"), b"old").unwrap();
    let long = "x".repeat(300);
    assert_hits(
        &fx,
        &[
            // Grok H2: a wrapper that moves the cwd or hides the command.
            "env -C {D} rm -f app.db",
            "env --chdir={D} rm -f app.db",
            "sudo -D {D} rm -f app.db",
            "flock -c 'rm -f {P}'",
            "env -S 'rm -f {P}'",
            "sudo -i rm -f app.db",
            // Grok H1: `cp -l` makes a hard link like `ln`.
            "cp -l {P} h && : > h",
            "cp --link {P} h2 && : > h2",
            // Astra H1: a `cd` that fails leaves the old cwd.
            "set +e; cd {D}; cd /work/missing; rm -f app.db",
            "cd {D}; cd {T}/nowhere; rm -f app.db",
            // Fable limit A: the same inside `if`/`elif`/`else`/`case` bodies.
            "if true; then cd {D}; cd /work/missing; rm -f app.db; fi",
            "if false; then :; elif true; then cd {D}; cd /work/missing; rm -f app.db; fi",
            "if false; then :; else cd {D}; cd /work/missing; rm -f app.db; fi",
            "case x in x) cd {D}; cd /work/missing; rm -f app.db;; esac",
            // Astra H7: an unreadable ancestor proves nothing about where the target is.
            &format!("rm -f {{W}}/{long}/x"),
            // Fable M: a name removed earlier on the line can be linked again.
            "rm -f {W}/l && ln -s {D} {W}/l && : > {W}/l/app.db",
        ],
    );
    assert_clear(
        &fx,
        &[
            "env -C {W} rm -f l",
            "cd {D} && cd {W} && rm -f app.db",
            "cp -l {W}/l {W}/l3 && : > {W}/l3",
        ],
    );

    // Grok M3: nested shells deeper than the guard follows ask; shallower ones are judged.
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let nest = |n: usize| (0..n).fold("echo hi".to_owned(), |s, _| format!("sh -c {}", quote(&s)));
    assert!(!fx.hits(&nest(3)), "{}", nest(3));
    assert!(fx.hits(&nest(6)), "{}", nest(6));

    // Astra H5: a symlinked `$FUIGO_HOME` written through its physical path is still an authority file.
    let physical = fx.t.join("fuigo-physical");
    std::fs::create_dir_all(&physical).unwrap();
    std::fs::write(physical.join("config.toml"), b"c").unwrap();
    let fuigo = fx.home.join(".fuigo");
    symlink(&physical, &fuigo).unwrap();
    let guard = OutsideGuard::default();
    guard.install_env(GuardEnv::with_roots(
        vec![fx.work.clone(), fuigo.clone()],
        Some(fx.home.clone()),
        Some(fuigo.clone()),
    ));
    guard.set_rules_once(Vec::new());
    for cmd in [
        format!(": > {}/config.toml", physical.display()),
        format!(": > {}/config.toml", fuigo.display()),
    ] {
        let effects = s1_effects(&cmd, &fx.work, Some(&fx.home));
        assert!(guard.evaluate(&effects, true).change.is_some(), "{cmd}");
    }
    let notes = format!(": > {}/notes.md", physical.display());
    let effects = s1_effects(&notes, &fx.work, Some(&fx.home));
    assert!(guard.evaluate(&effects, true).change.is_none(), "{notes}");
}

/// Friction probe: `S1_CORPUS=<json [{src,kind,cmd}]> cargo test ... friction_probe -- --ignored --nocapture` counts
/// the corpus commands that do not parse and those that would ask.
#[test]
#[ignore]
fn friction_probe() {
    let fx = Fx::new();
    let path = std::env::var("S1_CORPUS").expect("S1_CORPUS");
    let corpus: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut unparsed, mut hits) = (0, 0);
    for entry in &corpus {
        let cmd = entry["cmd"].as_str().unwrap();
        let effects = fx.effects(cmd);
        let u = effects.iter().any(|e| e.kind == EffectKind::Unparsed);
        let h = fx.guard.evaluate(&effects, true).change.is_some();
        unparsed += usize::from(u);
        hits += usize::from(h);
        if u || h {
            eprintln!(
                "PROBE {} {} unparsed={u} hit={h}",
                entry["kind"], entry["src"]
            );
        }
        if u && let Some(tree) = try_parse_shell(cmd) {
            let mut stack = vec![tree.root_node()];
            while let Some(n) = stack.pop() {
                if n.is_error() || n.is_missing() {
                    let line = cmd.lines().nth(n.start_position().row).unwrap_or("");
                    eprintln!("  ERR at {}: {line}", n.start_position().row);
                    break;
                }
                let mut c = n.walk();
                let kids: Vec<_> = n.children(&mut c).collect();
                stack.extend(kids.into_iter().rev());
            }
        }
    }
    eprintln!(
        "PROBE TOTAL n={} unparsed={unparsed} hits={hits}",
        corpus.len()
    );
}

/// Friction: the unparsable-asks rule must not fire on ordinary valid shell (heredocs, arrays, `[[ ]]`, case,
/// functions, arithmetic, process substitution, brace expansion).
#[test]
fn ordinary_shell_idioms_parse_and_do_not_ask() {
    let fx = Fx::new();
    assert_clear(
        &fx,
        &[
            "cat <<EOF > out.txt\nhello $USER\nEOF",
            "cat <<'EOF'\nraw $x\nEOF",
            "arr=(a b c); for x in \"${arr[@]}\"; do echo \"$x\"; done",
            "if [[ -f Cargo.toml && $x == foo* ]]; then echo yes; fi",
            "case \"$1\" in a|b) echo ab;; *) echo other;; esac",
            "f() { local a=$1; echo \"$a\"; }; f x",
            "echo $((1 + 2 * 3)); (( i++ ))",
            "diff <(sort a) <(sort b)",
            "while read -r line; do echo \"$line\"; done < file.txt",
            "set -euo pipefail; trap 'echo done' EXIT",
            "declare -A m=([a]=1 [b]=2); echo ${m[a]} ${var:-d} ${var%%.*} ${#var}",
            "python3 - <<'PY'\nimport sys\nprint(sys.argv)\nPY",
            "for i in {1..5}; do echo $i; done; echo {a,b}{c,d}",
            "cd src && { make; make install; } > build.log 2>&1",
            "mapfile -t lines < <(git ls-files)",
            "git commit -m \"$(cat <<'EOF'\nmsg\n\nbody\nEOF\n)\"",
            "exec 3>&1; ls >&3",
            "nohup ./server > /dev/null 2>&1 &",
            "shopt -s globstar; ls **/*.rs",
            "docker run --rm -v \"$PWD\":/w -w /w img sh -c 'make test'",
        ],
    );
}
