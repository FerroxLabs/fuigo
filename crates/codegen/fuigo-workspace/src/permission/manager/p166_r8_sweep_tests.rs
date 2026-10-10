//! P166 round 8A: generated spellings. For EVERY program of the r7 writer table each unquoted-`{P}` template is also
//! run with the protected path ANSI-C quoted, brace-expanded and reached through `env -C`; every interpreter also
//! gets an assignment-plus-use case, an ANSI-C script, a here-string and a here-document; every program with
//! value-taking options gets a separate-value case. Each generated case must hit the protected floor.

use super::p166_r7_sweep_tests::{PROTECTED_PATHS, WRITERS};
use super::{PermissionState, bash_protected_write_target, evaluate_bash};

pub(super) fn floor(cwd: &std::path::Path, cmd: &str) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    let state = PermissionState::default();
    let evaluation = evaluate_bash(cmd, &state, true);
    bash_protected_write_target(&evaluation, cwd, None)
}

/// Whether the first `{P}` of `template` sits outside every quote and outside a redirect/pipe (so a spelling swap
/// would still be a shell word).
pub(super) fn plain_slot(template: &str) -> bool {
    let Some(at) = template.find("{P}") else { return false };
    let (mut single, mut double) = (false, false);
    for c in template[..at].chars() {
        match c {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            _ => {}
        }
    }
    !single && !double && !template.contains(['|', '<', '>'])
}

fn ansi(path: &str) -> String {
    format!("$'{path}'")
}

/// The same brace word with the protected alternative last (the shell makes it the last of two words: a destination
/// operand; with the protected alternative first it is an option value).
fn brace_last(path: &str) -> String {
    match path {
        ".mcp.json" => "{zz,.mcp}.json".to_owned(),
        _ => "{zz,.git}/hooks/pre-commit".to_owned(),
    }
}

/// A brace spelling writes the protected file when either order of the alternatives does (an option value in the
/// first, a destination operand in the last).
fn floor_either(cwd: &std::path::Path, template: &str, path: &str) -> bool {
    floor(cwd, &template.replace("{P}", &brace(path))).is_some() || floor(cwd, &template.replace("{P}", &brace_last(path))).is_some()
}

fn brace(path: &str) -> String {
    match path {
        ".mcp.json" => "{.mcp,zz}.json".to_owned(),
        _ => "{.git,zz}/hooks/pre-commit".to_owned(),
    }
}

/// Interpreters: `(program, command reading the path from env var V, script template with {P}, stdin reader)`.
const INTERPRETERS: &[(&str, &str, &str, &str)] = &[
    ("python3", "python3 -c 'import os; open(os.environ[\"V\"],\"w\")'", "python3 -c {S}", "open(\"{P}\",\"w\")"),
    ("python", "python -c 'import os; open(os.environ[\"V\"],\"w\")'", "python -c {S}", "open(\"{P}\",\"w\")"),
    ("node", "node -e \"require('fs').writeFileSync(process.env.V,'')\"", "node -e {S}", "require(\"fs\").writeFileSync(\"{P}\",\"\")"),
    ("perl", "perl -e 'open F, \">$ENV{V}\"'", "perl -e {S}", "open F, \">{P}\""),
    ("ruby", "ruby -e 'File.write(ENV[\"V\"],\"x\")'", "ruby -e {S}", "File.write(\"{P}\",\"x\")"),
    ("php", "php -r 'file_put_contents(getenv(\"V\"),\"\");'", "php -r {S}", "file_put_contents(\"{P}\",\"\");"),
    ("lua", "lua -e 'io.open(os.getenv(\"V\"),\"w\")'", "lua -e {S}", "io.open(\"{P}\",\"w\")"),
    ("deno", "deno eval 'Deno.writeTextFileSync(Deno.env.get(\"V\"),\"\")'", "deno eval {S}", "Deno.writeTextFileSync(\"{P}\",\"\")"),
];

/// Common value-taking options, protected path as the SEPARATE next word.
const SEPARATE_VALUE: &[(&str, &str)] = &[
    ("cp", "cp -t {P} a"), ("cp", "cp -S {P} a b"), ("rsync", "rsync -a --backup-dir {P} src/ dest/"),
    ("rsync", "rsync -a --partial-dir {P} src/ dest/"), ("rsync", "rsync -a -T {P} src/ dest/"),
    ("rsync", "rsync -a -e 'ssh -E {P}' src/ dest/"), ("scp", "scp -o 'UserKnownHostsFile={P}' host:x out/"),
    ("scp", "scp -S {P} host:x out/"), ("docker", "docker run -v {P}:/h alpine ls"),
    ("docker", "docker run --mount type=bind,source={P},target=/h alpine ls"),
    ("docker", "docker -H unix:///x cp c:/x {P}"), ("docker", "docker --context c cp c:/x {P}"),
    ("podman", "podman run --volume {P}:/h alpine ls"), ("podman", "podman -c c cp c:/x {P}"),
    ("kubectl", "kubectl --context c cp ns/pod:/x {P}"), ("install", "install -t {P} a"),
    ("ln", "ln -s -t {P} a"), ("tar", "tar -cf a.tar src --index-file {P}"), ("tar", "tar -xf a.tar -C {P}"),
    ("tar", "tar -cf {P} src"), ("zip", "zip -b {P} out.zip src"), ("unzip", "unzip a.zip -d {P}"),
    ("cpio", "cpio -o -O {P}"), ("pax", "pax -w -f {P} src"), ("curl", "curl --output-dir {P} -O https://x.invalid/f"),
    ("curl", "curl -o {P} https://x.invalid/f"), ("curl", "curl --cookie-jar {P} https://x.invalid/f"),
    ("wget", "wget https://x.invalid -P {P}"), ("wget", "wget https://x.invalid -O {P}"),
    ("wget", "wget -e dir_prefix={P} https://x.invalid"), ("patch", "patch -o {P} f p.diff"),
    ("patch", "patch -d {P} f p.diff"), ("less", "less -o {P} README"), ("less", "less -O {P} README"),
    ("less", "less --log-file {P} README"), ("tree", "tree -o {P}"), ("rg", "rg --pre {P} foo ."),
    ("sed", "sed -e 'w {P}' in"), ("awk", "awk -v out={P} 'BEGIN{system(\"touch \" out)}'"),
];

fn setup() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("out")).unwrap();
    std::fs::create_dir_all(project.path().join("src")).unwrap();
    project
}

fn report(cases: usize, wrong: Vec<String>) {
    eprintln!("SWEEP {} cases={cases} wrong={}", std::thread::current().name().unwrap_or("?"), wrong.len());
    assert!(wrong.is_empty(), "{} of {cases} generated cases wrong:\n{}", wrong.len(), wrong.join("\n"));
}

/// Every plain-slot writer template, three more spellings of the protected path.
#[cfg(unix)]
#[test]
fn p166_r8_sweep_spellings_of_every_writer() {
    let project = setup();
    let cwd = project.path();
    let (mut cases, mut wrong) = (0usize, Vec::new());
    for (program, templates) in WRITERS {
        for template in templates.iter().filter(|t| plain_slot(t)) {
            for path in PROTECTED_PATHS {
                let relative = if *path == ".mcp.json" { ("src", "../.mcp.json") } else { (".git/hooks", "pre-commit") };
                let variants = [
                    ("ansi", template.replace("{P}", &ansi(path))),
                    ("brace", template.replace("{P}", &brace(path))),
                    ("env -C", format!("env -C {} {}", relative.0, template.replace("{P}", relative.1))),
                ];
                for (kind, cmd) in variants {
                    cases += 1;
                    let fires = if kind == "brace" { floor_either(cwd, template, path) } else { floor(cwd, &cmd).is_some() };
                    if !fires {
                        wrong.push(format!("[{program}/{kind}] {cmd}"));
                    }
                }
            }
        }
    }
    report(cases, wrong);
}

/// P166 r11: every plain-slot writer template with the protected path spelled `$PWD/<path>` (the tracked working
/// directory), and every scp/rsync destination row with a zone-id host and a URI host.
#[cfg(unix)]
#[test]
fn p166_r11_sweep_pwd_zone_and_uri_spellings() {
    let project = setup();
    let cwd = project.path();
    let (mut cases, mut wrong) = (0usize, Vec::new());
    for (program, templates) in WRITERS {
        for template in templates.iter().filter(|t| plain_slot(t)) {
            for path in PROTECTED_PATHS {
                let mut variants = vec![("pwd", template.replace("{P}", &format!("$PWD/{path}")))];
                variants.push(("pwd-braced", template.replace("{P}", &format!("\"${{PWD}}/{path}\""))));
                if matches!(*program, "scp" | "rsync") && template.ends_with(" {P}") {
                    for host in ["[::1%1]:", "user@[::1%lo0]:", "[::1%251]:", "scp://localhost/", "sftp://127.0.0.1/", "rsync://localhost/"] {
                        variants.push(("host", template.replace("{P}", &format!("'{host}{path}'"))));
                    }
                }
                for (kind, cmd) in variants {
                    cases += 1;
                    if floor(cwd, &cmd).is_none() {
                        wrong.push(format!("[{program}/{kind}] {cmd}"));
                    }
                }
            }
        }
    }
    report(cases, wrong);
}

/// Interpreters: assignment (plain, `env`), ANSI-C script, here-string and here-document, `env -C`.
#[cfg(unix)]
#[test]
fn p166_r8_sweep_interpreters() {
    let project = setup();
    let cwd = project.path();
    let (mut cases, mut wrong) = (0usize, Vec::new());
    for (program, env_cmd, script_cmd, script) in INTERPRETERS {
        for path in PROTECTED_PATHS {
            let ansi_script = format!("$'{}'", script.replace("{P}", path));
            let relative = if *path == ".mcp.json" { ("src", "../.mcp.json") } else { (".git/hooks", "pre-commit") };
            let cmds = [
                format!("V={path} {env_cmd}"),
                format!("env V={path} {env_cmd}"),
                format!("V={} {env_cmd}", ansi(path)),
                format!("V={} {env_cmd}", brace(path)),
                script_cmd.replace("{S}", &ansi_script),
                format!("env -C {} {}", relative.0, script_cmd.replace("{S}", &format!("'{}'", script.replace("{P}", relative.1)))),
                format!("{program} x.py <<< {path}"),
                format!("{program} x.py <<EOF\n{path}\nEOF"),
                format!("{program} x.py <<'EOF'\n{path}\nEOF"),
            ];
            for cmd in cmds {
                cases += 1;
                let brace_cmd = cmd.contains("{.mcp,zz}") || cmd.contains("{.git,zz}");
                let fires = if brace_cmd { floor_either(cwd, &cmd.replace(&brace(path), "{P}"), path) } else { floor(cwd, &cmd).is_some() };
                if !fires {
                    wrong.push(format!("[{program}] {cmd}"));
                }
            }
        }
    }
    report(cases, wrong);
}

/// Common value-taking options with the path as a separate word, in plain, ANSI-C and brace spelling.
#[cfg(unix)]
#[test]
fn p166_r8_sweep_separate_option_values() {
    let project = setup();
    let cwd = project.path();
    let (mut cases, mut wrong) = (0usize, Vec::new());
    for (program, template) in SEPARATE_VALUE {
        for path in PROTECTED_PATHS {
            for spelling in [path.to_string(), ansi(path), brace(path)] {
                if spelling != *path && !plain_slot(template) {
                    continue;
                }
                let cmd = template.replace("{P}", &spelling);
                cases += 1;
                let fires = if spelling == brace(path) { floor_either(cwd, template, path) } else { floor(cwd, &cmd).is_some() };
                if !fires {
                    wrong.push(format!("[{program}] {cmd}"));
                }
            }
        }
    }
    report(cases, wrong);
}
