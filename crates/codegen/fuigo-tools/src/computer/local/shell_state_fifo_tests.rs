//! Audit L3, bash below 4: the state dump travels through a private FIFO, so no program the user command runs
//! inherits a descriptor to it. Bash 4+ and zsh keep the descriptor channel, byte for byte.
//!
//! The inheritance test needs a real bash 3.2: set `FUIGO_TEST_BASH32` to its path (it skips without, unless `FUIGO_REQUIRE_BASH32=1`, which makes it fail). The FIFO
//! mechanics run on any bash by forcing the FIFO channel (`prepare_command_for(.., Some(3))`).

#![allow(
    clippy::disallowed_methods,
    reason = "test code: spawns and reaps its own shell children"
)]

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use command_fds::CommandFdExt;

use super::*;
use crate::computer::local::SearchShadowConfig;

fn system_bash() -> Option<&'static str> {
    let path = ShellKind::Bash.binary_path();
    Path::new(path).exists().then_some(path)
}

/// The bash 3.2 under test, from `FUIGO_TEST_BASH32`. Without one the tests that need it skip (public CI), unless
/// `FUIGO_REQUIRE_BASH32=1` is set (the release gate sets it): then a missing bash 3.2 FAILS, so the bash < 4 FIFO
/// path cannot ship untested on a green suite.
fn bash32() -> Option<String> {
    let found = std::env::var("FUIGO_TEST_BASH32")
        .ok()
        .filter(|p| Path::new(p).exists());
    assert!(
        found.is_some() || !bash32_required(),
        "FUIGO_REQUIRE_BASH32=1 but FUIGO_TEST_BASH32 does not name an existing bash 3.2"
    );
    found
}

fn bash32_required() -> bool {
    std::env::var("FUIGO_REQUIRE_BASH32").is_ok_and(|v| v == "1")
}

fn empty_state(shell: ShellKind) -> ShellState {
    ShellState {
        cwd: std::env::current_dir().unwrap(),
        snapshot: String::new(),
        shell,
        trust: Default::default(),
    }
}

/// `dev:inode` of an open descriptor, the form `stat -L -c %d:%i` prints for `/proc/<pid>/fd/N`.
fn dev_ino(fd: RawFd) -> String {
    // SAFETY: `st` is a plain-data out parameter and `fd` is open for the call.
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        assert_eq!(libc::fstat(fd, &mut st), 0);
        st
    };
    format!("{}:{}", st.st_dev, st.st_ino)
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    /// `dev:inode` of the parent's read end of the dump channel.
    channel_key: String,
    fifo: Option<PathBuf>,
    elapsed: Duration,
}

async fn run(state: &mut ShellState, command: &str, binary: &str, major: Option<u32>) -> Outcome {
    let started = Instant::now();
    let prep = state
        .prepare_command_for(command, None, SearchShadowConfig::default(), None, major)
        .unwrap();
    let channel_key = dev_ino(prep.state_out_read.as_raw_fd());
    let fifo = prep.state_out_read.fifo_path().map(Path::to_path_buf);
    let mut cmd = tokio::process::Command::new(binary);
    cmd.args(&prep.args)
        .current_dir(&prep.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.fd_mappings(prep.fd_mappings).unwrap();
    let child = cmd.spawn().unwrap();
    drop(cmd);
    let mut reader = prep.state_out_read;
    reader.watch_child(child.id());
    let snapshot = state.replay_script();
    let write = tokio::spawn(write_snapshot_to_pipe(snapshot, prep.state_in_write));
    let read = tokio::spawn(read_dump_from_pipe(reader));
    let output = child.wait_with_output().await.unwrap();
    write.await.unwrap().unwrap();
    let dump = read.await.unwrap().unwrap();
    state.update_from_dump(&dump);
    Outcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        channel_key,
        fifo,
        elapsed: started.elapsed(),
    }
}

fn assert_removed(fifo: &Path) {
    assert!(!fifo.exists(), "FIFO {} was left behind", fifo.display());
    let dir = fifo.parent().unwrap();
    assert!(!dir.exists(), "directory {} was left behind", dir.display());
}

/// No program the user command runs holds the dump channel: an external `sh` lists the `dev:inode` of every
/// descriptor it has, and none is the channel's. Fails on bash 3.2 with the pipe channel (the shell's saved copy of
/// the redirected descriptor sits on fd 10/11 in the program).
#[tokio::test]
async fn bash32_programs_do_not_inherit_the_dump_channel() {
    let Some(bash) = bash32() else { return };
    let major = probe_bash_major(&bash);
    assert_eq!(major, Some(3), "FUIGO_TEST_BASH32 must be a bash 3");
    let mut state = empty_state(ShellKind::Bash);
    let out = run(
        &mut state,
        "sh -c 'for f in /proc/$$/fd/*; do stat -L -c %d:%i \"$f\" 2>/dev/null; done'",
        &bash,
        major,
    )
    .await;
    let held: Vec<&str> = out.stdout.lines().map(str::trim).collect();
    assert!(held.len() >= 3, "the probe saw no descriptors: {held:?}");
    assert!(
        !held.contains(&out.channel_key.as_str()),
        "a program inherited the dump channel {}: {held:?}",
        out.channel_key
    );
}

/// The state still round-trips through the FIFO: cwd, an export and a function reach the next command.
#[tokio::test]
async fn fifo_channel_round_trips_state() {
    let mut targets: Vec<(String, Option<u32>)> = Vec::new();
    if let Some(bash) = system_bash() {
        targets.push((bash.to_owned(), Some(3)));
    }
    if let Some(bash) = bash32() {
        let major = probe_bash_major(&bash);
        targets.push((bash, major));
    }
    for (bash, major) in targets {
        let mut state = empty_state(ShellKind::Bash);
        let first = run(
            &mut state,
            "cd /tmp && export L3_V=ok && l3fn() { echo fn; }",
            &bash,
            major,
        )
        .await;
        assert_eq!(first.code, Some(0), "{bash}");
        let second = run(&mut state, "pwd; echo \"$L3_V\"; l3fn", &bash, major).await;
        assert_eq!(
            second.stdout.split_whitespace().collect::<Vec<_>>(),
            ["/tmp", "ok", "fn"],
            "{bash}"
        );
        assert!(
            second.fifo.is_some(),
            "{bash}: the FIFO channel was not used"
        );
    }
}

/// FIFO and directory are private, and removed after a normal end, after the shell exits without a dump (an
/// `exit` in the command: the reader must not wait out its timeout), after the reader is aborted (kill), and when
/// the command is prepared but never run.
#[tokio::test]
async fn fifo_and_directory_are_removed_in_every_ending() {
    let Some(bash) = system_bash() else { return };

    // Private: directory 0700, FIFO 0600.
    let state = empty_state(ShellKind::Bash);
    let prep = state
        .prepare_command_for("true", None, SearchShadowConfig::default(), None, Some(3))
        .unwrap();
    let fifo = prep.state_out_read.fifo_path().unwrap().to_path_buf();
    let dir = fifo.parent().unwrap();
    assert_eq!(
        std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let meta = std::fs::metadata(&fifo).unwrap();
    assert!(meta.file_type().is_fifo());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    // Prepared, never run: dropping it removes both.
    drop(prep);
    assert_removed(&fifo);

    // Normal end.
    let mut state = empty_state(ShellKind::Bash);
    let out = run(&mut state, "echo hi", bash, Some(3)).await;
    assert_eq!((out.code, out.stdout.trim()), (Some(0), "hi"));
    assert_removed(out.fifo.as_deref().unwrap());

    // Error: `exit` ends the shell before it dumps; the reader sees the shell is gone and returns at once.
    let out = run(&mut state, "exit 7", bash, Some(3)).await;
    assert_eq!(out.code, Some(7));
    assert!(
        out.elapsed < Duration::from_secs(3),
        "the reader waited {:?} for a dump that was never coming",
        out.elapsed
    );
    assert_removed(out.fifo.as_deref().unwrap());

    // Kill: the child is killed and the reader task aborted, as the terminal does.
    let prep = state
        .prepare_command_for(
            "sleep 30",
            None,
            SearchShadowConfig::default(),
            None,
            Some(3),
        )
        .unwrap();
    let fifo = prep.state_out_read.fifo_path().unwrap().to_path_buf();
    let mut cmd = tokio::process::Command::new(bash);
    cmd.args(&prep.args)
        .current_dir(&prep.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    cmd.fd_mappings(prep.fd_mappings).unwrap();
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    let mut reader = prep.state_out_read;
    reader.watch_child(child.id());
    let read = tokio::spawn(read_dump_from_pipe(reader));
    drop(prep.state_in_write);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(fifo.exists(), "the FIFO must exist while the command runs");
    child.kill().await.unwrap();
    read.abort();
    let _ = read.await;
    let deadline = Instant::now() + Duration::from_secs(3);
    while fifo.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_removed(&fifo);
}

/// Bash 4+, an unknown bash and zsh get the same wrapper text and the same descriptors as before the FIFO channel
/// existed: only bash below 4 differs.
#[test]
fn descriptor_channel_is_unchanged_for_bash4_plus_and_zsh() {
    let bash = empty_state(ShellKind::Bash);
    let zsh = empty_state(ShellKind::Zsh);
    let prepare = |state: &ShellState, major| {
        state
            .prepare_command_for("echo $1", None, SearchShadowConfig::default(), None, major)
            .unwrap()
    };
    let children = |prep: &PreparedCommand| {
        prep.fd_mappings
            .iter()
            .map(|m| m.child_fd)
            .collect::<Vec<_>>()
    };
    // The credential-name list in the dump script is process-global and other tests edit it while this runs, so it
    // is cut out before texts are compared; everything else is compared byte for byte.
    let wrapper = |prep: &PreparedCommand| {
        let text = prep.args.iter().max_by_key(|a| a.len()).unwrap().clone();
        let open = "case \"$__fuigo_env_name\" in (";
        let close = ") builtin unset \"$__fuigo_env_name\"";
        match (text.find(open), text.find(close)) {
            (Some(from), Some(to)) if from < to => {
                format!("{}{}", &text[..from + open.len()], &text[to..])
            }
            _ => panic!("no credential case in the wrapper"),
        }
    };

    let reference = prepare(&bash, Some(5));
    let reference_text = wrapper(&reference);
    assert!(reference_text.starts_with("exec 200>&4 4>&-; "));
    assert!(reference_text.contains("dump_bash_state >&200; builtin exit $COMMAND_EXIT_CODE"));
    assert!(reference_text.contains("builtin eval \"$__fuigo_user_cmd\" 2>&1 200>&-; "));
    assert!(!reference_text.contains("fuigo-dump-"));
    assert_eq!(children(&reference), [3, 4]);
    assert!(reference.state_out_read.fifo_path().is_none());
    for major in [None, Some(4), Some(5), Some(6)] {
        let prep = prepare(&bash, major);
        assert_eq!(wrapper(&prep), reference_text, "bash major {major:?}");
        assert_eq!(prep.args[..3], reference.args[..3], "bash major {major:?}");
        assert_eq!(prep.args[4..], reference.args[4..], "bash major {major:?}");
        assert_eq!(children(&prep), [3, 4], "bash major {major:?}");
        assert!(prep.state_out_read.fifo_path().is_none());
    }

    for major in [None, Some(3), Some(5)] {
        let prep = prepare(&zsh, major);
        let text = wrapper(&prep);
        assert!(text.contains("dump_zsh_state >&4; builtin exit $COMMAND_EXIT_CODE"));
        assert!(text.contains("builtin eval \"$__fuigo_user_cmd\" 2>&1 4>&-; "));
        assert_eq!(children(&prep), [3, 4]);
        assert!(prep.state_out_read.fifo_path().is_none());
        assert_eq!(
            text,
            wrapper(&prepare(&zsh, None)),
            "zsh ignores the bash major"
        );
    }

    let legacy = prepare(&bash, Some(3));
    let text = wrapper(&legacy);
    assert!(!text.contains("200"), "no descriptor 200 on the FIFO path");
    assert!(text.contains("fuigo-dump-"));
    assert_eq!(
        children(&legacy),
        [3],
        "fd 4 is not mapped on the FIFO path"
    );
}

/// The dump-read timeout covers the dump, not the command: state set after a command that ran past it survives,
/// on bash (descriptor channel and FIFO channel) and zsh.
#[tokio::test]
async fn state_survives_a_command_longer_than_the_dump_timeout() {
    let mut targets: Vec<(ShellKind, String, Option<u32>)> = Vec::new();
    if let Some(bash) = system_bash() {
        targets.push((ShellKind::Bash, bash.to_owned(), None));
        targets.push((ShellKind::Bash, bash.to_owned(), Some(3)));
    }
    let zsh = ShellKind::Zsh.binary_path();
    if Path::new(zsh).exists() && zsh.ends_with("zsh") {
        targets.push((ShellKind::Zsh, zsh.to_owned(), None));
    }
    for (kind, binary, major) in targets {
        let mut state = empty_state(kind);
        let first = run(
            &mut state,
            "sleep 7; cd /tmp; export U46_STTO=1",
            &binary,
            major,
        )
        .await;
        assert_eq!(first.code, Some(0), "{binary} {major:?}");
        let second = run(
            &mut state,
            "pwd; echo \"v=${U46_STTO:-unset}\"",
            &binary,
            major,
        )
        .await;
        assert_eq!(
            second.stdout.split_whitespace().collect::<Vec<_>>(),
            ["/tmp", "v=1"],
            "{binary} {major:?}: state lost after a long command"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// r1h3: a running command can write a complete frame of its own into the dump channel. The shell's dump is the LAST
// frame, and whatever frame is installed never carries a denied variable into the next command.
// ---------------------------------------------------------------------------------------------------------------

/// Shell text that builds a forged frame in `$frame`: it exports SUDO_ASKPASS, GPG_TTY and FORGED, and claims a
/// directory that does not exist.
const FORGE_FRAME: &str = r#"p=$(printf '%s\n' 'declare -x SUDO_ASKPASS="/tmp/ask"' 'declare -x GPG_TTY="/dev/pts/9"' 'declare -x FORGED=yes' | base64 | tr -d '\n'); frame=$(printf '__FUIGO_BASH_STATE_START__\n/nonexistent-forged\nfuigo_snap_ENV_VARS_B64=$(command base64 -d <<\047FUIGO_SNAP_EOF_ENV_VARS_B64\047\n%s\nFUIGO_SNAP_EOF_ENV_VARS_B64\n)\n__FUIGO_BASH_STATE_END__\n' "$p"); "#;

const PROBE: &str = r#"printf 'ASK=%s TTY=%s FORGED=%s KEPT=%s' "${SUDO_ASKPASS-unset}" "${GPG_TTY-unset}" "${FORGED-unset}" "${KEPT-unset}""#;

async fn forged_frame_case(command: &str, major: Option<u32>) {
    let Some(bash) = system_bash() else { return };
    let mut state = empty_state(ShellKind::Bash);
    let cwd = state.cwd.clone();
    let first = run(&mut state, command, bash, major).await;
    assert_eq!(first.code, Some(0), "{}", first.stdout);
    assert_eq!(state.cwd, cwd, "the forged directory was installed");
    let next = run(&mut state, PROBE, bash, major).await;
    assert!(
        !next.stdout.contains("/tmp/ask") && !next.stdout.contains("/dev/pts/9"),
        "a forged export reached the next command: {}",
        next.stdout
    );
    assert!(
        next.stdout.contains("FORGED=unset"),
        "the forged frame was installed: {}",
        next.stdout
    );
    assert!(
        next.stdout.contains("KEPT=yes"),
        "the real dump was not installed: {}",
        next.stdout
    );
}

/// (a) the FIFO channel (bash below 4): the path is in the wrapper's own command line.
#[tokio::test]
async fn r1h3_forged_frame_on_the_fifo_is_not_installed() {
    let command = format!(
        "export KEPT=yes; {FORGE_FRAME}path=$(ps -ww -o args= -p $$ | sed -n \"s/.*>'\\([^']*\\/dump\\)'.*/\\1/p\" | head -1); [ -p \"$path\" ] || exit 9; printf '%s\\n' \"$frame\" > \"$path\""
    );
    forged_frame_case(&command, Some(3)).await;
}

/// (b) the descriptor channel (bash 4+, zsh): the shell's saved copy of the channel sits on a descriptor from 10 up.
#[tokio::test]
async fn r1h3_forged_frame_on_the_fd_channel_is_not_installed() {
    let command = format!(
        "export KEPT=yes; {FORGE_FRAME}wrote=0; for fd in 10 11 12 13 14 15 16 17 18 19 20; do {{ printf '%s\\n' \"$frame\" >&$fd; }} 2>/dev/null && wrote=1; done; [ $wrote = 1 ] || exit 9"
    );
    forged_frame_case(&command, None).await;
}

/// The reader keeps the last frame: two frames in one read, the second wins.
#[test]
fn r1h3_parse_dump_takes_the_last_frame() {
    let raw = "__FUIGO_BASH_STATE_START__\n/forged\nx\n__FUIGO_BASH_STATE_END__\n\
               __FUIGO_BASH_STATE_START__\n/real\ny\n__FUIGO_BASH_STATE_END__\n";
    let (cwd, rest) = parse_dump(ShellKind::Bash, raw).unwrap();
    assert_eq!(cwd, PathBuf::from("/real"));
    assert!(rest.contains('y') && !rest.contains('x'));
}

/// Installing a frame never re-introduces a denied variable, however the line is written; ordinary exports stay.
#[test]
fn r1h3_scrub_env_block_drops_denied_names_only() {
    let script = b"declare -x PATH=\"/usr/bin\"\n\
declare -x SUDO_ASKPASS=\"/tmp/ask\"\n\
declare -x A=\"x\"; export gpg_tty=/dev/pts/9\n\
declare -x KEPT=\"multi\nline; value\"\n\
declare -x HTTPS_PROXY=\"http://p\"\n\
typeset -x $'SSH_AUTH_SOCK'=/s\n\
declare -x FINE=1\n\
declare -x X=$(touch /tmp/pwn)\n";
    let kept = String::from_utf8(scrub_env_block(script)).unwrap();
    for gone in [
        "SUDO_ASKPASS",
        "gpg_tty",
        "HTTPS_PROXY",
        "SSH_AUTH_SOCK",
        "touch",
    ] {
        assert!(!kept.contains(gone), "{gone} survived: {kept}");
    }
    for stays in ["PATH=", "KEPT=\"multi\nline; value\"", "FINE=1"] {
        assert!(kept.contains(stays), "{stays} was dropped: {kept}");
    }
}

/// r1h3: the reader that waits for the shell to be gone adds no per-command wait on any channel, and state carries.
/// Prints median/max per command for the three channels (run with `--nocapture`).
#[tokio::test]
async fn r1h3_sequential_commands_are_not_slowed_and_keep_state() {
    let zsh = ShellKind::Zsh.binary_path();
    let mut targets: Vec<(&str, ShellKind, String, Option<u32>)> = Vec::new();
    if let Some(bash) = system_bash() {
        targets.push(("bash-fd", ShellKind::Bash, bash.to_owned(), None));
        targets.push(("bash-fifo", ShellKind::Bash, bash.to_owned(), Some(3)));
    }
    if Path::new(zsh).exists() {
        targets.push(("zsh-fd", ShellKind::Zsh, zsh.to_owned(), None));
    }
    for (label, shell, binary, major) in targets {
        let mut state = empty_state(shell);
        let mut times = Vec::new();
        for i in 0..20 {
            let command = match i % 3 {
                0 => "true".to_owned(),
                1 => "cd /tmp".to_owned(),
                _ => format!("export A=r1h3_{i}"),
            };
            let out = run(&mut state, &command, &binary, major).await;
            assert_eq!(out.code, Some(0), "{label} {command}");
            times.push(out.elapsed);
            let check = run(&mut state, "pwd; echo \"${A-unset}\"", &binary, major).await;
            let seen: Vec<&str> = check.stdout.split_whitespace().collect();
            if i >= 1 {
                assert_eq!(seen[0], "/tmp", "{label}: cwd lost after {command}");
            }
            if i >= 2 {
                let last_export = (0..=i).rev().find(|n| n % 3 == 2).unwrap();
                assert_eq!(
                    seen[1],
                    format!("r1h3_{last_export}"),
                    "{label}: export lost"
                );
            }
        }
        times.sort();
        eprintln!("TIMING {label}: median {:?} max {:?}", times[10], times[19]);
        assert!(
            times[19] < Duration::from_secs(3),
            "{label}: waited {:?}",
            times[19]
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// u46 r2: a forged frame is installed only as data; the reader notices a killed shell that is not reaped yet, and a
// background holder of the descriptor channel adds no per-command wait.
// ---------------------------------------------------------------------------------------------------------------

/// One snapshot block in the dump's format.
fn snap_block(name: &str, text: &str) -> String {
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::STANDARD.encode(text);
    format!(
        "fuigo_snap_{name}=$(command base64 -d <<'FUIGO_SNAP_EOF_{name}'\n{payload}\nFUIGO_SNAP_EOF_{name}\n)\n"
    )
}

/// Fable r2 H1 (item 2): a forged frame left as the LAST frame (the wrapper SIGKILLed right after it, so no real dump
/// follows) is installed, but only as data: none of its hostile env, option or alias lines runs or installs a denied
/// variable (`eval`, `+=` appends, a nameref), while a plain export it carries does.
#[tokio::test]
async fn u46_forged_frame_then_sigkill_installs_data_only() {
    use base64::Engine as _;
    let Some(bash) = system_bash() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mark = dir.path().join("mark");
    let m = mark.display();
    let env = format!(
        "eval 'export SUDO_ASKPASS=/x'\nexport SSH_AUTH_SOCK+=/tmp/s\nexport http_proxy+=http://h\n\
         declare -x -n r=SUDO_ASKPASS\nexport r=/x\ntouch {m}\nexport KEPT='a b'\n"
    );
    let frame = format!(
        "__FUIGO_BASH_STATE_START__\n{}\n{}{}{}__FUIGO_BASH_STATE_END__\n",
        dir.path().display(),
        snap_block("ENV_VARS_B64", &env),
        snap_block("POSIX_OPTS_B64", &format!("set -o noclobber; touch {m}\n")),
        snap_block("ALIASES_B64", &format!("alias ll='ls -l'; touch {m}\n")),
    );
    let frame = base64::engine::general_purpose::STANDARD.encode(frame);
    let command = format!(
        "for fd in 10 11 12 13 14 15 16 17 18 19 20; do {{ printf '%s' '{frame}' | base64 -d >&$fd; }} 2>/dev/null; done; kill -9 $$"
    );
    let mut state = empty_state(ShellKind::Bash);
    let first = run(&mut state, &command, bash, None).await;
    assert_eq!(
        first.code, None,
        "the wrapper was not killed: {}",
        first.stdout
    );
    assert_eq!(state.cwd, dir.path(), "the forged frame was not installed");
    let next = run(
        &mut state,
        r#"printf 'ASK=%s SOCK=%s HP=%s KEPT=%s\n' "${SUDO_ASKPASS-unset}" "${SSH_AUTH_SOCK-unset}" "${http_proxy-unset}" "${KEPT-unset}"; [ -o noclobber ] && echo NOCLOBBER"#,
        bash,
        None,
    )
    .await;
    for gone in ["ASK=/x", "/tmp/s", "http://h", "NOCLOBBER"] {
        assert!(
            !next.stdout.contains(gone),
            "{gone} reached the next command: {}",
            next.stdout
        );
    }
    assert!(next.stdout.contains("KEPT=a b"), "{}", next.stdout);
    assert!(!mark.exists(), "a command in the forged frame ran");
}

/// Fable r2 M2: on the FIFO channel a shell that was killed but is not reaped yet (a zombie, as after a command's
/// timeout kill) counts as gone, so the reader ends at once instead of waiting out the actor's 5 s bound.
#[tokio::test]
async fn u46_fifo_reader_ends_for_a_killed_unreaped_shell() {
    let Some(bash) = system_bash() else { return };
    let state = empty_state(ShellKind::Bash);
    let prep = state
        .prepare_command_for(
            "sleep 30",
            None,
            SearchShadowConfig::default(),
            None,
            Some(3),
        )
        .unwrap();
    assert!(
        prep.state_out_read.fifo_path().is_some(),
        "not the FIFO channel"
    );
    let mut cmd = tokio::process::Command::new(bash);
    cmd.args(&prep.args)
        .current_dir(&prep.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    cmd.fd_mappings(prep.fd_mappings).unwrap();
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    let pid = child.id().unwrap();
    let mut reader = prep.state_out_read;
    reader.watch_child(Some(pid));
    let write = tokio::spawn(write_snapshot_to_pipe(
        state.replay_script(),
        prep.state_in_write,
    ));
    let read = tokio::spawn(read_dump_from_pipe(reader));
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The whole group (shell and its `sleep`), and no reap: the shell stays a zombie while the reader runs.
    // SAFETY: plain signal to the process group this test made.
    unsafe { libc::kill(-libc::pid_t::try_from(pid).unwrap(), libc::SIGKILL) };
    let started = Instant::now();
    let dump = tokio::time::timeout(Duration::from_secs(3), read).await;
    let elapsed = started.elapsed();
    let _ = child.wait().await;
    let _ = write.await;
    let dump = dump
        .expect("the reader kept waiting for a killed, unreaped shell")
        .unwrap()
        .unwrap();
    assert!(elapsed < Duration::from_secs(1), "reader took {elapsed:?}");
    assert!(parse_dump(ShellKind::Bash, &dump).is_none());
}

/// Fable r2 L1: on the descriptor channel a background job holding the shell's saved copy of the dump pipe adds no
/// wait: once the frame is in, the reader watches for the shell's exit on the short tick, so it ends within a few
/// milliseconds of the shell (round 1: 100-200 ms per command).
#[tokio::test]
async fn u46_background_holder_adds_no_wait_on_the_fd_channel() {
    let Some(bash) = system_bash() else { return };
    let mut state = empty_state(ShellKind::Bash);
    let mut after_exit = Vec::new();
    for _ in 0..9 {
        let prep = state
            .prepare_command_for(
                "{ sleep 0.6; :; } >/dev/null 2>&1 &",
                None,
                SearchShadowConfig::default(),
                None,
                None,
            )
            .unwrap();
        assert!(
            prep.state_out_read.fifo_path().is_none(),
            "not the descriptor channel"
        );
        let mut cmd = tokio::process::Command::new(bash);
        cmd.args(&prep.args)
            .current_dir(&prep.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        cmd.fd_mappings(prep.fd_mappings).unwrap();
        let mut child = cmd.spawn().unwrap();
        drop(cmd);
        let mut reader = prep.state_out_read;
        reader.watch_child(child.id());
        let write = tokio::spawn(write_snapshot_to_pipe(
            state.replay_script(),
            prep.state_in_write,
        ));
        let read = tokio::spawn(read_dump_from_pipe(reader));
        assert!(child.wait().await.unwrap().success());
        let exited = Instant::now();
        let dump = read.await.unwrap().unwrap();
        after_exit.push(exited.elapsed());
        write.await.unwrap().unwrap();
        assert!(state.update_from_dump(&dump), "no dump: {dump:?}");
    }
    after_exit.sort();
    eprintln!(
        "TIMING fd background holder: reader ends {:?} (median) / {:?} (max) after the shell",
        after_exit[4], after_exit[8]
    );
    assert!(
        after_exit[4] < Duration::from_millis(40),
        "the reader waited {:?} after the shell exited",
        after_exit[4]
    );
    // The background sleeps end on their own.
    tokio::time::sleep(Duration::from_millis(700)).await;
}
