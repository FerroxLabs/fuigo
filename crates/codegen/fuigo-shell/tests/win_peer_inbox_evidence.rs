//! Windows evidence for the peer inbox (Fuigo 1.0.25 packet 10; DESIGN S3.8).
//!
//! NOT RUN BY THE BUILDER. Every test is `#[ignore]` so no ordinary lane runs it; each prints one line
//! `P10-EVIDENCE <case> PASS|FAIL <detail>`. Run all of them, on a Windows machine, with:
//!
//! ```text
//! cargo test --locked -p fuigo-shell --test win_peer_inbox_evidence -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Needs: `FUIGO_P10_USER2` / `FUIGO_P10_PASS2` (a second LOCAL account that can log on interactively or batch; on
//! Windows Server it needs the user right "Log on as a batch job", because its helper runs as a scheduled task) for
//! `second_local_account_refused`; `FUIGO_P10_SYSTEM_LAUNCHER` (path of a `psexec.exe`-compatible launcher that accepts
//! `-accepteula -s <program> <args>` and returns the program's exit code) for `system_client_refused`; File and
//! Printer Sharing (SMB) on for `remote_client_refused`. `foreign_token_reaches_the_verdict` needs BOTH the second
//! account and the launcher AND the environment variable `FUIGO_P10_EVIDENCE_OPEN_ACL=1` (a debug-only switch read
//! only by this test's server; the production `start` never reads it and a release build does not compile the
//! case). A missing prerequisite FAILS the case with a clear message. Debug builds only (`cargo test` default).
//!
//! HOW TO RUN: from an INTERACTIVE or BATCH logon (a logged-in console or RDP session, or a scheduled task), NOT from
//! sshd. A Fuigo process started from an SSH session or any other network logon carries the NETWORK group (S-1-5-2) and
//! is refused as a remote client, also when it is the same user: `same_user_round_trip` then reports
//! `last_refusal=ClientRemote`. That is the intended fail-closed limit, not a bug.
//!
//! The second-account helper is launched as a one-shot SCHEDULED TASK registered for `FUIGO_P10_USER2` with its
//! password (`schtasks /Create /RU .. /RP .. /SC ONCE`, `/Run`, bounded poll, `/Delete`), because a plain
//! `CreateProcessWithLogonW` child started from a non-interactive session dies with 0xC0000142. The helper writes its
//! outcome to a file in a fresh directory under `%PUBLIC%` (the task's exit code is not returned to us). The task and the
//! directory are removed on every path. Only if the task cannot be created does it fall back to
//! `Start-Process -Credential -LoadUserProfile`. The account running the test needs rights to create tasks (an
//! administrator) and the password is passed to `schtasks` on its command line (a test machine only).
#![cfg(all(windows, debug_assertions))]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use fuigo_peer::HostId;
use fuigo_shell::win_peer_evidence as ev;

fn host_id(salt: u128) -> HostId {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1);
    HostId::new(&format!("{:032x}", nanos ^ (salt << 64) ^ u128::from(std::process::id()))).expect("32 hex")
}

fn report(case: &str, ok: bool, detail: &str) {
    println!("P10-EVIDENCE {case} {} {detail}", if ok { "PASS" } else { "FAIL" });
    assert!(ok, "P10-EVIDENCE {case} FAIL {detail}");
}

fn need_env(case: &str, name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            report(case, false, &format!("prerequisite missing: set the environment variable {name} (see the file header)"));
            unreachable!()
        }
    }
}

/// The PowerShell a foreign client runs: connect to the pipe at IDENTIFICATION level (as production does), write 4
/// bytes. Exit 0 = connected, 5 = access denied, 9 = anything else. With `result` the exit code is also written to that
/// file (the scheduled-task launch cannot return it). No double quotes, so it survives being passed as one argument.
fn child_script(full_pipe_name: &str, result: Option<&std::path::Path>) -> String {
    let short = full_pipe_name.trim_start_matches(r"\\.\pipe\");
    let tail = match result {
        Some(p) => format!("Set-Content -Path '{}' -Value $code -Encoding ascii; ", p.display()),
        None => String::new(),
    };
    format!(
        "$code = 9; try {{ $c = New-Object System.IO.Pipes.NamedPipeClientStream('.','{short}',\
         [System.IO.Pipes.PipeDirection]::InOut,[System.IO.Pipes.PipeOptions]::None,\
         [System.Security.Principal.TokenImpersonationLevel]::Identification); \
         $c.Connect(3000); $b = [byte[]](1,2,3,4); $c.Write($b,0,4); $c.Flush(); $code = 0 }} \
         catch [System.UnauthorizedAccessException] {{ $code = 5 }} catch {{ $code = 9 }}; {tail}exit $code"
    )
}

async fn run_blocking(mut cmd: Command) -> Result<i32, String> {
    tokio::task::spawn_blocking(move || cmd.status().map_err(|e| format!("could not start the helper: {e}")))
        .await
        .map_err(|_| "helper task failed".to_owned())?
        .map(|s| s.code().unwrap_or(-1))
}

/// Judge a foreign client's exit code and the server's counters after it ran.
async fn judge_foreign(case: &str, who: &str, exit: i32, inbox: &ev::EvidenceInbox) {
    tokio::time::sleep(Duration::from_millis(700)).await;
    let (acc, refd, last) = (inbox.accepted(), inbox.refused(), inbox.last_refusal());
    let detail = format!("{who} child exit={exit} accepted={acc} refused={refd} last_refusal={last:?}");
    match exit {
        5 => report(case, acc == 0, &format!("{detail} (the pipe's own access list denied the open)")),
        0 => report(case, acc == 0 && refd >= 1, &format!("{detail} (connected; the server must have refused it unread)")),
        _ => report(case, false, &format!("{detail} (inconclusive: the helper did not reach the pipe)")),
    }
}

/// Fallback launch of the second account: `Start-Process -Credential` (CreateProcessWithLogonW) with the profile loaded.
fn user2_fallback_cmd(pipe: &str) -> Command {
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-Command",
        "$pw = ConvertTo-SecureString $env:FUIGO_P10_PASS2 -AsPlainText -Force; \
         $c = New-Object System.Management.Automation.PSCredential($env:FUIGO_P10_USER2,$pw); \
         $p = Start-Process powershell.exe -Credential $c -LoadUserProfile -WorkingDirectory C:\\Windows\\System32 \
         -ArgumentList '-NoProfile','-Command',$env:FUIGO_P10_CHILD -PassThru -Wait -WindowStyle Hidden; exit $p.ExitCode",
    ]);
    cmd.env("FUIGO_P10_CHILD", child_script(pipe, None));
    cmd
}

/// Removes the one-shot task and the shared directory on every path (drop runs on panic too).
struct TaskGuard {
    name: String,
    dir: PathBuf,
    created: bool,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        if self.created {
            let _ = Command::new("schtasks").args(["/Delete", "/TN", &self.name, "/F"]).output();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn schtasks(args: &[&str]) -> Result<String, String> {
    let o = Command::new("schtasks").args(args).output().map_err(|e| format!("schtasks did not start: {e}"))?;
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    if o.status.success() { Ok(text) } else { Err(format!("schtasks {} failed: {}", args[0], String::from_utf8_lossy(&o.stderr).trim())) }
}

/// "Last Result" of the task: `None` while it has not run yet or is still running.
fn task_last_result(name: &str) -> Option<i32> {
    let text = schtasks(&["/Query", "/TN", name, "/FO", "LIST", "/V"]).ok()?;
    let line = text.lines().find(|l| l.trim_start().starts_with("Last Result:"))?;
    let v: i64 = line.split(':').nth(1)?.trim().parse().ok()?;
    // 267009 = running, 267011 = has not run yet.
    if v == 267_009 || v == 267_011 { None } else { Some(v as i32) }
}

/// Run the foreign client as `FUIGO_P10_USER2` through a one-shot scheduled task (a batch logon, which works from a
/// non-interactive session). Returns the helper's exit code (from its result file; else the task's Last Result).
fn run_as_user2(pipe: &str) -> Result<i32, String> {
    let user = std::env::var("FUIGO_P10_USER2").map_err(|_| "FUIGO_P10_USER2 unset".to_owned())?;
    let pass = std::env::var("FUIGO_P10_PASS2").map_err(|_| "FUIGO_P10_PASS2 unset".to_owned())?;
    let public = std::env::var("PUBLIC").unwrap_or_else(|_| r"C:\Users\Public".to_owned());
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1);
    let tag = format!("p10-ev-{}-{nanos}", std::process::id());
    let dir = PathBuf::from(public).join(&tag);
    let mut guard = TaskGuard { name: tag.clone(), dir: dir.clone(), created: false };
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    // Both accounts must be able to write here: Everyone, modify, inherited.
    let _ = Command::new("icacls").arg(&dir).args(["/grant", "*S-1-1-0:(OI)(CI)M"]).output();
    let result = dir.join("result.txt");
    let script = dir.join("child.ps1");
    std::fs::write(&script, child_script(pipe, Some(&result))).map_err(|e| format!("cannot write the helper: {e}"))?;
    let run = format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\"", script.display());
    let created = schtasks(&["/Create", "/RU", &user, "/RP", &pass, "/SC", "ONCE", "/ST", "00:00", "/TN", &tag, "/TR", &run, "/F"]);
    if let Err(e) = created {
        // The password never appears in this text (schtasks does not echo it).
        println!("P10-EVIDENCE note scheduled task not created ({e}); falling back to Start-Process -Credential");
        return user2_fallback_cmd(pipe).status().map(|s| s.code().unwrap_or(-1)).map_err(|e| format!("fallback launch failed: {e}"));
    }
    guard.created = true;
    schtasks(&["/Run", "/TN", &tag])?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if let Ok(t) = std::fs::read_to_string(&result) {
            if let Ok(code) = t.trim().parse::<i32>() {
                return Ok(code);
            }
        }
        if let Some(last) = task_last_result(&tag) {
            // The task ended. Give the result file a moment, then report the task's own code (e.g. 0xC0000142).
            std::thread::sleep(Duration::from_millis(500));
            if let Ok(code) = std::fs::read_to_string(&result).unwrap_or_default().trim().parse::<i32>() {
                return Ok(code);
            }
            return Ok(last);
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    Err("the scheduled task did not finish in 60 s".to_owned())
}

async fn run_user2(pipe: String) -> i32 {
    tokio::task::spawn_blocking(move || run_as_user2(&pipe)).await.ok().and_then(Result::ok).unwrap_or(-1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; run by hand"]
async fn same_user_accepts_and_round_trips() {
    let case = "same_user_round_trip";
    let (h, me) = (host_id(1), host_id(2));
    let inbox = ev::start(&h).await.unwrap_or_else(|e| {
        report(case, false, &format!("start failed: {e}"));
        unreachable!()
    });
    let r = ev::dial_list(&me, &h).await;
    let (acc, refd) = (inbox.accepted(), inbox.refused());
    inbox.shutdown().await;
    report(case, r == Ok(0) && acc == 1 && refd == 0, &format!("dial={r:?} accepted={acc} refused={refd}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; needs FUIGO_P10_USER2 / FUIGO_P10_PASS2"]
async fn second_local_account_refused() {
    let case = "second_local_account";
    let _ = need_env(case, "FUIGO_P10_USER2");
    let _ = need_env(case, "FUIGO_P10_PASS2");
    let h = host_id(3);
    let inbox = ev::start(&h).await.expect("start");
    let exit = run_user2(inbox.pipe_name()).await;
    judge_foreign(case, "user2", exit, &inbox).await;
    inbox.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; needs FUIGO_P10_SYSTEM_LAUNCHER"]
async fn system_client_refused() {
    let case = "system_client";
    let launcher = PathBuf::from(need_env(case, "FUIGO_P10_SYSTEM_LAUNCHER"));
    let h = host_id(4);
    let inbox = ev::start(&h).await.expect("start");
    let mut cmd = Command::new(launcher);
    cmd.args(["-accepteula", "-s", "powershell.exe", "-NoProfile", "-Command", &child_script(&inbox.pipe_name(), None)]);
    let exit = run_blocking(cmd).await.unwrap_or(-1);
    judge_foreign(case, "system", exit, &inbox).await;
    inbox.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; needs SMB / File and Printer Sharing"]
async fn remote_client_refused() {
    let case = "remote_client";
    let computer = need_env(case, "COMPUTERNAME");
    let (h, me) = (host_id(5), host_id(6));
    let inbox = ev::start(&h).await.expect("start");
    let local = inbox.pipe_name();
    let remote = format!(r"\\{computer}\pipe\{}", local.trim_start_matches(r"\\.\pipe\"));
    let r = ev::dial_list_at(&remote, &me, &h).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (acc, refd) = (inbox.accepted(), inbox.refused());
    inbox.shutdown().await;
    let detail = format!("dial through the network path = {r:?} accepted={acc} refused={refd}");
    // `NoServer` could mean "SMB is off", which proves nothing: that is inconclusive, so it fails.
    let reached_and_refused = matches!(&r, Err(e) if e != "NoServer" && e != "Timeout") && acc == 0;
    let unreadable_after_connect = r.is_err() && acc == 0 && refd >= 1;
    report(case, reached_and_refused || unreadable_after_connect, &detail);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; run by hand"]
async fn pre_created_pipe_makes_start_fail_closed() {
    let case = "pre_created_pipe";
    let h = host_id(7);
    let name = ev::pipe_name_for(&h).expect("name");
    // An attacker-style squatter: it claims the name first, with the default access list.
    let squatter = tokio::net::windows::named_pipe::ServerOptions::new().first_pipe_instance(true).create(&name);
    let Ok(_squatter) = squatter else {
        report(case, false, "could not create the squatter pipe for the test");
        return;
    };
    let r = ev::start(&h).await;
    let detail = format!("start = {:?}", r.as_ref().err());
    report(case, matches!(&r, Err(e) if e.contains("already in use")), &detail);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; run by hand"]
async fn feature_off_does_not_create_the_pipe() {
    let case = "feature_off";
    let h = host_id(8);
    let r = ev::start_disabled(&h).await;
    let name = ev::pipe_name_for(&h).expect("name");
    let exists = std::fs::metadata(&name).is_ok();
    report(case, matches!(&r, Err(e) if e.contains("feature is off")) && !exists, &format!("start={:?} pipe_exists={exists}", r.as_ref().err()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; run by hand"]
async fn file_and_junction_at_the_name_are_refused() {
    let case = "non_pipe_and_reparse";
    let (h, me) = (host_id(9), host_id(10));
    let dir = std::env::temp_dir().join(format!("p10-evidence-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("target")).expect("temp dir");
    let file = dir.join("not-a-pipe.txt");
    std::fs::write(&file, b"x").expect("file");
    let junction = dir.join("junction");
    let made = Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(dir.join("target"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let on_file = ev::dial_list_at(&file.to_string_lossy(), &me, &h).await;
    let on_junction = if made { Some(ev::dial_list_at(&junction.to_string_lossy(), &me, &h).await) } else { None };
    let _ = std::fs::remove_dir_all(&dir);
    let detail = format!("file={on_file:?} junction_created={made} junction={on_junction:?}");
    let file_ok = matches!(&on_file, Err(e) if e == "NotAPipe");
    let junction_ok = matches!(&on_junction, Some(Err(_)));
    report(case, file_ok && junction_ok, &detail);
}

/// One foreign client against the widened pipe: the OS must let it connect and the SERVER's verdict must refuse it.
async fn verdict_layer_case(case: &str, who: &str, exit: i32, inbox: &ev::EvidenceInbox, before: u64, expect: &[&str]) -> bool {
    tokio::time::sleep(Duration::from_millis(900)).await;
    let (acc, refd, last) = (inbox.accepted(), inbox.refused(), inbox.last_refusal());
    let matches_expected = last.as_deref().is_some_and(|l| expect.contains(&l));
    // The judge is the SERVER's own record, not the helper's exit code: a client that the verdict function refuses is
    // disconnected and exits non-zero (9 on the first Windows run), which says nothing about which layer refused it.
    // Refused by the verdict = the server counted one more refusal, its reason is one of the expected ones, and it
    // accepted nobody. Exit 5 (access denied at open) means the pipe's own ACL stopped the client: no evidence here.
    let refused_by_verdict = matches_expected && acc == 0 && refd == before + 1;
    let layer = if refused_by_verdict {
        "server verdict function"
    } else if exit == 5 {
        "pipe ACL (the widened DACL did not apply: no evidence)"
    } else if refd == before {
        "inconclusive: the helper did not reach the pipe"
    } else {
        "connected, but the verdict refusal was not the expected one"
    };
    let ok = refused_by_verdict;
    println!("P10-EVIDENCE {case} {who} refused_by_layer={layer} expected={expect:?} last_refusal={last:?} exit={exit} accepted={acc}");
    ok
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Windows evidence; needs FUIGO_P10_USER2 / FUIGO_P10_PASS2 / FUIGO_P10_SYSTEM_LAUNCHER / FUIGO_P10_EVIDENCE_OPEN_ACL=1"]
async fn foreign_token_reaches_the_verdict() {
    let case = "foreign_token_verdict";
    let _ = need_env(case, "FUIGO_P10_USER2");
    let _ = need_env(case, "FUIGO_P10_PASS2");
    let launcher = PathBuf::from(need_env(case, "FUIGO_P10_SYSTEM_LAUNCHER"));
    let _ = need_env(case, "FUIGO_P10_EVIDENCE_OPEN_ACL");
    let h = host_id(11);
    let inbox = match ev::start_open_acl(&h).await {
        Ok(i) => i,
        Err(e) => {
            report(case, false, &format!("start failed: {e}"));
            unreachable!()
        }
    };
    let before = inbox.refused();
    let exit = run_user2(inbox.pipe_name()).await;
    let user2_ok = verdict_layer_case(case, "user2", exit, &inbox, before, &["DifferentAccount"]).await;
    let mut sys = Command::new(launcher);
    sys.args(["-accepteula", "-s", "powershell.exe", "-NoProfile", "-Command", &child_script(&inbox.pipe_name(), None)]);
    let before = inbox.refused();
    let exit = run_blocking(sys).await.unwrap_or(-1);
    // Either refusal is a refusal by the server's verdict function: SYSTEM recognised, or its token unreadable (fail closed).
    let system_ok = verdict_layer_case(case, "system", exit, &inbox, before, &["ClientSystemOrService", "ClientUnreadable"]).await;
    inbox.shutdown().await;
    report(case, user2_ok && system_ok, &format!("user2_refused_by_verdict={user2_ok} system_refused_by_verdict={system_ok}"));
}
