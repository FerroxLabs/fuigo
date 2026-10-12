//! Packet 14a: REAL-PROCESS gate tests for peer messaging (`features.peer_messaging`, forced on with
//! `FUIGO_PEER_MESSAGING=1` in the child's environment only).
//!
//! The children are real `fuigo-pager` processes on a PTY (the pager, leader off or behind a leader, is the only
//! host whose sessions are opted in on this base). A raw client in this test speaks the inbox wire protocol
//! (4-byte big-endian length + JSON: hello each way, one op, one reply) on the real unix socket of the child.
//! Model endpoints are the loopback mock of the PTY harness with fake keys. Every child uses a temp HOME.
//!
//! Needs the binary: set `PAGER_BINARY=<target>/debug/fuigo-pager` (built with `-p fuigo-pager-bin`).
//! Run: `cargo test -p fuigo-pager --test peer_real_process -- --test-threads=1` (inside `unshare -n` with lo up).
//!
//! No test signals anything but a child it spawned, and only through a pidfd opened right after the spawn
//! (`pidfd_send_signal`): a pidfd names that one process for good, so a pid that was reaped and recycled can never be
//! hit (the call fails with ESRCH). No raw pid is ever kept or signalled. Every wait is bounded; a watchdog thread
//! signals the registered pidfds and aborts if a test runs past its hard limit.
//!
//! Linux only (pidfd, `/proc`).
#![cfg(unix)]
#![cfg(target_os = "linux")]
#![allow(clippy::print_stderr, reason = "the watchdog must say why it aborted the process")]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fuigo_pager_pty_harness::{ContentController, EnvOp, PtyHarness, pager_binary, submit_turn};
use fuigo_peer::address::Address;
use fuigo_peer::envelope::{Envelope, OperatorKind};
use fuigo_peer::locator_row::{HostDir, HostRow, parse_rows, socket_path};
use fuigo_peer::mode::{PeerBase, PeerMode};
use fuigo_peer::wire::{Hello, HostId, Op};
use serde_json::Value;

const ROWS: u16 = 50;
const COLS: u16 = 120;
const T: Duration = Duration::from_secs(120);
const OUR_HOST: &str = "abababababababababababababababab";

// ---- pidfd and watchdog --------------------------------------------------------------------------------------------

/// A pidfd of one child this test spawned. Signals go only through it; it never refers to a recycled pid.
struct PidFd(OwnedFd);

impl PidFd {
    /// Open right after the spawn, while the child is certainly not yet reaped (only this test reaps it).
    fn open(pid: u32) -> Arc<Self> {
        // SAFETY: plain syscall with integer arguments; the result is checked before it is wrapped.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        assert!(fd >= 0, "pidfd_open({pid}) failed: {}", std::io::Error::last_os_error());
        // SAFETY: `fd` is a fresh, owned, valid descriptor returned by pidfd_open.
        Arc::new(Self(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
    }
    fn signal(&self, sig: i32) -> std::io::Result<()> {
        // SAFETY: the fd is a live pidfd owned by `self`; null siginfo and zero flags are the documented defaults.
        let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.0.as_raw_fd(), sig, std::ptr::null::<libc::c_void>(), 0) };
        if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
}

/// Hard overall timeout: on expiry signal the registered children (through their pidfds) and abort the test process.
struct Watchdog {
    fds: Arc<Mutex<Vec<Arc<PidFd>>>>,
    done: Arc<AtomicBool>,
}

impl Watchdog {
    fn start(limit: Duration) -> Self {
        let fds: Arc<Mutex<Vec<Arc<PidFd>>>> = Arc::default();
        let done = Arc::new(AtomicBool::new(false));
        let (p, d) = (fds.clone(), done.clone());
        std::thread::spawn(move || {
            let end = Instant::now() + limit;
            while Instant::now() < end {
                if d.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            // A reaped child's pidfd answers ESRCH; nothing else can be hit.
            for fd in p.lock().unwrap().iter() {
                let _ = fd.signal(libc::SIGCONT);
                let _ = fd.signal(libc::SIGKILL);
            }
            eprintln!("peer_real_process watchdog: hard timeout, children killed");
            std::process::abort();
        });
        Self { fds, done }
    }
    fn register_pid(&self, pid: u32) -> Arc<PidFd> {
        let fd = PidFd::open(pid);
        self.fds.lock().unwrap().push(fd.clone());
        fd
    }
    fn register(&self, h: &PtyHarness) -> Arc<PidFd> {
        self.register_pid(h.child_pid().expect("child pid right after spawn"))
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
    }
}

// ---- raw inbox client ----------------------------------------------------------------------------------------------

fn write_frame(s: &mut UnixStream, v: &Value) -> std::io::Result<()> {
    let b = serde_json::to_vec(v).unwrap();
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(&b)?;
    s.flush()
}

fn read_frame(s: &mut UnixStream) -> std::io::Result<Value> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l)?;
    let n = u32::from_be_bytes(l) as usize;
    if n > 70_000 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame over cap"));
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    serde_json::from_slice(&b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Connect with a real connect timeout (a full accept backlog blocks `connect`): the connect runs on a helper thread.
fn connect(sock: &Path, to: Duration) -> std::io::Result<UnixStream> {
    let (tx, rx) = std::sync::mpsc::channel();
    let path = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(UnixStream::connect(path));
    });
    let s = match rx.recv_timeout(to) {
        Ok(r) => r?,
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")),
    };
    s.set_read_timeout(Some(to))?;
    s.set_write_timeout(Some(to))?;
    Ok(s)
}

fn hello() -> Value {
    serde_json::to_value(Hello::new(HostId::new(OUR_HOST).unwrap())).unwrap()
}

/// hello each way, one op, one reply.
fn exchange(sock: &Path, op: &Op, to: Duration) -> std::io::Result<Value> {
    let mut s = connect(sock, to)?;
    write_frame(&mut s, &hello())?;
    let _theirs = read_frame(&mut s)?;
    write_frame(&mut s, &serde_json::to_value(op).unwrap())?;
    read_frame(&mut s)
}

fn list(sock: &Path, to: Duration) -> std::io::Result<Vec<Value>> {
    let r = exchange(sock, &Op::List { page: 0 }, to)?;
    assert_eq!(r["reply"], "list", "list reply: {r}");
    Ok(r["rows"].as_array().cloned().unwrap_or_default())
}

fn envelope(to: &Address, n: u64, body: &str) -> (Address, Envelope) {
    let from = Address::new(OUR_HOST, "raw-sender", 1).unwrap();
    let env = Envelope {
        message_id: format!("raw-msg-{n}-{}", std::process::id()),
        seq: n,
        from,
        from_name: String::new(),
        from_auto_title: None,
        from_ref: "raw".into(),
        from_mode: PeerMode::new(false, PeerBase::Default, false),
        from_operator: OperatorKind::Human,
        conversation_id: format!("conv-{n}"),
        hop: 0,
        denied_recently: vec![],
        body: body.into(),
    };
    (to.clone(), env)
}

fn send(sock: &Path, to: &Address, n: u64, body: &str, tmo: Duration) -> std::io::Result<Value> {
    let (to, envelope) = envelope(to, n, body);
    exchange(sock, &Op::Send { to, envelope, watch: false }, tmo)
}

fn first_address(rows: &[Value]) -> Address {
    rows.first().and_then(|r| r["address"].as_str()).expect("a listed session").parse().expect("address")
}

// ---- host plumbing -------------------------------------------------------------------------------------------------

fn fuigo_home(c: &ContentController) -> PathBuf {
    c.home().join(".fuigo")
}

fn rows_of(home: &Path) -> Vec<HostRow> {
    std::fs::read(home.join("peers").join("hosts.json")).ok().and_then(|b| parse_rows(&b).ok()).unwrap_or_default()
}

fn sock_of(home: &Path, row: &HostRow) -> PathBuf {
    assert_eq!(row.dir, HostDir::Home, "test home is short enough for the home layout");
    socket_path(&home.join("peers"), &row.host_id)
}

fn spawn_pager(c: &ContentController, extra: &[&str]) -> PtyHarness {
    let bin = pager_binary().expect("pager binary (set PAGER_BINARY)");
    PtyHarness::spawn_with_content_env(&bin, ROWS, COLS, c, extra, &[("FUIGO_PEER_MESSAGING", "1")]).expect("spawn pager")
}

/// Start a pager (leader off), run one turn so its session exists, return it with the new host row.
fn start_host(c: &ContentController, wd: &Watchdog, known: &[HostRow]) -> (PtyHarness, HostRow, Arc<PidFd>) {
    let mut h = spawn_pager(c, &["--no-leader"]);
    let pidfd = wd.register(&h);
    h.wait_for_text("Quit", T).expect("welcome");
    submit_turn(&mut h, "go", "PEERBOOT", T);
    let home = fuigo_home(c);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let rows = rows_of(&home);
        if let Some(r) = rows.iter().find(|r| !known.iter().any(|k| k.host_id == r.host_id)) {
            let row = r.clone();
            // the session must be listed (opted in) before the host counts as up
            while Instant::now() < deadline {
                if list(&sock_of(&home, &row), Duration::from_secs(5)).map(|l| !l.is_empty()).unwrap_or(false) {
                    return (h, row, pidfd);
                }
                h.update(Duration::from_millis(200));
            }
        }
        assert!(Instant::now() < deadline, "host row / session never appeared\n{}", h.screen_contents());
        h.update(Duration::from_millis(200));
    }
}

/// How many of the sockets are still open from the server's side: a non-blocking read that ends in EOF or a reset is closed;
/// WouldBlock (or data, e.g. a hello) is open. Takes no time per socket.
fn open_count(conns: &[UnixStream]) -> usize {
    conns
        .iter()
        .filter(|s| {
            let mut s = (*s).try_clone().expect("clone");
            s.set_nonblocking(true).expect("nonblocking");
            let mut b = [0u8; 512];
            loop {
                match s.read(&mut b) {
                    Ok(0) => break false,
                    Ok(_) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break true,
                    Err(_) => break false,
                }
            }
        })
        .count()
}

fn fd_count(h: &PtyHarness) -> usize {
    let pid = h.child_pid().expect("child pid");
    std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap_or_else(|e| panic!("cannot read /proc/{pid}/fd: {e}")).count()
}

/// The marker the pager prints at the end of every turn (slash commands included).
const DONE: &str = "Worked for";

/// What one slash command produced.
struct Fresh {
    /// Text the child wrote to the terminal AFTER the command was sent (escape sequences removed). Nothing older is in it.
    slice: String,
    /// The full screen text once the slice was complete. DIAGNOSTICS ONLY (failure messages): no assertion reads it, because
    /// it includes scrollback that an older command wrote.
    screen: String,
}

impl Fresh {
    /// Positive check: the text is in what THIS command wrote (never scrollback).
    fn shows(&self, s: &str) -> bool {
        self.slice.contains(s)
    }
    /// Negative check: the text is not in what THIS command wrote.
    fn lacks(&self, s: &str) -> bool {
        !self.slice.contains(s)
    }
}

/// Remove CSI/OSC/other escape sequences and carriage returns from raw terminal output.
fn strip_ansi(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            0x1b => {
                i += 1;
                match raw.get(i) {
                    Some(b'[') => {
                        i += 1;
                        while i < raw.len() && !(0x40..=0x7e).contains(&raw[i]) {
                            i += 1;
                        }
                        i += 1;
                    }
                    Some(b']') => {
                        i += 1;
                        while i < raw.len() && raw[i] != 0x07 && !(raw[i] == 0x1b && raw.get(i + 1) == Some(&b'\\')) {
                            i += 1;
                        }
                        i += if raw.get(i) == Some(&0x07) { 1 } else { 2 };
                    }
                    _ => i += 1,
                }
            }
            b'\r' => i += 1,
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Type a slash command and wait for ITS result: the offset of the child's raw terminal output is taken before the
/// command is sent, and only output written after that offset counts. The result is complete when the new output
/// contains `marker` and the turn-end marker and has stopped changing between two polls. An identical earlier list
/// still on screen can neither satisfy the wait nor the caller's assertions.
fn run_slash(h: &mut PtyHarness, cmd: &str, marker: &str, tmo: Duration) -> Fresh {
    h.update(Duration::from_millis(100));
    let offset = h.raw_output().len();
    h.inject_keys(format!("{cmd}\r").as_bytes()).unwrap();
    let end = Instant::now() + tmo;
    let mut last: Option<String> = None;
    loop {
        h.update(Duration::from_millis(250));
        let slice = strip_ansi(&h.raw_output()[offset.min(h.raw_output().len())..]);
        if slice.contains(marker) && slice.contains(DONE) {
            if last.as_deref() == Some(slice.as_str()) {
                return Fresh { slice, screen: h.full_text() };
            }
            last = Some(slice);
        }
        assert!(Instant::now() < end, "`{cmd}` never printed {marker:?} in new output\n{}", h.full_text());
    }
}

// ---- test 1: two processes, crash and stop -------------------------------------------------------------------------

/// How the product classifies a stream error of a dial (`peer_inbox/dial.rs` `from_io`, `DialError`).
#[derive(Debug, PartialEq, Eq)]
enum Dial {
    Timeout,
    Refused,
    NoSuchFile,
    Other,
}

fn classify(e: &std::io::Error) -> Dial {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::NotFound => Dial::NoSuchFile,
        K::ConnectionRefused => Dial::Refused,
        K::TimedOut | K::WouldBlock => Dial::Timeout,
        _ => Dial::Other,
    }
}

/// The raw test client's OWN connect/read/write socket timeout (`connect()`); not a product constant.
const RAW_CLIENT_TIMEOUT: Duration = Duration::from_secs(12);
/// `REMOTE_ONE` / `REMOTE_LIST_TOTAL` in `fuigo-shell/src/peer_inbox/tool_host.rs:45-46`: the per-host and total budget of the
/// remote part of `/peers list`.
const REMOTE_ONE: Duration = Duration::from_secs(1);
const REMOTE_LIST_TOTAL: Duration = Duration::from_secs(3);
/// Scheduling slack on top of a documented bound (loaded shared box).
const SLACK: Duration = Duration::from_secs(8);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_list_send_kill9_and_sigstop() {
    let wd = Watchdog::start(Duration::from_secs(900));
    let c = ContentController::start().await.expect("content");
    c.set_response("PEERBOOT ok");
    let home = fuigo_home(&c);

    // (a) A and B up; A lists, sends to B; B shows it.
    let (mut a, a_row, _a_fd) = start_host(&c, &wd, &[]);
    let (mut b, b_row, b_fd) = start_host(&c, &wd, std::slice::from_ref(&a_row));
    let b_id = b_row.host_id.as_str().to_owned();
    let a_sock = sock_of(&home, &a_row);
    let b_sock = sock_of(&home, &b_row);
    let b_session = first_address(&list(&b_sock, Duration::from_secs(10)).unwrap());
    // A's own `/peers list` shows B (this command's own output only).
    let t = run_slash(&mut a, "/peers list", "This session is", Duration::from_secs(60));
    assert!(t.shows(&b_id), "A's list offers B before the kill\n{}", t.screen);
    let marker = "PEERMSG-from-raw-1";
    c.set_response("PEERREPLY ok");
    let r = send(&b_sock, &b_session, 1, marker, Duration::from_secs(15)).expect("send to B");
    assert_eq!(r["reply"], "send", "{r}");
    assert_eq!(r["outcome"]["outcome"], "delivered", "send to B: {r}");
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        b.update(Duration::from_millis(250));
        if c.request_bodies().iter().any(|v| v.to_string().contains(marker)) {
            break;
        }
        assert!(Instant::now() < end, "B never acted on the message\n{}", b.screen_contents());
    }

    // (b) kill -9 B (through its pidfd).
    b_fd.signal(libc::SIGKILL).expect("SIGKILL B");
    let t0 = Instant::now();
    // A's next list is a NEW turn's output; it must not offer B (A's dial to B fails fast) and must not hang.
    let t = run_slash(&mut a, "/peers list", "This session is", Duration::from_secs(60));
    assert!(t0.elapsed() < Duration::from_secs(60));
    assert!(t.lacks(&b_id), "A offered dead B again in its fresh list\nnew output: {}\nscreen: {}", t.slice, t.screen);
    assert!(t.shows("This session is"), "the fresh list is missing");
    // A send to the dead host is a typed failure, not a hang: the stale socket refuses (or is gone).
    let e = send(&b_sock, &b_session, 2, "to-the-dead", Duration::from_secs(10)).expect_err("dead host must not answer");
    assert!(
        matches!(classify(&e), Dial::Refused | Dial::NoSuchFile),
        "unexpected error kind for a dead host: {e:?}"
    );
    // B's stale row and socket stay until the NEXT inbox start reaps them (receipt 8e: reaping runs at start only).
    assert!(rows_of(&home).iter().any(|r| r.host_id == b_row.host_id), "row is only reaped by a later start");
    drop(b); // reaps the child; b_fd now answers ESRCH and can never hit a recycled pid
    c.set_response("PEERBOOT ok");
    let (b2, b2_row, b2_fd) = start_host(&c, &wd, &[a_row.clone(), b_row.clone()]);
    let rows = rows_of(&home);
    assert!(!rows.iter().any(|r| r.host_id == b_row.host_id), "B's stale row was not reaped by B2's start: {rows:?}");
    assert!(!b_sock.exists(), "B's stale socket was not reaped");
    assert!(rows.iter().any(|r| r.host_id == a_row.host_id) && rows.iter().any(|r| r.host_id == b2_row.host_id));
    assert!(list(&a_sock, Duration::from_secs(10)).is_ok(), "A stays serving");

    // (c) SIGSTOP B2: the dial times out as documented, A's list returns, A stays responsive, then SIGCONT.
    let b2_sock = sock_of(&home, &b2_row);
    let b2_id = b2_row.host_id.as_str().to_owned();
    let t = run_slash(&mut a, "/peers list", "This session is", Duration::from_secs(60));
    assert!(t.shows(&b2_id), "A's list offers B2 while it runs\n{}", t.screen);
    b2_fd.signal(libc::SIGSTOP).expect("SIGSTOP B2");
    // (c1) THE PRODUCT: A's fresh `/peers list` dials the stopped B2 itself (`tool_host.rs` `remote_rows`: per host
    // `dial` under `REMOTE_ONE` = 1 s, the whole remote part under `REMOTE_LIST_TOTAL` = 3 s, `tool_host.rs:45-46`). The kernel
    // accepts the connect (backlog) but B2 never answers the hello, so the dial runs into REMOTE_ONE (a LOWER bound: the list
    // cannot be answered earlier) and the host is then skipped (`tool_host.rs:167`: only `Ok(Ok(Reply::List))` adds rows), so the
    // documented result is: B2's id is absent from the fresh output and A's own session is still listed. The elapsed time is
    // measured from before the command is typed until its output is complete.
    let t0 = Instant::now();
    let t = run_slash(&mut a, "/peers list", "This session is", Duration::from_secs(90));
    let list_took = t0.elapsed();
    assert!(t.shows("This session is"), "the fresh list is missing\n{}", t.screen);
    assert!(t.lacks(&b2_id), "A still offered the stopped B2 in its fresh list\nnew output: {}", t.slice);
    assert!(list_took >= REMOTE_ONE, "A's list returned in {list_took:?}, before its per-host dial deadline {REMOTE_ONE:?}");
    assert!(
        list_took < REMOTE_LIST_TOTAL + SLACK,
        "A's list took {list_took:?} with B2 stopped; documented total {REMOTE_LIST_TOTAL:?} + slack {SLACK:?}"
    );
    eprintln!("p14a: A's fresh list with B2 stopped took {list_took:?}");
    // (c2) The raw client's own view (NOT the product's deadline): its 12 s socket timeout expires because the stopped process
    // never answers. It proves B2 does not answer and that the client is not hung; the product's 2 s + 10 s dial deadlines
    // (`dial.rs:24`, `conn.rs:28`) are not measured here.
    let b2_addr: Address = format!("fuigo-peer:{}/x/1", b2_row.host_id.as_str()).parse().expect("address");
    let t0 = Instant::now();
    let e = send(&b2_sock, &b2_addr, 3, "to-stopped", RAW_CLIENT_TIMEOUT).expect_err("a stopped host answered");
    let took = t0.elapsed();
    assert_eq!(classify(&e), Dial::Timeout, "a stopped host must not answer; the raw client's socket timeout expires, got {e:?}");
    assert!(
        took >= RAW_CLIENT_TIMEOUT - Duration::from_secs(1) && took < RAW_CLIENT_TIMEOUT + SLACK,
        "raw client ended after {took:?}, its own socket timeout is {RAW_CLIENT_TIMEOUT:?}"
    );
    let t = run_slash(&mut a, "/peers status", "Peer inbox: ready", Duration::from_secs(30));
    assert!(a.is_running().unwrap(), "A died\n{}", t.screen);
    assert!(list(&a_sock, Duration::from_secs(10)).is_ok(), "A stopped answering");
    b2_fd.signal(libc::SIGCONT).expect("SIGCONT B2");
    let end = Instant::now() + Duration::from_secs(30);
    while list(&b2_sock, Duration::from_secs(5)).is_err() {
        assert!(Instant::now() < end, "B2 did not recover after SIGCONT");
        std::thread::sleep(Duration::from_millis(300));
    }
    drop(b2);
    drop(a);
}

// ---- test 3: socket flood against a real session -------------------------------------------------------------------

/// `MAX_CONNECTIONS` in `fuigo-shell/src/peer_inbox/inbox.rs`.
const MAX_CONNECTIONS: usize = 32;
/// Allowed fds above `baseline + MAX_CONNECTIONS`: the listener's accept in flight, epoll/timer fds, one transient
/// reply socket while a sample is taken. Anything more means connections beyond the cap stay open.
const FD_SLACK: usize = 8;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socket_flood_against_a_real_session() {
    let wd = Watchdog::start(Duration::from_secs(600));
    let c = ContentController::start().await.expect("content");
    c.set_response("PEERBOOT ok");
    let home = fuigo_home(&c);
    let (mut p, row, _p_fd) = start_host(&c, &wd, &[]);
    let sock = sock_of(&home, &row);
    let session = first_address(&list(&sock, Duration::from_secs(10)).unwrap());
    p.update(Duration::from_secs(1));
    let fds_before = fd_count(&p);
    assert!(fds_before > 0, "could not read /proc fds");

    // 1. 200 simultaneous connections that only sit there: the cap is 32, the rest are closed at once, unread.
    let conns: Vec<UnixStream> = (0..200).filter_map(|_| connect(&sock, Duration::from_secs(3)).ok()).collect();
    assert!(conns.len() >= 150, "only {} of 200 connects succeeded; the flood proves nothing", conns.len());
    // fd use stays within the cap, sampled over several seconds (not once)
    for i in 0..6 {
        std::thread::sleep(Duration::from_millis(700));
        // Held-open count, taken without waiting (all well inside the 10 s exchange deadline, so idle sockets are not yet
        // closed by it). A missing connection cap leaves about 200 open: this fails.
        let open = open_count(&conns);
        assert!(open <= MAX_CONNECTIONS + 2, "sample {i}: {open} of {} idle connections are still open; cap is {MAX_CONNECTIONS}", conns.len());
        let during = fd_count(&p);
        assert!(
            during <= fds_before + MAX_CONNECTIONS + FD_SLACK,
            "sample {i}: fd use {during} (baseline {fds_before}) exceeds the cap of {MAX_CONNECTIONS} + slack {FD_SLACK}"
        );
    }
    drop(conns);

    // 2. garbage, oversized frames, slow loris: each is closed BY THE SERVER (EOF or reset) within the exchange
    //    deadline (10 s, `conn.rs` EXCHANGE_DEADLINE) plus slack; the client read timeout is much larger.
    let bound = Duration::from_secs(10) + SLACK;
    let read_timeout = Duration::from_secs(40);
    let mut bad: Vec<(&str, UnixStream, Instant)> = Vec::new();
    for (name, bytes) in [
        ("garbage", vec![0xFFu8; 4096]),
        ("oversized-prefix", 0xFFFF_FFF0u32.to_be_bytes().to_vec()),
        ("over-64k-prefix", 70_000u32.to_be_bytes().to_vec()),
        ("not-json", [&8u32.to_be_bytes()[..], b"notjson!"].concat()),
        ("loris-prefix", vec![0, 0]),
    ] {
        let mut s = connect(&sock, read_timeout).expect("connect");
        let _ = s.write_all(&bytes);
        bad.push((name, s, Instant::now()));
    }
    for (name, mut s, t0) in bad {
        let mut buf = [0u8; 8192];
        // The server may send its hello first; read until EOF or a reset.
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) => break,
                Err(e) => panic!("{name}: the server did not close the connection (client read failed: {e:?}) after {:?}", t0.elapsed()),
            }
            assert!(t0.elapsed() < bound, "{name}: still open after {:?}", t0.elapsed());
        }
        assert!(t0.elapsed() < bound, "{name}: closed after {:?}, bound {bound:?}", t0.elapsed());
    }

    // 3. valid messages above the per-pair limit (10/min): the answers are typed and the excess is rejected.
    let (mut accepted, mut limited, mut other) = (0u32, 0u32, Vec::new());
    let mut accepted_ids = Vec::new();
    for n in 0..40u64 {
        let r = send(&sock, &session, 100 + n, &format!("FLOODMSG-{n}"), Duration::from_secs(15)).expect("send");
        match (r["reply"].as_str(), r["outcome"]["outcome"].as_str(), r["outcome"]["reason"].as_str()) {
            (Some("send"), Some("delivered" | "held" | "watching"), _) => {
                accepted += 1;
                accepted_ids.push(n);
            }
            (Some("send"), Some("rejected"), Some("rate_limited")) => limited += 1,
            (Some("send"), Some("rejected"), Some("saturated")) => limited += 1,
            _ => other.push(r.to_string()),
        }
    }
    assert!(other.is_empty(), "untyped answers: {other:?}");
    assert!(accepted >= 1, "all 40 valid sends were rejected; nothing was accepted");
    assert!(accepted <= 10, "{accepted} messages accepted above the 10/min pair limit");
    assert!(limited >= 20, "only {limited} rate-limited answers");
    assert_eq!(accepted + limited, 40, "every send is either accepted or typed-rejected");
    // the messages that reach the mock model are exactly the accepted ones (accepted ones may take a turn to arrive)
    // `FLOODMSG-1` must not match `FLOODMSG-10`: the character after the tag must not be a digit.
    let has_tag = |text: &str, n: u64| {
        let tag = format!("FLOODMSG-{n}");
        text.match_indices(&tag).any(|(i, _)| !text[i + tag.len()..].starts_with(|ch: char| ch.is_ascii_digit()))
    };
    let reached = |c: &ContentController| -> Vec<u64> {
        let bodies: Vec<String> = c.request_bodies().iter().map(Value::to_string).collect();
        (0..40u64).filter(|n| bodies.iter().any(|b| has_tag(b, *n))).collect()
    };
    let end = Instant::now() + Duration::from_secs(60);
    while reached(&c) != accepted_ids && Instant::now() < end {
        p.update(Duration::from_millis(500));
    }
    assert_eq!(reached(&c), accepted_ids, "the messages that reached the model are not exactly the accepted ones");

    // 4. still alive, still answering, fds back near the baseline.
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        p.update(Duration::from_millis(500));
        let now = fd_count(&p);
        if now <= fds_before + 4 {
            break;
        }
        assert!(Instant::now() < end, "fds {now} did not return to baseline {fds_before}");
    }
    assert!(p.is_running().unwrap(), "pager died\n{}", p.screen_contents());
    assert!(!list(&sock, Duration::from_secs(10)).expect("legit list after the flood").is_empty());
    run_slash(&mut p, "/peers status", "Peer inbox: ready", Duration::from_secs(30));
}

// ---- test 2: one leader, two windows -------------------------------------------------------------------------------

/// A leader process this test spawned. Dropped: killed and reaped through its own `Child` handle (`Child::kill`), nothing else.
/// `Child` records a reaped status (set by `try_wait`/`wait`) and then `kill` sends nothing and returns `Ok(())` (std docs: "If the child
/// has already exited, `Ok(())` is returned"; std `send_signal` skips the signal once `status` is set, so a recycled pid is never hit).
struct LeaderProc {
    child: Option<std::process::Child>,
    log: PathBuf,
}

impl LeaderProc {
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    fn alive(&mut self) -> bool {
        self.child.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }
}

impl Drop for LeaderProc {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// An EAGER leader (`agent leader` without `--relay-on-demand`: it connects its relay at startup when it has one),
/// with the sandbox environment of `c`, on its own socket. `extra_env` is added; `FUIGO_API_KEY` is dropped when
/// `oauth` (so the seeded first-party session is the credential).
#[allow(clippy::disallowed_methods, reason = "the child is held in LeaderProc and killed by its own pid on drop")]
fn spawn_leader(c: &ContentController, wd: &Watchdog, sock: &Path, oauth: bool, extra_env: &[(&str, &str)]) -> LeaderProc {
    let bin = pager_binary().expect("pager binary (set PAGER_BINARY)");
    let log = c.home().join("leader-p14a.log");
    let out = std::fs::File::create(&log).expect("leader log");
    let err = out.try_clone().expect("leader log clone");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["agent", "leader", "--no-exit-on-disconnect", "--no-auto-update"]);
    cmd.current_dir(c.sandbox().workspace());
    c.sandbox().apply_to_std_command(&mut cmd);
    cmd.env("FUIGO_PEER_MESSAGING", "1").env("FUIGO_LEADER_SOCKET", sock).env("RUST_LOG", "fuigo_shell=info");
    if oauth {
        cmd.env_remove("FUIGO_API_KEY");
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::null()).stdout(out).stderr(err);
    let child = cmd.spawn().expect("spawn leader");
    let _ = wd.register_pid(child.id());
    LeaderProc { child: Some(child), log }
}

/// A pager window attached to the leader on `sock` (its own new session).
fn spawn_window(c: &ContentController, wd: &Watchdog, sock: &Path, oauth: bool, extra_env: &[(&str, &str)]) -> PtyHarness {
    let bin = pager_binary().expect("pager binary (set PAGER_BINARY)");
    let mut ops = vec![EnvOp::set("FUIGO_PEER_MESSAGING", "1")];
    if oauth {
        ops.push(EnvOp::remove("FUIGO_API_KEY"));
    }
    ops.extend(extra_env.iter().map(|(k, v)| EnvOp::set(k, v)));
    let args = ["--leader", "--leader-socket", sock.to_str().expect("utf-8 socket path")];
    let mut h = PtyHarness::spawn_with_content_env_ops(&bin, ROWS, COLS, c, &args, &ops).expect("spawn window");
    let _ = wd.register(&h);
    h.wait_for_text("Quit", T).expect("welcome");
    submit_turn(&mut h, "go", "PEERBOOT", T);
    h
}

fn wait_for_path(p: &Path, what: &str, secs: u64) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !p.exists() {
        assert!(Instant::now() < end, "{what} never appeared at {}", p.display());
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn host_row(home: &Path, secs: u64) -> Option<HostRow> {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(r) = rows_of(home).into_iter().next() {
            return Some(r);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn sid8(row: &Value) -> String {
    let a = row["address"].as_str().expect("address");
    let sid = a.split('/').nth(1).expect("session id in address");
    // the leading characters of a session id are time-ordered and shared between sessions; the tail is not
    sid.chars().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_with_two_windows_list_each_other_and_receive_messages() {
    let wd = Watchdog::start(Duration::from_secs(1200));

    // (a) a plain leader with two windows. (b)/(c) remote attach and detach are NOT covered here: see the receipt.
    let c = ContentController::start().await.expect("content");
    c.set_response("PEERBOOT ok");
    let home = fuigo_home(&c);
    let sock = home.join("leader-p14a.sock");
    let mut leader = spawn_leader(&c, &wd, &sock, false, &[]);
    wait_for_path(&sock, "leader socket", 60);
    let mut w1 = spawn_window(&c, &wd, &sock, false, &[]);
    let mut w2 = spawn_window(&c, &wd, &sock, false, &[]);
    assert!(leader.alive(), "leader died\n{}", leader.log_text());
    let row = host_row(&home, 60).unwrap_or_else(|| panic!("no host row\n{}", leader.log_text()));
    assert_eq!(rows_of(&home).len(), 1, "one leader process is one host");
    let inbox = sock_of(&home, &row);
    let end = Instant::now() + Duration::from_secs(60);
    let rows = loop {
        let l = list(&inbox, Duration::from_secs(5)).unwrap_or_default();
        if l.len() >= 2 {
            break l;
        }
        assert!(Instant::now() < end, "the leader never listed two sessions: {l:?}");
        w1.update(Duration::from_millis(200));
        w2.update(Duration::from_millis(200));
    };
    assert_eq!(rows.len(), 2, "two windows, two sessions: {rows:?}");
    let (p1, p2) = (sid8(&rows[0]), sid8(&rows[1]));
    assert_ne!(p1, p2);
    // each window's `/peers list` names itself and the other session
    for (name, w) in [("window 1", &mut w1), ("window 2", &mut w2)] {
        let t = run_slash(w, "/peers list", "relation=", Duration::from_secs(60));
        assert!(t.shows(&p1) && t.shows(&p2), "{name} does not list both sessions\n{}", t.screen);
        assert!(t.lacks("No other sessions"), "{name} sees no other session\n{}", t.screen);
    }
    // a message to each session reaches a model request; the send outcome is exactly `delivered` for both
    c.set_response("PEERREPLY ok");
    for (n, (row, tag)) in rows.iter().zip(["LEADMSG-ONE", "LEADMSG-TWO"]).enumerate() {
        let to: Address = row["address"].as_str().unwrap().parse().expect("address");
        let r = send(&inbox, &to, 1 + n as u64, tag, Duration::from_secs(15)).expect("send to the leader");
        assert_eq!(r["reply"], "send", "{r}");
        // both windows are idle and in the same (default) mode, so the exact outcome is `delivered`
        assert_eq!(r["outcome"]["outcome"], "delivered", "send to session {n}: {r}");
    }
    let end = Instant::now() + Duration::from_secs(90);
    loop {
        w1.update(Duration::from_millis(250));
        w2.update(Duration::from_millis(250));
        let bodies = c.request_bodies();
        if ["LEADMSG-ONE", "LEADMSG-TWO"].iter().all(|m| bodies.iter().any(|v| v.to_string().contains(m))) {
            break;
        }
        assert!(Instant::now() < end, "a message never reached a model request\n{}\n{}", w1.screen_contents(), w2.screen_contents());
    }
    drop((w1, w2, leader));
}
