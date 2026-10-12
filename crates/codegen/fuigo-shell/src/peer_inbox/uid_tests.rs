//! Packet 8d: tests with a REAL second uid (65534) through `setpriv`, run as root on the build box. The second
//! account is driven by a tiny Python helper written into the test's own temp directory (the test binary lives under
//! `/root`, which uid 65534 cannot enter, so it cannot be its own helper). Skipping is explicit: if `setpriv` or
//! `python3` cannot run as uid 65534 the test FAILS with a clear message unless `FUIGO_TEST_ALLOW_NO_SETPRIV=1`, in
//! which case it prints a line starting `P8D-UID-SKIP` and returns.
//!
//! The host side runs as the test process (root on the box); the peer uid is 65534, so the uid comparison is root
//! against a non-root account. Directory/file permission tests rely on the owner (root) NOT being the second uid.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fuigo_peer::{HostDir, Op};

use super::dial::{DialError, dial};
use super::inbox::PeerInbox;
use super::inbox_tests::{hid, home_in, on, tmp};

const PRIV: [&str; 4] = ["--reuid=65534", "--regid=65534", "--clear-groups", "python3"];

#[allow(clippy::print_stdout, reason = "the skip line is the contract: the release log must show P8D-UID-SKIP")]
/// Whether the second-uid machinery works here. Panics (a failed test) when it does not, unless allowed to skip.
fn second_uid_available(t: &std::path::Path) -> bool {
    let probe = t.join("probe.py");
    std::fs::write(&probe, "import os; print(os.getuid())").unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = Command::new("setpriv").args(PRIV).arg("-I").arg(&probe).output();
    let ok = matches!(&out, Ok(o) if o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "65534");
    if ok {
        return true;
    }
    if std::env::var("FUIGO_TEST_ALLOW_NO_SETPRIV").as_deref() == Ok("1") {
        println!("P8D-UID-SKIP setpriv or python3 cannot run as uid 65534 here");
        return false;
    }
    panic!(
        "the second-uid tests need `setpriv --reuid=65534 python3` to work (as root); set FUIGO_TEST_ALLOW_NO_SETPRIV=1 to skip knowingly"
    );
}

fn script(t: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = t.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    p
}

fn as_other(script: &std::path::Path, args: &[&std::path::Path]) -> Command {
    let mut c = Command::new("setpriv");
    c.args(PRIV).arg("-I").arg(script).args(args);
    c
}

/// The temp root must be enterable by the second uid for the directory test to mean anything.
fn open_up(t: &std::path::Path) {
    std::fs::set_permissions(t, std::fs::Permissions::from_mode(0o755)).unwrap();
}

const STAT: &str = r#"
import os, sys, errno
for p in sys.argv[1:]:
    try:
        os.stat(p)
        print("OK")
    except OSError as e:
        print(errno.errorcode[e.errno])
"#;

const CLIENT: &str = r#"
import socket, sys, json, struct
s = socket.socket(socket.AF_UNIX); s.settimeout(4)
s.connect(sys.argv[1])
def frame(o):
    b = json.dumps(o).encode(); return struct.pack(">I", len(b)) + b
try:
    s.sendall(frame({"version": 1, "host_id": "ab" * 16}))
    s.sendall(frame({"op": "notice", "message_id": "m-1", "kind": "released"}))
except OSError:
    pass
got = b""
try:
    got = s.recv(4096)
except OSError:
    pass
print("BYTES=%d" % len(got))
"#;

const SERVER: &str = r#"
import socket, sys, os
d = sys.argv[1]
p = os.path.join(d, "s.sock")
s = socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p, 0o666); s.listen(4)
open(os.path.join(d, "ready"), "w").close()
s.settimeout(20)
n = -1
try:
    c, _ = s.accept(); c.settimeout(3)
    try:
        n = len(c.recv(4096))
    except OSError:
        n = 0
except OSError:
    pass
open(os.path.join(d, "got"), "w").write(str(n))
"#;

#[tokio::test]
async fn a_second_uid_cannot_traverse_the_peers_directory() {
    let t = tmp();
    open_up(t.path());
    if !second_uid_available(t.path()) {
        return;
    }
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let sock = a.locations().socket(a.host_id(), HostDir::Home).unwrap();
    let st = script(t.path(), "stat.py", STAT);
    let out = as_other(&st, &[&home, &home.join("peers"), &sock]).output().unwrap();
    let lines: Vec<_> = String::from_utf8_lossy(&out.stdout).lines().map(str::to_owned).collect();
    assert_eq!(lines, vec!["OK", "OK", "EACCES"], "can see home and the directory itself, not enter it: {out:?}");
}

#[tokio::test]
async fn with_a_test_only_chmod_a_second_uid_connects_and_is_dropped_unread() {
    let t = tmp();
    open_up(t.path());
    if !second_uid_available(t.path()) {
        return;
    }
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    a.directory().set_notice_sink(Arc::new(move |_, _, _| {
        h2.fetch_add(1, Ordering::SeqCst);
    }));
    let sock = a.locations().socket(a.host_id(), HostDir::Home).unwrap();
    // TEST-ONLY: open the directory and the socket to everybody, to prove the uid check itself drops the peer.
    std::fs::set_permissions(home.join("peers"), std::fs::Permissions::from_mode(0o711)).unwrap();
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
    let cl = script(t.path(), "client.py", CLIENT);
    let sock2 = sock.clone();
    let out = tokio::task::spawn_blocking(move || as_other(&cl, &[&sock2]).output().unwrap()).await.unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("BYTES=0"), "no reply byte, ever: {text:?} {out:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the host was never called");
}

#[tokio::test]
async fn a_client_refuses_a_server_of_the_second_uid_reached_through_a_symlinked_sock() {
    let t = tmp();
    open_up(t.path());
    if !second_uid_available(t.path()) {
        return;
    }
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let theirs = t.path().join("other");
    std::fs::create_dir(&theirs).unwrap();
    std::os::unix::fs::chown(&theirs, Some(65534), Some(65534)).unwrap();
    std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o755)).unwrap();
    let srv = script(t.path(), "server.py", SERVER);
    let theirs2 = theirs.clone();
    let child = tokio::task::spawn_blocking(move || as_other(&srv, &[&theirs2]).output().unwrap());
    // Wait (bounded, in the test only) until the helper's socket exists.
    for _ in 0..200 {
        if theirs.join("ready").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(theirs.join("ready").exists(), "the second-uid server did not start");
    let x = hid("5e5e0000000000005e5e000000000000");
    std::os::unix::fs::symlink(theirs.join("s.sock"), home.join("peers").join(format!("{x}.sock"))).unwrap();
    let r = dial(a.locations(), a.host_id(), &x, HostDir::Home, Op::List { page: 0 }).await;
    assert_eq!(r.err(), Some(DialError::WrongUser));
    let out = child.await.unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(theirs.join("got")).unwrap(), "0", "not one byte was written to it");
}
