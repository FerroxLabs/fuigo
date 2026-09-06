// webbrowser's macOS backend does not use the Unix/Linux `BROWSER` template.
#![cfg(all(unix, not(target_os = "macos")))]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

struct BrowserEnvGuard(Option<std::ffi::OsString>);

impl Drop for BrowserEnvGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => unsafe { std::env::set_var("BROWSER", value) },
            None => unsafe { std::env::remove_var("BROWSER") },
        }
    }
}

fn invoke_and_read(script: &Path, output: &Path, target: &str) -> Vec<String> {
    unsafe {
        std::env::set_var(
            "BROWSER",
            format!("{} {} --sentinel %s", script.display(), output.display()),
        )
    };
    webbrowser::open(target).expect("fake browser must launch");

    let deadline = Instant::now() + Duration::from_secs(2);
    while !output.exists() {
        assert!(
            Instant::now() < deadline,
            "fake browser did not record argv"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::read_to_string(output)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn browser_template_keeps_arguments_separate() {
    let _env = BrowserEnvGuard(std::env::var_os("BROWSER"));
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("fake-browser");
    std::fs::write(
        &script,
        "#!/bin/sh\nout=$1\nshift\nprintf '%s\\n' \"$@\" > \"$out\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&script, permissions).unwrap();

    let custom = invoke_and_read(
        &script,
        &tmp.path().join("custom.argv"),
        "fuigo://plugin/install path?name=two words",
    );
    assert_eq!(
        custom,
        [
            "--sentinel",
            "fuigo://plugin/install%20path?name=two%20words"
        ]
    );

    let https = invoke_and_read(
        &script,
        &tmp.path().join("https.argv"),
        "https://example.test/install path?name=two words",
    );
    assert_eq!(
        https,
        [
            "--sentinel",
            "https://example.test/install%20path?name=two%20words"
        ]
    );
}
