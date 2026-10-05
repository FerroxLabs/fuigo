//! P17-F1: the MCP server writers replace `config.toml` atomically, under a
//! lock, and refuse to rewrite a file they could not parse.

use super::save_mcp_server_config_at;
use fuigo_config_types::McpServerConfig;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const PADDING: usize = 512 * 1024;

fn server() -> McpServerConfig {
    toml::from_str("command = \"echo\"\n").unwrap()
}

fn padded_seed() -> String {
    format!(
        "[padding]\nblob = \"{}\"\n\n[endpoints]\nsentinel = \"end\"\n",
        "x".repeat(PADDING)
    )
}

fn complete(content: &str) -> bool {
    let Ok(v) = toml::from_str::<toml::Value>(content) else {
        return false;
    };
    v.get("padding")
        .and_then(|t| t.get("blob"))
        .and_then(toml::Value::as_str)
        .is_some_and(|b| b.len() == PADDING)
        && v.get("endpoints")
            .and_then(|t| t.get("sentinel"))
            .and_then(toml::Value::as_str)
            == Some("end")
}

/// An unparseable config is not an empty one. Saving a server into it used to
/// rewrite the whole file down to that one server.
#[tokio::test]
async fn saving_a_server_refuses_to_overwrite_an_unparseable_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let broken = "[ui]\ntheme = \"dark\"\n[[[not toml\n";
    std::fs::write(&path, broken).unwrap();

    let err = save_mcp_server_config_at(&path, "srv", &server())
        .await
        .expect_err("an unparseable config must be refused");

    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
}

/// Two writers saving different servers into one file concurrently: every
/// save lands (no lost update) and a reader polling the file never sees it
/// torn. The writers used to share the fixed temp name `config.toml.tmp`, so
/// one could truncate the temp file the other was about to rename into place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_server_saves_neither_tear_nor_lose_updates() {
    const EACH: usize = 20;
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("config.toml"));
    std::fs::write(&*path, padded_seed()).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (stop, path) = (Arc::clone(&stop), Arc::clone(&path));
        std::thread::spawn(move || {
            let (mut reads, mut torn) = (0usize, 0usize);
            while !stop.load(Ordering::Relaxed) {
                if !std::fs::read_to_string(&*path).is_ok_and(|s| complete(&s)) {
                    torn += 1;
                }
                reads += 1;
            }
            (reads, torn)
        })
    };
    let spawn = |prefix: &'static str| {
        let path = Arc::clone(&path);
        tokio::spawn(async move {
            for i in 0..EACH {
                save_mcp_server_config_at(&path, &format!("{prefix}{i}"), &server())
                    .await
                    .unwrap();
            }
        })
    };
    let (a, b) = (spawn("a"), spawn("b"));
    a.await.unwrap();
    b.await.unwrap();
    stop.store(true, Ordering::Relaxed);
    let (reads, torn) = reader.join().unwrap();

    assert!(reads > 0, "the reader never ran");
    assert_eq!(torn, 0, "{torn} of {reads} reads saw a torn config.toml");
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(&*path).unwrap()).unwrap();
    let servers = v["mcp_servers"].as_table().unwrap();
    let missing: Vec<String> = ["a", "b"]
        .iter()
        .flat_map(|p| (0..EACH).map(move |i| format!("{p}{i}")))
        .filter(|name| !servers.contains_key(name))
        .collect();
    assert!(missing.is_empty(), "lost updates: {missing:?}");
    let strays: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(strays.is_empty(), "temp files left behind: {strays:?}");
}
