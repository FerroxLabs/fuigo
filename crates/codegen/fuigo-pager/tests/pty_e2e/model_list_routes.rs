// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// A provider key in the environment plus its cached model list (the list a `/models` fetch leaves),
/// next to the Flux key the harness already holds: `/model` shows ONE ranked list with the route badge
/// on each row, and Right-arrow opens a model's other routes with a one-line reason each. The cache is
/// fresh, so nothing is fetched; nothing leaves the machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn model_list_shows_route_badges_and_right_arrow_opens_the_alternate_routes() {
    let content = ContentController::start().await.expect("start content");
    let binary = pager_binary().expect("resolve pager binary");
    let fuigo_home = content.home().join(".fuigo");
    std::fs::create_dir_all(fuigo_home.join("provider-keys")).expect("provider-keys dir");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(
        fuigo_home.join("provider-keys").join("models-openai.json"),
        format!(r#"{{"fetched_at":{now},"ids":["test-model","gpt-5"]}}"#),
    )
    .expect("seed the cached OpenAI model list");
    let ops = [EnvOp::set("OPENAI_API_KEY", "sk-pty-fake-openai-key-0123456789")];
    let mut harness = PtyHarness::spawn_with_content_env_ops_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &[],
        &ops,
        Some(content.home()),
    )
    .expect("spawn pager with a Flux key and an OpenAI key");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome");

    harness.inject_keys(b"/model\r").expect("open /model");
    harness
        .wait_for_text("your OpenAI key", WELCOME_TIMEOUT)
        .expect("the key's own model is listed with its route badge");
    let list = harness.screen_contents();
    eprintln!("--- /model list (pty) ---\n{list}\n-------------------------");
    assert!(list.contains("via Flux Router"), "{list}");
    assert!(list.contains("gpt-5") && list.contains("your OpenAI key"), "{list}");
    assert!(!list.contains("sk-pty-fake-openai-key"), "the key must never be painted: {list}");

    // Right-arrow on the first row (test-model: Flux Router and the OpenAI key) opens its routes.
    harness.inject_keys(b"\x1b[C").expect("Right-arrow");
    harness
        .wait_for_text("billed to your OpenAI key", WELCOME_TIMEOUT)
        .expect("the alternate-routes panel shows the OpenAI key route with its reason");
    let panel = harness.screen_contents();
    eprintln!("--- alternate routes (pty) ---\n{panel}\n------------------------------");
    assert!(panel.contains("via Flux Router"), "{panel}");

    harness.inject_keys(b"\x1b").expect("Esc steps back");
    harness.quit().expect("clean quit");
}
