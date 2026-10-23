// Per-test-case module for the `pty_e2e` integration test crate.
#[allow(unused_imports)]
use super::common::*;

/// Variables that would give the first run a credential of its own.
fn no_credentials() -> Vec<EnvOp<'static>> {
    let mut ops = Vec::from(oauth_credential_ops());
    for var in [
        "FLUX_API_KEY",
        "FUIGO_CODE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "XAI_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "DEEPSEEK_API_KEY",
        "MISTRAL_API_KEY",
    ] {
        ops.push(EnvOp::remove(var));
    }
    ops
}

/// First run with no credential of any kind: the picker offers Flux Router first and recommended. Choosing
/// it, entering a (fake) key and pressing Enter lands at the prompt on the catalog's default model, reached
/// through Flux Router. The mock server stands in for the gateway; nothing leaves the machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn first_run_picker_then_flux_key_lands_at_the_prompt_on_the_default_model() {
    let content = ContentController::start().await.expect("start content");
    let binary = pager_binary().expect("resolve pager binary");
    let mut harness = PtyHarness::spawn_with_content_env_ops_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &[],
        &no_credentials(),
        Some(content.home()),
    )
    .expect("spawn pager with no credentials");

    harness
        .wait_for_text("Choose how Fuigo reaches a model.", WELCOME_TIMEOUT)
        .expect("the picker heading");
    eprintln!(
        "--- first run picker (pty) ---\n{}\n------------------------------",
        harness.screen_contents()
    );
    let screen = harness.screen_contents();
    let flux = screen.find("Flux Router: one key, every model (recommended)").expect("flux row");
    let chatgpt = screen.find("ChatGPT subscription").expect("chatgpt row");
    let grok = screen.find("Grok subscription").expect("grok row");
    let keys = screen.find("Provider API key...").expect("provider key row");
    assert!(flux < chatgpt && chatgpt < grok && grok < keys, "{screen}");
    assert!(!screen.to_lowercase().contains("enterprise"), "{screen}");
    assert!(!screen.contains("OAuth2 issuer"), "{screen}");

    // Row 1 is Flux Router: the key screen names it and says where to get a key.
    harness.inject_keys(b"1").expect("choose Flux Router");
    harness
        .wait_for_text("Paste your Flux Router API key", WELCOME_TIMEOUT)
        .expect("flux key entry");
    harness
        .inject_keys(b"sk-pty-fake-flux-key-1234567890\r")
        .expect("type a fake key");

    harness
        .wait_for_text_absent("Choose how Fuigo reaches a model.", Duration::from_secs(30))
        .expect("the picker is gone once the key is accepted");
    harness
        .wait_for_text("test-model", Duration::from_secs(30))
        .expect("the prompt shows the catalog's default model");
    eprintln!(
        "--- after the key (pty) ---\n{}\n---------------------------",
        harness.screen_contents()
    );
    let after = harness.screen_contents();
    assert!(!after.contains("Grok subscription"), "{after}");
    assert!(
        !after.contains("sk-pty-fake-flux-key"),
        "the key must never be painted: {after}"
    );

    harness.quit().expect("clean quit");
}

/// `/login` opens the same picker over a signed-in session and Cancel returns without changing anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn login_command_opens_the_picker_with_cancel_not_the_oidc_error() {
    let content = ContentController::start().await.expect("start content");
    let binary = pager_binary().expect("resolve pager binary");
    let mut harness =
        PtyHarness::spawn_with_content(&binary, DEFAULT_ROWS, DEFAULT_COLS, &content, &[])
            .expect("spawn pager with the harness key");
    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome");

    harness.inject_keys(b"/login\r").expect("type /login");
    harness
        .wait_for_text("Choose how Fuigo reaches a model.", WELCOME_TIMEOUT)
        .expect("the picker opens");
    eprintln!(
        "--- /login picker (pty) ---\n{}\n---------------------------",
        harness.screen_contents()
    );
    let screen = harness.screen_contents();
    assert!(screen.contains("Cancel"), "{screen}");
    assert!(!screen.contains("OAuth2 issuer"), "{screen}");
    assert!(!screen.to_lowercase().contains("enterprise"), "{screen}");

    harness.inject_keys(b"q").expect("cancel");
    harness
        .wait_for_text_absent("Choose how Fuigo reaches a model.", Duration::from_secs(10))
        .expect("cancel closes the picker");

    harness.quit().expect("clean quit");
}
