//! Plain CLI logout removes subscription credentials before the next token lookup.

use fuigo_shell::auth::subscription::{SubscriptionError, SubscriptionProvider, SubscriptionStore};

fn pager_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PAGER_BINARY") {
        return std::path::absolute(path).expect("absolute pager binary path");
    }
    option_env!("CARGO_BIN_EXE_fuigo-pager")
        .map(std::path::PathBuf::from)
        .expect("pager binary supplied by the build server")
}

#[tokio::test]
async fn plain_logout_deletes_all_subscription_tokens_and_requires_sign_in() {
    let sandbox = fuigo_test_support::TestSandbox::builder().build();
    let subscriptions = sandbox.fuigo_home().join("subscriptions");
    std::fs::create_dir_all(&subscriptions).unwrap();
    let credentials = subscriptions.join("credentials.json");
    std::fs::write(
        &credentials,
        serde_json::to_vec(&serde_json::json!({
            "chatgpt": {
                "selected": "a",
                "accounts": {"a": {
                    "provider": "chatgpt",
                    "issuer": "https://auth.openai.com",
                    "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
                    "account": "a",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expires_at": 4102444800_u64,
                    "refresh_pending": false
                }}
            },
            "xai": {
                "selected": "b",
                "accounts": {"b": {
                    "provider": "xai",
                    "issuer": "https://auth.x.ai",
                    "client_id": "b1a00492-073a-47ea-816f-4c329264a828",
                    "account": "b",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expires_at": 4102444800_u64,
                    "refresh_pending": false
                }}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let store = SubscriptionStore::new(sandbox.fuigo_home());
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        assert_eq!(store.status(provider).await.unwrap().len(), 1);
    }
    let mut command = tokio::process::Command::new(pager_binary());
    command
        .args(["--no-auto-update", "logout"])
        .env_clear()
        .envs(sandbox.env())
        .current_dir(sandbox.workspace())
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), command.output())
        .await
        .expect("logout completed before deadline")
        .expect("run logout");
    assert!(
        output.status.success(),
        "logout failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!credentials.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("provider tokens were not revoked"));
    for provider in [SubscriptionProvider::Chatgpt, SubscriptionProvider::Xai] {
        assert!(matches!(
            store.access(provider, None).await,
            Err(SubscriptionError::LoginRequired)
        ));
    }
    assert!(!credentials.exists());
}
