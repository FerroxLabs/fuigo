//! The saved-API-key helpers must use the same store as the auth manager: `FUIGO_AUTH_PATH` when set.
//! Its own process, because it sets that variable and in-crate tests read it unguarded.

use fuigo_shell::auth::{auth_json_path, clear_api_key, read_api_key, read_auth_json, store_api_key};

#[test]
fn api_key_helpers_use_the_auth_path_override() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let override_path = dir.path().join("elsewhere").join("creds.json");
    std::fs::create_dir_all(override_path.parent().unwrap()).unwrap();
    // SAFETY: this test binary has a single test, so nothing else touches the environment.
    unsafe { std::env::set_var("FUIGO_AUTH_PATH", &override_path) };

    store_api_key(&home, "k-123").unwrap();
    let store = read_auth_json(&auth_json_path(&home)).unwrap();
    assert!(store.keys().any(|k| k.contains("api_key")), "{:?}", store.keys().collect::<Vec<_>>());
    assert!(!home.join("auth.json").exists(), "the key must not land in the default file");
    assert_eq!(read_api_key(&home).as_deref(), Some("k-123"));

    clear_api_key(&home).unwrap();
    assert!(read_api_key(&home).is_none());
    assert!(!override_path.exists());
}
