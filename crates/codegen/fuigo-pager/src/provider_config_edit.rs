//! Write a `[model_providers.<id>]` entry — and the `[model.<key>]` bindings that
//! route models through it — into `~/.fuigo/config.toml`.
//!
//! Writing the provider table alone changes nothing that the agent reads: the
//! model resolver at `fuigo-shell/src/agent/config.rs` walks `cfg.config_models`
//! (the `[model.<key>]` entries) and looks a provider up only via each entry's
//! `model_provider`. So a provider with no model bound to it is inert, and this
//! module always writes both halves together.

use std::io;
use std::path::Path;


/// One provider entry plus the model keys that should route through it.
pub(crate) struct ProviderWrite<'a> {
    pub id: &'a str,
    pub base_url: &'a str,
    /// Environment VARIABLE NAME, never a key value. This struct deliberately has
    /// no field that could carry a secret; see `writes_env_var_name_and_has_no_field_for_a_secret`.
    pub env_key: &'a str,
    /// `"chat_completions"` | `"responses"` | `"messages"`, or None to omit.
    pub api_backend: Option<&'a str>,
    /// `"bearer"` | `"x_api_key"`, or None to omit.
    pub auth_scheme: Option<&'a str>,
    /// Literal headers, e.g. `[("anthropic-version", "2023-06-01")]`.
    pub extra_headers: &'a [(&'a str, &'a str)],
    /// `max_completion_tokens` for the provider table, or None to omit.
    ///
    /// Written only when the key is absent, unlike `api_backend` /
    /// `auth_scheme` / `extra_headers`: those spell the vendor's wire protocol
    /// and are not the user's to disagree with, whereas this is a token budget
    /// a user may legitimately have tuned for the model they run. Writing it at
    /// all is the point of the field -- the flow that creates the entry is the
    /// only one that can make the number visible and editable.
    pub max_completion_tokens: Option<u32>,
    /// Model keys to bind to this provider, e.g. `["claude-opus-4-6", "openai/gpt-4o"]`.
    pub models: &'a [&'a str],
}

/// What a write actually did. The caller must not report success from
/// `Ok(_)` alone: [`ProviderWriteOutcome::SkippedUnparseableConfig`] is a
/// successful *call* that changed no bytes on disk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProviderWriteOutcome {
    /// The document was rendered and renamed over the target.
    ///
    /// `kept` lists the `[model_providers.<id>]` settings that were already
    /// present with a different value and were therefore left as the user
    /// wrote them, as `(key, existing value)`. Empty when this call assigned
    /// every key it owns. Because `base_url` and `env_key` are decided as one
    /// unit and a half-set pair is refused (see [`Self::PartialProviderPair`]),
    /// `kept` holds either none of that pair or both of it — never one.
    Written { kept: Vec<(&'static str, String)> },
    /// The existing file was non-blank and did not parse, so nothing was
    /// written and the file is byte-identical.
    SkippedUnparseableConfig,
    /// `[model_providers.<id>]` already carried exactly one of `base_url` /
    /// `env_key` with a value this call did not choose, so keeping the user's
    /// pair whole would leave the pair half-set. Nothing was written and the
    /// file is byte-identical.
    ///
    /// `present` is the key that is set, `present_value` its value, and
    /// `missing` the one that is absent. See [`write_provider_at`] for why this
    /// is refused rather than completed.
    PartialProviderPair {
        present: &'static str,
        present_value: String,
        missing: &'static str,
    },
}

/// Write the provider into the `config.toml` at `path` (the user's is
/// `~/.fuigo/config.toml`; `/provider` passes it). Blocking I/O: it waits for
/// `config.toml.lock`, so callers run it off the input thread.
///
/// Creates the file and parent dir when missing. Returns
/// [`ProviderWriteOutcome::SkippedUnparseableConfig`] without writing when the
/// existing file is non-blank but unparseable, matching `config_toml_edit`'s
/// refusal to clobber a malformed config.
///
/// Only the keys named on [`ProviderWrite`] are assigned; every other key in the
/// two touched tables keeps its existing value and position, because the edit
/// runs on a parsed [`toml_edit::DocumentMut`] rather than re-serializing a struct.
///
/// `base_url` and `env_key` are treated as one unit: if either is already
/// present with a different value, BOTH are left as the user wrote them and
/// reported in [`ProviderWriteOutcome::Written`]'s `kept`. Deciding them
/// separately would let a hand-written corporate `env_key` survive while
/// `base_url` was reset to the vendor's public endpoint -- pointing a private
/// credential at a public host, a pairing the user never chose.
///
/// A pair kept whole can still be HALF-SET -- a custom `env_key` with no
/// `base_url` at all, or the reverse -- and that is refused outright with
/// [`ProviderWriteOutcome::PartialProviderPair`], writing nothing. Keeping such
/// a pair and still binding the model produces the same mispairing by omission:
/// with no `base_url` anywhere, `ModelOverride::apply` falls back to
/// `ModelEntry::fallback`, whose `base_url` is `endpoints.resolve_inference_base_url()`
/// -- the default inference endpoint -- while `resolve_credentials` reads the
/// custom `env_key` first, so the user's private credential is sent to a host
/// they never chose. Refusing keeps the invariant this module's docs claim:
/// the two halves are always written together or not at all.
///
/// `api_backend`, `auth_scheme` and `extra_headers` are still assigned
/// unconditionally: they spell the vendor's wire protocol rather than a routing
/// choice.
///
/// The read-modify-rename goes through `fuigo_config::fs_atomic::edit_locked`:
/// the rename runs under `config.toml.lock` and only onto the version that was
/// read, so a concurrent writer that also takes that lock cannot have this
/// change renamed away, or rename it away. Writers that do not take
/// it still can; the lock's own docs list which ones do.
pub(crate) fn write_provider_at(
    path: &Path,
    entry: &ProviderWrite<'_>,
) -> io::Result<ProviderWriteOutcome> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    fuigo_config::fs_atomic::edit_locked(
        path,
        |bytes| fuigo_config::fs_atomic::stage_atomically_from_existing(path, bytes, 0o600),
        |current| plan_provider_write(path, entry, current),
    )
    .map_err(io::Error::from)
}

/// Body of [`write_provider_at`]: read the config and decide what to write.
/// Runs inside `edit_locked`, which may call it more than once and renames the
/// result only if the file is still the version this read.
fn plan_provider_write(
    path: &Path,
    entry: &ProviderWrite<'_>,
    current: fuigo_config::fs_atomic::Current<'_>,
) -> io::Result<fuigo_config::fs_atomic::Edit<ProviderWriteOutcome>> {
    use fuigo_config::fs_atomic::Edit;
    let Some(mut doc) = crate::config_toml_edit::config_document_for_edit(path, current) else {
        return Ok(Edit::Keep(ProviderWriteOutcome::SkippedUnparseableConfig));
    };

    let root = doc.as_table_mut();
    let mut kept: Vec<(&'static str, String)> = Vec::new();

    {
        // `[model_providers]` itself carries no direct keys, so it is created
        // implicit: the rendered file gets `[model_providers.<id>]` and no bare
        // `[model_providers]` header above it.
        let providers = subtable_mut(root, "model_providers", true)?;
        let provider = subtable_mut(providers, entry.id, false)?;

        // `base_url` and `env_key` are decided TOGETHER, not key by key. They are
        // a destination and the credential for that destination, and mixing one
        // user value with one generated value produces a pairing nobody chose:
        // keep a corporate `env_key` while assigning the vendor's public
        // `base_url`, and the corporate credential is now pointed at the public
        // endpoint. Either the user's pair survives intact or the requested pair
        // is written intact.
        let existing_pair =
            [("base_url", entry.base_url), ("env_key", entry.env_key)].map(|(key, wanted)| {
                let existing = provider
                    .get(key)
                    .and_then(toml_edit::Item::as_str)
                    .map(str::to_owned);
                (key, wanted, existing)
            });
        let user_customised = existing_pair
            .iter()
            .any(|(_, wanted, existing)| existing.as_deref().is_some_and(|c| c != *wanted));
        // Keeping the user's pair whole is only meaningful if the pair IS
        // whole. When exactly one half is set, "keep both" leaves the other
        // absent, and resolution then supplies its own default for it: an
        // absent `base_url` becomes the default inference endpoint, an absent
        // `env_key` falls through to the ambient credential. Either way the
        // model would be bound to a (host, credential) pair nobody chose, so
        // refuse before touching the document — nothing is written.
        if user_customised && let Some(partial) = half_set_pair(&existing_pair) {
            return Ok(Edit::Keep(partial));
        }
        for (key, wanted, existing) in existing_pair {
            match existing {
                // One of the pair differs, so the whole pair is the user's.
                // Report both, including one that happens to match, so the
                // message describes the configuration they are actually left
                // with.
                Some(current) if user_customised => kept.push((key, current)),
                _ if user_customised => {}
                _ => provider[key] = toml_edit::value(wanted),
            }
        }

        if let Some(backend) = entry.api_backend {
            provider["api_backend"] = toml_edit::value(backend);
        }
        if let Some(scheme) = entry.auth_scheme {
            provider["auth_scheme"] = toml_edit::value(scheme);
        }
        if !entry.extra_headers.is_empty() {
            let headers = subtable_mut(provider, "extra_headers", false)?;
            for (name, value) in entry.extra_headers {
                headers[*name] = toml_edit::value(*value);
            }
        }
        // A budget the user may have tuned, so an existing value stands. See
        // `ProviderWrite::max_completion_tokens` for why this differs from the
        // three wire-protocol keys above.
        if let Some(max_tokens) = entry.max_completion_tokens
            && !provider.contains_key("max_completion_tokens")
        {
            provider["max_completion_tokens"] = toml_edit::value(i64::from(max_tokens));
        }
    }

    if !entry.models.is_empty() {
        let models = subtable_mut(root, "model", true)?;
        for key in entry.models {
            let model = subtable_mut(models, key, false)?;
            model["model_provider"] = toml_edit::value(entry.id);
        }
    }

    // Resolve the prospective document through runtime's complete layer/model
    // resolution before renaming anything. A model override can retain another
    // provider's credential even though model_provider now names this one.
    let mut layers = fuigo_config::ConfigLayers::load()?;
    layers.user = toml::from_str(&doc.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fuigo_config::expand_env_vars_in_toml(&mut layers.user);
    fuigo_config::apply_version_overrides_with_registered(&mut layers.user)?;
    let effective = fuigo_shell::util::config::effective_config_from_layers(&layers)?;
    fuigo_shell::agent::model_providers::validate_provider_binding(
        &effective,
        entry.id,
        entry.models,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // The caller's `stage` (`stage_atomically_from_existing`) creates a uniquely
    // named temp beside the target with `create_new`, with the mode the config
    // already has (minus group/world), or `0600` for a new one -- `config.toml`
    // supports `[model.<key>].api_key` -- and unlinks it on any error.
    Ok(Edit::Replace {
        contents: doc.to_string().into_bytes(),
        value: ProviderWriteOutcome::Written { kept },
    })
}


/// [`ProviderWriteOutcome::PartialProviderPair`] when exactly one of the two
/// `(key, wanted, existing)` entries is already set on disk; `None` when both
/// are set or neither is.
///
/// Called only once the pair has been judged the user's, so the alternative to
/// refusing is writing a provider whose surviving half is silently completed by
/// a resolution default.
fn half_set_pair(pair: &[(&'static str, &str, Option<String>); 2]) -> Option<ProviderWriteOutcome> {
    let [(first_key, _, first), (second_key, _, second)] = pair;
    let (present, present_value, missing) = match (first, second) {
        (Some(value), None) => (*first_key, value.clone(), *second_key),
        (None, Some(value)) => (*second_key, value.clone(), *first_key),
        // Both set or neither: the pair is whole, so there is nothing to refuse.
        _ => return None,
    };
    Some(ProviderWriteOutcome::PartialProviderPair {
        present,
        present_value,
        missing,
    })
}

/// Borrow `parent[key]` as a table, inserting an empty one when absent.
///
/// `implicit` applies only to a freshly inserted table: a table that already
/// exists in the parsed document keeps whatever header form the user wrote.
///
/// Errors (before anything is written) when the key exists but holds a
/// non-table, so a `model_providers = 5` in a hand-edited config is reported
/// rather than replaced.
fn subtable_mut<'d>(
    parent: &'d mut toml_edit::Table,
    key: &str,
    implicit: bool,
) -> io::Result<&'d mut toml_edit::Table> {
    if !parent.contains_key(key) {
        let mut fresh = toml_edit::Table::new();
        fresh.set_implicit(implicit);
        parent.insert(key, toml_edit::Item::Table(fresh));
    }
    parent[key].as_table_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.toml key `{key}` is not a table"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_test_support::EnvGuard;
    use std::fs;
    use tempfile::tempdir;

    fn sample<'a>(id: &'a str, models: &'a [&'a str]) -> ProviderWrite<'a> {
        ProviderWrite {
            id,
            base_url: "https://api.anthropic.com/v1",
            env_key: "ANTHROPIC_API_KEY",
            api_backend: Some("messages"),
            auth_scheme: Some("x_api_key"),
            extra_headers: &[("anthropic-version", "2023-06-01")],
            max_completion_tokens: Some(32_000),
            models,
        }
    }

    fn parse(path: &Path) -> toml::Table {
        toml::from_str(&fs::read_to_string(path).unwrap()).expect("written config must parse")
    }

    /// The `kept` list of a write that must have succeeded.
    fn kept_of(outcome: ProviderWriteOutcome) -> Vec<(&'static str, String)> {
        match outcome {
            ProviderWriteOutcome::Written { kept } => kept,
            other => panic!("expected a write, got {other:?}"),
        }
    }

    /// P13: before this, a `/provider`-written Anthropic entry carried the wire
    /// protocol but no token budget, so the sampler's own default decided
    /// `max_tokens` and nothing in the file it just wrote could change it. The
    /// number has to land in the config the flow creates, or it is not
    /// discoverable from the flow that created the problem.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_written_provider_entry_states_its_max_completion_tokens() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        kept_of(write_provider_at(&path, &sample("anthropic", &["claude-x"])).unwrap());
        assert_eq!(
            parse(&path)["model_providers"]["anthropic"]["max_completion_tokens"].as_integer(),
            Some(32_000),
        );
    }

    /// A budget, not a wire-protocol key: a value the user already chose stands.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn an_existing_max_completion_tokens_is_left_alone() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[model_providers.anthropic]\nbase_url = \"https://api.anthropic.com/v1\"\nenv_key = \"ANTHROPIC_API_KEY\"\nmax_completion_tokens = 8192\n",
        )
        .unwrap();
        kept_of(write_provider_at(&path, &sample("anthropic", &["claude-x"])).unwrap());
        assert_eq!(
            parse(&path)["model_providers"]["anthropic"]["max_completion_tokens"].as_integer(),
            Some(8192),
        );
    }

    /// `None` writes nothing: the OpenAI-compatible providers state no budget
    /// rather than inheriting Anthropic's, the same discipline `extra_headers`
    /// already follows with its empty slice.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_provider_with_no_budget_writes_no_max_completion_tokens() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        write_provider_at(
            &path,
            &ProviderWrite {
                id: "openai",
                base_url: "https://api.openai.com/v1",
                env_key: "OPENAI_API_KEY",
                api_backend: Some("responses"),
                auth_scheme: Some("bearer"),
                extra_headers: &[],
                max_completion_tokens: None,
                models: &["gpt-4o"],
            },
        )
        .unwrap();
        assert!(
            parse(&path)["model_providers"]["openai"]
                .get("max_completion_tokens")
                .is_none()
        );
    }

    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn provider_rebinding_refuses_conflicting_model_settings_atomically() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        for (key, value) in [
            ("env_key", "\"OLD_PROVIDER_KEY\""),
            ("env_key", r#"["ANTHROPIC_API_KEY", "OLD_PROVIDER_KEY"]"#),
            ("api_key", "\"old-secret\""),
            ("base_url", "\"https://old.example/v1\""),
            ("api_base_url", "\"https://old.example/v1\""),
            ("auth_provider", "\"old-helper\""),
            ("auth_scheme", "\"bearer\""),
            ("api_backend", "\"responses\""),
            ("extra_headers", "{ Authorization = \"old-secret\" }"),
            ("env_http_headers", "{ Authorization = \"OLD_KEY\" }"),
            ("query_params", "{ api_key = \"old-secret\" }"),
        ] {
            let dir = tempdir().unwrap();
            let _home = EnvGuard::set("FUIGO_HOME", dir.path());
            let path = dir.path().join("config.toml");
            let original = format!("[model.existing]\n{key} = {value}\n");
            fs::write(&path, &original).unwrap();
            let result = write_provider_at(&path, &sample("anthropic", &["new", "existing"]));
            let error =
                result.expect_err("conflicting model settings must refuse the entire write");
            assert!(error.to_string().contains(key), "{error}");
            assert!(!error.to_string().contains("old-secret"));
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn provider_rebinding_accepts_matching_model_settings() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        fs::write(&path, "[model.existing]\nenv_key = \"ANTHROPIC_API_KEY\"\nbase_url = \"https://api.anthropic.com/v1\"\ncontext_window = 123456\n").unwrap();
        kept_of(write_provider_at(&path, &sample("anthropic", &["existing"])).unwrap());
        assert_eq!(
            parse(&path)["model"]["existing"]["context_window"].as_integer(),
            Some(123456)
        );
    }

    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn provider_rebinding_accepts_single_element_env_key_array() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[model.existing]\nenv_key = [\"ANTHROPIC_API_KEY\"]\n",
        )
        .unwrap();
        kept_of(write_provider_at(&path, &sample("anthropic", &["existing"])).unwrap());
        assert!(parse(&path)["model"]["existing"]["env_key"].is_array());
    }

    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn provider_rebinding_accepts_an_inline_key_owned_by_the_provider() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
[model_providers.anthropic]
base_url = "https://api.anthropic.com/v1"
env_key = "ANTHROPIC_API_KEY"
api_key = "same-owned-key"
[model.existing]
base_url = "https://api.anthropic.com/v1"
api_key = "same-owned-key"
"#,
        )
        .unwrap();
        kept_of(write_provider_at(&path, &sample("anthropic", &["existing"])).unwrap());
        assert_eq!(
            parse(&path)["model"]["existing"]["api_key"].as_str(),
            Some("same-owned-key")
        );
    }

    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn provider_rebinding_checks_inherited_model_settings() {
        let Some(dir) = fuigo_test_support::env::fresh_process_home(
            "provider_config_edit::tests::provider_rebinding_checks_inherited_model_settings",
        ) else {
            return;
        };
        fs::write(
            dir.as_path().join("managed_config.toml"),
            "[model.existing]\nenv_key = \"CORPORATE_KEY\"\n",
        )
        .unwrap();
        let path = dir.as_path().join("config.toml");
        fs::write(&path, "# keep this file unchanged\n").unwrap();
        let error = write_provider_at(&path, &sample("anthropic", &["existing"]))
            .expect_err("effective managed model credential must be checked");
        assert!(error.to_string().contains("env_key"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# keep this file unchanged\n"
        );
    }

    /// Req 1: the provider table carries base_url, env_key, both optional scalars,
    /// and every extra header in a nested `extra_headers` table.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn writes_provider_table_with_scalars_and_nested_extra_headers() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let provider = parse(&path)["model_providers"]["anthropic"].clone();
        assert_eq!(
            provider["base_url"].as_str(),
            Some("https://api.anthropic.com/v1")
        );
        assert_eq!(provider["env_key"].as_str(), Some("ANTHROPIC_API_KEY"));
        assert_eq!(provider["api_backend"].as_str(), Some("messages"));
        assert_eq!(provider["auth_scheme"].as_str(), Some("x_api_key"));
        assert_eq!(
            provider["extra_headers"]["anthropic-version"].as_str(),
            Some("2023-06-01")
        );
    }

    /// Req 1 (negative): `None` optionals produce no key at all, rather than an
    /// empty string the resolver would have to special-case. An empty
    /// `extra_headers` slice likewise leaves no empty table behind.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn omits_optional_fields_when_none() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(
            &path,
            &ProviderWrite {
                id: "local",
                base_url: "http://127.0.0.1:8080/v1",
                env_key: "LOCAL_API_KEY",
                api_backend: None,
                auth_scheme: None,
                extra_headers: &[],
                max_completion_tokens: None,
                models: &["local-model"],
            },
        )
        .unwrap();

        let provider = parse(&path)["model_providers"]["local"].clone();
        assert!(provider.get("api_backend").is_none());
        assert!(provider.get("auth_scheme").is_none());
        assert!(provider.get("extra_headers").is_none());
    }

    /// Req 2: every model key gets `model_provider = "<id>"`. This is the half the
    /// agent's model resolver actually reads; the provider table alone arms nothing.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn binds_every_model_key_to_the_provider() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(
            &path,
            &sample("anthropic", &["claude-opus-4-6", "claude-sonnet-4-6"]),
        )
        .unwrap();

        let models = parse(&path)["model"].clone();
        for key in ["claude-opus-4-6", "claude-sonnet-4-6"] {
            assert_eq!(
                models[key]["model_provider"].as_str(),
                Some("anthropic"),
                "{key} should route through the provider"
            );
        }
    }

    /// A destination and its credential are one decision, and a HALF of that
    /// decision is not a decision at all. A custom `env_key` with no `base_url`
    /// used to be "kept" — which wrote no `base_url` and bound the model
    /// anyway, leaving resolution to supply the default inference endpoint for
    /// the corporate credential. Nothing is written now.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_half_set_pair_is_refused_and_writes_nothing() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        // The user set only `env_key`; `base_url` is absent.
        let original = "[model_providers.anthropic]\nenv_key = \"CORP_ANTHROPIC_KEY\"\n";
        std::fs::write(&path, original).unwrap();

        let outcome = write_provider_at(
            &path,
            &ProviderWrite {
                id: "anthropic",
                base_url: "https://api.anthropic.com/v1",
                env_key: "ANTHROPIC_API_KEY",
                api_backend: Some("messages"),
                auth_scheme: Some("x_api_key"),
                extra_headers: &[],
                max_completion_tokens: None,
                models: &["claude-x"],
            },
        )
        .unwrap();

        assert_eq!(
            outcome,
            ProviderWriteOutcome::PartialProviderPair {
                present: "env_key",
                present_value: "CORP_ANTHROPIC_KEY".to_owned(),
                missing: "base_url",
            }
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original,
            "a refused write must leave the file byte-identical"
        );
    }

    /// The refusal is symmetric: a custom `base_url` with no `env_key` is the
    /// same defect facing the other way — a corporate host paired with whatever
    /// ambient credential resolution finds.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_half_set_pair_is_refused_with_base_url_set_and_env_key_absent() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        let original = "[model_providers.anthropic]\nbase_url = \"https://claude-proxy.corp/v1\"\n";
        fs::write(&path, original).unwrap();

        let outcome = write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        assert_eq!(
            outcome,
            ProviderWriteOutcome::PartialProviderPair {
                present: "base_url",
                present_value: "https://claude-proxy.corp/v1".to_owned(),
                missing: "env_key",
            }
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    /// The half-set case must not get a `[model.*]` binding. That binding is
    /// the only half the resolver reads (`resolve_model_list` walks `[model.*]`
    /// and looks up `model_provider` there), so writing it is what arms the
    /// mispairing.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_half_set_pair_gets_no_model_binding() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(
            &path,
            "[model_providers.anthropic]\nenv_key = \"CORP_ANTHROPIC_KEY\"\n",
        )
        .unwrap();

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let doc = parse(&path);
        assert!(
            doc.get("model").is_none(),
            "no model may be bound to a half-set provider, got {:?}",
            doc.get("model")
        );
    }

    /// The pair that WOULD have reached resolution, asserted on the exact bytes
    /// on disk.
    ///
    /// This is not a live `resolve_credentials` call: that function and
    /// `try_resolve_model_credentials` are `pub(crate)` in `fuigo-shell`, so no
    /// test in this crate can invoke them. What it asserts instead is the input
    /// resolution would receive, and the chain it feeds (verified by reading
    /// `fuigo-shell`, not by executing it) is:
    /// `resolve_model_list` -> `ModelOverride::apply`, where a `[model.<key>]`
    /// with no `base_url` and a provider with no `base_url` falls through to
    /// `ModelEntry::fallback`, whose `info.base_url` is
    /// `endpoints.resolve_inference_base_url()` -- the DEFAULT inference
    /// endpoint -- while `resolve_credentials` takes `model.own_credential()`
    /// first, which reads the `env_key` copied down from the provider.
    /// So the pre-fix write produced (default inference host, CORP_ANTHROPIC_KEY).
    ///
    /// Post-fix there is no `[model.*]` entry at all, so resolution never sees
    /// this provider and no such pair exists.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_half_set_pair_leaves_no_host_credential_pair_for_resolution_to_find() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(
            &path,
            "[model_providers.anthropic]\nenv_key = \"CORP_ANTHROPIC_KEY\"\n",
        )
        .unwrap();

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let doc = parse(&path);
        // No binding: nothing routes through the provider, so the provider
        // table is inert configuration rather than an armed mispairing.
        assert!(doc.get("model").is_none());
        // And the provider half is exactly as the user left it — no `base_url`
        // was invented for the corporate key.
        let provider = doc["model_providers"]["anthropic"].clone();
        assert_eq!(provider["env_key"].as_str(), Some("CORP_ANTHROPIC_KEY"));
        assert!(provider.get("base_url").is_none());
        assert!(
            provider.get("api_backend").is_none(),
            "a refused write assigns nothing at all"
        );
    }

    /// Req 3: unrelated keys in a pre-existing `[model.<key>]` and
    /// `[model_providers.<id>]`, and unrelated sibling tables, all survive.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn merges_into_existing_tables_without_dropping_keys() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(
            &path,
            "[ui]\ncompact_mode = false\n\n\
             [model_providers.anthropic]\nrequest_max_retries = 3\n\n\
             [model.\"claude-opus-4-6\"]\ncontext_window = 100000\napi_key = \"pre-existing\"\n",
        )
        .unwrap();

        let original = fs::read_to_string(&path).unwrap();
        let error = write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"]))
            .expect_err("an existing model key must not be rebound");
        assert!(error.to_string().contains("api_key"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert_eq!(
            parse(&path)["model"]["claude-opus-4-6"]["api_key"].as_str(),
            Some("pre-existing")
        );
        // After the user removes the conflicting auth override, unrelated keys survive.
        fs::write(&path, original.replace("api_key = \"pre-existing\"\n", "")).unwrap();
        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let doc = parse(&path);
        assert_eq!(doc["ui"]["compact_mode"].as_bool(), Some(false));
        let provider = doc["model_providers"]["anthropic"].clone();
        assert_eq!(provider["request_max_retries"].as_integer(), Some(3));
        assert_eq!(
            provider["base_url"].as_str(),
            Some("https://api.anthropic.com/v1"),
            "an absent base_url is assigned"
        );
        let model = doc["model"]["claude-opus-4-6"].clone();
        assert_eq!(model["context_window"].as_integer(), Some(100_000));
        assert!(model.get("api_key").is_none());
        assert_eq!(model["model_provider"].as_str(), Some("anthropic"));
    }

    /// F5: a hand-written `base_url` and `env_key` are the user's routing and
    /// auth decisions. Overwriting them would move traffic off a corporate
    /// proxy and break the credential lookup, so both are kept, reported, and
    /// the model is bound to the provider as it stands.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn keeps_a_customised_base_url_and_env_key_and_reports_them() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(
            &path,
            "[model_providers.anthropic]\n\
             base_url = \"https://claude-proxy.corp/v1\"\n\
             env_key = \"CORP_ANTHROPIC_KEY\"\n",
        )
        .unwrap();

        let kept =
            kept_of(write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap());

        assert_eq!(
            kept,
            vec![
                ("base_url", "https://claude-proxy.corp/v1".to_owned()),
                ("env_key", "CORP_ANTHROPIC_KEY".to_owned()),
            ],
            "both customised settings must be reported as kept"
        );
        let doc = parse(&path);
        let provider = doc["model_providers"]["anthropic"].clone();
        assert_eq!(
            provider["base_url"].as_str(),
            Some("https://claude-proxy.corp/v1")
        );
        assert_eq!(provider["env_key"].as_str(), Some("CORP_ANTHROPIC_KEY"));
        assert_eq!(
            provider["api_backend"].as_str(),
            Some("messages"),
            "protocol keys are still assigned"
        );
        assert_eq!(
            doc["model"]["claude-opus-4-6"]["model_provider"].as_str(),
            Some("anthropic"),
            "the model is bound to the provider the user configured"
        );
    }

    /// F5 (negative): matching values are not "kept" — there is nothing the
    /// user would lose, so the outcome must not claim a customisation.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn reports_nothing_kept_when_the_existing_values_already_match() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        let entry = sample("anthropic", &["claude-opus-4-6"]);
        assert!(kept_of(write_provider_at(&path, &entry).unwrap()).is_empty());
        assert!(
            kept_of(write_provider_at(&path, &entry).unwrap()).is_empty(),
            "a re-run over an identical table keeps nothing"
        );
    }

    /// Req 4: model keys containing `/` or `.` are not bare TOML keys. Assert both
    /// the rendered spelling (toml_edit quotes them) and that a full re-parse finds
    /// the key exactly as given — a dotted key would otherwise nest a sub-table.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn quoted_model_keys_round_trip_exactly() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(&path, &sample("mixed", &["openai/gpt-4o", "gpt-4.1"])).unwrap();

        let body = fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("[model.\"openai/gpt-4o\"]"),
            "toml_edit must quote a key containing `/`, got:\n{body}"
        );
        assert!(
            body.contains("[model.\"gpt-4.1\"]"),
            "toml_edit must quote a key containing `.`, got:\n{body}"
        );

        let models = parse(&path)["model"].clone();
        assert_eq!(
            models["openai/gpt-4o"]["model_provider"].as_str(),
            Some("mixed")
        );
        assert_eq!(models["gpt-4.1"]["model_provider"].as_str(), Some("mixed"));
        assert!(
            models.get("openai").is_none() && models.get("gpt-4").is_none(),
            "a quoted key must not be re-parsed as a dotted path"
        );
    }

    /// Req 5: the written file carries the environment VARIABLE NAME. There is no
    /// secret to leak because [`ProviderWrite`] has no field holding a key value —
    /// `env_key` is the only credential-adjacent field and it names a variable.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn writes_env_var_name_and_has_no_field_for_a_secret() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(
            &path,
            &ProviderWrite {
                id: "openai",
                base_url: "https://api.openai.com/v1",
                env_key: "OPENAI_API_KEY",
                api_backend: Some("responses"),
                auth_scheme: Some("bearer"),
                extra_headers: &[],
                max_completion_tokens: None,
                models: &["gpt-4o"],
            },
        )
        .unwrap();

        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("OPENAI_API_KEY"), "got:\n{body}");
        assert_eq!(
            parse(&path)["model_providers"]["openai"]["env_key"].as_str(),
            Some("OPENAI_API_KEY")
        );
    }

    /// F4 + Req 6: a non-blank unparseable config is left byte-identical AND the
    /// caller is told nothing was written, so `/provider` cannot report success
    /// for a write that did not happen.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn unparseable_config_is_reported_as_skipped_and_left_byte_identical() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        let bad = "this is [not valid toml\n";
        fs::write(&path, bad).unwrap();

        let outcome = write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        assert_eq!(outcome, ProviderWriteOutcome::SkippedUnparseableConfig);
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
    }

    /// Req 7: the temp file is created beside the target (so `rename` stays within
    /// one filesystem) and nothing but the config and its write lock remains
    /// once the rename commits. The lock file is deliberately left in place —
    /// `flock` releases on close, and unlinking it would let the next writer
    /// create a fresh one and contend on nothing.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn leaves_no_temp_file_beside_the_target() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        // The config sits in its own directory: with FUIGO_HOME set, this process's fresh logger creates `logs/` under the home,
        // and the assertion is about what the write leaves beside the config, not about the home's other contents
        let cfg_dir = dir.path().join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let path = cfg_dir.join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let mut names: Vec<String> = fs::read_dir(&cfg_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let config = fuigo_config::USER_CONFIG_FILENAME.to_string();
        assert_eq!(
            names,
            vec![config.clone(), format!("{config}.lock")],
            "only the config and its lock should remain"
        );
    }

    /// F3: a write that fails after the temp file exists must not leave it
    /// behind. A directory at the target path lets the temp file be created and
    /// written, then fails the `rename` onto it.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn an_unreadable_config_is_skipped_without_writing_anything() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        // A directory where the config should be: readable as an entry, but not
        // as a file. This used to fall through to a write that failed at the
        // rename; now the read refuses first, which is the safer end of the same
        // problem -- a config this process cannot read is never replaced.
        fs::create_dir(&path).unwrap();

        let outcome = write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"]))
            .expect("an unreadable config is skipped, not an error");
        assert!(matches!(
            outcome,
            ProviderWriteOutcome::SkippedUnparseableConfig
        ));

        let strays: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
    }

    /// The temp-file cleanup property, exercised where the write itself fails:
    /// the temp is created and then the write into it fails (an injected fault,
    /// `fuigo_config::fs_atomic::stage_fault`). P49 bounded temp names, so the
    /// old obstacle -- a config name too long to take the temp suffix -- no
    /// longer fails; and a `chmod 0500` directory cannot be used, since the
    /// suite runs as root, which bypasses permission bits.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_failed_write_leaves_no_temp_file_behind() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("config.toml");
        fs::write(&path, "[ui]\ntheme = \"dark\"\n").unwrap();

        fuigo_config::fs_atomic::stage_fault::FAIL_WRITE.with(|f| f.set(true));
        let result = write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"]));
        fuigo_config::fs_atomic::stage_fault::FAIL_WRITE.with(|f| f.set(false));
        let err = result.expect_err("a write that fails filling its temp must fail");
        assert!(
            err.to_string().contains("injected write failure"),
            "the write must fail filling the temp, not somewhere earlier: {err}"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[ui]\ntheme = \"dark\"\n",
            "the config is untouched"
        );

        let strays: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[ui]\ntheme = \"dark\"\n",
            "a failed write must leave the original untouched"
        );
    }

    /// Req 8: a repeated write is a no-op on content — no duplicated tables or keys.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn second_write_produces_identical_content() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        let entry = sample("anthropic", &["claude-opus-4-6", "openai/gpt-4o"]);
        write_provider_at(&path, &entry).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        write_provider_at(&path, &entry).unwrap();
        let second = fs::read_to_string(&path).unwrap();

        assert_eq!(first, second);
    }

    /// Req 9: a missing parent directory and a missing file are both created.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn creates_missing_parent_dir_and_file() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join("nested/deeper/config.toml");

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        assert!(path.exists());
        assert_eq!(
            parse(&path)["model"]["claude-opus-4-6"]["model_provider"].as_str(),
            Some("anthropic")
        );
    }

    /// A hand-edited config where `model_providers` is not a table is reported
    /// rather than silently replaced, and the file is left untouched.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn non_table_model_providers_is_an_error_and_does_not_write() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        let original = "model_providers = 5\n";
        fs::write(&path, original).unwrap();

        let err = write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"]))
            .expect_err("a non-table should not be overwritten");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    /// F2: concurrent writers must not interleave bytes. Each thread renames its
    /// own uniquely named temp file, so whichever rename lands last wins whole —
    /// the file always parses and always carries a complete provider table.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn concurrent_writes_never_produce_a_torn_file() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = crate::test_util::memory_backed_tempdir();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let path = path.clone();
                scope.spawn(move || {
                    write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();
                });
            }
        });

        let doc = parse(&path);
        let provider = doc["model_providers"]["anthropic"].clone();
        assert_eq!(
            provider["base_url"].as_str(),
            Some("https://api.anthropic.com/v1")
        );
        assert_eq!(provider["env_key"].as_str(), Some("ANTHROPIC_API_KEY"));
        assert_eq!(provider["api_backend"].as_str(), Some("messages"));
        assert_eq!(provider["auth_scheme"].as_str(), Some("x_api_key"));
        assert_eq!(
            provider["extra_headers"]["anthropic-version"].as_str(),
            Some("2023-06-01")
        );
        assert_eq!(
            doc["model"]["claude-opus-4-6"]["model_provider"].as_str(),
            Some("anthropic")
        );

        let strays: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
    }

    /// Concurrent writers must not LOSE each other's changes, which is a
    /// stronger claim than "the file is never torn". Eight threads each write a
    /// DIFFERENT provider: without a lock across read-modify-rename they all
    /// read the same original and the last rename keeps only one entry.
    ///
    /// This exercises real `write_provider_at` calls on separate threads, each
    /// opening its own handle on `config.toml.lock`. `flock` is per open file
    /// description, so those handles contend with one another exactly as two
    /// processes would — the thing this proves is the lock, not thread-locality.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn concurrent_writes_of_different_providers_all_survive() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = crate::test_util::memory_backed_tempdir();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        let ids: Vec<String> = (0..8).map(|n| format!("vendor{n}")).collect();

        std::thread::scope(|scope| {
            for id in &ids {
                let path = path.clone();
                scope.spawn(move || {
                    let model = format!("{id}-model");
                    write_provider_at(&path, &sample(id, &[model.as_str()])).unwrap();
                });
            }
        });

        let doc = parse(&path);
        for id in &ids {
            assert!(
                doc["model_providers"].get(id).is_some(),
                "{id} was lost; surviving providers: {:?}",
                doc["model_providers"]
            );
            assert_eq!(
                doc["model"][format!("{id}-model")]["model_provider"].as_str(),
                Some(id.as_str()),
                "{id}'s model binding was lost"
            );
        }
    }

    /// `/provider` and the shell's settings writer are different processes
    /// editing the same file, so `/provider`'s change and a `[ui]` toggle must
    /// both survive a race.
    ///
    /// WHAT THIS PROVES: the real `/provider` writer (`write_provider_at`) and
    /// a writer of a different shape contend on ONE lock, taken through the
    /// same `fuigo_config::fs_atomic::lock_config_for_write` and derived from
    /// the same config path, and neither loses the other's change.
    ///
    /// WHAT IT DOES NOT PROVE: it does not execute `fuigo-shell`'s
    /// `util::config::persist::update_config`. That function resolves its path
    /// from `fuigo_home()`, which is cached process-wide in a `OnceLock`, so a
    /// unit test cannot point it at a temp dir without risking a write to the
    /// developer's real `~/.fuigo/config.toml`. The second writer here is a
    /// stand-in that reproduces `save_config_locked`'s shape — read the whole
    /// file as `toml::Value`, merge a `[ui]` section, re-render, rename — and
    /// takes the lock the way `update_config` now does. That the two lock calls
    /// actually exclude each other is asserted directly in `fs_atomic`'s own
    /// `a_second_holder_is_refused_until_the_first_drops`.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_provider_write_racing_a_settings_shaped_write_keeps_both() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = crate::test_util::memory_backed_tempdir();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ntheme = \"dark\"\n").unwrap();

        // Same shape as `fuigo-shell`'s `save_config_locked`: whole-file read,
        // section merge, re-render, atomic rename — under the shared lock.
        let settings_write = |n: usize| {
            fuigo_config::fs_atomic::locked_read_modify_write(&path, || {
                let mut root: toml::Table =
                    toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
                let ui = root
                    .entry("ui".to_string())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                ui.as_table_mut()
                    .unwrap()
                    .insert(format!("setting_{n}"), toml::Value::Boolean(true));
                fuigo_config::fs_atomic::write_atomically(
                    &path,
                    &toml::to_string_pretty(&root).unwrap(),
                    None,
                )
                .unwrap();
            })
            .unwrap();
        };

        std::thread::scope(|scope| {
            for n in 0..4 {
                scope.spawn(move || settings_write(n));
            }
            for n in 0..4 {
                let path = path.clone();
                scope.spawn(move || {
                    let id = format!("vendor{n}");
                    let model = format!("{id}-model");
                    write_provider_at(&path, &sample(&id, &[model.as_str()])).unwrap();
                });
            }
        });

        let doc = parse(&path);
        assert_eq!(
            doc["ui"]["theme"].as_str(),
            Some("dark"),
            "the pre-existing setting was lost"
        );
        for n in 0..4 {
            assert_eq!(
                doc["ui"][format!("setting_{n}")].as_bool(),
                Some(true),
                "settings write {n} was lost"
            );
            let id = format!("vendor{n}");
            assert!(
                doc["model_providers"].get(&id).is_some(),
                "/provider write {id} was lost"
            );
            assert_eq!(
                doc["model"][format!("{id}-model")]["model_provider"].as_str(),
                Some(id.as_str()),
                "/provider binding {id} was lost"
            );
        }
    }

    /// `/provider` must take the lock at the one name every other writer uses,
    /// or "the lock" is several locks and serializes nothing.
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn a_provider_write_takes_the_shared_config_lock() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        assert!(
            fuigo_config::fs_atomic::config_lock_path(&path).exists(),
            "the write did not go through config.toml.lock"
        );
    }

    /// F1: `rename` replaces the inode, so the target's mode is re-applied to
    /// the replacement at creation. A `chmod 600 config.toml` must survive a
    /// `/provider` run — the file supports `[model.<key>].api_key`.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn preserves_an_existing_restrictive_mode() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);
        fs::write(&path, "[ui]\ncompact_mode = false\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    /// F1: a config this command creates is `0600`, not whatever the umask
    /// would have produced, because it may come to hold an `api_key`.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial(FUIGO_HOME)]
    fn creates_a_new_config_readable_only_by_its_owner() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let _home = EnvGuard::set("FUIGO_HOME", dir.path());
        let path = dir.path().join(fuigo_config::USER_CONFIG_FILENAME);

        write_provider_at(&path, &sample("anthropic", &["claude-opus-4-6"])).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }
}
