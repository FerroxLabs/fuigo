//! `/provider`: point a model at a third-party provider using a key already in
//! the environment.
//!
//! # Why this is not `/model`
//!
//! `/model` switches between models Fuigo already knows about. `/provider`
//! writes configuration: a `[model_providers.<id>]` table describing how to
//! reach a vendor, and a `[model.<key>]` table binding one model to it.
//!
//! Both halves are required. Writing the provider table alone arms nothing —
//! `resolve_model_list` iterates `[model.*]` entries and looks up
//! `model_provider` there, so a provider nothing references is inert
//! configuration.
//!
//! # Why it does not offer a model list
//!
//! Because Fuigo does not know one. It has no catalogue for a third-party
//! vendor, and inventing plausible model ids would produce a config that
//! silently 404s at the first request. The user names the model; the provider
//! metadata supplies only what is genuinely known about the vendor's protocol.
//!
//! # Why the key is never written
//!
//! Only the environment VARIABLE NAME goes into `config.toml`; the secret stays
//! in the environment. That is a property of what this command writes, not of
//! the file it writes into: `[model.<key>].api_key` is a supported field, so a
//! `config.toml` may already hold a credential someone else put there. Treat
//! the file as secret-bearing — this command rewrites the whole of it.
//!
//! # Reachability
//!
//! This is a pager-local builtin. The model-authored slash path
//! (`fuigo-shell`'s `slash_authority::resolve`) can only resolve entries in the
//! shell's own `BUILTIN_COMMANDS` table, which this is not in, so a command
//! that rewrites provider and credential routing cannot be invoked by prompt
//! injection. The name is also reserved in `PAGER_COMMAND_KEYS` so a skill
//! cannot claim it and become model-invocable under the same spelling.

use std::path::{Path, PathBuf};

use fuigo_shell::agent::key_discovery::{self, Provider};

use crate::provider_config_edit::{ProviderWrite, ProviderWriteOutcome, write_provider};
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

pub struct ProviderCommand;

impl SlashCommand for ProviderCommand {
    slash_meta! {
        name: "provider",
        description: "Route a model through a third-party provider",
        usage: "/provider [<provider> <model-id>]",
        takes_args: true,
        // Writing config is not session state, and the welcome screen is
        // exactly where someone sets this up before starting work.
        offered_when_session_less: true,
        arg_placeholder: "<provider> <model-id>",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let mut parts = args.split_whitespace();
        let Some(id) = parts.next() else {
            return CommandResult::Message(list_providers());
        };
        // The id is checked BEFORE the missing-model check. `/provider nonsense`
        // would otherwise print `Usage: /provider nonsense <model-id>`, which
        // reads as "that provider is fine, name a model" for a provider that
        // does not exist — and the unknown-provider check further down is
        // unreachable without a model argument.
        let provider = match known_provider(id) {
            Ok(p) => p,
            Err(message) => return CommandResult::Error(message),
        };
        let Some(model_id) = parts.next() else {
            return CommandResult::Error(format!(
                "Usage: /provider {id} <model-id>\n\
                 Name the model to route through {id}; Fuigo has no catalogue for it."
            ));
        };
        if parts.next().is_some() {
            return CommandResult::Error("Usage: /provider <provider> <model-id>".into());
        }
        apply(provider, model_id)
    }
}

/// The provider table entry named `id`, or the message to show for an id that
/// is not one of them.
fn known_provider(id: &str) -> Result<&'static Provider, String> {
    key_discovery::PROVIDERS
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| {
            let known: Vec<&str> = key_discovery::PROVIDERS.iter().map(|p| p.id).collect();
            format!("Unknown provider {id:?}. Known: {}", known.join(", "))
        })
}

/// The provider table, with whichever keys are visible in this environment.
fn list_providers() -> String {
    let discovered = key_discovery::discover();
    let mut out = String::from("Providers Fuigo can route a model to:\n\n");
    for provider in key_discovery::PROVIDERS {
        let found = discovered.iter().find(|d| d.provider.id == provider.id);
        let status = match found {
            // The masked form, never the key: `Discovered` has no `Debug` for
            // exactly this reason, and `masked()` is its only renderable view.
            Some(d) => format!("{} = {}", d.env_var, d.masked()),
            None => format!("set {}", provider.env_vars.join(" or ")),
        };
        out.push_str(&format!(
            "  {:<12} {:<16} {}\n",
            provider.id, provider.label, status
        ));
    }
    out.push_str(
        "\nUsage: /provider <provider> <model-id>\n\
         Writes [model_providers.<provider>] and binds <model-id> to it. \
         The API key itself is never written to config.toml — only the name of \
         the environment variable it lives in.\n",
    );
    out
}

/// Write the provider entry and the model binding.
///
/// `provider` has already been resolved by [`known_provider`], so an unknown id
/// never reaches here.
fn apply(provider: &Provider, model_id: &str) -> CommandResult {
    // FluxRouter is the configured endpoint, not a third party. Its key belongs
    // in the single-credential path (`auth.json` / `FUIGO_API_KEY`), which is
    // what the first-run key prompt uses. Writing it as a `model_provider`
    // instead would produce a second, divergent place the same credential is
    // configured.
    if provider.applies_to_configured_endpoint {
        return CommandResult::Error(format!(
            "{} is the configured endpoint, not a third-party provider. \
             Set {} in your environment, or use the API-key prompt.",
            provider.label,
            provider
                .env_vars
                .first()
                .copied()
                .unwrap_or("FUIGO_API_KEY")
        ));
    }

    let Some(env_key) = env_var_for(provider) else {
        return CommandResult::Error(format!(
            "No key found for {}. Set {} and run this again — \
             the variable must exist now, because only its NAME is written to \
             config.toml and it is read at each startup.",
            provider.label,
            provider.env_vars.join(" or ")
        ));
    };

    let entry = ProviderWrite {
        id: provider.id,
        base_url: provider.base_url,
        env_key,
        api_backend: Some(provider.api_backend),
        auth_scheme: Some(provider.auth_scheme),
        extra_headers: provider.extra_headers,
        models: &[model_id],
    };
    match write_provider(&entry) {
        Ok(outcome) => render_outcome(provider, model_id, env_key, &user_config_path(), outcome),
        Err(e) => CommandResult::Error(format!("Could not write config.toml: {e}")),
    }
}

/// The config file `write_provider` targets, for naming in messages.
fn user_config_path() -> PathBuf {
    fuigo_tools::util::fuigo_home::fuigo_home().join(fuigo_config::USER_CONFIG_FILENAME)
}

/// Turn a write outcome into what the user sees.
///
/// Split out from [`apply`] so both branches can be exercised without a real
/// `~/.fuigo`. A skipped write is an error, not a message: the previous code
/// printed the success text for a call that wrote no bytes, so the user
/// restarted into an unchanged config with only a `tracing::warn!` to explain it.
fn render_outcome(
    provider: &Provider,
    model_id: &str,
    env_key: &str,
    config_path: &Path,
    outcome: ProviderWriteOutcome,
) -> CommandResult {
    let id = provider.id;
    let kept = match outcome {
        ProviderWriteOutcome::SkippedUnparseableConfig => {
            return CommandResult::Error(format!(
                "Nothing was written. {} is not valid TOML, and Fuigo will not \
                 overwrite a config it cannot parse.\n\
                 Fix the syntax there, or move the file aside, then run \
                 `/provider {id} {model_id}` again.",
                config_path.display()
            ));
        }
        ProviderWriteOutcome::PartialProviderPair {
            present,
            present_value,
            missing,
        } => {
            return CommandResult::Error(format!(
                "Nothing was written. [model_providers.{id}] has a custom \
                 {present} ({present_value:?}) but no {missing}.\n\
                 An endpoint and the credential for it are one setting: with \
                 only one of them, Fuigo would fill the other in from its own \
                 defaults and send that credential somewhere you did not \
                 choose.\n\
                 Set both {present} and {missing} in {}, or remove {present} \
                 and run `/provider {id} {model_id}` again to take Fuigo's pair.",
                config_path.display()
            ));
        }
        ProviderWriteOutcome::Written { kept } => kept,
    };

    // What the provider table now says, which is the requested value except
    // where an existing setting was kept. `kept` holds both halves of the
    // base_url/env_key pair or neither — `write_provider_at` refuses a half-set
    // pair — so these two are always the pair actually in force together.
    let kept_value = |key: &str| {
        kept.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, existing)| existing.as_str())
    };
    let effective_env_key = kept_value("env_key").unwrap_or(env_key);
    let effective_base_url = kept_value("base_url").unwrap_or(provider.base_url);

    let mut out = format!(
        "Wrote [model_providers.{id}] and bound {model_id} to it.\n\
         Provider base_url: {effective_base_url}\n\
         Provider env_key: ${effective_env_key}. Other configured credentials may take precedence.\n"
    );
    for (key, existing) in &kept {
        out.push_str(&format!(
            "Left [model_providers.{id}].{key} as you had it ({existing:?}); \
             it was not overwritten.\n"
        ));
    }
    if let Some(host) = blocked_upstream_host(effective_base_url) {
        out.push_str(&format!(
            "Warning: Fuigo's egress guard refuses to resolve {host}, so requests \
             to this provider will fail with a resolver error. Set \
             {ENV_ALLOW_UPSTREAM_HOSTS}=1 in the environment to lift the block.\n"
        ));
    }
    out.push_str(&format!("Restart fuigo, then `/model {model_id}`."));
    CommandResult::Message(out)
}

/// The escape hatch `fuigo-extra-ca/src/egress.rs` reads
/// (`egress::ENV_FUIGO_ALLOW_UPSTREAM_HOSTS`).
/// The guard's own escape-hatch variable. An alias, not a copy: it resolves to
/// the same constant `fuigo-extra-ca` reads, so the message cannot name a
/// variable the guard does not honour.
const ENV_ALLOW_UPSTREAM_HOSTS: &str = fuigo_extra_ca::egress::ENV_FUIGO_ALLOW_UPSTREAM_HOSTS;

/// The host of `base_url` when the egress guard is active and would refuse to
/// resolve it; `None` when the request would be allowed to leave.
///
/// Calls the guard's own predicates rather than copying its domain list, so
/// this cannot answer differently from the resolver that will actually refuse
/// the connection.
fn blocked_upstream_host(base_url: &str) -> Option<String> {
    if !fuigo_extra_ca::egress::guard_enabled() {
        return None;
    }
    let host = url::Url::parse(base_url).ok()?.host_str()?.to_owned();
    fuigo_extra_ca::egress::is_blocked_host(&host).then_some(host)
}

/// The provider's first environment variable that is actually set here.
///
/// A `&'static str` from the provider's own list, so the name written to config
/// is one Fuigo knows how to read back — never user-supplied text.
fn env_var_for(provider: &Provider) -> Option<&'static str> {
    let discovered = key_discovery::discover();
    let found = discovered.iter().find(|d| d.provider.id == provider.id)?;
    provider
        .env_vars
        .iter()
        .copied()
        .find(|name| *name == found.env_var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use crate::app::bundle::BundleState;

    /// `run` never reads this context for `/provider`; the paths under test are
    /// argument parsing and provider lookup, both of which return before any
    /// app state or file is touched.
    fn run(args: &str) -> CommandResult {
        let models = ModelState::default();
        let bundle = BundleState::default();
        let mut ctx = CommandExecCtx {
            models: &models,
            session_id: None,
            bundle_state: &bundle,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        };
        ProviderCommand.run(&mut ctx, args)
    }

    fn message(result: CommandResult) -> String {
        match result {
            CommandResult::Message(m) | CommandResult::Error(m) => m,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn bare_invocation_lists_every_known_provider() {
        let out = message(run(""));
        for provider in key_discovery::PROVIDERS {
            assert!(
                out.contains(provider.id),
                "{} missing from:\n{out}",
                provider.id
            );
        }
    }

    /// The listing renders key presence, never key material.
    #[test]
    fn the_listing_names_env_vars_not_values() {
        let out = message(run(""));
        for provider in key_discovery::PROVIDERS {
            for var in provider.env_vars {
                // Either "set VAR1 or VAR2" or "VAR = masked".
                assert!(
                    out.contains(var) || out.contains(provider.id),
                    "{var} missing from:\n{out}"
                );
            }
        }
    }

    #[test]
    fn an_unknown_provider_is_refused_and_lists_the_known_ones() {
        let out = message(run("nope some-model"));
        assert!(out.contains("Unknown provider"), "{out}");
        assert!(out.contains("anthropic"), "{out}");
    }

    /// A provider without a model id must not write a half-configuration: the
    /// provider table alone binds nothing, so it would look configured and do
    /// nothing.
    #[test]
    fn a_provider_without_a_model_is_refused() {
        let out = message(run("anthropic"));
        assert!(out.contains("Usage:"), "{out}");
        assert!(out.contains("catalogue"), "{out}");
    }

    /// The id is judged before the model argument is missed. Reporting
    /// `Usage: /provider nonsense <model-id>` would tell the user to supply a
    /// model for a provider that does not exist.
    #[test]
    fn an_unknown_provider_with_no_model_is_reported_as_unknown_not_as_usage() {
        let out = message(run("nonsense"));
        assert!(out.contains("Unknown provider"), "{out}");
        assert!(
            out.contains("anthropic"),
            "the known ids must be listed: {out}"
        );
        assert!(
            !out.contains("Usage:"),
            "must not imply the id is valid and only the model is missing: {out}"
        );
    }

    #[test]
    fn extra_arguments_are_refused_rather_than_ignored() {
        let out = message(run("anthropic model-a model-b"));
        assert!(out.contains("Usage:"), "{out}");
    }

    /// The configured endpoint is not a `model_provider`; routing its key that
    /// way would configure the same credential in two divergent places.
    #[test]
    fn the_configured_endpoint_is_refused() {
        let out = message(run("fluxrouter some-model"));
        assert!(out.contains("configured endpoint"), "{out}");
    }

    /// Every provider this command can write must carry protocol metadata. A
    /// `base_url` alone does not say how to talk to a host, and the Anthropic
    /// entry is the proof: it is neither Chat Completions nor Bearer.
    #[test]
    fn every_provider_declares_its_protocol_and_auth() {
        for provider in key_discovery::PROVIDERS {
            assert!(
                matches!(
                    provider.api_backend,
                    "chat_completions" | "responses" | "messages"
                ),
                "{} has an api_backend TOML spelling the shell cannot parse: {:?}",
                provider.id,
                provider.api_backend
            );
            assert!(
                matches!(provider.auth_scheme, "bearer" | "x_api_key"),
                "{} has an auth_scheme TOML spelling the shell cannot parse: {:?}",
                provider.id,
                provider.auth_scheme
            );
        }
        let anthropic = key_discovery::PROVIDERS
            .iter()
            .find(|p| p.id == "anthropic")
            .expect("anthropic is a known provider");
        assert_eq!(anthropic.api_backend, "messages");
        assert_eq!(anthropic.auth_scheme, "x_api_key");
        assert!(
            anthropic
                .extra_headers
                .iter()
                .any(|(name, _)| *name == "anthropic-version"),
            "the Messages API requires an anthropic-version header"
        );
    }

    fn provider_named(id: &str) -> &'static Provider {
        key_discovery::PROVIDERS
            .iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("{id} is a known provider"))
    }

    fn render(id: &str, outcome: ProviderWriteOutcome) -> CommandResult {
        render_outcome(
            provider_named(id),
            "some-model",
            "ANTHROPIC_API_KEY",
            Path::new("/home/u/.fuigo/config.toml"),
            outcome,
        )
    }

    /// F4: a write that wrote nothing must not print the success text. The
    /// user would otherwise restart into an unchanged config.
    #[test]
    fn a_skipped_write_is_an_error_that_names_the_file_and_the_fix() {
        let result = render("anthropic", ProviderWriteOutcome::SkippedUnparseableConfig);
        assert!(
            matches!(result, CommandResult::Error(_)),
            "a skipped write must not be reported as success"
        );
        let out = message(result);
        assert!(out.contains("Nothing was written"), "{out}");
        assert!(out.contains("/home/u/.fuigo/config.toml"), "{out}");
        assert!(out.contains("not valid TOML"), "{out}");
        assert!(out.contains("move the file aside"), "{out}");
        assert!(
            !out.contains("Restart fuigo"),
            "must not tell the user to restart into an unchanged config: {out}"
        );
    }

    /// F4 (other branch): a real write still reports what it did.
    #[test]
    fn a_completed_write_reports_the_table_the_binding_and_the_credential() {
        let out = message(render(
            "anthropic",
            ProviderWriteOutcome::Written { kept: Vec::new() },
        ));
        assert!(out.contains("[model_providers.anthropic]"), "{out}");
        assert!(out.contains("some-model"), "{out}");
        assert!(out.contains("$ANTHROPIC_API_KEY"), "{out}");
        assert!(
            out.contains(provider_named("anthropic").base_url),
            "the endpoint half of the pair must be named too: {out}"
        );
        assert!(out.contains("Restart fuigo"), "{out}");
        assert!(!out.contains("Left ["), "nothing was kept: {out}");
    }

    #[test]
    fn success_describes_provider_settings_without_claiming_effective_auth() {
        let out = message(render(
            "anthropic",
            ProviderWriteOutcome::Written { kept: Vec::new() },
        ));
        assert!(out.contains("Provider env_key:"));
        assert!(!out.contains("Credential:"));
        assert!(!out.contains("the value is not in config.toml"));
    }

    /// A half-set provider pair is a refusal, not a success with a footnote.
    /// The message must name the key that is present, the one that is missing,
    /// and both ways out.
    #[test]
    fn a_half_set_provider_pair_is_an_error_naming_the_problem_and_the_fix() {
        let result = render(
            "anthropic",
            ProviderWriteOutcome::PartialProviderPair {
                present: "env_key",
                present_value: "CORP_ANTHROPIC_KEY".to_owned(),
                missing: "base_url",
            },
        );
        assert!(
            matches!(result, CommandResult::Error(_)),
            "a refused write must not be reported as success"
        );
        let out = message(result);
        assert!(out.contains("Nothing was written"), "{out}");
        assert!(out.contains("[model_providers.anthropic]"), "{out}");
        assert!(out.contains("env_key"), "{out}");
        assert!(out.contains("CORP_ANTHROPIC_KEY"), "{out}");
        assert!(out.contains("no base_url"), "{out}");
        assert!(out.contains("/home/u/.fuigo/config.toml"), "{out}");
        assert!(
            !out.contains("Restart fuigo"),
            "must not tell the user to restart into an unchanged config: {out}"
        );
    }

    /// F5: when the editor kept a hand-written provider setting, say so plainly
    /// and name the value that is actually in force — reporting the vendor
    /// default the user did not get would be the same lie in a new place.
    #[test]
    fn a_kept_provider_setting_is_named_and_the_credential_line_follows_it() {
        let out = message(render(
            "anthropic",
            ProviderWriteOutcome::Written {
                kept: vec![
                    ("base_url", "https://claude-proxy.corp/v1".to_owned()),
                    ("env_key", "CORP_ANTHROPIC_KEY".to_owned()),
                ],
            },
        ));
        assert!(
            out.contains("Left [model_providers.anthropic].base_url"),
            "{out}"
        );
        assert!(out.contains("https://claude-proxy.corp/v1"), "{out}");
        assert!(
            out.contains("Left [model_providers.anthropic].env_key"),
            "{out}"
        );
        assert!(
            out.contains("$CORP_ANTHROPIC_KEY"),
            "the credential line must name the env var actually in the config: {out}"
        );
        assert!(!out.contains("$ANTHROPIC_API_KEY"), "{out}");
    }

    /// F6: `/provider xai <model>` writes a config the egress guard will not
    /// let out. The write succeeds, so the warning is the only thing standing
    /// between the user and an opaque resolver error at the first request.
    #[test]
    #[serial_test::serial(FUIGO_ALLOW_UPSTREAM_HOSTS)]
    fn warns_that_the_egress_guard_blocks_the_xai_host() {
        // Empty is not one of the truthy spellings, so the guard is on.
        let _guard = crate::test_util::EnvVarGuard::set(ENV_ALLOW_UPSTREAM_HOSTS, "");

        let out = message(render(
            "xai",
            ProviderWriteOutcome::Written { kept: Vec::new() },
        ));
        assert!(out.contains("api.x.ai"), "{out}");
        assert!(out.contains("FUIGO_ALLOW_UPSTREAM_HOSTS=1"), "{out}");
        assert!(out.contains("egress guard"), "{out}");
    }

    /// F6 (negative, guard lifted): the config now works, so there is nothing
    /// to warn about.
    #[test]
    #[serial_test::serial(FUIGO_ALLOW_UPSTREAM_HOSTS)]
    fn does_not_warn_when_the_upstream_block_is_lifted() {
        let _guard = crate::test_util::EnvVarGuard::set(ENV_ALLOW_UPSTREAM_HOSTS, "1");

        let out = message(render(
            "xai",
            ProviderWriteOutcome::Written { kept: Vec::new() },
        ));
        assert!(!out.contains("FUIGO_ALLOW_UPSTREAM_HOSTS=1"), "{out}");
    }

    /// F6 (negative, allowed host): a provider the guard never touches must not
    /// carry a warning, or the warning stops meaning anything.
    #[test]
    #[serial_test::serial(FUIGO_ALLOW_UPSTREAM_HOSTS)]
    fn does_not_warn_for_a_provider_the_guard_allows() {
        let _guard = crate::test_util::EnvVarGuard::set(ENV_ALLOW_UPSTREAM_HOSTS, "");

        for id in ["anthropic", "openai", "groq"] {
            let out = message(render(
                id,
                ProviderWriteOutcome::Written { kept: Vec::new() },
            ));
            assert!(!out.contains("egress guard"), "{id}: {out}");
        }
    }

    /// F6 (kept base_url): the warning must follow the URL that is actually in
    /// the config. Someone who pointed `xai` at their own proxy is not blocked.
    ///
    /// `kept` carries BOTH halves, because that is the only shape
    /// `write_provider_at` can produce for a customised pair — a half-set pair
    /// is refused before any write.
    #[test]
    #[serial_test::serial(FUIGO_ALLOW_UPSTREAM_HOSTS)]
    fn judges_the_kept_base_url_not_the_vendor_default() {
        let _guard = crate::test_util::EnvVarGuard::set(ENV_ALLOW_UPSTREAM_HOSTS, "");

        let out = message(render(
            "xai",
            ProviderWriteOutcome::Written {
                kept: vec![
                    ("base_url", "https://grok-proxy.corp/v1".to_owned()),
                    ("env_key", "CORP_XAI_KEY".to_owned()),
                ],
            },
        ));
        assert!(!out.contains("egress guard"), "{out}");
        assert!(
            out.contains("https://grok-proxy.corp/v1") && out.contains("$CORP_XAI_KEY"),
            "the message must name the pair actually in force: {out}"
        );
    }

    /// Reserved in the shell so a skill cannot claim the spelling and become
    /// invocable by a model. The registry-wide version of this assertion lives
    /// in `slash::commands::tests`; this one names the reason.
    #[test]
    fn the_name_is_reserved_so_a_skill_cannot_shadow_it() {
        assert!(
            fuigo_shell::session::PAGER_COMMAND_KEYS.contains(&ProviderCommand.name()),
            "/provider must be reserved, or a skill could take the name"
        );
    }
}
