//! `fuigo models` subcommand.

use anyhow::Result;
use fuigo_shell::agent::config::Config as AgentConfig;
use fuigo_shell::cli_models::{AuthStatus, list_models};
use tokio_util::sync::CancellationToken;

use crate::client_identity::{PAGER_CLIENT_TYPE, PAGER_CLIENT_VERSION};

pub async fn list_available_models(agent_config: &AgentConfig) -> Result<()> {
    match AuthStatus::resolve(agent_config) {
        AuthStatus::ApiKey => fuigo_tty_utils::cli_println!("You are using FUIGO_API_KEY."),
        AuthStatus::LoggedIn(host) => fuigo_tty_utils::cli_println!("You are logged in with {}.", host),
        AuthStatus::ModelCredentials(model) => {
            fuigo_tty_utils::cli_println!("Model '{model}' is using its own API key.");
        }
        AuthStatus::DeploymentKey => fuigo_tty_utils::cli_println!("You are authenticated via deployment key."),
        AuthStatus::NotAuthenticated => fuigo_tty_utils::cli_println!("You are not authenticated."),
    }
    fuigo_tty_utils::cli_println!();
    // Output-only command: once the reader is gone (`fuigo models | head -1`, a parent that
    // exited) there is nobody to list models for, so skip starting the agent.
    if fuigo_tty_utils::best_effort_stdout::reader_gone() {
        return Ok(());
    }

    let cancel = CancellationToken::new();
    fuigo_telemetry::startup::mark_utility_process();
    let spawned = crate::acp::spawn::spawn_fuigo_shell(agent_config.clone(), &cancel, None).await?;
    // Cancel and join on every return path, including the `?` below
    let _agent_guard =
        crate::acp::spawn::AgentShutdownGuard::new(cancel.clone(), Some(spawned.thread_handle));

    let state = list_models(&spawned.channel.tx, PAGER_CLIENT_TYPE, PAGER_CLIENT_VERSION).await?;

    fuigo_tty_utils::cli_println!("Default model: {}", state.current_model_id.0);
    fuigo_tty_utils::cli_println!();
    fuigo_tty_utils::cli_println!("Available models:");
    for m in state.available_models {
        if m.model_id == state.current_model_id {
            fuigo_tty_utils::cli_println!("  * {} (default)", m.model_id.0);
        } else {
            fuigo_tty_utils::cli_println!("  - {}", m.model_id.0);
        }
    }

    Ok(())
}
