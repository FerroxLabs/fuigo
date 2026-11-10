use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

use agent_client_protocol as acp;

use crate::acp::meta::NotificationMeta;
use crate::acp::tracker::AcpUpdateTracker;
use crate::scrollback::export::render_blocks_to_markdown;
use crate::scrollback::state::ScrollbackState;

#[derive(Debug, clap::Args, Clone)]
pub struct ExportArgs {
    /// Session ID to export
    pub session_id: String,
    /// Output file path (default: stdout)
    pub output: Option<PathBuf>,
    /// Copy to clipboard instead of writing to stdout
    #[arg(long, short)]
    pub clipboard: bool,
}

/// Empties a shell command's captured output in a tool result. The export keeps one summary line per tool, never the
/// output, so there is no reason to hold it (or hand it to the tracker) once it has been read off disk.
pub(crate) fn drop_bash_output(raw: &mut Option<serde_json::Value>) {
    use fuigo_tools::types::output::ToolOutput;
    let Some(value) = raw.as_ref() else { return };
    if let Ok(ToolOutput::Bash(mut bash)) = serde_json::from_value::<ToolOutput>(value.clone()) {
        bash.output = Vec::new();
        bash.output_for_prompt = String::new();
        if let Ok(slim) = serde_json::to_value(ToolOutput::Bash(bash)) {
            *raw = Some(slim);
        }
    }
}

fn drop_tool_output(update: &mut acp::SessionUpdate) {
    match update {
        acp::SessionUpdate::ToolCall(tc) => drop_bash_output(&mut tc.raw_output),
        acp::SessionUpdate::ToolCallUpdate(tcu) => drop_bash_output(&mut tcu.fields.raw_output),
        _ => {}
    }
}

/// The session's transcript as markdown, built by streaming its updates off disk one at a time (no list of every
/// update, no full scrollback of shell output). `Ok(None)` when the session has nothing to replay.
fn transcript_markdown_at(session_id: &str, fuigo_home: &std::path::Path) -> Result<Option<String>> {
    let mut tracker = AcpUpdateTracker::new();
    let mut scrollback = ScrollbackState::new();
    let replay_meta = NotificationMeta {
        is_replay: true,
        ..Default::default()
    };
    let emission = fuigo_shell::session::storage::stream_replay_updates_at(session_id, fuigo_home, |mut update| {
        drop_tool_output(&mut update);
        tracker.handle_update(update, &replay_meta, &mut scrollback);
    })?;
    if emission == fuigo_shell::session::storage::ReplayEmission::Empty {
        return Ok(None);
    }
    let blocks: Vec<_> = (0..scrollback.len())
        .filter_map(|i| scrollback.entry(i).map(|e| &e.block))
        .collect();
    Ok(Some(render_blocks_to_markdown(blocks)))
}

pub fn run(args: ExportArgs) -> Result<()> {
    tracing::info!(session_id = %args.session_id, "export_cmd: starting session export");

    let md = match transcript_markdown_at(&args.session_id, &fuigo_shell::util::fuigo_home::fuigo_home())? {
        Some(md) => md,
        None if fuigo_shell::session::resolve_local_session_any_cwd(&args.session_id).is_none() => {
            anyhow::bail!("Session '{}' not found.", args.session_id)
        }
        None => String::new(),
    };

    if md.is_empty() {
        anyhow::bail!(
            "Session '{}' has no conversation content to export",
            args.session_id
        );
    }

    if let Some(path) = args.output {
        let expanded = PathBuf::from(shellexpand::tilde(&path.to_string_lossy()).as_ref());
        // An existing file is never replaced
        crate::clipboard::write_text_to_new_file(&md, &expanded, false).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "{} already exists; not overwriting it. Choose another name or remove it first",
                    expanded.display()
                )
            } else {
                anyhow::Error::new(error).context(format!("Failed to write {}", expanded.display()))
            }
        })?;
        tracing::info!(
            session_id = %args.session_id,
            path = %expanded.display(),
            bytes = md.len(),
            "export_cmd: wrote transcript to file"
        );
        fuigo_tty_utils::cli_eprintln!(
            "Conversation exported to {}",
            fuigo_tty_utils::untrusted(expanded.display())
        );
    } else if args.clipboard {
        let _ = crate::clipboard::copy_text(&md);
        let lines = md.lines().count();
        tracing::info!(
            session_id = %args.session_id,
            bytes = md.len(),
            lines,
            "export_cmd: copied transcript to clipboard"
        );
        fuigo_tty_utils::cli_eprintln!(
            "Conversation copied to clipboard ({} chars, {} lines)",
            md.len(),
            lines
        );
    } else {
        let mut out = fuigo_tty_utils::best_effort_stdout::display_stdout();
        out.write_all(md.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::drop_bash_output;

    fn bash_value(output: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "Bash", "output": output.as_bytes(), "output_for_prompt": output, "exit_code": 3,
            "command": "make", "truncated": false, "signal": null, "timed_out": false, "description": null,
            "current_dir": "/w", "output_file": "", "total_bytes": output.len()
        })
    }

    /// 78.P1: a shell command's captured output is dropped as soon as it is read; its exit code and command are kept.
    #[test]
    fn bash_output_is_dropped_but_the_rest_of_the_result_is_kept() {
        let mut raw = Some(bash_value(&"x".repeat(100_000)));
        drop_bash_output(&mut raw);
        let slim = raw.expect("kept");
        assert_eq!(slim["output"].as_array().map(Vec::len), Some(0));
        assert_eq!(slim["output_for_prompt"], "");
        assert_eq!(slim["exit_code"], 3);
        assert_eq!(slim["command"], "make");
    }

    /// Anything that is not a bash result passes through untouched.
    #[test]
    fn other_results_are_untouched() {
        let other = serde_json::json!({ "type": "ReadFile", "content": "keep me" });
        let mut raw = Some(other.clone());
        drop_bash_output(&mut raw);
        assert_eq!(raw, Some(other));
        let mut none = None;
        drop_bash_output(&mut none);
        assert!(none.is_none());
    }
}
