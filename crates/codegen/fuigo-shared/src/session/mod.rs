use std::path::PathBuf;

pub mod info;

pub use info::Info;

// Re-export shared feedback wire types used by downstream crates (e.g. fuigo-pager-render).
pub use prod_mc_cli_chat_proxy_types::feedback_types::FeedbackTerminalInfo;

#[allow(clippy::disallowed_methods, reason = "the producer definition: computes <cwd bucket>/<id>; this crate never writes there (design F5 5.4.3)")]
pub fn session_dir(info: &Info) -> PathBuf {
    fuigo_tools::util::fuigo_home::sessions_cwd_dir(&info.cwd).join(info.id.to_string())
}
