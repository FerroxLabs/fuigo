use crate::terminal::tmux_probe;

pub type TmuxProbeResult<T> = tmux_probe::TmuxQueryResult<T>;

pub trait TmuxOptionQuery {
    fn show_option(&self, option: &str) -> TmuxProbeResult<String>;

    /// A server-scope option such as `escape-time`.
    /// Defaults to unavailable so implementors that never read one stay silent.
    fn show_server_option(&self, _option: &str) -> TmuxProbeResult<String> {
        TmuxProbeResult::Unavailable
    }

    fn option_support(&self, option: &str) -> TmuxProbeResult<()>;

    fn control_mode(&self) -> TmuxProbeResult<bool>;

    /// The attached client's resolved terminal features.
    /// They decide whether tmux forwards 24-bit color or reduces it to the client terminfo palette.
    fn client_features(&self) -> TmuxProbeResult<String>;
}

pub struct LiveTmuxProbe;

impl TmuxOptionQuery for LiveTmuxProbe {
    fn show_option(&self, option: &str) -> TmuxProbeResult<String> {
        tmux_probe::query_option(option)
    }

    fn show_server_option(&self, option: &str) -> TmuxProbeResult<String> {
        tmux_probe::query_server_option(option)
    }

    fn option_support(&self, option: &str) -> TmuxProbeResult<()> {
        tmux_probe::query_option_support(option)
    }

    fn control_mode(&self) -> TmuxProbeResult<bool> {
        tmux_probe::query_control_mode()
    }

    fn client_features(&self) -> TmuxProbeResult<String> {
        tmux_probe::query_client_features()
    }
}
