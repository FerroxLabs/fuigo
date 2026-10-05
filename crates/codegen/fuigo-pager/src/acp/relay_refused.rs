//! Decode `fuigo/relay/refused` (P125) into the text the TUI shows for a relay the agent refused.
//!
//! The notification says which relay was refused, why and how to trust it (the shell's own refusal text). The text
//! crosses a process boundary, so control characters are dropped before it reaches the terminal.

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayRefusedParams {
    origin: Option<String>,
    message: Option<String>,
    session_id: Option<String>,
}

/// What the TUI shows for a refused relay: the full explanation for the scrollback and a short line for a toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayRefusal {
    /// The session whose relay sync was refused; `None` for the leader's refusal of its relay (every session).
    pub(crate) session_id: Option<String>,
    pub(crate) text: String,
    pub(crate) toast: String,
}

fn scrub(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// `None` when the params carry no usable message.
pub(crate) fn relay_refusal(params: &str) -> Option<RelayRefusal> {
    let parsed: RelayRefusedParams = serde_json::from_str(params).ok()?;
    let message = scrub(parsed.message.as_deref()?);
    if message.trim().is_empty() {
        return None;
    }
    let origin = parsed
        .origin
        .as_deref()
        .map(scrub)
        .filter(|o| !o.trim().is_empty());
    let toast = match origin {
        Some(origin) => format!("Relay {origin} refused: not trusted. Details are in the session"),
        None => "Relay refused: its URL is not usable. Details are in the session".to_owned(),
    };
    Some(RelayRefusal {
        session_id: parsed.session_id.as_deref().map(scrub).filter(|s| !s.is_empty()),
        text: message,
        toast,
    })
}
