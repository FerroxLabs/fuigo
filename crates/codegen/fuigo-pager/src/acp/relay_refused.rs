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
    fuigo_tty_utils::scrub_unsafe_display(text, None).into_owned()
}

/// A session id routes the refusal to one session by exact match, so only controls are removed from it (as before),
/// never the joiners a valid id may hold. It is not shown.
fn scrub_id(text: &str) -> String {
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
        session_id: parsed.session_id.as_deref().map(scrub_id).filter(|s| !s.is_empty()),
        text: message,
        toast,
    })
}

#[cfg(test)]
mod tests {
    use super::relay_refusal;

    /// P181: a refusal crosses a process boundary, so tag characters, soft hyphens and line separators are dropped from what is shown.
    #[test]
    fn hidden_characters_are_dropped_from_every_field() {
        let params = serde_json::json!({
            "origin": "https://r\u{e0041}.exa\u{00ad}mple",
            "message": "bad\u{2028}text\u{e0042}",
            "sessionId": "s\u{200d}1\u{7}",
        })
        .to_string();
        let refusal = relay_refusal(&params).expect("a message is present");
        assert_eq!(refusal.text, "badtext");
        // The id routes by exact match: controls go, a joiner a valid id may hold stays
        assert_eq!(refusal.session_id.as_deref(), Some("s\u{200d}1"));
        assert!(refusal.toast.contains("https://r.example"), "{}", refusal.toast);
    }
}
