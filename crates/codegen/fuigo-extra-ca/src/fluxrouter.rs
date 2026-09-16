//! FluxRouter, Fuigo's default inference route, and the gate for request extensions only it may receive.
//!
//! Strict providers (OpenAI, Anthropic, xAI) reject an unknown body field with a 400, so a FluxRouter-only
//! request field is gated on the destination host. Configuration trust is the wrong gate: a user may configure
//! a direct OpenAI base URL as a trusted origin, and loopback gateways are trusted too.

/// FluxRouter's API host. It serves `/v1` (Chat Completions, Responses) and `/anthropic` (Messages).
pub const FLUXROUTER_API_HOST: &str = "api.fluxrouter.ai";

/// Whether `url` addresses [`FLUXROUTER_API_HOST`], on any scheme, port or path.
///
/// An exact host match after `Url::parse` (which lowercases the host and separates userinfo, so
/// `https://api.fluxrouter.ai@evil.example/` is `evil.example`) and removal of the DNS root dot.
/// Lookalikes such as `api.fluxrouter.ai.evil.example`, and the website `fluxrouter.ai`, are not the API.
pub fn is_fluxrouter_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| {
        parsed
            .host_str()
            .is_some_and(|host| host.trim_end_matches('.') == FLUXROUTER_API_HOST)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fluxrouter_api_urls_match_on_every_surface_and_spelling() {
        for url in [
            "https://api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai/anthropic",
            "https://api.fluxrouter.ai/v1/chat/completions",
            "http://api.fluxrouter.ai/v1",
            "HTTPS://API.FLUXROUTER.AI/v1",
            "https://api.fluxrouter.ai./v1",
            "https://api.fluxrouter.ai:8443/v1",
            "https://user@api.fluxrouter.ai/v1",
        ] {
            assert!(is_fluxrouter_url(url), "{url} is FluxRouter's API");
        }
    }

    #[test]
    fn other_hosts_and_lookalikes_do_not_match() {
        for url in [
            "https://api.openai.com/v1",
            "https://api.anthropic.com/v1",
            "https://api.x.ai/v1",
            "https://openrouter.ai/api/v1",
            "https://fluxrouter.ai/v1",
            "https://www.fluxrouter.ai/v1",
            "https://staging.api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "https://evil-api.fluxrouter.ai.attacker.com/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            "https://evil.example/api.fluxrouter.ai/v1",
            "http://localhost:8080/v1",
            "http://127.0.0.1:8080/v1",
            "api.fluxrouter.ai",
            "not a url",
            "",
        ] {
            assert!(!is_fluxrouter_url(url), "{url} is not FluxRouter's API");
        }
    }
}
