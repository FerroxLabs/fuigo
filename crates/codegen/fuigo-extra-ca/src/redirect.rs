//! Credential-bearing requests may redirect only within their original origin.
//! reqwest strips Authorization cross-origin, but not arbitrary provider headers
//! or replayable request bodies. Reject the hop before either can be delivered.

use reqwest::Url;

fn same_credential_origin(original: &Url, next: &Url) -> bool {
    matches!(next.scheme(), "http" | "https")
        && original.username().is_empty()
        && original.password().is_none()
        && next.username().is_empty()
        && next.password().is_none()
        && original.origin() == next.origin()
}

pub(crate) fn credential_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 10 {
            return attempt.error("fuigo redirect limit exceeded");
        }
        if !attempt
            .previous()
            .first()
            .is_some_and(|original| same_credential_origin(original, attempt.url()))
        {
            return attempt.error("fuigo refuses a credential-bearing redirect to another origin");
        }
        if crate::egress::guard_enabled()
            && attempt
                .url()
                .host_str()
                .is_some_and(crate::egress::is_blocked_host)
        {
            return attempt.error("fuigo refuses a redirect to an upstream vendor host");
        }
        attempt.follow()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_origin_covers_scheme_port_and_userinfo() {
        let original = Url::parse("https://provider.example/v1").unwrap();
        for next in [
            "https://provider.example/v2",
            "https://PROVIDER.example:443/v1",
        ] {
            assert!(same_credential_origin(
                &original,
                &Url::parse(next).unwrap()
            ));
        }
        for next in [
            "http://provider.example/v1",
            "https://provider.example:8443/v1",
            "https://other.example/v1",
            "https://user@provider.example/v1",
            "https://user:password@provider.example/v1",
            "ftp://provider.example/v1",
        ] {
            assert!(!same_credential_origin(
                &original,
                &Url::parse(next).unwrap()
            ));
        }
        let with_user = Url::parse("https://user@provider.example/v1").unwrap();
        assert!(!same_credential_origin(&with_user, &original));
    }
}
