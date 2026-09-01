/// Apply auth headers to outbound visibility requests.
/// Implemented by `fuigo-shell::util::fuigo_auth_credentials::FuigoAuthCredentials`.
/// Shell owns credential construction; data-collector builds the request without importing shell types.
pub trait HttpAuth: Send + Sync {
    fn apply(&self, builder: reqwest::RequestBuilder, base_url: &str) -> reqwest::RequestBuilder;
}
