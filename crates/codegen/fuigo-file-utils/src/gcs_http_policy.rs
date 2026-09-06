//! GCS storage/IAM request adapter for its reqwest 0.13/middleware 0.5 stack.
//! gcloud-auth token-source clients are separate and are not wrapped here.
use reqwest_middleware05 as middleware;
use reqwest13 as reqwest;

struct Egress;

#[async_trait::async_trait]
impl middleware::Middleware for Egress {
    async fn handle(
        &self,
        request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: middleware::Next<'_>,
    ) -> middleware::Result<reqwest::Response> {
        fuigo_extra_ca::dispatch::check_url(request.url())
            .map_err(|error| middleware::Error::Middleware(error.into()))?;
        next.run(request, extensions).await
    }
}

fn guarded(client: reqwest::Client) -> middleware::ClientWithMiddleware {
    middleware::ClientBuilder::new(client).with(Egress).build()
}

#[allow(clippy::disallowed_methods)] // reviewed 0.13 TLS/redirect builder with pre-dispatch middleware
pub(crate) fn client() -> reqwest::Result<middleware::ClientWithMiddleware> {
    fuigo_extra_ca::ensure_default_crypto_provider();
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > 10 {
            return attempt.error("GCS redirect limit exceeded");
        }
        let next = attempt.url();
        if !attempt.previous().first().is_some_and(|original| {
            original.origin() == next.origin()
                && original.username().is_empty()
                && original.password().is_none()
                && next.username().is_empty()
                && next.password().is_none()
        }) {
            return attempt.error("cross-origin GCS credential redirect refused");
        }
        if let Err(error) = fuigo_extra_ca::dispatch::check_url(next) {
            return attempt.error(error);
        }
        attempt.follow()
    });
    let mut builder = reqwest::Client::builder()
        .tls_backend_rustls()
        .redirect(policy);
    for der in fuigo_extra_ca::extra_root_ders() {
        match reqwest::Certificate::from_der(der) {
            Ok(cert) => builder = builder.add_root_certificate(cert),
            Err(error) => tracing::warn!(%error, "extra CA rejected by GCS HTTP client; skipping"),
        }
    }
    builder.build().map(guarded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(clippy::disallowed_methods)] // non-forwarding local proxy observer
    #[tokio::test]
    async fn gcs_egress_policy_rejects_before_proxy_contact() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        fuigo_extra_ca::ensure_default_crypto_provider();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let client = guarded(
            reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(proxy).unwrap())
                .build()
                .unwrap(),
        );
        let error = client
            .get("https://api.x.ai/storage/v1/b/fake")
            .send()
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refuses to contact upstream vendor host")
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
