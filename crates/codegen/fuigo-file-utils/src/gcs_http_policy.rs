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
    configure(reqwest::Client::builder()).build().map(guarded)
}

fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
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
    let mut builder = builder
        .tls_backend_rustls()
        .redirect(policy);
    for der in fuigo_extra_ca::extra_root_ders() {
        match reqwest::Certificate::from_der(der) {
            Ok(cert) => builder = builder.add_root_certificate(cert),
            Err(error) => tracing::warn!(%error, "extra CA rejected by GCS HTTP client; skipping"),
        }
    }
    builder
}

pub(crate) fn install_auth_policy() -> anyhow::Result<()> {
    static INSTALLED: std::sync::OnceLock<Result<(), &'static str>> = std::sync::OnceLock::new();
    let result = INSTALLED.get_or_init(|| {
        use gcloud_storage::client::google_cloud_auth::http_transport;
        http_transport::install(http_transport::Policy {
            configure,
            check_url: |url| fuigo_extra_ca::dispatch::check_url(url).map_err(|e| e.to_string()),
        })
    });
    result.map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_transport_environment_proxy_and_redirect_boundaries() {
        const CASE: &str = "FUIGO_GCS_AUTH_BOUNDARY_CHILD";
        if std::env::var_os(CASE).is_none() {
            let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            proxy.set_nonblocking(true).unwrap();
            let url = format!("http://{}", proxy.local_addr().unwrap());
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "gcs_http_policy::tests::auth_transport_environment_proxy_and_redirect_boundaries", "--nocapture"])
                .env(CASE, "1")
                .env("HTTPS_PROXY", &url).env("https_proxy", &url)
                .env("HTTP_PROXY", &url).env("http_proxy", &url)
                .env("ALL_PROXY", &url).env("all_proxy", &url)
                .env("NO_PROXY", "127.0.0.1").env("no_proxy", "127.0.0.1")
                .env_remove("FUIGO_ALLOW_UPSTREAM_HOSTS")
                .status().unwrap();
            assert!(status.success());
            assert_eq!(proxy.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            return;
        }
        use gcloud_storage::client::google_cloud_auth::http_transport::{self, RequestPolicyExt};
        install_auth_policy().unwrap();
        let http = http_transport::client(std::time::Duration::from_secs(3)).unwrap();
        let error = http.post("https://api.x.ai/token").body("fake-refresh")
            .send_guarded().await.unwrap_err();
        assert!(matches!(error, http_transport::Error::Denied));

        let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let location = format!("http://{}/token", target.local_addr().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new().route("/token", axum::routing::post(move || {
            let location = location.clone();
            async move { (axum::http::StatusCode::TEMPORARY_REDIRECT, [(axum::http::header::LOCATION, location)]) }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let result = http.post(format!("http://{address}/token")).body("fake-refresh")
            .send_guarded().await;
        server.abort();
        let _ = server.await;
        assert!(matches!(result.unwrap_err(), http_transport::Error::Http(error) if error.is_redirect()));
        assert_eq!(target.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
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
