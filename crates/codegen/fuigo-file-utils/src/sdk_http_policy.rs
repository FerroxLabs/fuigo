//! Egress check at Smithy's final connector boundary, before any proxy contact.
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        connector_metadata::ConnectorMetadata,
        http::{
            HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings,
            SharedHttpClient, SharedHttpConnector,
        },
        orchestrator::HttpRequest,
        result::ConnectorError,
        runtime_components::{RuntimeComponents, RuntimeComponentsBuilder},
    },
};
use aws_smithy_types::config_bag::ConfigBag;

#[derive(Debug)]
struct CheckedConnector(SharedHttpConnector);

impl HttpConnector for CheckedConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let url = match reqwest::Url::parse(request.uri()) {
            Ok(url) => url,
            Err(_) => {
                return HttpConnectorFuture::ready(Err(ConnectorError::user(
                    "invalid SDK request URL".into(),
                )
                .never_connected()));
            }
        };
        if let Err(error) = fuigo_extra_ca::dispatch::check_url(&url) {
            return HttpConnectorFuture::ready(Err(
                ConnectorError::user(Box::new(error)).never_connected()
            ));
        }
        self.0.call(request)
    }
}

#[derive(Debug)]
struct CheckedClient(SharedHttpClient);

impl HttpClient for CheckedClient {
    fn http_connector(
        &self,
        settings: &HttpConnectorSettings,
        components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(CheckedConnector(
            self.0.http_connector(settings, components),
        ))
    }

    fn validate_base_client_config(
        &self,
        components: &RuntimeComponentsBuilder,
        config: &ConfigBag,
    ) -> Result<(), BoxError> {
        self.0.validate_base_client_config(components, config)
    }

    fn validate_final_config(
        &self,
        components: &RuntimeComponents,
        config: &ConfigBag,
    ) -> Result<(), BoxError> {
        self.0.validate_final_config(components, config)
    }

    fn connector_metadata(&self) -> Option<ConnectorMetadata> {
        self.0.connector_metadata()
    }
}

pub(crate) fn checked_client(client: SharedHttpClient) -> SharedHttpClient {
    SharedHttpClient::new(CheckedClient(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
    use aws_smithy_types::body::SdkBody;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Observer(Arc<AtomicUsize>);
    impl HttpConnector for Observer {
        fn call(&self, _: HttpRequest) -> HttpConnectorFuture {
            self.0.fetch_add(1, Ordering::SeqCst);
            HttpConnectorFuture::ready(Ok(HttpResponse::new(
                200.try_into().unwrap(),
                SdkBody::empty(),
            )))
        }
    }

    #[tokio::test]
    async fn egress_policy_checks_sdk_uri_before_delegation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let checked = CheckedConnector(SharedHttpConnector::new(Observer(calls.clone())));
        for url in [
            "https://api.x.ai/object",
            "http://assets.grok.com/object",
            "https://API.X.AI./object",
        ] {
            let mut request = HttpRequest::new(SdkBody::empty());
            request.set_uri(url).unwrap();
            assert!(checked.call(request).await.unwrap_err().is_user());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let mut request = HttpRequest::new(SdkBody::empty());
        request.set_uri("https://bucket.s3.example/object").unwrap();
        assert_eq!(checked.call(request).await.unwrap().status().as_u16(), 200);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn egress_policy_is_installed_on_production_s3_factory() {
        const CHILD: &str = "FUIGO_S3_EGRESS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let client =
                crate::s3::build_s3_client("us-east-1", None, None, Some("https://api.x.ai"))
                    .await
                    .unwrap();
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client.head_bucket().bucket("fake-bucket").send(),
            )
            .await
            .expect("policy rejection must precede network timeout")
            .unwrap_err();
            assert!(format!("{error:?}").contains("refuses to contact upstream vendor host"));
            println!("s3-egress-child-entered");
            return;
        }
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        proxy.set_nonblocking(true).unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
        let home = tempfile::tempdir().unwrap();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sdk_http_policy::tests::egress_policy_is_installed_on_production_s3_factory",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", home.path())
            .env(CHILD, "1")
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("NO_PROXY", "")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("s3-egress-child-entered"));
        assert_eq!(
            proxy.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
