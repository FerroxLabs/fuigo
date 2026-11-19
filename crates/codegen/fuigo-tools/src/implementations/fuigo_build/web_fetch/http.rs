//! Cached HTTP client with atomic invalidation for `web_fetch`.
//!
//! The `reqwest::Client` is held behind an `ArcSwapOption` so it can be
//! atomically invalidated on transport errors, forcing the next call to rebuild
//! with a fresh connection pool. This prevents connection pool poisoning
//! (half-read connections being returned to the pool and corrupting subsequent
//! requests).

use std::sync::Arc;

use arc_swap::ArcSwapOption;

use super::config::WebFetchParams;
use super::error::WebFetchError;

/// Cached, invalidatable HTTP client for web fetching.
///
/// - **Normal path:** `get_or_rebuild()` returns the cached client via a
///   lock-free atomic load.
/// - **On transport error:** call `invalidate()` to atomically set the
///   client to `None`. The next `get_or_rebuild()` falls through and
///   builds a fresh client with a clean connection pool.
#[derive(Clone, Debug)]
pub(crate) struct HttpClient {
    inner: Arc<ArcSwapOption<reqwest::Client>>,
    /// For a destination that is itself a configured proxy's host (delta review D4), with no proxy exemption.
    proxy_destination: Arc<ArcSwapOption<(String, reqwest::Client)>>,
    params: WebFetchParams,
}

impl HttpClient {
    pub(crate) fn new(params: &WebFetchParams) -> Result<Self, WebFetchError> {
        // Validate the proxy eagerly; the transport builds lazily
        // (`invalidate()` promises a fresh pool).
        if let Some(ref endpoint) = params.proxy_endpoint {
            reqwest::Proxy::all(endpoint)
                .map_err(|e| WebFetchError::ProxyConfigError(e.to_string()))?;
        }
        Ok(Self {
            inner: Arc::new(ArcSwapOption::from(None)),
            proxy_destination: Arc::new(ArcSwapOption::from(None)),
            params: params.clone(),
        })
    }

    /// Get the current client, rebuilding if it was invalidated.
    pub(crate) fn get_or_rebuild(&self) -> Result<Arc<reqwest::Client>, WebFetchError> {
        // Fast path: lock-free atomic load.
        if let Some(client) = self.inner.load_full() {
            return Ok(client);
        }
        // Client was invalidated — rebuild with a fresh connection pool.
        let fresh = Arc::new(Self::build(
            &self.params,
            &|name| std::env::var_os(name),
            None,
        )?);
        self.inner.store(Some(Arc::clone(&fresh)));
        Ok(fresh)
    }

    /// The client for a request to `url`: [`Self::get_or_rebuild`], unless the destination host is one of the
    /// configured proxies' names. That name is exempt from the address check only while it is dialled as a proxy; as
    /// a destination its addresses are judged like any other (delta review D4). Redirects stay on the same host.
    pub(crate) fn get_or_rebuild_for(
        &self,
        url: &url::Url,
    ) -> Result<Arc<reqwest::Client>, WebFetchError> {
        let env = |name: &str| std::env::var_os(name);
        let Some(host) = url.host_str() else {
            return self.get_or_rebuild();
        };
        let proxies = proxy_hosts(self.params.proxy_endpoint.as_deref(), &env);
        if !proxies.iter().any(|proxy| proxy.eq_ignore_ascii_case(host)) {
            return self.get_or_rebuild();
        }
        if let Some(cached) = self.proxy_destination.load_full()
            && cached.0.eq_ignore_ascii_case(host)
        {
            return Ok(Arc::new(cached.1.clone()));
        }
        let fresh = Self::build(&self.params, &env, Some(host))?;
        self.proxy_destination
            .store(Some(Arc::new((host.to_owned(), fresh.clone()))));
        Ok(Arc::new(fresh))
    }

    /// Atomically invalidate the cached client. The next `get_or_rebuild()`
    /// will construct a fresh one with a clean connection pool.
    pub(crate) fn invalidate(&self) {
        self.inner.store(None);
        self.proxy_destination.store(None);
    }

    /// `env` reads the proxy variables (the process environment outside tests).
    fn build(
        params: &WebFetchParams,
        env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
        destination: Option<&str>,
    ) -> Result<reqwest::Client, WebFetchError> {
        // Route all traffic through the egress proxy when configured.
        let proxy = params
            .proxy_endpoint
            .as_ref()
            .map(reqwest::Proxy::all)
            .transpose()
            .map_err(|e| WebFetchError::ProxyConfigError(e.to_string()))?;
        let configure = |builder: reqwest::ClientBuilder| {
            let mut builder = builder
                .timeout(params.timeout_secs())
                .connect_timeout(std::time::Duration::from_secs(10))
                // We manage redirects for SSRF.
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(2)
                .pool_idle_timeout(std::time::Duration::from_secs(30))
                .tcp_nodelay(true)
                // Reduce size of incoming payloads.
                .gzip(true)
                .brotli(true)
                .deflate(true);
            if let Some(proxy) = proxy.clone() {
                builder = builder.proxy(proxy);
            }
            builder
        };
        // The client's own resolver judges the addresses it connects to, so a name that answers
        // differently the second time cannot reach a private address (audit S5-F8). That holds for
        // every direct connection, including requests a configured proxy does not carry
        // (`NO_PROXY`, or a scheme it does not serve; audit R03). Only the names of the configured
        // proxies are exempt: dialling a proxy resolves its name, and that name may be private. Not the
        // `destination` host itself: a client built for a request to a proxy's own name judges it (delta review D4).
        let check = super::ssrf::address_check(params.allow_local());
        let mut proxy_hosts = proxy_hosts(params.proxy_endpoint.as_deref(), env);
        proxy_hosts
            .retain(|proxy| destination.is_none_or(|host| !proxy.eq_ignore_ascii_case(host)));
        let check: fuigo_extra_ca::egress::AddressCheck = if proxy_hosts.is_empty() {
            check
        } else {
            Arc::new(move |host, addrs| {
                if proxy_hosts
                    .iter()
                    .any(|proxy| proxy.eq_ignore_ascii_case(host))
                {
                    Ok(())
                } else {
                    check(host, addrs)
                }
            })
        };
        fuigo_extra_ca::build_reqwest_client_checked(configure, check)
            .map_err(WebFetchError::ClientBuildError)
    }
}

/// The environment variables naming a proxy reqwest would use on its own.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Whether the environment names a proxy reqwest would use on its own.
#[cfg(test)]
fn system_proxy_in_environment(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    PROXY_VARIABLES
        .iter()
        .any(|name| env(name).is_some_and(|value| !value.is_empty()))
}

/// Host names of the proxies this client may dial: the configured endpoint and any named in the
/// environment. A value without a scheme is read as `http://`, as reqwest reads it.
fn proxy_hosts(
    endpoint: Option<&str>,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<String> {
    let from_env = PROXY_VARIABLES
        .iter()
        .filter_map(|name| env(name)?.into_string().ok());
    endpoint
        .map(str::to_owned)
        .into_iter()
        .chain(from_env)
        .filter_map(|value| {
            let value = value.trim();
            let url = if value.contains("://") {
                url::Url::parse(value)
            } else {
                url::Url::parse(&format!("http://{value}"))
            };
            Some(url.ok()?.host_str()?.to_owned())
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test clients hit localhost mocks"
)]
mod tests {
    use super::*;

    #[test]
    fn get_or_rebuild_returns_client() {
        let client = HttpClient::new(&WebFetchParams::default()).unwrap();
        let http = client.get_or_rebuild().unwrap();
        assert!(Arc::strong_count(&http) >= 1);
    }

    #[test]
    fn invalidate_forces_rebuild() {
        let client = HttpClient::new(&WebFetchParams::default()).unwrap();
        let first = client.get_or_rebuild().unwrap();
        let first_ptr = Arc::as_ptr(&first);

        client.invalidate();

        let second = client.get_or_rebuild().unwrap();
        let second_ptr = Arc::as_ptr(&second);

        // After invalidation, we should get a different client instance.
        assert_ne!(first_ptr, second_ptr);
    }

    #[test]
    fn build_with_proxy_endpoint() {
        let params = WebFetchParams {
            proxy_endpoint: Some("https://proxy.corp.example.com".into()),
            ..Default::default()
        };
        // Should succeed — reqwest accepts the proxy URL.
        let client = HttpClient::new(&params);
        assert!(client.is_ok());
    }

    #[test]
    fn build_without_proxy_is_default() {
        let params = WebFetchParams::default();
        assert!(params.proxy_endpoint.is_none());
        let client = HttpClient::new(&params);
        assert!(client.is_ok());
    }

    #[test]
    fn build_with_invalid_proxy_endpoint() {
        let params = WebFetchParams {
            proxy_endpoint: Some("not a valid url".into()),
            ..Default::default()
        };
        let result = HttpClient::new(&params);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("proxy"),
            "Expected proxy-related error, got: {err}"
        );
    }

    /// Fable delta-3 Low 7: the tests below build clients that read the process environment, so a runner with a proxy
    /// set would route their requests through it. Each runs in a child process with every proxy variable removed
    /// (and must report `1 passed`), so it neither returns early nor depends on the runner. In the parent this
    /// returns `false` once the child has passed; in the child it returns `true` and the test body runs.
    fn run_in_clean_child(test: &str) -> bool {
        const MARK: &str = "FUIGO_WEB_FETCH_CLEAN_CHILD";
        if std::env::var_os(MARK).is_some() {
            return true;
        }
        let module = module_path!().split_once("::").unwrap().1;
        let name = format!("{module}::{test}");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(MARK, "1");
        for var in PROXY_VARIABLES
            .iter()
            .chain(&["NO_PROXY", "no_proxy", "REQUEST_METHOD"])
        {
            command.env_remove(var);
        }
        let output = command.stdin(std::process::Stdio::null()).output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{test} failed in a clean child\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    /// The client's own resolver refuses a name that answers with a blocked address, so the
    /// address judged is the address dialled (audit S5-F8). `localhost` answers loopback without
    /// the network; the listener must never see a connection.
    #[tokio::test]
    async fn client_resolver_refuses_a_name_that_answers_loopback() {
        if !run_in_clean_child("client_resolver_refuses_a_name_that_answers_loopback") {
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = HttpClient::new(&WebFetchParams::default())
            .unwrap()
            .get_or_rebuild()
            .unwrap();
        let result = client.get(format!("http://localhost:{port}/")).send().await;
        assert!(result.is_err(), "a loopback answer must be refused");
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "nothing may have connected to the listener"
        );
    }

    /// Audit R03: a proxy named in the environment does not cover every request (`NO_PROXY`, or a
    /// scheme it does not serve), and those requests dial directly; they must still have their
    /// resolved address judged. Here only `HTTPS_PROXY` is set and the request is plain `http`.
    #[tokio::test]
    async fn a_direct_request_beside_an_environment_proxy_still_checks_the_address() {
        if !run_in_clean_child(
            "a_direct_request_beside_an_environment_proxy_still_checks_the_address",
        ) {
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let env = |name: &str| {
            (name == "HTTPS_PROXY").then(|| std::ffi::OsString::from("http://proxy.invalid:3128"))
        };
        let client = HttpClient::build(&WebFetchParams::default(), &env, None).unwrap();
        let result = client.get(format!("http://localhost:{port}/")).send().await;
        assert!(result.is_err(), "a loopback answer must be refused");
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "nothing may have connected to the listener"
        );
    }

    /// Delta review D4: a configured proxy's name dialled as the destination itself (here plain `http`, which an
    /// `HTTPS_PROXY` does not carry, so the connection is direct) still has its address judged.
    #[tokio::test]
    async fn a_proxy_name_used_as_the_destination_is_still_checked() {
        if !run_in_clean_child("a_proxy_name_used_as_the_destination_is_still_checked") {
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let env = |name: &str| {
            (name == "HTTPS_PROXY")
                .then(|| std::ffi::OsString::from(format!("http://localhost:{port}")))
        };
        let client =
            HttpClient::build(&WebFetchParams::default(), &env, Some("localhost")).unwrap();
        let result = client.get(format!("http://localhost:{port}/")).send().await;
        assert!(result.is_err(), "a loopback answer must be refused");
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "nothing may have connected to the listener"
        );
    }

    /// Audit R03: only the configured proxies' names skip the address check, read from the
    /// endpoint and the environment, with or without a scheme.
    #[test]
    fn only_configured_proxy_names_are_exempt() {
        let env = |name: &str| match name {
            "https_proxy" => Some(std::ffi::OsString::from("corp-proxy.internal:8080")),
            "ALL_PROXY" => Some(std::ffi::OsString::from("")),
            _ => None,
        };
        let hosts = proxy_hosts(Some("http://egress.local:3128"), &env);
        assert_eq!(
            hosts,
            vec!["egress.local".to_owned(), "corp-proxy.internal".to_owned()]
        );
        assert!(proxy_hosts(None, &|_| None).is_empty());
    }

    /// The child half of [`direct_requests_beside_a_real_environment_proxy_still_check_the_address`].
    /// It does nothing unless the parent started it with a real proxy environment.
    #[tokio::test]
    async fn proxy_environment_child() {
        let Ok(direct_port) = std::env::var("FUIGO_PROXY_CHILD_DIRECT_PORT") else {
            return;
        };
        let control_url = std::env::var("FUIGO_PROXY_CHILD_CONTROL_URL").unwrap();
        assert!(
            system_proxy_in_environment(&|name| std::env::var_os(name)),
            "the child must run with a real proxy environment"
        );
        println!("PROXY_CHILD_RAN");
        let client = HttpClient::new(&WebFetchParams::default())
            .unwrap()
            .get_or_rebuild()
            .unwrap();
        // Positive control: this request is covered by the environment proxy, so it dials the proxy.
        let wait = std::time::Duration::from_secs(2);
        let _ = tokio::time::timeout(wait, client.get(control_url).send()).await;
        // The request the proxy does not cover dials directly; its resolved address is still judged.
        let direct = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client
                .get(format!("http://localhost:{direct_port}/"))
                .send(),
        )
        .await
        .expect("the direct request must finish");
        assert!(direct.is_err(), "a loopback answer must be refused");
    }

    /// Runs [`proxy_environment_child`] in its own process whose environment really names a proxy
    /// (a local listener) as `proxy_variables`, with `no_proxy` when given. The proxy must see the
    /// covered `control_url` request and the direct listener must never see a connection.
    fn run_with_environment_proxy(
        proxy_variables: &[&str],
        no_proxy: Option<&str>,
        control_url: &str,
    ) {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let direct = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_url = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());
        let module = module_path!().split_once("::").unwrap().1;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([&format!("{module}::proxy_environment_child"), "--exact"])
            .args(["--nocapture", "--test-threads=1"]);
        for name in PROXY_VARIABLES.iter().chain(&["NO_PROXY", "no_proxy"]) {
            command.env_remove(name);
        }
        for name in proxy_variables {
            command.env(name, &proxy_url);
        }
        if let Some(no_proxy) = no_proxy {
            command.env("NO_PROXY", no_proxy);
        }
        command
            .env(
                "FUIGO_PROXY_CHILD_DIRECT_PORT",
                direct.local_addr().unwrap().port().to_string(),
            )
            .env("FUIGO_PROXY_CHILD_CONTROL_URL", control_url);
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("PROXY_CHILD_RAN"),
            "the child test did not run: {stdout}"
        );
        assert!(
            output.status.success(),
            "child failed: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        proxy.set_nonblocking(true).unwrap();
        assert!(
            proxy.accept().is_ok(),
            "positive control: the environment proxy was never dialled"
        );
        direct.set_nonblocking(true).unwrap();
        let seen = direct.accept();
        assert!(
            matches!(&seen, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "nothing may have connected to the direct listener: {seen:?}"
        );
    }

    /// Audit R03: with a real proxy in the process environment, a request the proxy does not carry
    /// (`NO_PROXY`, or a scheme it does not serve) dials directly and is still address-checked.
    #[test]
    fn direct_requests_beside_a_real_environment_proxy_still_check_the_address() {
        // Covered by NO_PROXY: only localhost is exempt from the proxy.
        run_with_environment_proxy(
            &["HTTP_PROXY"],
            Some("localhost"),
            "http://control.invalid/",
        );
        // Uncovered scheme: only HTTPS_PROXY is set and the request is plain http.
        run_with_environment_proxy(&["HTTPS_PROXY"], None, "https://control.invalid/");
    }
}
