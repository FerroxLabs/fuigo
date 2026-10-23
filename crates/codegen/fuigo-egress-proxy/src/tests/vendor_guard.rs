//! Fuigo-specific: the upstream-vendor egress guard (fuigo-extra-ca) is absolute and sits
//! before the website policy, so an origin the policy allows is still refused when it is a
//! vendor host, and nothing is resolved or dialled for it.

use super::*;

fn http_get(fixture: &Fixture, host: &str) -> String {
    format!(
        "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {}\r\n\r\n",
        fixture.auth()
    )
}

#[tokio::test]
async fn policy_allowed_vendor_hosts_are_refused_without_resolving() {
    let hosts = [
        "api.x.ai",
        "x.ai",
        "cli-chat-proxy.grok.com",
        "api.mixpanel.com",
    ];
    let origins = hosts.map(|host| format!("http://{host}"));
    let refs: Vec<&str> = origins.iter().map(String::as_str).collect();
    let fixture = Fixture::start(allow(&refs)).await;
    for host in hosts {
        fixture.resolver.answer(host, vec![public_v4(80)]);
        let response = send(fixture.addr(), http_get(&fixture, host).as_bytes()).await;
        assert_eq!(status(&response), 403, "{host}");
    }
    assert!(fixture.connector.addresses().is_empty());
    let metrics = fixture.handle.metrics();
    assert_eq!(metrics.policy_denied, 4);
    assert_eq!(metrics.ok, 0);
    fixture.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn vendor_host_is_refused_over_connect_before_any_tls() {
    let fixture = Fixture::start(allow(&["https://api.x.ai"])).await;
    fixture.resolver.answer("api.x.ai", vec![public_v4(443)]);
    let mut stream = TcpStream::connect(fixture.addr()).await.unwrap();
    let request = format!(
        "CONNECT api.x.ai:443 HTTP/1.1\r\nHost: api.x.ai:443\r\nProxy-Authorization: {}\r\n\r\n",
        fixture.auth()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    read_response_head(&mut stream, &mut response).await;
    assert_eq!(status(&response), 403);
    assert!(fixture.connector.addresses().is_empty());
    fixture.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn lookalike_hosts_outside_the_vendor_domains_are_not_refused() {
    let fixture = Fixture::start(allow(&["http://api.x.ai.evil.example"])).await;
    fixture
        .resolver
        .answer("api.x.ai.evil.example", vec![public_v4(80)]);
    let peer = fixture.connector.push();
    let upstream = http_upstream(peer, &[]).await;
    let response = send(
        fixture.addr(),
        http_get(&fixture, "api.x.ai.evil.example").as_bytes(),
    )
    .await;
    assert_eq!(status(&response), 302);
    upstream.await.unwrap();
    fixture.handle.shutdown().await.unwrap();
}

/// The vendor guard refuses names, and a literal has none. The proxy's origins are hostnames
/// only (`WebsiteOrigin` rejects IP literals), so a request that names an address — dotted, in
/// the decimal, hex or octal spellings a resolver would still read, or bracketed IPv6 — is
/// refused as malformed before the policy, the decider, DNS or any dial: no address, vendor's
/// or not, is reachable through the proxy. Pinned here because a policy that allowed "the origin
/// of an IP literal" would silently open exactly the hole `fuigo-extra-ca` documents.
#[tokio::test]
async fn ip_literal_hosts_are_refused_before_any_dial_whatever_the_policy_says() {
    let fixture = Fixture::start(allow(&["http://example.com"])).await;
    for host in [
        "8.8.8.8",
        "8.8.8.8:80",
        "134744072",
        "0x08080808",
        "010.010.010.010",
        "8.8.2056",
        "[2606:4700:4700::1111]",
        "[::ffff:8.8.8.8]:80",
    ] {
        let response = send(fixture.addr(), http_get(&fixture, host).as_bytes()).await;
        assert_eq!(status(&response), 400, "GET {host}");
    }
    for authority in ["8.8.8.8:443", "134744072:443", "[2606:4700:4700::1111]:443"] {
        let mut stream = TcpStream::connect(fixture.addr()).await.unwrap();
        let request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {}\r\n\r\n",
            fixture.auth()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        read_response_head(&mut stream, &mut response).await;
        assert_eq!(status(&response), 400, "CONNECT {authority}");
    }
    assert!(fixture.connector.addresses().is_empty());
    fixture.handle.shutdown().await.unwrap();
}
