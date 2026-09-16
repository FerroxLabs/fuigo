use gcloud_metadata::{email, on_gce, transport, Error};

#[tokio::test]
async fn test_on_gce() {
    let result = on_gce().await;
    assert!(!result);
    println!("executed first");
    let result = on_gce().await;
    assert!(!result);
    println!("executed second");
}

#[tokio::test]
async fn test_email() {
    let result = email("default").await;
    if let Err(e) = result {
        match e {
            // Upstream 1.0.2 dispatched with `reqwest::RequestBuilder::send`, so a
            // failed metadata request arrived here as `Error::HttpError`. Fuigo's
            // local modification (commit 1bac6c5, "fix(security): guard GCS auth and
            // metadata HTTP") routes every metadata request through the process
            // transport policy in `src/transport.rs` via `send_guarded`, which
            // returns `transport::Error`; `?` in `get_etag` therefore now yields
            // `Error::TransportPolicy(transport::Error::Http(_))`. That is the
            // intended shape: it is the variant `gcloud-auth` mirrors in its own
            // error enum, and the one `policy_tests` asserts on. `Error::HttpError`
            // still exists for failures after a response arrives (`response.text()`).
            Error::TransportPolicy(transport::Error::Http(e)) => println!("http error {e:?}"),
            _ => unreachable!(),
        }
    } else {
        unreachable!()
    }
}
