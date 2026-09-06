//! Compile-only control: `--cfg f06_raw_dispatch` must fail the dispatch lint.
#![allow(dead_code, unexpected_cfgs)]

#[cfg(f06_raw_dispatch)]
async fn async_raw(client: reqwest::Client, request: reqwest::Request) {
    let _ = client.get("https://example.invalid").send().await;
    let _ = client.execute(request).await;
}

#[cfg(f06_raw_dispatch)]
fn blocking_raw(client: reqwest::blocking::Client, request: reqwest::blocking::Request) {
    let _ = client.get("https://example.invalid").send();
    let _ = client.execute(request);
}

#[cfg(not(f06_raw_dispatch))]
async fn async_checked(client: reqwest::Client, request: reqwest::Request) {
    let _ = fuigo_extra_ca::dispatch::send(client.get("https://example.invalid")).await;
    let _ = fuigo_extra_ca::dispatch::execute(&client, request).await;
}

#[cfg(not(f06_raw_dispatch))]
fn blocking_checked(client: reqwest::blocking::Client, request: reqwest::blocking::Request) {
    let _ = fuigo_extra_ca::dispatch::send_blocking(client.get("https://example.invalid"));
    let _ = fuigo_extra_ca::dispatch::execute_blocking(&client, request);
}

fn main() {}
