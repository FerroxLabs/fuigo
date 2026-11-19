#![no_main]
//! The ACP stdin path: the escaped-slash line normaliser, the capped line reader, the envelope parse (batch arrays
//! are rejected, never mis-read as a message) and `LineBufferedRead` (lossless over any chunking).

use futures::executor::LocalPool;
use futures::io::AsyncRead;
use futures::task::LocalSpawnExt;
use futures::AsyncReadExt as _;
use libfuzzer_sys::fuzz_target;
use std::io::{BufRead, Read};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Yields `data` in chunks whose sizes cycle through `sizes` (each at least one byte).
struct Chunked {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    i: usize,
}

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let want = this.sizes[this.i % this.sizes.len()].max(1);
        this.i += 1;
        let n = want.min(buf.len()).min(this.data.len() - this.pos);
        buf[..n].copy_from_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(n))
    }
}

fuzz_target!(|data: &[u8]| {
    let (head, body) = match data.split_first() {
        Some((h, rest)) => (*h, rest),
        None => return,
    };

    // 1. Normaliser: no panic; no escaped slash means untouched; the line terminator is always preserved.
    let line = body.to_vec();
    let out = fuigo_acp_lib::fuzz_support::normalize_json_line(line.clone());
    if !line.windows(2).any(|w| w == br"\/") {
        assert_eq!(out, line);
    }
    let tail = |v: &[u8]| v.iter().rev().take_while(|&&b| b == b'\n' || b == b'\r').count();
    if out != line {
        assert_eq!(&out[out.len() - tail(&out)..], &line[line.len() - tail(&line)..]);
        // A rewrite is only ever made to a line that parses as JSON, and the result still does.
        assert!(serde_json::from_slice::<serde_json::Value>(&out).is_ok());
    }

    // 2. Envelope parse: never panics; a batch array is never accepted as a message.
    let parsed = serde_json::from_slice::<agent_client_protocol::RawIncomingMessage>(body);
    if body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[') {
        assert!(parsed.is_err(), "a JSON-RPC batch array must be rejected");
    }

    // 3. Capped reader equals read_until under the cap, and never holds more than cap+one fill beyond it.
    let max = (head as usize % 64) + 1;
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut ra = std::io::BufReader::with_capacity(7, body);
    let mut rb = std::io::BufReader::with_capacity(7, body);
    let ca = fuigo_acp_lib::fuzz_support::read_until_capped(&mut ra, &mut a, max).unwrap();
    rb.read_until(b'\n', &mut b).unwrap();
    assert_eq!(ca, a.len());
    if b.len() <= max {
        assert_eq!(a, b);
    } else {
        assert!(a.len() > max && b.starts_with(&a[..max]) && a.len() <= max + 7);
    }
    let mut rest = Vec::new();
    ra.read_to_end(&mut rest).unwrap();
    let mut rest_b = Vec::new();
    if b.len() <= max {
        rb.read_to_end(&mut rest_b).unwrap();
        assert_eq!(rest, rest_b);
    }

    // 4. LineBufferedRead: concatenated output equals the input for any chunking (lines are far below the cap).
    let sizes: Vec<usize> = body.iter().take(4).map(|b| (*b as usize % 9) + 1).collect();
    let sizes = if sizes.is_empty() { vec![3] } else { sizes };
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let mut reader = fuigo_acp_lib::LineBufferedRead::new(
        Chunked { data: body.to_vec(), pos: 0, sizes, i: 0 },
        |fut| spawner.spawn_local(fut).unwrap(),
    );
    let got = pool.run_until(async move {
        let mut v = Vec::new();
        reader.read_to_end(&mut v).await.unwrap();
        v
    });
    assert_eq!(got, body);
});
