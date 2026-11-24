//! 1.0.47 S2 (SL-06), design §7 test 11: the at-rest layer's cost. The same writer method is timed on a transcript
//! `rel` (transformed) and on the verbatim rewind store (not transformed, i.e. the base write path), interleaved so
//! host noise lands on both. Accepted: streams in 512 B and larger writes and the rewrite at least [`FLOOR_MB_S`] (an
//! absolute floor, Sean 11-21); 80 B writes at most [`MAX_ADDED_US_80B`] added per write (a raw 80 B write itself runs
//! under 200 MB/s; coordinator decision 11-21); ≤10% p99 on small appends against base; no allocation on a no-match
//! write. The 50 MB rewrite is also copied in record by record (the fork/import path), on the same floor. Includes
//! Fable r2 #4's long values (a 4 KB multi-line PEM-like value and a 2.5 KB JSON value) at 80 B, 512 B and 8 KiB writes, with 50 and 500 recorded values sharing one prefix, and 50 distinct
//! values with varied vendor prefixes and none (Fable confirm review #1: more than 16 distinct values give the matcher
//! more than 64 needle heads, so its packed SIMD prefilter drops out; this case measures that path).
//!
//! Run by the release gate: `scripts/strike/pty-targets.txt` lists it as a `release-lib` target, so
//! `final-gate.sh --pty` (and `release-gate.sh`) builds it optimized and runs it with `--ignored`.
//!
//! Timing needs an optimized build. The crate's other tests need debug assertions, so:
//! `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo test --release -p fuigo-session-writer --lib -- --ignored s2_perf`.

use std::time::{Duration, Instant};

use crate::SessionWriter;

const VERBATIM: &str = "rewind_points.jsonl";

/// Stream and rewrite throughput floor, MB/s. Not a ratio to base: matching costs about 0.6 µs per 8 KiB, which by
/// itself uses up a 10% budget against a page-cache write.
const FLOOR_MB_S: f64 = 200.0;

/// The layer's added cost per 80 B write, µs: (transformed - base) / writes.
const MAX_ADDED_US_80B: f64 = 2.0;

/// `bytes` written in `took`, as MB/s.
fn mb_s(bytes: usize, took: Duration, base: Duration) -> f64 {
    let rate = bytes as f64 / took.as_secs_f64() / 1e6;
    eprintln!("  transformed {took:?} ({rate:.0} MB/s), base {base:?}");
    rate
}

fn writer(tag: &str) -> (tempfile::TempDir, SessionWriter) {
    let dir = tempfile::tempdir().expect("dir");
    let id = format!("s2-perf-{tag}-{}", std::process::id());
    let w = SessionWriter::try_claim(&id, dir.path().join("sessions").join(&id)).expect("claim");
    (dir, w)
}

/// `n` distinct recordable values, plus the two long ones (split literals: nothing token-shaped in the source).
fn record_values(n: usize) {
    for i in 0..n {
        fuigo_secrets::at_rest::record(&format!("{}{i:04}{}", concat!("pf", "_live_"), "Qx7Lm2Vt"));
    }
    let pem: String = (0..64)
        .map(|i| {
            format!(
                "{}{i:02}{}\n",
                concat!("MIIE", "vQIBADAN"),
                "BgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
            )
        })
        .collect();
    fuigo_secrets::at_rest::record(&pem);
    let json: String = format!(
        "{{\"type\":\"service_account\",\"private_key_id\":\"{}\",\"pad\":\"{}\"}}",
        concat!("pk", "_id_9f8e7d6c5b4a"),
        "abcdefghij0123456789".repeat(120)
    );
    fuigo_secrets::at_rest::record(&json);
}

/// `n` distinct values shaped like real credentials: half carry a vendor prefix, half (like an AWS secret key or a hex
/// token) begin with random characters, so no two share a head (generated: nothing token-shaped in the source).
fn record_distinct_values(n: usize) {
    const PREFIXES: [&str; 6] = ["sk-proj-", "ghp_", "xoxb-", "glpat-", "AKIA", "npm_"];
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ALNUM[(seed >> 33) as usize % ALNUM.len()] as char
    };
    for i in 0..n {
        let body: String = (0..24 + i % 17).map(|_| next()).collect();
        let prefix = if i % 2 == 0 {
            PREFIXES[i / 2 % PREFIXES.len()]
        } else {
            ""
        };
        fuigo_secrets::at_rest::record(&format!("{prefix}{body}"));
    }
}

/// Terminal-like output with no recorded value in it.
fn output(len: usize) -> Vec<u8> {
    let line = b"   Compiling fuigo-shell v1.0.47 (/root/src/crates/codegen/fuigo-shell) target/debug/deps\n";
    line.iter().copied().cycle().take(len).collect()
}

fn ratio(transformed: Duration, base: Duration) -> f64 {
    eprintln!("  transformed {transformed:?}, base {base:?}");
    transformed.as_secs_f64() / base.as_secs_f64()
}

/// Best of `trials` interleaved runs of `run(rel)` on the transcript and on the verbatim rel.
fn best_of(trials: usize, mut run: impl FnMut(&str) -> Duration) -> (Duration, Duration) {
    let (mut t, mut b) = (Duration::MAX, Duration::MAX);
    for _ in 0..trials {
        t = t.min(run("terminal/out.log"));
        b = b.min(run(VERBATIM));
    }
    (t, b)
}

fn stream_case(w: &SessionWriter, total: usize, chunk: usize) -> (Duration, Duration) {
    let data = output(total);
    best_of(5, |rel| {
        let _ = std::fs::remove_file(w.dir().join(rel));
        let log = w.open_append_stream(rel).expect("open");
        let start = Instant::now();
        for piece in data.chunks(chunk) {
            log.write_all(piece).expect("write");
        }
        log.finish().expect("finish");
        start.elapsed()
    })
}

#[test]
#[ignore = "timing: run with --release (test 11)"]
fn s2_perf_gate() {
    let mut report = Vec::new();
    let mut floors: Vec<(String, f64)> = Vec::new();
    for (values, distinct) in [(50usize, false), (500, false), (50, true)] {
        fuigo_secrets::at_rest::clear_for_tests();
        if distinct {
            record_distinct_values(values);
            record_values(0);
        } else {
            record_values(values);
        }
        let values = if distinct {
            format!("{values} distinct")
        } else {
            values.to_string()
        };
        let (_d, w) = writer(&format!("v{}", values.replace(' ', "-")));

        // No allocation on a no-match write.
        let clean = output(64 * 1024);
        assert!(matches!(
            fuigo_secrets::at_rest::transform_whole(&clean),
            std::borrow::Cow::Borrowed(_)
        ));

        // 64 MiB through a stream in 8 KiB and 512 B chunks.
        for chunk in [8 * 1024, 512] {
            let (t, b) = stream_case(&w, 64 << 20, chunk);
            floors.push((
                format!("stream 64MiB/{chunk}B, {values} values"),
                mb_s(64 << 20, t, b),
            ));
        }
        // Long values: 8 MiB at 80 B, 512 B and 8 KiB writes.
        for chunk in [80, 512, 8 * 1024] {
            let (t, b) = stream_case(&w, 8 << 20, chunk);
            if chunk == 80 {
                let writes = (8usize << 20).div_ceil(80) as f64;
                let added = (t.as_secs_f64() - b.as_secs_f64()) * 1e6 / writes;
                eprintln!("  transformed {t:?}, base {b:?}, added {added:.2} µs/write");
                report.push((
                    format!("stream 8MiB/80B long values, {values} values, µs added per write"),
                    added,
                    MAX_ADDED_US_80B,
                ));
                continue;
            }
            floors.push((
                format!("stream 8MiB/{chunk}B long values, {values} values"),
                mb_s(8 << 20, t, b),
            ));
        }
        // A 50 MB chat_history.jsonl rewrite.
        let line = br#"{"type":"assistant","content":[{"type":"text","text":"The build finished; 1428 tests passed in 92s."}]}"#;
        let mut big = Vec::with_capacity(50 << 20);
        while big.len() < 50 << 20 {
            big.extend_from_slice(line);
            big.push(b'\n');
        }
        let (t, b) = best_of(3, |rel| {
            let rel = if rel == VERBATIM {
                VERBATIM
            } else {
                "chat_history.jsonl"
            };
            let start = Instant::now();
            w.replace_atomic_sync(rel, &big).expect("rewrite");
            start.elapsed()
        });
        floors.push((
            format!("rewrite 50MB, {values} values"),
            mb_s(big.len(), t, b),
        ));
        // The same 50 MB copied in (a fork's sidecar, an import: record by record through `AtRestLines`; Fable round-3
        // Medium 3). Base: the verbatim store, a plain file copy.
        let src = w
            .dir()
            .join("..")
            .join(format!("copy-src-{}.jsonl", values.replace(' ', "-")));
        std::fs::write(&src, &big).expect("src");
        let (t, b) = best_of(3, |rel| {
            let rel = if rel == VERBATIM {
                VERBATIM
            } else {
                "fork/chat_history.jsonl"
            };
            let start = Instant::now();
            w.copy_in_sync(&src, rel).expect("copy");
            start.elapsed()
        });
        let _ = std::fs::remove_file(&src);
        floors.push((format!("copy 50MB, {values} values"), mb_s(big.len(), t, b)));
        // 10k small appends, p99, interleaved.
        let small = br#"{"type":"tool_result","id":"call-17","ok":true}"#.to_vec();
        let (mut ts, mut bs) = (Vec::with_capacity(10_000), Vec::with_capacity(10_000));
        for _ in 0..10_000 {
            let start = Instant::now();
            w.append_sync("updates.jsonl", &small).expect("append");
            ts.push(start.elapsed());
            let start = Instant::now();
            w.append_sync(VERBATIM, &small).expect("append");
            bs.push(start.elapsed());
        }
        ts.sort();
        bs.sort();
        report.push((
            format!("10k appends p99, {values} values"),
            ratio(ts[9_899], bs[9_899]),
            1.10,
        ));
    }
    for (name, r, limit) in &report {
        eprintln!("{name}: {r:.3} (limit {limit:.2})");
    }
    for (name, rate) in &floors {
        eprintln!("{name}: {rate:.0} MB/s (floor {FLOOR_MB_S:.0} MB/s)");
    }
    let failed: Vec<_> = report.iter().filter(|(_, r, limit)| r > limit).collect();
    let slow: Vec<_> = floors
        .iter()
        .filter(|(_, rate)| *rate < FLOOR_MB_S)
        .collect();
    assert!(
        failed.is_empty() && slow.is_empty(),
        "over the accepted cost: {failed:?}; under the floor: {slow:?}"
    );
}
