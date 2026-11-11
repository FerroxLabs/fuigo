use fuigo_sampling_types::refusal::{PromptSM, classify, decide, from_upstream, fuigo_upstream};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-11-10T20:07:21Z")
        .unwrap()
        .to_utc()
}
fn endpoint(s: &str) -> &str {
    match s {
        "/v1/chat/completions" => "chat",
        "/v1/responses" => "resp",
        "/v1/messages" => "msg",
        _ => s,
    }
}
fn leaves(value: &Value, prefix: &str, out: &mut BTreeMap<String, Value>) {
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if !v.is_object() {
                continue;
            }
            if v.get("status").is_some() && (v.get("body").is_some() || v.get("headers").is_some())
            {
                out.insert(format!("{prefix}{}", endpoint(k)), v.clone());
            } else {
                leaves(v, &format!("{prefix}{}/", k.replace("_variant", "")), out);
            }
        }
    }
}
fn fixtures() -> BTreeMap<String, Value> {
    let mut all = BTreeMap::new();
    for (sub, pre) in [("", ""), ("siblings", ""), ("target-654", "t654:")] {
        let Ok(dir) = std::fs::read_dir(root().join("flux-fixtures").join(sub)) else {
            continue;
        };
        for entry in dir {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy();
            if !name.ends_with(".json") || name.starts_with("._") {
                continue;
            }
            let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            if v["not_reachable_in_prod"] == true {
                continue;
            }
            let stem = name.split('-').next().unwrap();
            let prefix = format!("{pre}{stem}.");
            if v.get("body").is_some() || v.get("headers").is_some() {
                all.insert(
                    format!("{prefix}{}", endpoint(v["endpoint"].as_str().unwrap())),
                    v.clone(),
                );
            }
            leaves(&v["per_endpoint"], &prefix, &mut all);
        }
    }
    all
}
fn rows() -> Vec<Vec<String>> {
    let bytes = std::fs::read(root().join("busyloop_expected.tsv")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "691fb460e66023bd7c2dd4699ed6ba41d99a2b6b09ae3d8e03015e6930e6c035"
    );
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .skip(1)
        .filter(|l| !l.is_empty())
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}
fn inputs() -> BTreeMap<String, (String, u16, Value, Value)> {
    let mut fx = fixtures();
    let mut inputs = BTreeMap::new();
    for r in rows() {
        let (st, h, b) = if r[3] == "fixture" {
            let v = fx
                .remove(&r[0])
                .unwrap_or_else(|| panic!("missing leaf {}", r[0]));
            (
                v["status"].as_u64().unwrap() as u16,
                v["headers"].clone(),
                v["body"].clone(),
            )
        } else {
            (
                r[3].parse().unwrap(),
                serde_json::from_str(&r[4]).unwrap(),
                serde_json::from_str(&r[5]).unwrap(),
            )
        };
        inputs.insert(r[0].clone(), (r[2].clone(), st, h, b));
    }
    assert!(fx.is_empty(), "leaves without rows: {:?}", fx.keys());
    inputs
}
fn reference(key: &str) -> Value {
    let all: Value =
        serde_json::from_slice(&std::fs::read(root().join("busyloop_reference.json")).unwrap())
            .unwrap();
    all[key].clone()
}
#[test]
fn fa13_tsv_port_parity_126_rows_zero_mismatches() {
    let inputs = inputs();
    let mut failures = vec![];
    let mut revoked_rows = 0;
    for r in rows() {
        let (ep, st, h, b) = &inputs[&r[0]];
        let got = classify(ep, *st, h, b, now());
        revoked_rows += usize::from(got.reason == "keyRevoked");
        assert_eq!(
            fuigo_sampling_types::refusal::key_rejected_mark(&got.reason),
            got.reason == "keyRevoked",
            "{} key mark",
            r[0]
        );
        if (got.reason.as_str(), got.action.as_str(), got.wait.as_str())
            != (r[6].as_str(), r[7].as_str(), r[8].as_str())
        {
            failures.push(format!("{} expected {:?}, got {:?}", r[0], &r[6..9], got));
        }
        if ep == "resp" {
            let u = fuigo_upstream(*st, h, b);
            let raw = fuigo_sampling_types::refusal::extract(ep, *st, h, b, now());
            let projected = from_upstream(&u, "", now());
            assert_eq!(raw.codes, projected.codes, "{} code projection", r[0]);
            let e = &b["error"];
            let typ = e["type"].as_str().unwrap_or("");
            let msg = e["message"].as_str().unwrap_or("");
            let inner = if !typ.is_empty() && !msg.is_empty() {
                format!("{typ}: {msg}")
            } else {
                format!("{typ}{msg}")
            };
            let text = format!("API error (status {st}): {inner}")
                .chars()
                .take(280)
                .collect::<String>();
            let via = decide(&from_upstream(&u, &text, now()));
            if via != got {
                failures.push(format!("{} upstream parity: {:?} != {:?}", r[0], via, got));
            }
        }
    }
    assert!(revoked_rows > 0);
    assert_eq!(inputs.len(), 126);
    assert_eq!(reference("expected_counts")["rows"], 126);
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("126 rows, 93 fixture leaves, 0 mismatches");
}
#[test]
fn fixture_manifest_is_byte_identical() {
    let manifest: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(root().join("MANIFEST.json")).unwrap()).unwrap();
    for (path, sha) in manifest {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(root().join(&path)).unwrap())
            ),
            sha,
            "{path}"
        );
    }
}
#[test]
fn prompt_sm_w1_w25_from_reference_traces() {
    let traces = reference("witness_traces");
    let inputs = inputs();
    for trace in traces.as_array().unwrap() {
        let refreshable = trace[1].as_bool().unwrap();
        let mut sm = PromptSM::new(refreshable);
        for event in trace[2].as_array().unwrap() {
            match event[0].as_str().unwrap() {
                "d" => sm.dispatch(event[1].as_str().unwrap()),
                "t" => sm.refresh_token(),
                "new" => sm = PromptSM::new(refreshable),
                _ => {
                    let kind = event[1].as_str().unwrap();
                    let id = event[2].as_str().unwrap();
                    if id == "ok" {
                        sm.respond(kind, 200, None);
                    } else {
                        let (ep, st, h, b) = &inputs[id];
                        sm.respond(kind, *st, Some(&classify(ep, *st, h, b, now())));
                    }
                }
            }
        }
        assert_eq!(
            json!(sm.verdict()),
            trace[3],
            "{} {:?}",
            trace[0],
            sm.violations
        );
    }
}

#[test]
fn original_a21_124_row_fixture_is_retained_byte_identical_and_still_passes() {
    let bytes = std::fs::read(root().join("busyloop_expected_v21.tsv")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "0cbb945cbc3b45d4c7477a80e847e6a67b897f4802950f1c4e054bdac9d3977e"
    );
    let inputs = inputs();
    let text = String::from_utf8(bytes).unwrap();
    let mut count = 0;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let r: Vec<_> = line.split('\t').collect();
        let (ep, st, h, b) = &inputs[r[0]];
        let got = classify(ep, *st, h, b, now());
        assert_eq!(
            (got.reason.as_str(), got.action.as_str(), got.wait.as_str()),
            (r[6], r[7], r[8]),
            "{}",
            r[0]
        );
        count += 1;
    }
    assert_eq!(count, 124);
    assert_eq!(reference("expected_counts")["rows_v21"], 124);
}
#[test]
fn fa11_projection_required_is_loaded_from_the_reference() {
    let required = reference("projection_required");
    let inputs = inputs();
    for (id, keys) in required.as_object().unwrap() {
        let (_, st, h, b) = &inputs[id];
        let got = serde_json::to_value(fuigo_upstream(*st, h, b)).unwrap();
        for (key, want) in keys.as_object().unwrap() {
            assert_eq!(&got[key], want, "{id}: {key}");
        }
    }
}
