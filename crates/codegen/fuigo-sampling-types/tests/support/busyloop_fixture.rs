use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuigo-sampling-types/tests/fixtures")
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
pub fn rows() -> Vec<Vec<String>> {
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
pub fn inputs() -> BTreeMap<String, (String, u16, Value, Value)> {
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
pub fn reference(key: &str) -> Value {
    let all: Value =
        serde_json::from_slice(&std::fs::read(root().join("busyloop_reference.json")).unwrap())
            .unwrap();
    all[key].clone()
}
