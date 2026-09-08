//! Offline production retrieval evaluation. No answer generation or network.
//! Run with --features test-support. Third argument optionally supplies exact-text local vectors.
use async_trait::async_trait;
use fuigo_config_types::{MemoryIndexConfig, MemorySearchConfig};
use fuigo_memory::{
    MemoryIndex, MemoryStorage, embedding::EmbeddingProvider, init_sqlite_vec,
    search::hybrid_search,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

struct Vectors {
    identity: String,
    dimensions: usize,
    values: HashMap<String, Vec<f32>>,
}
#[async_trait]
impl EmbeddingProvider for Vectors {
    async fn embed_batch(
        &self,
        texts: &[&str],
    ) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
        texts
            .iter()
            .map(|text| {
                self.values
                    .get(*text)
                    .cloned()
                    .ok_or_else(|| "Missing exact-text local vector".into())
            })
            .collect()
    }
    fn model_name(&self) -> &str {
        &self.identity
    }
    fn dimensions(&self) -> usize {
        self.dimensions
    }
}
fn string(v: &Value, key: &str) -> String {
    v[key].as_str().expect("corpus string").to_owned()
}
fn ids(v: &Value) -> HashSet<String> {
    v.as_array()
        .expect("corpus array")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(3..=5).contains(&args.len()) {
        return Err("Usage: memory_eval CORPUS OUTPUT [LOCAL_VECTORS]".into());
    }
    let raw = std::fs::read(&args[1])?;
    let corpus: Value = serde_json::from_slice(&raw)?;
    let queries = corpus["queries"].as_array().ok_or("queries missing")?;
    if queries.len() != corpus["expected_queries"].as_u64().unwrap_or(240) as usize
        || queries.is_empty()
    {
        return Err("Expected frozen 240-query corpus".into());
    }
    let vectors = if let Some(path) = args.get(3) {
        let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        if value["corpus"] != corpus {
            return Err("Vector corpus identity mismatch".into());
        }
        let dimensions = value["dimensions"].as_u64().ok_or("dimensions missing")? as usize;
        let mut values = HashMap::new();
        for (text, vector) in value["vectors"].as_object().ok_or("vectors missing")? {
            let vector: Vec<f32> = serde_json::from_value(vector.clone())?;
            values.insert(
                text.clone(),
                fuigo_memory::embedding::normalize_vector(&vector, dimensions)?,
            );
        }
        Some(Vectors {
            identity: string(&value, "identity"),
            dimensions,
            values,
        })
    } else {
        None
    };
    init_sqlite_vec();
    let mut rows = vec![];
    for query in queries {
        let root = tempfile::tempdir()?;
        let storage = MemoryStorage::with_paths(
            root.path().join("memory"),
            root.path().join("memory/workspace"),
        )
        .with_global_enabled(false);
        storage.ensure_initialized()?;
        let mut index = MemoryIndex::open_or_create(
            &root.path().join("index.sqlite"),
            storage.clone(),
            MemoryIndexConfig::default(),
            vectors.as_ref().map_or(4, |v| v.dimensions),
        )?;
        let allowed = ids(&query["allowedScopes"]);
        // Host-authorized scopes map into one isolated Fuigo workspace. Foreign
        // records remain on disk outside it; reindex must reject those paths.
        for source in corpus["sources"].as_array().unwrap() {
            let id = string(source, "id");
            let permitted = allowed.contains(&string(source, "scope"));
            let dir = if permitted {
                storage.sessions_dir()
            } else {
                root.path().join("foreign")
            };
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{id}.md"));
            std::fs::write(&path, string(source, "text"))?;
            let result = index.reindex_file(&path, "workspace");
            if permitted {
                result?;
            } else if result.is_ok() {
                return Err("Foreign index admission succeeded".into());
            }
            // Preserve stale indexed candidates, then remove retired sources.
            // This measures file invalidation, not Murage record approval.
            if source["state"] != "active" {
                std::fs::remove_file(&path)?;
            }
        }
        for n in 0..query["distractorCount"].as_u64().unwrap_or(0) {
            let path = storage.sessions_dir().join(format!("distractor-{n}.md"));
            std::fs::write(
                &path,
                format!("Unrelated inventory item {n}: warehouse shelf and packing material."),
            )?;
            index.reindex_file(&path, "workspace")?;
        }
        let mut embedded_chunks = 0;
        if let Some(provider) = &vectors {
            if !index.vec_available() {
                return Err("Local vector mode requires sqlite-vec".into());
            }
            index.bind_embedding_provider(provider)?;
            for (id, text) in index.chunks_without_embeddings()? {
                // Retired chunks intentionally retain no vectors; their FTS rows
                // remain eligible for the source validation negative controls.
                let Some(chunk) = index.get_chunk(&id)? else {
                    continue;
                };
                if !index.chunk_is_current(&chunk) {
                    continue;
                }
                let vector = provider.embed_batch(&[&text]).await?;
                index.upsert_embedding_if_current(&id, &text, &vector[0])?;
                embedded_chunks += 1;
            }
        }
        let config = MemorySearchConfig {
            max_results: 10,
            semantic_min_score: args.get(4).map(|value| value.parse::<f32>()).transpose()?,
            ..Default::default()
        };
        let vector_candidates = if let Some(provider) = &vectors {
            let query_vector = provider.embed_batch(&[&string(query, "query")]).await?;
            index.vector_search(&query_vector[0], 30)?.len()
        } else {
            0
        };
        let started = std::time::Instant::now();
        let results = hybrid_search(
            &index,
            vectors.as_ref().map(|v| v as &dyn EmbeddingProvider),
            &string(query, "query"),
            &config,
        )
        .await?;
        let delivered: HashSet<String> = results
            .iter()
            .map(|r| {
                Path::new(&r.path)
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let expected = ids(&query["expected"]);
        let forbidden = ids(&query["forbidden"]);
        let correct = delivered.intersection(&expected).count();
        rows.push(json!({"id":query["id"],"family":query["family"],"embedded_chunks":embedded_chunks,"vector_candidates":vector_candidates,"vector_available":index.vec_available(),"delivered":delivered,"expected":expected,"correct":correct,"recall":if expected.is_empty(){None}else{Some(correct as f64/expected.len() as f64)},"forbidden":delivered.intersection(&forbidden).collect::<Vec<_>>(),"unsupported":delivered.difference(&expected).collect::<Vec<_>>(),"latency_ms":started.elapsed().as_secs_f64()*1000.0}));
    }
    let result = json!({"mode":if vectors.is_some(){"real-local-vector-replay"}else{"lexical"},"model":vectors.as_ref().map(|v|&v.identity),"corpus_blake3":blake3::hash(&raw).to_hex().as_str(),"cases":rows,"limitations":["File-backed scope projection; not Murage record lifecycle or approval parity","Retrieval only; no capture or generated-answer claim","Quality misses are reported, not hidden by changing thresholds"]});
    std::fs::write(&args[2], serde_json::to_vec_pretty(&result)?)?;
    println!(
        "Evaluated {} cases; inspect quality scores in {}",
        queries.len(),
        args[2]
    );
    Ok(())
}
