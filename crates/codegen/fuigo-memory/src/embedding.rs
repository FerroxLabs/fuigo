//! Embedding provider abstraction for memory vector search.
//!
//! The sqlite-vec `chunks_vec` virtual table is the embedding cache; there is no separate cache.

use async_trait::async_trait;

/// Maximum retry attempts for transient API errors (429, 5xx).
const MAX_RETRIES: usize = 3;
/// Initial backoff delay in milliseconds (doubles on each retry: 1s, 2s, 4s).
const INITIAL_BACKOFF_MS: u64 = 1000;

/// Generates text embeddings.
/// The `Send + Sync` bound lets implementations run inside `Send` futures such as `tokio::spawn`.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Embed a batch of texts, returning one vector per input text.
    async fn embed_batch(
        &self,
        texts: &[&str],
    ) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>>;

    fn model_name(&self) -> &str;

    fn dimensions(&self) -> usize;

    fn cache_identity(&self) -> String {
        format!("v2-unit-cosine:{}:{}", self.model_name(), self.dimensions())
    }
}

/// All distance math uses unit vectors. Refuse malformed vectors rather than
/// silently comparing incompatible or non-finite values.
pub fn normalize_vector(vector: &[f32], dimensions: usize) -> Result<Vec<f32>, &'static str> {
    if vector.len() != dimensions || vector.is_empty() || vector.iter().any(|v| !v.is_finite()) {
        return Err("invalid embedding dimensions or values");
    }
    let norm = vector
        .iter()
        .map(|v| f64::from(*v).powi(2))
        .sum::<f64>()
        .sqrt();
    if norm <= f64::EPSILON {
        return Err("zero embedding");
    }
    Ok(vector
        .iter()
        .map(|v| (f64::from(*v) / norm) as f32)
        .collect())
}

fn parse_embeddings(
    body: &serde_json::Value,
    count: usize,
    dimensions: usize,
) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
    let data = body
        .get("data")
        .and_then(|d| d.as_array())
        .ok_or("missing embedding data")?;
    if data.len() != count {
        return Err("embedding response count mismatch".into());
    }
    let mut ordered = vec![None; count];
    for item in data {
        let index = item
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or("missing embedding index")? as usize;
        if index >= count || ordered[index].is_some() {
            return Err("invalid or duplicate embedding index".into());
        }
        let raw: Vec<f32> = item
            .get("embedding")
            .and_then(|v| v.as_array())
            .ok_or("missing embedding vector")?
            .iter()
            .map(|v| {
                v.as_f64()
                    .map(|v| v as f32)
                    .ok_or("invalid embedding value")
            })
            .collect::<Result<_, _>>()?;
        ordered[index] = Some(normalize_vector(&raw, dimensions)?);
    }
    ordered
        .into_iter()
        .map(|v| v.ok_or_else(|| "incomplete embeddings".into()))
        .collect()
}

/// API-based embedding provider using an OpenAI-compatible embeddings endpoint.
pub struct ApiEmbeddingProvider {
    api_base: String,
    model: String,
    dimensions: usize,
    client: reqwest_middleware::ClientWithMiddleware,
    max_batch_size: usize,
}

impl ApiEmbeddingProvider {
    pub fn new(
        api_base: String,
        model: String,
        dimensions: usize,
        client: reqwest_middleware::ClientWithMiddleware,
    ) -> Self {
        Self {
            api_base,
            model,
            dimensions,
            client,
            max_batch_size: 32,
        }
    }

    pub fn from_config(
        config: &fuigo_config_types::MemoryEmbeddingConfig,
        api_base: String,
        client: reqwest_middleware::ClientWithMiddleware,
    ) -> Option<Self> {
        if config.provider != "api" {
            return None;
        }
        let model = config.model.clone().filter(|m| !m.is_empty())?;
        Some(Self::new(api_base, model, config.dimensions, client))
    }

    pub fn from_session(
        config: &fuigo_config_types::MemoryEmbeddingConfig,
        proxy_base_url: String,
        auth_key: String,
    ) -> Option<Self> {
        let client = build_static_middleware_client(Some(auth_key));
        Self::from_config(config, proxy_base_url, client)
    }
}

pub(super) fn build_middleware_client(
    credentials: std::sync::Arc<dyn fuigo_auth::AuthCredentialProvider>,
) -> reqwest_middleware::ClientWithMiddleware {
    fuigo_http::with_auth_retry(fuigo_http::shared_client(), credentials)
}

fn build_static_middleware_client(
    api_key: Option<String>,
) -> reqwest_middleware::ClientWithMiddleware {
    let provider: std::sync::Arc<dyn fuigo_auth::AuthCredentialProvider> = std::sync::Arc::new(
        fuigo_auth::StaticAuthCredentialProvider::new(Box::new(NoopHttpAuth), api_key),
    );
    build_middleware_client(provider)
}

struct NoopHttpAuth;

impl fuigo_auth::HttpAuth for NoopHttpAuth {
    fn apply(&self, builder: reqwest::RequestBuilder, _base_url: &str) -> reqwest::RequestBuilder {
        builder
    }
}

#[async_trait]
impl EmbeddingProvider for ApiEmbeddingProvider {
    #[tracing::instrument(name = "memory.embed_batch", skip_all, fields(batch_size = texts.len()))]
    async fn embed_batch(
        &self,
        texts: &[&str],
    ) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
        if texts
            .iter()
            .any(|text| !super::safety::is_safe_memory(text))
        {
            return Err("unsafe embedding input".into());
        }
        if texts.is_empty() {
            return Ok(vec![]);
        }

        let mut all_embeddings = Vec::with_capacity(texts.len());

        // The API caps payload size, so texts are sent in chunks of max_batch_size
        for batch in texts.chunks(self.max_batch_size) {
            let input: Vec<&str> = batch.to_vec();
            let body_json = serde_json::json!({
                "model": self.model,
                "input": input,
                "dimensions": self.dimensions,
            });

            // Transient errors (429, 5xx) are retried with exponential backoff
            let mut last_err = String::new();
            let mut success = false;
            for attempt in 0..MAX_RETRIES {
                if attempt > 0 {
                    let delay = INITIAL_BACKOFF_MS * 2u64.pow(attempt as u32 - 1);
                    tracing::warn!(
                        attempt,
                        delay_ms = delay,
                        "retrying embedding API call after transient error"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }

                let request = fuigo_http::shared_client()
                    .post(format!("{}/embeddings", self.api_base))
                    .json(&body_json)
                    .header("X-XAI-Token-Auth", "xai-grok-cli")
                    .header("x-fuigo-client-version", fuigo_version::VERSION);

                let req = match request.build() {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(format!("failed to build embedding request: {e}").into());
                    }
                };
                let response = match self.client.execute(req).await {
                    Ok(r) => r,
                    Err(e) => {
                        last_err = format!("request failed: {e}");
                        continue;
                    }
                };

                let status = response.status();
                if status.is_success() {
                    const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
                    let mut response = response;
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response.chunk().await? {
                        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                            return Err("embedding response too large".into());
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
                    all_embeddings.extend(parse_embeddings(&body, batch.len(), self.dimensions)?);
                    success = true;
                    break;
                }

                // Retry on 429 (rate limit) or 5xx (server error)
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                    last_err = format!("HTTP {status}");
                    continue;
                }

                // Any other status is not retryable, so fail immediately
                return Err(format!("embedding API error {status}").into());
            }

            if !success {
                return Err(format!(
                    "embedding API failed after {MAX_RETRIES} attempts: {last_err}"
                )
                .into());
            }
        }

        Ok(all_embeddings)
    }

    fn cache_identity(&self) -> String {
        let endpoint = reqwest::Url::parse(&self.api_base)
            .map(|mut u| {
                u.set_query(None);
                u.set_fragment(None);
                let _ = u.set_username("");
                let _ = u.set_password(None);
                u.to_string()
            })
            .unwrap_or_default();
        blake3::hash(
            format!(
                "v2-unit-cosine:api:{endpoint}:{}:{}",
                self.model, self.dimensions
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string()
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }
}

/// A mock provider for tests: each vector is derived from the blake3 hash of the text, so results are deterministic.
#[cfg(any(test, feature = "test-support"))]
pub struct MockEmbeddingProvider {
    pub dimensions: usize,
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl EmbeddingProvider for MockEmbeddingProvider {
    async fn embed_batch(
        &self,
        texts: &[&str],
    ) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
        Ok(texts
            .iter()
            .map(|text| {
                let hash = blake3::hash(text.as_bytes());
                let bytes = hash.as_bytes();
                (0..self.dimensions)
                    .map(|i| bytes[i % 32] as f32 / 255.0)
                    .collect()
            })
            .collect())
    }

    fn model_name(&self) -> &str {
        "mock-embedding"
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_embedding_deterministic() {
        let provider = MockEmbeddingProvider { dimensions: 4 };
        let r1 = provider.embed_batch(&["hello"]).await.unwrap();
        let r2 = provider.embed_batch(&["hello"]).await.unwrap();
        assert_eq!(r1, r2);
    }

    #[tokio::test]
    async fn test_mock_embedding_different_texts() {
        let provider = MockEmbeddingProvider { dimensions: 4 };
        let results = provider.embed_batch(&["hello", "world"]).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_ne!(results[0], results[1]);
    }

    #[tokio::test]
    async fn test_mock_embedding_empty_input() {
        let provider = MockEmbeddingProvider { dimensions: 4 };
        let results = provider.embed_batch(&[]).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_mock_embedding_correct_dimensions() {
        let provider = MockEmbeddingProvider { dimensions: 128 };
        let results = provider.embed_batch(&["test"]).await.unwrap();
        assert_eq!(results[0].len(), 128);
    }
}

#[cfg(test)]
mod repair_tests {
    use super::*;
    #[test]
    fn response_indices_and_unit_norm_are_enforced() {
        let body = serde_json::json!({"data": [
            {"index": 1, "embedding": [0.0, 4.0]}, {"index": 0, "embedding": [3.0, 0.0]}
        ]});
        assert_eq!(
            parse_embeddings(&body, 2, 2).unwrap(),
            vec![vec![1.0, 0.0], vec![0.0, 1.0]]
        );
        let duplicate = serde_json::json!({"data": [{"index":0,"embedding":[1.0,0.0]}, {"index":0,"embedding":[1.0,0.0]}]});
        assert!(parse_embeddings(&duplicate, 2, 2).is_err());
        assert!(normalize_vector(&[f32::NAN, 0.0], 2).is_err());
        assert!(normalize_vector(&[0.0, 0.0], 2).is_err());
        assert!(normalize_vector(&[1.0], 2).is_err());
    }
}
