use super::*;

/// Boxed future returned by [`ModelsEndpoint::fetch_models`].
pub(crate) type ModelsFetchFuture =
    Pin<Box<dyn Future<Output = Option<IndexMap<String, ModelEntry>>> + Send>>;

/// What one `/v1/models` fetch came to. The refresh code treats a 401 differently from every other failure.
pub(crate) enum ModelsFetchOutcome {
    Fetched(IndexMap<String, ModelEntry>),
    /// A fresh on-disk catalog answered; no request was sent, so this neither clears nor extends a 401 wait.
    Cached(IndexMap<String, ModelEntry>),
    /// The server answered 401: the key or sign-in in use was rejected. (A 403 is `Unavailable`, as before.)
    AuthRejected,
    Unavailable,
}

/// Boxed future returned by [`ModelsEndpoint::fetch_models_outcome`].
pub(crate) type ModelsOutcomeFuture = Pin<Box<dyn Future<Output = ModelsFetchOutcome> + Send>>;

/// The `/v1/models` fetch behind a trait so tests can inject a fake.
pub(crate) trait ModelsEndpoint: Send + Sync {
    fn fetch_models(
        &self,
        endpoints: config::EndpointsConfig,
        auth: Option<FuigoAuth>,
        fetch_auth: ModelFetchAuth,
    ) -> ModelsFetchFuture;

    /// Like [`Self::fetch_models`] but says when the server rejected the credential (401). The default cannot tell,
    /// so a fake that only implements `fetch_models` reports every failure as `Unavailable`.
    fn fetch_models_outcome(
        &self,
        endpoints: config::EndpointsConfig,
        auth: Option<FuigoAuth>,
        fetch_auth: ModelFetchAuth,
    ) -> ModelsOutcomeFuture {
        let fut = self.fetch_models(endpoints, auth, fetch_auth);
        Box::pin(async move {
            match fut.await {
                Some(models) => ModelsFetchOutcome::Fetched(models),
                None => ModelsFetchOutcome::Unavailable,
            }
        })
    }
}

/// The default implementation: the real `/v1/models` fetch.
pub(crate) struct HttpModelsEndpoint;

impl ModelsEndpoint for HttpModelsEndpoint {
    fn fetch_models(
        &self,
        endpoints: config::EndpointsConfig,
        auth: Option<FuigoAuth>,
        fetch_auth: ModelFetchAuth,
    ) -> ModelsFetchFuture {
        Box::pin(fetch_models_async(endpoints, auth, fetch_auth))
    }

    fn fetch_models_outcome(
        &self,
        endpoints: config::EndpointsConfig,
        auth: Option<FuigoAuth>,
        fetch_auth: ModelFetchAuth,
    ) -> ModelsOutcomeFuture {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                prefetch_models_outcome_blocking(&endpoints, auth.as_ref(), fetch_auth)
            })
            .await
            .unwrap_or(ModelsFetchOutcome::Unavailable)
        })
    }
}

pub(crate) async fn fetch_models_async(
    endpoints: config::EndpointsConfig,
    auth: Option<FuigoAuth>,
    fetch_auth: ModelFetchAuth,
) -> Option<IndexMap<String, ModelEntry>> {
    tokio::task::spawn_blocking(move || {
        prefetch_models_blocking(&endpoints, auth.as_ref(), fetch_auth)
    })
    .await
    .unwrap_or(None)
}
