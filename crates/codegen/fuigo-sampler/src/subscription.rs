//! Subscription-only request adaptation. Auth is resolved immediately before
//! dispatch and can never be substituted by the ordinary API-key transport.
use fuigo_extra_ca::subscription::{Recipient, SubscriptionClient};
use fuigo_sampling_types::{Result, SamplingError};
use futures_util::future::BoxFuture;
use reqwest::{Request, Response};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionKind {
    Chatgpt,
    Xai,
}
impl SubscriptionKind {
    pub fn base_url(self) -> &'static str {
        match self {
            Self::Chatgpt => "https://chatgpt.com/backend-api/codex",
            Self::Xai => "https://api.x.ai/v1",
        }
    }
    fn recipient(self) -> Recipient {
        match self {
            Self::Chatgpt => Recipient::ChatGptInference,
            Self::Xai => Recipient::XaiInference,
        }
    }
    fn accepts(self, request: &Request) -> bool {
        request.method() == reqwest::Method::POST
            && ["responses", "chat/completions"]
                .into_iter()
                .filter(|path| self == Self::Xai || *path == "responses")
                .any(|path| request.url().as_str() == format!("{}/{path}", self.base_url()))
    }
}

pub struct SubscriptionBearer {
    token: String,
    account: String,
    expires_at: u64,
}
impl std::fmt::Debug for SubscriptionBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubscriptionBearer([REDACTED])")
    }
}
impl SubscriptionBearer {
    pub fn new(token: String, account: String, expires_at: u64) -> Self {
        Self {
            token,
            account,
            expires_at,
        }
    }
}
pub trait SubscriptionResolver: Send + Sync + std::fmt::Debug {
    fn resolve(&self) -> BoxFuture<'_, Result<SubscriptionBearer>>;
    #[cfg(test)]
    fn test_endpoint(&self) -> Option<String> {
        None
    }
}
pub type SharedSubscriptionResolver = Arc<dyn SubscriptionResolver>;

pub(crate) fn adapt_body(kind: SubscriptionKind, body: &mut serde_json::Value) -> Result<()> {
    if kind == SubscriptionKind::Xai {
        return Ok(());
    }
    let body = body
        .as_object_mut()
        .ok_or(SamplingError::InvalidConfiguration(
            "invalid subscription request body",
        ))?;
    // The Codex backend is stateless/streaming. Keep encrypted reasoning and call IDs
    // already round-tripped by Fuigo; remove only unsupported top-level parameters.
    body.retain(|key, _| {
        [
            "model",
            "input",
            "instructions",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "reasoning",
            "include",
            "text",
            "stream",
            "store",
        ]
        .contains(&key.as_str())
    });
    // The ChatGPT Codex backend rejects system-role input messages. Keep their
    // content/order as developer instructions instead of dropping the system prompt.
    if let Some(input) = body
        .get_mut("input")
        .and_then(serde_json::Value::as_array_mut)
    {
        for item in input {
            if item.get("role").and_then(serde_json::Value::as_str) == Some("system") {
                item["role"] = "developer".into();
            }
        }
    }
    body.insert("stream".into(), true.into());
    body.insert("store".into(), false.into());
    if !body.get("instructions").is_some_and(|v| v.is_string()) {
        body.insert(
            "instructions".into(),
            "You are Fuigo, a coding assistant.".into(),
        );
    }
    Ok(())
}

fn authorize_request(
    request: &mut Request,
    bearer: SubscriptionBearer,
    kind: SubscriptionKind,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if bearer.expires_at <= now || bearer.token.is_empty() || bearer.account.is_empty() {
        return Err(SamplingError::InvalidConfiguration(
            "subscription login required; credential expired or missing",
        ));
    }
    let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", bearer.token))
        .map_err(|_| SamplingError::InvalidConfiguration("invalid subscription credential"))?;
    auth.set_sensitive(true);
    // Rebuild the header set rather than forwarding first-party/auxiliary headers.
    *request.headers_mut() = reqwest::header::HeaderMap::new();
    request
        .headers_mut()
        .insert(reqwest::header::AUTHORIZATION, auth);
    request.headers_mut().insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    request.headers_mut().insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("text/event-stream"),
    );
    request.headers_mut().insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("Fuigo/subscription"),
    );
    if kind == SubscriptionKind::Chatgpt {
        request.headers_mut().insert(
            "originator",
            reqwest::header::HeaderValue::from_static("fuigo"),
        );
        let account = reqwest::header::HeaderValue::from_str(&bearer.account).map_err(|_| {
            SamplingError::InvalidConfiguration("invalid subscription account metadata")
        })?;
        request.headers_mut().insert("chatgpt-account-id", account);
    }
    Ok(())
}

pub(crate) async fn dispatch(
    kind: SubscriptionKind,
    resolver: Option<&SharedSubscriptionResolver>,
    mut request: Request,
) -> Result<Response> {
    // Reject a changed recipient before reading/refreshing credentials.
    if !kind.accepts(&request) {
        return Err(SamplingError::InvalidConfiguration(
            "subscription endpoint or protocol mismatch",
        ));
    }
    let bytes =
        request
            .body()
            .and_then(|b| b.as_bytes())
            .ok_or(SamplingError::InvalidConfiguration(
                "subscription requires a JSON request",
            ))?;
    let mut body: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| SamplingError::InvalidConfiguration("invalid subscription request JSON"))?;
    adapt_body(kind, &mut body)?;
    *request.body_mut() = Some(
        serde_json::to_vec(&body)
            .map_err(SamplingError::Serialization)?
            .into(),
    );
    let resolver = resolver.ok_or(SamplingError::InvalidConfiguration(
        "subscription auth must be reattached after loading config",
    ))?;
    let bearer = if let Some(remaining) = crate::request_accounting::remaining_time()? {
        tokio::time::timeout(remaining, resolver.resolve()).await.map_err(|_|
            SamplingError::InvalidConfiguration("execution deadline exhausted during subscription authentication"))??
    } else {
        resolver.resolve().await?
    };
    authorize_request(&mut request, bearer, kind)?;
    crate::request_accounting::clamp_deadline(&mut request)?;
    let client = SubscriptionClient::new(kind.recipient())
        .map_err(|_| SamplingError::InvalidConfiguration("subscription HTTP client unavailable"))?;
    #[cfg(test)]
    let local = resolver.test_endpoint();
    #[cfg(test)]
    if let Some(endpoint) = local {
        let url = reqwest::Url::parse(&endpoint).unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        *request.url_mut() = url;
        let client =
            fuigo_extra_ca::build_reqwest_client(|b| b.redirect(reqwest::redirect::Policy::none()))
                .unwrap();
        crate::request_accounting::dispatched();
        let response = fuigo_extra_ca::dispatch::execute(&client, request)
            .await
            .unwrap();
        return classify(response);
    }
    crate::request_accounting::dispatched();
    let response = client.execute(request).await.map_err(|_| {
        SamplingError::InvalidConfiguration("subscription transport failed; no API-key fallback")
    })?;
    classify(response)
}
fn classify(response: Response) -> Result<Response> {
    if !response.status().is_success() {
        return Err(SamplingError::Api {
            status: response.status(), message: "Subscription request rejected; check login, model access and subscription limits. No API-key fallback was attempted.".into(),
            model_metadata: None, retry_after_secs: None, should_retry: Some(false), error_code: None,
        });
    }
    Ok(response)
}

/// Reasoning siblings precede the assistant item carrying their emitting model.
/// Request-local filtering keeps visible messages/tool associations and leaves
/// persisted history intact, while preventing foreign opaque reasoning replay.
pub(crate) fn retain_reasoning_for_model(
    items: &mut Vec<fuigo_sampling_types::ConversationItem>,
    model: &str,
) {
    use fuigo_sampling_types::ConversationItem;
    let mut keep = vec![true; items.len()];
    let mut same_model = false;
    for (index, item) in items.iter().enumerate().rev() {
        match item {
            ConversationItem::Assistant(assistant) => {
                same_model = assistant.model_id.as_deref() == Some(model)
            }
            ConversationItem::Reasoning(_) => keep[index] = same_model,
            ConversationItem::User(_) | ConversationItem::System(_) => same_model = false,
            _ => {}
        }
    }
    let mut index = 0;
    items.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
}

/// Codex may send full output only in item.done events and an empty terminal
/// output array. Preserve those items, including encrypted reasoning and call IDs.
#[derive(Default)]
pub(crate) struct CodexOutput {
    items: std::collections::BTreeMap<u32, fuigo_sampling_types::rs::OutputItem>,
}
impl CodexOutput {
    pub(crate) fn observe(&mut self, event: &mut fuigo_sampling_types::rs::ResponseStreamEvent) {
        use fuigo_sampling_types::rs::ResponseStreamEvent as Event;
        let response = match event {
            Event::ResponseOutputItemDone(done) => {
                self.items.insert(done.output_index, done.item.clone());
                return;
            }
            Event::ResponseCompleted(done) => &mut done.response,
            Event::ResponseIncomplete(done) => &mut done.response,
            Event::ResponseFailed(done) => &mut done.response,
            _ => return,
        };
        if response.output.is_empty() {
            response.output = std::mem::take(&mut self.items).into_values().collect();
        } else {
            self.items.clear(); // A populated terminal response remains authoritative.
        }
    }
}

#[cfg(test)]
mod tests;
