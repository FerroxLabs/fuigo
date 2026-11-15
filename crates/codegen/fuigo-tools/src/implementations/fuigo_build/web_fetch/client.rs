//! `WebFetchClient` - shared HTTP client with cache, HTML-to-markdown
//! conversion, URL validation, and SSRF protection.

use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use std::path::PathBuf;

use crate::implementations::fuigo_build::storage::SessionFiles;
use std::sync::Arc;

use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, USER_AGENT};
use url::Url;

use super::cache::FetchCache;
use super::domain::DomainMatcher;
use super::config::{MAX_REDIRECTS, MAX_URL_LENGTH, USER_AGENT_STRING, WebFetchParams};
use super::error::WebFetchError;
use super::http::HttpClient;
use super::overflow::{OverflowHandler, RecoveryTools, inline_budget};
use super::ssrf;
use crate::implementations::fuigo_build::storage::SessionFileWriter;
use crate::types::output::{WebFetchContent, WebFetchOutput, WebFetchSourceArtifact};
use html5ever::tree_builder::{NodeOrText, TreeSink};
use scraper::{Html, HtmlTreeSink, Selector};

const DEFAULT_DOWNLOAD_DIR: &str = "downloads";

/// Shared HTTP client and cache for web fetching.
#[derive(Clone)]
pub struct WebFetchClient {
    http: HttpClient,
    cache: Arc<parking_lot::RwLock<FetchCache>>,
    converter: Arc<htmd::HtmlToMarkdown>,
    params: WebFetchParams,
    /// The static allowlist, built once (review L10).
    allowed: Arc<DomainMatcher>,
    download_writer: SessionFileWriter,
    image_writer: SessionFileWriter,
    video_writer: SessionFileWriter,
    overflow: OverflowHandler,
}

struct ProcessedText {
    content: String,
    content_type: String,
    bytes: usize,
    was_truncated: bool,
    artifact_path: Option<PathBuf>,
    inline_fallback: Option<String>,
}

impl WebFetchClient {
    pub fn new(params: &WebFetchParams) -> Result<Self, WebFetchError> {
        let converter = Arc::new(
            htmd::HtmlToMarkdown::builder()
                .skip_tags(vec![
                    "script", "style", "noscript", "svg", "iframe", "object", "embed",
                ])
                .add_handler(vec!["table"], unpadded_table_handler)
                .build(),
        );

        Ok(Self {
            // Reqwest client can fail to build.
            http: HttpClient::new(params)?,
            cache: Arc::new(parking_lot::RwLock::new(FetchCache::new(
                params.cache_ttl_secs(),
                params.max_cache_entries(),
            ))),
            converter,
            params: params.clone(),
            allowed: Arc::new(DomainMatcher::new(&params.allowed_domains())),
            download_writer: SessionFileWriter::new(DEFAULT_DOWNLOAD_DIR, "pdf"),
            image_writer: SessionFileWriter::new("images", "jpg"),
            video_writer: SessionFileWriter::new("videos", "mp4"),
            overflow: OverflowHandler::new(),
        })
    }

    /// Fetch a URL and return its content as markdown.
    ///
    /// Handles: validation, HTTPS upgrade, SSRF check, HTTP fetch with
    /// same-host redirects, HTML-to-markdown conversion, truncation, and
    /// caching. On transport errors, the HTTP client is invalidated so
    /// the next call gets a fresh connection pool (see [`HttpClient`]).
    pub(crate) async fn fetch(
        &self,
        raw_url: &str,
        session_folder: Option<&SessionFiles>,
        read_tool_name: Option<&str>,
        execute_tool_name: Option<&str>,
    ) -> Result<WebFetchOutput, WebFetchError> {
        let mut url = validate_url(raw_url)?;
        upgrade_to_https(&mut url);

        let url_str = url.to_string();

        // Check cache.
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&url_str) {
                tracing::debug!("web_fetch cache hit for {url_str}");
                return Ok(cached.clone());
            }
        }

        // SSRF check (policy from tool params — not process env at call time).
        ssrf::check_ssrf(&url, self.params.allow_local()).await?;

        // Make request and build output.
        let http = self.http.get_or_rebuild_for(&url)?;
        // A URL the static allowlist pre-approves stays inside it across redirects (audit S5-F10):
        // a same-host redirect out of an allowed path prefix comes back as a redirect to approve.
        let matcher = &*self.allowed;
        let scope = matcher.check(&url).is_none().then_some(matcher);
        let result = match fetch_url_scoped(
            &http,
            &url,
            self.params.max_content_length(),
            self.params.allow_local(),
            scope,
        )
        .await
        {
            Ok(result) => result,
            Err(e @ WebFetchError::HttpRequest(_)) => {
                self.http.invalidate();
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let (body, content_type, final_url, status_code) = match result {
            FetchResult::Content {
                body,
                content_type,
                final_url,
                status_code,
            } => (body, content_type, final_url, status_code),
            FetchResult::CrossHostRedirect {
                original_host,
                redirect_url,
            } => {
                return Ok(WebFetchOutput::CrossHostRedirect {
                    original_host,
                    redirect_url,
                });
            }
        };

        // PDF: save raw bytes to disk instead of lossy UTF-8 conversion.
        if is_pdf(&content_type) {
            let media_session_folder = require_media_session_folder(session_folder)?;
            let output = save_pdf(
                &self.download_writer,
                media_session_folder,
                &body,
                final_url,
                content_type,
                status_code,
                read_tool_name,
            )
            .await?;
            return Ok(output);
        }

        // Image: validate magic bytes, save to disk.
        if is_image(&content_type) {
            if !validate_media_magic_bytes(&content_type, &body) {
                return Err(WebFetchError::ContentTypeMismatch {
                    content_type,
                    url: final_url,
                });
            }
            let media_session_folder = require_media_session_folder(session_folder)?;
            let output = save_image(
                &self.image_writer,
                media_session_folder,
                &body,
                final_url,
                content_type,
                status_code,
                read_tool_name,
            )
            .await?;
            return Ok(output);
        }

        // Video: validate magic bytes, save to disk.
        if is_video(&content_type) {
            if !validate_media_magic_bytes(&content_type, &body) {
                return Err(WebFetchError::ContentTypeMismatch {
                    content_type,
                    url: final_url,
                });
            }
            let media_session_folder = require_media_session_folder(session_folder)?;
            let output = save_video(
                &self.video_writer,
                media_session_folder,
                &body,
                final_url,
                content_type,
                status_code,
            )
            .await?;
            return Ok(output);
        }

        // Reject binary content types that would produce garbage through lossy UTF-8.
        if is_binary_content_type(&content_type) {
            return Err(WebFetchError::UnsupportedContentType {
                content_type,
                url: final_url,
            });
        }

        let processed = self
            .process_text_content(
                &body,
                &content_type,
                session_folder,
                RecoveryTools {
                    read: read_tool_name,
                    execute: execute_tool_name,
                },
            )
            .await;
        let was_truncated = processed.was_truncated;

        let output = WebFetchOutput::Content(WebFetchContent {
            url: final_url,
            content: processed.content,
            content_type: processed.content_type,
            status_code,
            bytes: processed.bytes,
            source_artifact: processed
                .artifact_path
                .map(|path| WebFetchSourceArtifact { path }),
            inline_fallback: processed.inline_fallback,
            output_location: None,
        });

        // Insert into cache.
        {
            let mut cache = self.cache.write();
            cache.insert_text(url_str, output.clone(), was_truncated);
        }

        Ok(output)
    }

    async fn process_text_content(
        &self,
        body: &[u8],
        content_type: &str,
        session_folder: Option<&SessionFiles>,
        tools: RecoveryTools<'_>,
    ) -> ProcessedText {
        let raw_content = String::from_utf8_lossy(body);
        let content = if is_html(content_type) {
            html_to_markdown(&self.converter, &raw_content)
        } else {
            raw_content.into_owned()
        };
        let content = strip_base64_data_uris(content);
        let bytes = content.len();
        let output_content_type = if is_html(content_type) {
            "markdown".to_string()
        } else {
            content_type.to_owned()
        };
        let overflow = self
            .overflow
            .process(
                content,
                inline_budget(
                    self.params.context_window_tokens(),
                    self.params.max_markdown_length(),
                ),
                session_folder,
                &output_content_type,
                tools,
            )
            .await;
        ProcessedText {
            content: overflow.content,
            content_type: output_content_type,
            bytes,
            was_truncated: overflow.was_truncated,
            artifact_path: overflow.artifact_path,
            inline_fallback: overflow.path_free_content,
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// URL Validation
// ───────────────────────────────────────────────────────────────────────────

/// Validates URL scheme, length, credentials, and hostname labels.
fn validate_url(raw: &str) -> Result<Url, WebFetchError> {
    if raw.len() > MAX_URL_LENGTH {
        return Err(WebFetchError::UrlTooLong {
            max: MAX_URL_LENGTH,
        });
    }

    let parsed = Url::parse(raw)?; // uses #[from] url::ParseError

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(WebFetchError::UnsupportedScheme {
                scheme: scheme.to_string(),
            });
        }
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(WebFetchError::CredentialsInUrl);
    }

    if let Some(host) = parsed.host_str()
        && host.split('.').count() < 2
        // `localhost` is a single-label name; SSRF still requires
        // allow_local for explicit local hosts.
        && !ssrf::is_explicit_local_host(host)
    {
        return Err(WebFetchError::SingleLabelHost {
            host: host.to_string(),
        });
    }

    Ok(parsed)
}

/// Upgrade `http://` to `https://`, except for explicit loopback hosts.
///
/// Local dev servers almost always speak plain HTTP; forcing TLS would break
/// `http://127.0.0.1` / `http://localhost` when local binding is opted in.
fn upgrade_to_https(url: &mut Url) {
    if url.scheme() != "http" {
        return;
    }
    if let Some(host) = url.host_str()
        && ssrf::is_explicit_local_host(host)
    {
        return;
    }
    let _ = url.set_scheme("https");
}

// ───────────────────────────────────────────────────────────────────────────
// HTTP Fetching
// ───────────────────────────────────────────────────────────────────────────

enum FetchResult {
    Content {
        body: Vec<u8>,
        content_type: String,
        final_url: String,
        status_code: u16,
    },
    CrossHostRedirect {
        original_host: String,
        redirect_url: String,
    },
}

/// Fetch a URL with manual same-host redirect handling.
///
/// Re-runs SSRF checks on every hop so DNS rebinding between redirects cannot
/// sneak a previously-blocked address past the initial check (partial TOCTOU
/// mitigation; peer IP on the live TCP connection is not available from reqwest).
#[cfg(test)]
async fn fetch_url(
    client: &reqwest::Client,
    url: &Url,
    max_content_length: usize,
    allow_local: bool,
) -> Result<FetchResult, WebFetchError> {
    fetch_url_scoped(client, url, max_content_length, allow_local, None).await
}

/// [`fetch_url`] with an optional `scope`: when set, a same-host redirect to a URL the scope does
/// not allow (a path outside the pre-approved prefix) is returned as a redirect needing approval,
/// like a cross-host one.
async fn fetch_url_scoped(
    client: &reqwest::Client,
    url: &Url,
    max_content_length: usize,
    allow_local: bool,
    scope: Option<&DomainMatcher>,
) -> Result<FetchResult, WebFetchError> {
    let mut current_url = url.clone();
    let mut hops = 0;

    // Loop to follow redirects under the same host.
    loop {
        fuigo_extra_ca::dispatch::check_url(&current_url)?;
        // Re-check on every hop (including the first) so a rebinding name that
        // was public at the pre-fetch check cannot become loopback/private here.
        ssrf::check_ssrf(&current_url, allow_local).await?;

        let resp = client
            .get(current_url.as_str())
            .header(USER_AGENT, USER_AGENT_STRING)
            .header(
                ACCEPT,
                "text/markdown,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .send_checked()
            .await?;

        let status = resp.status();

        if status.is_redirection() {
            hops += 1;
            if hops > MAX_REDIRECTS {
                return Err(WebFetchError::TooManyRedirects { max: MAX_REDIRECTS });
            }

            // Follow same host; break on cross-host.
            if let Some(location) = resp.headers().get("location") {
                let location_str = location.to_str().unwrap_or("");
                let mut next_url = current_url
                    .join(location_str)
                    .map_err(|e| WebFetchError::InvalidRedirect(format!("{e}")))?;
                if is_same_host(&current_url, &next_url)
                    && scope.is_none_or(|scope| scope.check(&next_url).is_none())
                {
                    // Re-apply https upgrade on every hop: Location may be
                    // absolute `http://…` and would otherwise silently
                    // downgrade an https fetch. Local hosts still skip TLS.
                    upgrade_to_https(&mut next_url);
                    // check_ssrf runs at the top of the next loop iteration.
                    current_url = next_url;
                    continue;
                }
                return Ok(FetchResult::CrossHostRedirect {
                    original_host: current_url.host_str().unwrap_or("unknown").to_string(),
                    redirect_url: next_url.to_string(),
                });
            }
        }

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/html")
            .to_string();
        let final_url = resp.url().to_string();
        let status_code = status.as_u16();

        let body = read_body_capped(resp, max_content_length).await?;

        return Ok(FetchResult::Content {
            body,
            content_type,
            final_url,
            status_code,
        });
    }
}

/// Read a response body, refusing one larger than `max`.
/// A declared `Content-Length` over the limit is refused from the headers, before any of the body is downloaded;
/// a body of unknown length is cut off as soon as it passes the limit instead of being buffered whole first.
async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, WebFetchError> {
    if resp
        .content_length()
        .is_some_and(|declared| declared > max as u64)
    {
        return Err(WebFetchError::ResponseTooLarge { max });
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(WebFetchError::ResponseTooLarge { max });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Host equality, ASCII case ignored — no `www.` stripping. Distinct DNS labels (even when
/// one is a `www` subdomain of the other) have independent A records and must
/// surface as cross-host redirects rather than auto-follow.
fn is_same_host(a: &Url, b: &Url) -> bool {
    match (a.host_str(), b.host_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (None, None) => true,
        _ => false,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Content Processing
// ───────────────────────────────────────────────────────────────────────────

fn require_media_session_folder(
    session_folder: Option<&SessionFiles>,
) -> Result<&SessionFiles, WebFetchError> {
    session_folder.ok_or_else(|| {
        WebFetchError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "session folder is unavailable",
        ))
    })
}

fn is_html(content_type: &str) -> bool {
    content_type.contains("text/html") || content_type.contains("application/xhtml")
}

fn is_pdf(content_type: &str) -> bool {
    content_type.contains("application/pdf")
}

/// Returns `true` for image content types, excluding SVG (which can contain
/// `<script>` tags and event handlers — an XSS vector if saved and opened).
fn is_image(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("image/") && mime != "image/svg+xml"
}

fn is_video(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase()
        .starts_with("video/")
}

/// Validate that the first bytes of `body` match the magic bytes expected for
/// the claimed `content_type`. Returns `true` when the bytes match or when the
/// subtype is unknown (fail-open for niche formats).
fn validate_media_magic_bytes(content_type: &str, body: &[u8]) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    match mime.as_str() {
        "image/png" => body.starts_with(&[0x89, 0x50, 0x4E, 0x47]),
        "image/jpeg" => body.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/gif" => body.starts_with(b"GIF8"),
        "image/webp" => body.len() >= 12 && &body[..4] == b"RIFF" && &body[8..12] == b"WEBP",
        "video/mp4" => body.len() >= 8 && &body[4..8] == b"ftyp",
        "video/webm" => body.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]),
        _ => true, // unknown subtypes: allow (fail-open for niche formats)
    }
}

/// Map a media Content-Type to the correct file extension.
fn media_extension(content_type: &str) -> &'static str {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    match mime.as_str() {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/bmp" => "bmp",
        "image/tiff" => "tiff",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "video/x-msvideo" => "avi",
        _ => "bin",
    }
}

/// Returns `true` for content types that are binary and would produce garbage
/// through `String::from_utf8_lossy`. Text-like types (`text/*`,
/// `application/json`, `application/xml`, `application/javascript`, etc.)
/// return `false`.
fn is_binary_content_type(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();

    if mime.starts_with("text/") {
        return false;
    }
    !matches!(
        mime.as_str(),
        "application/json"
            | "application/xml"
            | "application/javascript"
            | "application/ecmascript"
            | "application/x-javascript"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "application/soap+xml"
            | "application/xslt+xml"
            | "application/mathml+xml"
            | "application/svg+xml"
            | "application/x-www-form-urlencoded"
            | "application/graphql"
            | "application/ld+json"
            | "application/schema+json"
            | "application/vnd.api+json"
            | "application/x-yaml"
            | "application/yaml"
            | "application/toml"
    )
}

/// Save fetched PDF bytes to the session download directory and return a
/// `WebFetchOutput` pointing the model at the saved file.
async fn save_pdf(
    writer: &SessionFileWriter,
    session_folder: &SessionFiles,
    body: &[u8],
    final_url: String,
    content_type: String,
    status_code: u16,
    read_tool_name: Option<&str>,
) -> Result<WebFetchOutput, WebFetchError> {
    let path = writer
        .save(session_folder, body, None)
        .await
        .map_err(|e| WebFetchError::IoError(std::io::Error::other(e.to_string())))?;

    tracing::info!(
        path = %path.display(),
        bytes = body.len(),
        "PDF saved to disk"
    );

    let read_hint = read_tool_name.map_or_else(String::new, |name| {
        format!(" Use the {name} tool to view its contents.")
    });
    let content = format!(
        "PDF downloaded ({} bytes) and saved to {}.{}",
        body.len(),
        path.display(),
        read_hint,
    );
    Ok(WebFetchOutput::Content(WebFetchContent {
        url: final_url,
        content: content.clone(),
        content_type,
        status_code,
        bytes: body.len(),
        source_artifact: None,
        inline_fallback: Some(content),
        output_location: None,
    }))
}

/// Save fetched image bytes to the session images directory and return a
/// `WebFetchOutput` pointing the model at the saved file.
async fn save_image(
    writer: &SessionFileWriter,
    session_folder: &SessionFiles,
    body: &[u8],
    final_url: String,
    content_type: String,
    status_code: u16,
    read_tool_name: Option<&str>,
) -> Result<WebFetchOutput, WebFetchError> {
    let ext = media_extension(&content_type);
    let path = writer
        .save(session_folder, body, Some(ext))
        .await
        .map_err(|e| WebFetchError::IoError(std::io::Error::other(e.to_string())))?;

    tracing::info!(
        path = %path.display(),
        bytes = body.len(),
        "Image saved to disk"
    );

    let read_hint = read_tool_name.map_or_else(String::new, |name| {
        format!(" Use the {name} tool to view its contents.")
    });
    let content = format!(
        "Image downloaded ({} bytes, {}) and saved to {}.{}",
        body.len(),
        content_type,
        path.display(),
        read_hint,
    );
    Ok(WebFetchOutput::Content(WebFetchContent {
        url: final_url,
        content: content.clone(),
        content_type,
        status_code,
        bytes: body.len(),
        source_artifact: None,
        inline_fallback: Some(content),
        output_location: None,
    }))
}

/// Save fetched video bytes to the session videos directory and return a
/// `WebFetchOutput` pointing the model at the saved file.
async fn save_video(
    writer: &SessionFileWriter,
    session_folder: &SessionFiles,
    body: &[u8],
    final_url: String,
    content_type: String,
    status_code: u16,
) -> Result<WebFetchOutput, WebFetchError> {
    let ext = media_extension(&content_type);
    let path = writer
        .save(session_folder, body, Some(ext))
        .await
        .map_err(|e| WebFetchError::IoError(std::io::Error::other(e.to_string())))?;

    tracing::info!(
        path = %path.display(),
        bytes = body.len(),
        "Video saved to disk"
    );

    let content = format!(
        "Video downloaded ({} bytes, {}) and saved to {}.",
        body.len(),
        content_type,
        path.display(),
    );
    Ok(WebFetchOutput::Content(WebFetchContent {
        url: final_url,
        content: content.clone(),
        content_type,
        status_code,
        bytes: body.len(),
        source_artifact: None,
        inline_fallback: Some(content),
        output_location: None,
    }))
}

/// Deepest element nesting a fetched page may have before it skips the HTML
/// parser and the markdown converter. Browsers cap parser depth at the same
/// value, so pages that rely on deeper nesting already render flattened. The
/// parser's scope checks are linear in depth and the converter recurses per
/// level, so an unbounded page could stall the call or overflow the stack.
const MAX_HTML_NESTING_DEPTH: usize = 512;

/// Most nodes (elements, comments, processing instructions) a fetched page may
/// build before it falls back to plain text. Far above ordinary pages; it
/// bounds the parser's own work when misnested formatting makes it clone many
/// elements per input byte.
const MAX_HTML_NODES: usize = 300_000;

/// Most attributes the parser may create, counted across every element it
/// builds (rebuilt formatting elements copy all of theirs). Bounds memory where
/// the node count alone does not.
const MAX_HTML_ATTRIBUTES: usize = 1_000_000;

/// Attribute bytes (names and values) the parser may create beyond the page's
/// own length. Rebuilt formatting elements copy their attributes, and the
/// cleaned markup writes every copy out, so the copies are bounded in bytes.
const HTML_ATTRIBUTE_BYTE_SLACK: usize = 1024 * 1024;

/// Longest one parse of a fetched page may take before it falls back to plain
/// text. A real page parses in well under a second; this bounds the parser's
/// work on markup no node or depth count sees (the tokenizer's per-tag scans).
const HTML_PARSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Input is fed to the parser in pieces this size, so a page that passes a
/// limit (or the deadline) is abandoned within one piece.
const HTML_PARSE_CHUNK: usize = 1024;

fn html_to_markdown(converter: &htmd::HtmlToMarkdown, html: &str) -> String {
    let Some(document) = parse_html_bounded(html) else {
        return html_to_plain_text(html);
    };
    let cleaned = clean_document(document);
    // The converter parses the cleaned markup again with its own parser, and
    // serialising then re-parsing does not always rebuild the same tree, so the
    // cleaned markup is held to the same bounds.
    let Some(reparsed) = parse_html_bounded(&cleaned) else {
        return html_to_plain_text(html);
    };
    if markdown_expansion_cost(&reparsed) > html.len().saturating_mul(8).saturating_add(MARKDOWN_EXPANSION_SLACK) {
        return html_to_plain_text(html);
    }
    convert_bounded(converter, &cleaned, html, MAX_HTML_NESTING_DEPTH, MAX_HTML_NODES)
}

/// Converts `cleaned` with the converter, after checking the tree the converter itself builds. The gate above reads
/// the page with the parser `scraper` is built on; the converter parses with its own (a different `html5ever`
/// version, review L11), so the tree it walks is held to the same depth and node bounds here, and a page over them
/// falls back to plain text like any other. `html` is the original page, for the fallbacks.
fn convert_bounded(converter: &htmd::HtmlToMarkdown, cleaned: &str, html: &str, max_depth: usize, max_nodes: usize) -> String {
    let Ok(tree) = converter.html_to_tree(cleaned) else {
        return html.to_string();
    };
    if htmd::HtmlToMarkdown::tree_exceeds(&tree, max_depth, max_nodes) {
        return html_to_plain_text(html);
    }
    converter.tree_to_markdown(&tree)
}

/// Converter output (beyond eight times the page's length) a page may cost
/// before it falls back to plain text. See [`markdown_expansion_cost`].
const MARKDOWN_EXPANSION_SLACK: usize = 8 * 1024 * 1024;

/// Upper bound on the converter's output beyond the page's own text: quotes
/// and lists are re-indented once per level, so each output line inside `n`
/// containers costs about `n * (n + 1) / 2` prefixes (counted as four bytes;
/// lines counted high: each element two plus the newlines in its attribute
/// values, each text node its newlines plus one). Tables do not add to it:
/// [`unpadded_table_handler`] renders each cell once. Every other construct
/// adds a bounded number of bytes per element, and the converter's own loops
/// are linear (its vendored copy, `third_party/htmd-0.5.4`).
///
/// Linear in the tree size.
fn markdown_expansion_cost(document: &Html) -> usize {
    use scraper::Node;
    let mut output = 0usize;
    let mut stack = vec![(document.tree.root(), 0usize)];
    while let Some((node, outer)) = stack.pop() {
        let nest = match node.value() {
            Node::Element(e) if matches!(e.name(), "blockquote" | "ul" | "ol" | "li" | "dl" | "dd") => outer + 1,
            _ => outer,
        };
        if nest > 0 {
            let lines = match node.value() {
                Node::Text(text) => text.matches('\n').count() + 1,
                Node::Element(e) => e.attrs().map(|(_, value)| value.matches('\n').count()).sum::<usize>() + 2,
                _ => 2,
            };
            output = output.saturating_add(lines.saturating_mul(nest.saturating_mul(nest + 1).saturating_mul(2)));
        }
        stack.extend(node.children().map(|child| (child, nest)));
    }
    output
}

/// The tag name of a converter tree node, if it is an element.
fn converter_tag(node: &htmd::Node) -> Option<&str> {
    match &node.data {
        markup5ever_rcdom::NodeData::Element { name, .. } => Some(name.local.as_ref()),
        _ => None,
    }
}

/// Table handler for the markdown converter: a pipe table with no column
/// padding, each caption and cell rendered exactly once. The converter's own
/// handler pads every row to each column's widest cell and renders a table
/// that yields no rows a second time, so its output can grow far faster than
/// the page (exponentially for tables nested in captions). Which tables become
/// pipe tables is unchanged: in the default mode, those with explicit headers
/// (`th` or `thead`, not counting nested tables) that are not inside a cell.
fn unpadded_table_handler(
    handlers: &dyn htmd::element_handler::Handlers,
    element: htmd::Element,
) -> Option<htmd::element_handler::HandlerResult> {
    use htmd::options::TranslationMode;
    let table = element.node;
    if handlers.options().translation_mode == TranslationMode::Pure {
        let mut inside_cell = false;
        let mut ancestor = table.parent.take();
        table.parent.set(ancestor.clone());
        while let Some(weak) = ancestor {
            let Some(parent) = weak.upgrade() else { break };
            if matches!(converter_tag(&parent), Some("td" | "th")) {
                inside_cell = true;
                break;
            }
            ancestor = parent.parent.take();
            parent.parent.set(ancestor.clone());
        }
        let mut explicit_headers = false;
        let mut pending: Vec<std::rc::Rc<htmd::Node>> = table.children.borrow().iter().cloned().collect();
        while let Some(node) = pending.pop() {
            match converter_tag(&node) {
                Some("th" | "thead") => {
                    explicit_headers = true;
                    break;
                }
                Some("table") => continue,
                _ => pending.extend(node.children.borrow().iter().cloned()),
            }
        }
        if inside_cell || !explicit_headers {
            // What the stock handler's own fallback does in this mode, without entering it (review L17).
            return Some(handlers.walk_children(table));
        }
    }
    // The stock handler's cell normalisation: one line, `|` as an entity (an escape that cannot compound when a
    // cell holds another table).
    let one_line = |content: &str| content.replace('\n', " ").replace('\r', "").replace('|', "&#124;").trim().to_string();
    let row_cells = |row: &std::rc::Rc<htmd::Node>| -> Vec<String> {
        let cells: Vec<std::rc::Rc<htmd::Node>> = row
            .children
            .borrow()
            .iter()
            .filter(|cell| matches!(converter_tag(cell), Some("td" | "th")))
            .cloned()
            .collect();
        cells.iter().map(|cell| one_line(&handlers.walk_children(cell).content)).collect()
    };
    let mut captions = Vec::new();
    let mut header: Option<Vec<String>> = None;
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut other = String::new();
    let children: Vec<std::rc::Rc<htmd::Node>> = table.children.borrow().iter().cloned().collect();
    for child in &children {
        match converter_tag(child) {
            // A caption keeps its own lines (it is not a cell).
            Some("caption") => captions.push(handlers.walk_children(child).content.trim().to_string()),
            Some("tr") => rows.push(row_cells(child)),
            Some(section_tag @ ("thead" | "tbody" | "tfoot")) => {
                let section: Vec<std::rc::Rc<htmd::Node>> = child.children.borrow().iter().cloned().collect();
                for row in &section {
                    match converter_tag(row) {
                        // The first row of the (first) header section is the header, wherever it sits.
                        Some("tr") if section_tag == "thead" && header.is_none() => header = Some(row_cells(row)),
                        Some("tr") => rows.push(row_cells(row)),
                        Some(_) => other.push_str(&handlers.handle(row).map(|r| r.content).unwrap_or_default()),
                        None => {}
                    }
                }
            }
            Some(_) => other.push_str(&handlers.handle(child).map(|r| r.content).unwrap_or_default()),
            None => {}
        }
    }
    rows.retain(|row| !row.is_empty());
    let header = match header.filter(|h| !h.is_empty()) {
        Some(header) => Some(header),
        None if rows.is_empty() => None,
        None => Some(rows.remove(0)),
    };
    let mut out = String::from("\n\n");
    for caption in captions.iter().filter(|c| !c.is_empty()) {
        out.push_str(caption);
        out.push('\n');
    }
    let push_row = |out: &mut String, row: &[String]| {
        out.push('|');
        for cell in row {
            out.push(' ');
            out.push_str(cell);
            out.push_str(" |");
        }
        out.push('\n');
    };
    if let Some(header) = &header {
        // The separator matches the header (a valid pipe table); longer body rows keep their extra cells.
        push_row(&mut out, header);
        out.push('|');
        for _ in 0..header.len() {
            out.push_str(" --- |");
        }
        out.push('\n');
        for row in &rows {
            push_row(&mut out, row);
        }
    }
    let other = other.trim_matches('\n');
    if !other.is_empty() {
        out.push_str(other);
        out.push('\n');
    }
    if out.trim().is_empty() {
        return None;
    }
    out.push('\n');
    Some(out.into())
}

/// Parses `html` with the real tree builder, fed in [`HTML_PARSE_CHUNK`]
/// pieces, and gives up (`None`) as soon as the tree nests deeper than
/// [`MAX_HTML_NESTING_DEPTH`], holds more than [`MAX_HTML_NODES`] nodes or
/// [`MAX_HTML_ATTRIBUTES`] attributes, or the parse runs past
/// [`HTML_PARSE_DEADLINE`]. The depth is measured on the tree itself as each
/// node is inserted, so it holds whatever rules the parser applies; an exact
/// walk after the parse covers subtrees the parser moved.
fn parse_html_bounded(html: &str) -> Option<Html> {
    parse_html_bounded_within(html, HTML_PARSE_DEADLINE)
}

fn parse_html_bounded_within(html: &str, deadline: std::time::Duration) -> Option<Html> {
    use html5ever::tendril::TendrilSink;
    let started = std::time::Instant::now();
    let sink = BoundedTreeSink {
        inner: HtmlTreeSink::new(Html::new_document()),
        nodes: std::cell::Cell::new(0),
        attributes: std::cell::Cell::new(0),
        attribute_bytes: std::cell::Cell::new(0),
        max_attribute_bytes: html.len().saturating_add(HTML_ATTRIBUTE_BYTE_SLACK),
        over: std::rc::Rc::new(std::cell::Cell::new(false)),
    };
    let over = std::rc::Rc::clone(&sink.over);
    let mut parser = html5ever::driver::parse_document(sink, Default::default());
    let mut rest = html;
    while !rest.is_empty() {
        let mut cut = rest.len().min(HTML_PARSE_CHUNK);
        while !rest.is_char_boundary(cut) {
            cut += 1;
        }
        parser.process(rest[..cut].into());
        if over.get() || started.elapsed() > deadline {
            return None;
        }
        rest = &rest[cut..];
    }
    let document = parser.finish();
    if over.get() || tree_deeper_than(&document, MAX_HTML_NESTING_DEPTH) {
        return None;
    }
    Some(document)
}

/// Exact depth check of a parsed tree, without recursion (the document node is depth 0).
fn tree_deeper_than(document: &Html, limit: usize) -> bool {
    let mut stack = vec![(document.tree.root(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > limit {
            return true;
        }
        stack.extend(node.children().map(|child| (child, depth + 1)));
    }
    false
}

/// The HTML document builder, with a running bound on how deep and how large the
/// tree gets. Every call is delegated unchanged; inserting a node under a parent
/// already at [`MAX_HTML_NESTING_DEPTH`], or creating more than [`MAX_HTML_NODES`]
/// nodes or [`MAX_HTML_ATTRIBUTES`] attributes, sets `over`, which the feeding
/// loop checks after each piece. Once `over` is set, new attributes are dropped,
/// so the rest of the current piece cannot grow the tree's memory.
struct BoundedTreeSink {
    inner: HtmlTreeSink,
    nodes: std::cell::Cell<usize>,
    attributes: std::cell::Cell<usize>,
    attribute_bytes: std::cell::Cell<usize>,
    max_attribute_bytes: usize,
    over: std::rc::Rc<std::cell::Cell<bool>>,
}

impl BoundedTreeSink {
    /// Flags `over` when a node placed directly under `parent` would be deeper
    /// than the limit. Walks at most the limit's worth of ancestors.
    fn check_child_of(&self, parent: &<Self as TreeSink>::Handle) {
        if self.over.get() {
            return;
        }
        let html = self.inner.0.borrow();
        let ancestors = html
            .tree
            .get(*parent)
            .map_or(0, |node| node.ancestors().take(MAX_HTML_NESTING_DEPTH).count());
        if ancestors >= MAX_HTML_NESTING_DEPTH {
            self.over.set(true);
        }
    }

    fn check_node(&self, parent: &<Self as TreeSink>::Handle, child: &NodeOrText<<Self as TreeSink>::Handle>) {
        if matches!(child, NodeOrText::AppendNode(_)) {
            self.check_child_of(parent);
        }
    }

    fn count_node(&self) {
        let nodes = self.nodes.get() + 1;
        self.nodes.set(nodes);
        if nodes > MAX_HTML_NODES {
            self.over.set(true);
        }
    }

    /// Counts `attrs` against the attribute budgets (count and bytes); past either (or past any bound) they are
    /// dropped.
    fn admit_attributes(&self, attrs: Vec<html5ever::Attribute>) -> Vec<html5ever::Attribute> {
        let attributes = self.attributes.get().saturating_add(attrs.len());
        self.attributes.set(attributes);
        let bytes = attrs
            .iter()
            .fold(self.attribute_bytes.get(), |n, a| n.saturating_add(a.name.local.len() + a.value.len()));
        self.attribute_bytes.set(bytes);
        if attributes > MAX_HTML_ATTRIBUTES || bytes > self.max_attribute_bytes {
            self.over.set(true);
        }
        if self.over.get() { Vec::new() } else { attrs }
    }
}

impl TreeSink for BoundedTreeSink {
    type Handle = <HtmlTreeSink as TreeSink>::Handle;
    type Output = Html;
    type ElemName<'a>
        = std::cell::Ref<'a, html5ever::QualName>
    where
        Self: 'a;

    fn finish(self) -> Html {
        self.inner.finish()
    }

    fn parse_error(&self, msg: std::borrow::Cow<'static, str>) {
        self.inner.parse_error(msg);
    }

    fn get_document(&self) -> Self::Handle {
        self.inner.get_document()
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> Self::ElemName<'a> {
        self.inner.elem_name(target)
    }

    fn create_element(
        &self,
        name: html5ever::QualName,
        attrs: Vec<html5ever::Attribute>,
        flags: html5ever::tree_builder::ElementFlags,
    ) -> Self::Handle {
        self.count_node();
        let attrs = self.admit_attributes(attrs);
        self.inner.create_element(name, attrs, flags)
    }

    fn create_comment(&self, text: html5ever::tendril::StrTendril) -> Self::Handle {
        self.count_node();
        self.inner.create_comment(text)
    }

    fn create_pi(&self, target: html5ever::tendril::StrTendril, data: html5ever::tendril::StrTendril) -> Self::Handle {
        self.count_node();
        self.inner.create_pi(target, data)
    }

    fn append(&self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        self.check_node(parent, &child);
        self.inner.append(parent, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Self::Handle,
        prev_element: &Self::Handle,
        child: NodeOrText<Self::Handle>,
    ) {
        // The node goes beside `element` or under `prev_element`; judging it as a child of either errs deep.
        self.check_node(element, &child);
        self.check_node(prev_element, &child);
        self.inner.append_based_on_parent_node(element, prev_element, child);
    }

    fn append_doctype_to_document(
        &self,
        name: html5ever::tendril::StrTendril,
        public_id: html5ever::tendril::StrTendril,
        system_id: html5ever::tendril::StrTendril,
    ) {
        self.inner.append_doctype_to_document(name, public_id, system_id);
    }

    fn mark_script_already_started(&self, node: &Self::Handle) {
        self.inner.mark_script_already_started(node);
    }

    fn pop(&self, node: &Self::Handle) {
        self.inner.pop(node);
    }

    fn get_template_contents(&self, target: &Self::Handle) -> Self::Handle {
        self.inner.get_template_contents(target)
    }

    fn same_node(&self, x: &Self::Handle, y: &Self::Handle) -> bool {
        self.inner.same_node(x, y)
    }

    fn set_quirks_mode(&self, mode: html5ever::tree_builder::QuirksMode) {
        self.inner.set_quirks_mode(mode);
    }

    fn append_before_sibling(&self, sibling: &Self::Handle, new_node: NodeOrText<Self::Handle>) {
        // A sibling's depth; judging the node as its child errs one deep.
        self.check_node(sibling, &new_node);
        self.inner.append_before_sibling(sibling, new_node);
    }

    fn add_attrs_if_missing(&self, target: &Self::Handle, attrs: Vec<html5ever::Attribute>) {
        let attrs = self.admit_attributes(attrs);
        self.inner.add_attrs_if_missing(target, attrs);
    }

    fn associate_with_form(
        &self,
        target: &Self::Handle,
        form: &Self::Handle,
        nodes: (&Self::Handle, Option<&Self::Handle>),
    ) {
        self.inner.associate_with_form(target, form, nodes);
    }

    fn remove_from_parent(&self, target: &Self::Handle) {
        self.inner.remove_from_parent(target);
    }

    fn reparent_children(&self, node: &Self::Handle, new_parent: &Self::Handle) {
        self.check_child_of(new_parent);
        self.inner.reparent_children(node, new_parent);
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &Self::Handle) -> bool {
        self.inner.is_mathml_annotation_xml_integration_point(handle)
    }

    fn set_current_line(&self, line_number: u64) {
        self.inner.set_current_line(line_number);
    }

    fn complete_script(&self, node: &Self::Handle) -> html5ever::tree_builder::NextParserState {
        self.inner.complete_script(node)
    }

    fn allow_declarative_shadow_roots(&self, intended_parent: &Self::Handle) -> bool {
        self.inner.allow_declarative_shadow_roots(intended_parent)
    }

    fn attach_declarative_shadow(
        &self,
        location: &Self::Handle,
        attrs: Vec<html5ever::Attribute>,
    ) -> Result<(), String> {
        self.inner.attach_declarative_shadow(location, attrs)
    }
}

/// Text of a page with every tag removed, for pages too deeply nested to
/// parse. Linear; script and style bodies are dropped.
fn html_to_plain_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let lower = html.to_ascii_lowercase();
    let mut rest = html;
    let mut rest_lower = lower.as_str();
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let after = &rest_lower[open..];
        let skip_to = if after.starts_with("<script") {
            after.find("</script").unwrap_or(after.len())
        } else if after.starts_with("<style") {
            after.find("</style").unwrap_or(after.len())
        } else {
            0
        };
        let tail_lower = &after[skip_to..];
        let close = tail_lower.find('>').map_or(tail_lower.len(), |c| c + 1);
        let next = open + skip_to + close;
        out.push(' ');
        rest = &rest[next..];
        rest_lower = &rest_lower[next..];
    }
    out.push_str(rest);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Remove common noisy elements from HTML before markdown conversion.
#[cfg(test)]
fn clean_html(html: &str) -> String {
    clean_document(Html::parse_document(html))
}

/// Remove common noisy elements from a parsed page and serialise it.
fn clean_document(mut document: Html) -> String {

    // Never detach the root element itself - the broad selectors below can match
    // attributes on <html> (e.g. class="...advert..."), which would leave the
    // tree with no root element. Looked up fallibly so we never assume one exists.
    let root_id = document
        .tree
        .root()
        .children()
        .find(|child| child.value().is_element())
        .map(|node| node.id());

    let selectors: Vec<Selector> = [
        "nav",
        "header",
        "footer",
        "[class*='cookie']",
        "[class*='sidebar']",
        "[class*='ad-']",
        "[class*='advert']",
        "[id*='cookie']",
        "[id*='sidebar']",
        "[id*='ad-']",
        "[id*='advert']",
    ]
    .iter()
    .filter_map(|s| Selector::parse(s).ok())
    .collect();

    selectors.iter().for_each(|selector| {
        document
            .select(selector)
            .map(|e| e.id())
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|id| {
                if Some(id) == root_id {
                    return;
                }
                if let Some(mut node) = document.tree.get_mut(id) {
                    node.detach();
                }
            });
    });

    // Serialize the whole document rather than `root_element()`, which panics if
    // the tree somehow has no root element.
    document.html()
}

/// Strip base64 data URIs from content to prevent token bloat.
///
/// Uses manual scanning (`find` + byte matching) instead of regex for
/// lower overhead — no compilation cost and O(n) linear scanning (the comma
/// search is bounded by the header limit).
fn strip_base64_data_uris(content: String) -> String {
    // A valid base64 quantum is 4 characters; anything shorter is noise.
    const MIN_BASE64_PAYLOAD: usize = 4;
    // RFC 2397 headers are short (MIME + parameters); reject oversized ones
    // to avoid echoing attacker-controlled megabyte strings into the output.
    const MAX_HEADER_LEN: usize = 120;

    if !content.contains("data:") {
        return content;
    }

    let s = content.as_str();
    let mut result = String::with_capacity(s.len());
    let mut last_end = 0;
    let mut search_from = 0;

    while let Some(rel) = s[search_from..].find("data:") {
        let start = search_from + rel;

        // "data:" must look like a URI scheme start, not a substring of
        // another word (e.g. "metadata:", "validata:").
        if start > 0 && s.as_bytes()[start - 1].is_ascii_alphanumeric() {
            search_from = start + 5;
            continue;
        }

        // A valid header is at most MAX_HEADER_LEN bytes, so look for its
        // comma only that far; searching the whole tail made the scan
        // quadratic on input with many comma-less "data:" tokens.
        let window_end = (start + 5 + MAX_HEADER_LEN + 1).min(s.len());
        if let Some(rel_comma) = s.as_bytes()[start..window_end].iter().position(|&b| b == b',') {
            let comma = start + rel_comma;
            let header = &s[start + 5..comma];

            // RFC 2397 forbids whitespace in the header, and real headers
            // are short ASCII. Reject anything that violates this.
            if header.len() > MAX_HEADER_LEN || header.bytes().any(|b| b.is_ascii_whitespace()) {
                search_from = start + 5;
                continue;
            }

            let mut parts = header.split(';');
            let mime = parts
                .next()
                .expect("split always yields at least one element");
            let mime = if mime.is_empty() { "unknown" } else { mime };

            if parts.any(|p| p.eq_ignore_ascii_case("base64")) {
                // Consume valid base64 characters after the comma.
                let payload_start = comma + 1;
                let payload_len = s[payload_start..]
                    .bytes()
                    .take_while(|b| {
                        matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
                    })
                    .count();

                if payload_len >= MIN_BASE64_PAYLOAD {
                    result.push_str(&s[last_end..start]);
                    result.push_str("[base64 ");
                    result.push_str(mime);
                    result.push_str(" data removed]");
                    last_end = payload_start + payload_len;
                    search_from = last_end;
                    continue;
                }
            }
        }

        search_from = start + 5;
    }

    if last_end == 0 {
        return content;
    }
    result.push_str(&s[last_end..]);
    result
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A fallback is bounded by the parse deadlines: up to three bounded parses (the page, the cleaned markup,
    /// and slack for cleaning and the plain-text pass), whatever the build profile or the host load.
    /// Review L16: shapes that fall back at a structural limit (depth, nodes, attributes) or convert in linear
    /// time are held to this much of the test thread's own CPU time, so a loaded host cannot fail them and a
    /// slow conversion cannot hide under the deadline-sized limit below. Measured: the slowest shape (the rebuilt
    /// formatting one) takes about 6 s in a debug build on an idle host and 10.5 s on a loaded gate host (the
    /// 10 s limit this replaces failed there, audit gate 20261115T020003Z), well under a second in release. The
    /// limit sits above two parse deadlines, so only work that stays slow past the deadlines fails it; a quadratic
    /// regression on these 100 000-element shapes runs for minutes, far past it.
    const QUICK_LIMIT: std::time::Duration = std::time::Duration::from_secs(25);

    const FALLBACK_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(3 * HTML_PARSE_DEADLINE.as_secs() + 10);

    /// Structural checks must not depend on how fast this host parses (debug builds under a loaded test run are
    /// far slower than a release build), so they get a deadline no test reaches.
    fn parse_structure(html: &str) -> Option<Html> {
        parse_html_bounded_within(html, std::time::Duration::from_secs(3600))
    }

    #[test]
    fn a45_deeply_nested_html_converts_without_overflow_or_stall() {
        // A fetched page may nest elements arbitrarily deep; conversion must
        // neither overflow the session thread's stack nor take long.
        let depth = 100_000;
        let html = format!(
            "<html><body>{}deep text{}</body></html>",
            "<div>".repeat(depth),
            "</div>".repeat(depth)
        );
        let started = std::time::Instant::now();
        let out = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || html_to_markdown(&test_converter(), &html))
            .unwrap()
            .join()
            .unwrap();
        assert!(out.contains("deep text"), "text lost: {}", &out[..out.len().min(200)]);
        assert!(started.elapsed() < std::time::Duration::from_secs(15), "took {:?}", started.elapsed());
    }

    #[test]
    fn a45_nesting_at_the_limit_still_converts_on_a_small_stack() {
        let depth = MAX_HTML_NESTING_DEPTH - 12;
        let html = format!(
            "<html><body>{}<b>kept</b>{}</body></html>",
            "<div>".repeat(depth),
            "</div>".repeat(depth)
        );
        assert!(parse_structure(&html).is_some());
        let out = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || html_to_markdown(&test_converter(), &html))
            .unwrap()
            .join()
            .unwrap();
        assert!(out.contains("**kept**"), "{out}");
    }

    #[test]
    fn a45_void_and_optional_end_tags_do_not_count_as_nesting() {
        let html = "<p>a<br><img src=x><li>b<!-- <div><div> --><script>if(a<b){}</script><input/>"
            .repeat(2000);
        assert!(parse_structure(&html).is_some());
        assert_eq!(html_to_plain_text("<style>x{}</style><b>a</b>  b<script>c<d</script>e"), "a b e");
    }

    /// Review r1/r2 on S5-F1/F2: markup shapes whose real nesting (or node count) grows while a scan of the raw
    /// markup can stay flat. The bound is measured on the parser's own tree, so every one must fall back, fast.
    #[test]
    fn a45_deep_or_node_flooding_shapes_fall_back_to_plain_text() {
        let n = 20_000;
        let distinct_formatting = |k: usize| format!("<div><b a={k}></div>");
        let shapes = [
            "<div><p>a</p>".repeat(n),
            "<div/>".repeat(n),
            "<div></x>".repeat(n),
            "<rt>".repeat(n),
            format!("<math>{}", "<td>".repeat(n)),
            format!("{}<textarea>{}</textarea>", "<div>".repeat(1000), "</div>".repeat(1000)),
            format!("{}<table>{}", "<div>".repeat(600), "</div>".repeat(600)),
            format!("{}<!--><!--->{}", "<span>".repeat(600), "x"),
            "<li><section>".repeat(n),
            "<option><b>".repeat(n),
            "<div><p>".repeat(n),
            "<p><div>".repeat(n),
            "<div></ </div>".repeat(n),
            "<svg><div></svg>".repeat(n),
            format!("<svg>{}", "<g a=b/>".repeat(n)),
            "<span><div></span>".repeat(n),
            "<b><div></b>".repeat(n),
            "<li><ul></li>".repeat(n),
            format!("<div>{}", "<div></body></html>".repeat(n)),
            (0..n).map(distinct_formatting).collect::<String>(),
            format!("<select><title></select>{}", "<div>".repeat(n)),
            format!("<svg><desc>{}", "<div><style></div></style>".repeat(n)),
            "<div><script><!--<script></script></div></script>".repeat(n),
            "<svg><title><span></svg>".repeat(n),
            format!("<svg>{}", "<g><![CDATA[></g>]]>".repeat(n)),
            // Formatting elements left open in a closed block are rebuilt under every new paragraph.
            format!(
                "<div>{}</div>{}",
                (0..500).map(|k| format!("<b a={k}>")).collect::<String>(),
                "<p>x".repeat(n * 5)
            ),
        ];
        for (k, html) in shapes.iter().enumerate() {
            let started = thread_time();
            assert!(parse_structure(html).is_none(), "shape {k} stayed under the bounds");
            let out = html_to_markdown(&test_converter(), html);
            assert!(out.len() <= html.len(), "shape {k}");
            assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "shape {k} took {:?}", thread_time().saturating_sub(started));
        }
    }

    /// Review r3 on S5-F2: a never-closed formatting element is rebuilt, with a full copy of its attributes, under
    /// every new paragraph; the attribute budget stops it long before memory grows.
    #[test]
    fn a45_rebuilt_formatting_attributes_spend_the_attribute_budget() {
        let attrs: String = (0..1000).map(|k| format!("a{k}=x ")).collect();
        let html = format!("<div><b {attrs}></div>{}", "<p>x".repeat(5_000));
        let started = thread_time();
        assert!(parse_structure(&html).is_none());
        assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "took {:?}", thread_time().saturating_sub(started));
    }

    /// Review r4 on S5-F2: one long attribute on a rebuilt formatting element is copied (and later written out)
    /// once per paragraph; the attribute byte budget stops it.
    #[test]
    fn a45_rebuilt_long_attribute_spends_the_attribute_byte_budget() {
        let value = "v".repeat(64 * 1024);
        for name in ["data-x", "class"] {
            let html = format!("<div><b {name}=\"{value}\"></div>{}", "<p>x".repeat(20_000));
            let started = thread_time();
            assert!(parse_structure(&html).is_none(), "{name}");
            let out = html_to_markdown(&test_converter(), &html);
            assert!(out.len() <= html.len(), "{name}");
            assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "{name} took {:?}", thread_time().saturating_sub(started));
        }
    }

    /// Review r4 U1: the converter repeats quote and list prefixes on every line and re-indents per level
    /// (measured: 226 KB nested 250 deep became 20 MB); deep containers with many lines fall back to plain text,
    /// while ordinary nesting keeps converting.
    #[test]
    fn a45_nested_containers_do_not_amplify_the_output() {
        for (open, close) in [("<blockquote>", "</blockquote>"), ("<ul><li>", "</li></ul>"), ("<ol><li>", "</li></ol>")] {
            let html = format!("{}{}{}", open.repeat(250), "<p>line</p>".repeat(20_000), close.repeat(250));
            let started = thread_time();
            let out = html_to_markdown(&test_converter(), &html);
            assert!(out.len() <= html.len(), "{open}: {} > {}", out.len(), html.len());
            assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "{open} took {:?}", thread_time().saturating_sub(started));
            let shallow = format!("{}{}{}", open.repeat(4), "<p>line</p>".repeat(20_000), close.repeat(4));
            let document = parse_structure(&shallow).unwrap();
            assert!(markdown_expansion_cost(&document) <= shallow.len() * 8 + MARKDOWN_EXPANSION_SLACK, "{open} shallow");
        }
    }

    /// Review r4/r5: tables are rendered by [`unpadded_table_handler`]: one huge header cell over many rows, or
    /// tables nested in captions, cost linear output and time; ordinary tables still become pipe tables.
    #[test]
    fn a45_tables_render_each_cell_once() {
        for header in ["th", "td"] {
            let html = format!(
                "<table><thead><tr><{header}>{}</{header}></tr></thead>{}</table>",
                "h".repeat(1024 * 1024),
                "<tr><td>x</td></tr>".repeat(20_000)
            );
            let started = thread_time();
            let out = html_to_markdown(&test_converter(), &html);
            assert!(out.len() <= html.len(), "{header}: {} > {}", out.len(), html.len());
            assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "{header} took {:?}", thread_time().saturating_sub(started));
        }
        // A table inside a caption, nested: the stock handler renders each level twice.
        let mut nested = String::from("x");
        for _ in 0..40 {
            nested = format!("<table><caption>{nested}</caption><thead></thead></table>");
        }
        let started = thread_time();
        let out = html_to_markdown(&test_converter(), &nested);
        assert!(out.len() <= nested.len(), "{} > {}", out.len(), nested.len());
        assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "nested captions took {:?}", thread_time().saturating_sub(started));
        let ordinary = format!(
            "<table><caption>Items</caption><thead><tr><th>name</th><th>description</th></tr></thead><tbody>{}</tbody></table>",
            "<tr><td>item</td><td>a short <a href=\"https://example.com/x\">description</a> | piped</td></tr>".repeat(2_000)
        );
        let md = html_to_markdown(&test_converter(), &ordinary);
        assert!(md.contains("Items\n| name | description |\n| --- | --- |\n| item | a short [description](https://example.com/x) &#124; piped |"), "{}", &md[..md.len().min(400)]);
        // The header section's row is the header wherever it sits; the separator matches the header.
        let late = html_to_markdown(
            &test_converter(),
            "<table><tbody><tr><td>1</td><td>2</td></tr></tbody><thead><tr><th colspan=2>Group</th></tr></thead></table>",
        );
        assert!(late.contains("| Group |\n| --- |\n| 1 | 2 |"), "{late}");
        // Cell text keeps its inner spacing.
        assert!(html_to_markdown(&test_converter(), "<table><tr><th>c</th></tr><tr><td><code>a  b</code></td></tr></table>").contains("`a  b`"));
        // Header-less tables keep the converter's plain rendering.
        assert!(!html_to_markdown(&test_converter(), "<table><tr><td>a</td><td>b</td></tr></table>").contains("---"));
    }

    /// Review r5-r7: the converter combines adjacent similar inline siblings and checks the newlines ending its
    /// output on every append; upstream did both in quadratic time (minutes for these pages). The vendored copy is
    /// linear, so the converter itself takes seconds. Measured as this thread's CPU time where the platform has
    /// it, so a loaded host does not skew it; called directly, since the production parse deadline may (rightly)
    /// send a page to the plain-text fallback on a loaded host.
    const LINEAR_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);

    fn thread_time() -> std::time::Duration {
        #[cfg(target_os = "linux")]
        {
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: clock_gettime writes one timespec through a valid, exclusive pointer.
            if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } == 0 {
                return std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
            }
        }
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START.get_or_init(std::time::Instant::now).elapsed()
    }

    fn convert_timed(html: &str) -> String {
        let started = thread_time();
        let out = test_converter().convert(html).expect("converts");
        let took = thread_time().saturating_sub(started);
        assert!(took < LINEAR_TIME_LIMIT, "took {took:?}");
        out
    }

    /// Runs just under the node cap: a few seconds here in a debug build, about 30 s on upstream's quadratic loop.
    #[test]
    fn a45_long_inline_runs_convert_in_linear_time() {
        let text = "x".repeat(25);
        for run in [
            format!("<p>{}</p>", format!("<b>{text}</b>").repeat(280_000)),
            format!("<p>{}</p>", format!("<i>{text}</i><em>{text}</em>").repeat(140_000)),
            format!("<math>{}</math>", format!("<template>{text}</template>").repeat(280_000)),
        ] {
            let out = convert_timed(&run);
            // Combined into one run of text.
            assert!(out.len() <= 280_000 * 25 + 8 && out.contains(&text), "{}", out.len());
        }
    }

    /// The combining rule itself is upstream's: equal attributes, one text child, i/em and b/strong alike, never
    /// links; the run's texts land in its first element.
    #[test]
    fn a45_sibling_combining_keeps_the_converter_output() {
        let md = |html: &str| html_to_markdown(&test_converter(), html);
        assert_eq!(md("<p><b>a</b><strong>b</strong><b>c</b> d</p>"), "**abc** d");
        assert_eq!(md("<p><i>a</i><em>b</em></p>"), "*ab*");
        assert_eq!(md("<p><a href=x>a</a><a href=x>b</a></p>"), "[a](x)[b](x)");
        assert_eq!(md("<p><b class=p>a</b><b class=q>b</b></p>"), "**a****b**");
        assert_eq!(md("<p><b>a</b><b>b</b>, <b>c</b><b><i>d</i></b></p>"), "**ab**, **c*****d***");
    }

    #[test]
    fn a45_long_newline_runs_convert_in_linear_time() {
        for page in [
            format!("<pre>x{}{}</pre>", "\n".repeat(1024 * 1024), "<span></span><wbr>".repeat(20_000)),
            format!("<pre>x{}</pre>", "\n<wbr>".repeat(200_000)),
            format!("<pre>x{}</pre>", format!("{}<wbr>", "\n".repeat(28)).repeat(30_000)),
        ] {
            let out = convert_timed(&page);
            assert!(out.starts_with('x') && out.len() <= page.len(), "{}", &out[..out.len().min(80)]);
        }
    }

    /// Review r6 P1: a caption holding a pipe table is not pipe-escaped once per level.
    #[test]
    fn a45_captions_are_not_pipe_escaped() {
        let mut nested = "<table><thead><tr><th>a|b</th></tr></thead></table>".to_string();
        for _ in 0..50 {
            nested = format!("<table><caption>{nested}</caption><thead><tr><th>h</th></tr></thead></table>");
        }
        let out = html_to_markdown(&test_converter(), &nested);
        assert!(out.len() <= nested.len(), "{} > {}", out.len(), nested.len());
        assert!(!out.contains("\\\\|"), "escapes compound: {}", &out[..out.len().min(300)]);
    }

    /// Review r5 N1: newlines inside attribute values become output lines; they count toward the indent bound.
    #[test]
    fn a45_attribute_newlines_count_as_lines() {
        let alt = "a\n".repeat(50_000);
        let html = format!("{}<img src=x alt=\"{alt}\">{}", "<blockquote>".repeat(200), "</blockquote>".repeat(200));
        let started = thread_time();
        let out = html_to_markdown(&test_converter(), &html);
        assert!(out.len() <= html.len(), "{} > {}", out.len(), html.len());
        assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "took {:?}", thread_time().saturating_sub(started));
    }

    /// Review r3 on S5-F2: one tag with a huge attribute list costs the tokenizer quadratic time before any node
    /// exists; the deadline (checked after every piece) bounds it.
    #[test]
    fn a45_parse_deadline_bounds_tokenizer_work_inside_one_tag() {
        let attrs: String = (0..100_000).map(|k| format!("a{k} ")).collect();
        let html = format!("<div {attrs}>x</div>");
        let started = thread_time();
        assert!(parse_html_bounded_within(&html, std::time::Duration::from_millis(500)).is_none());
        assert!(thread_time().saturating_sub(started) < QUICK_LIMIT, "took {:?}", thread_time().saturating_sub(started));
        // An ordinary page is nowhere near the deadline.
        assert!(parse_html_bounded_within("<p>a<p>b", std::time::Duration::from_secs(5)).is_some());
    }

    /// Ordinary pages (unclosed paragraphs and list items, tables without cell end tags, SVG sprites, comments,
    /// scripts, misnested formatting) must stay on the markdown path.
    #[test]
    fn a45_ordinary_page_stays_under_the_bounds() {
        let block = concat!(
            "<div class=card><p>para<p>para two<ul><li>a<li>b</ul>",
            "<table><tr><td>c<td>d<tr><td>e</table>",
            "<svg><use href=\"#i\"/><path d=\"M0 0\"/><path/></svg><img src=x><br>",
            "<!-- note --><script>if (a<b && c>d) {}</script><select><option>1<option>2</select>",
            "<dl><dt>t<dd>d</dl><b>bold <i>both</b> italic</i></div>",
            "<ul><li><p>item<li><p>item<li><div><p>item</div></ul>",
        );
        let page = |blocks: usize| {
            format!("<!doctype html><html><head><title>t</title></head><body>{}</body></html>", block.repeat(blocks))
        };
        assert!(parse_structure(&page(2000)).is_some());
        // Converted through the production deadline: a page small enough for any host to parse well inside it.
        assert!(html_to_markdown(&test_converter(), &page(100)).contains("para two"));
    }

    #[test]
    fn a45_data_uri_strip_is_linear_without_commas() {
        let mut body = "-data:".repeat(1024 * 1024 / 6);
        let started = std::time::Instant::now();
        let out = strip_base64_data_uris(body.clone());
        assert_eq!(out, body);
        body.push_str(",AAAA");
        let _ = strip_base64_data_uris(body);
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "took {:?}", started.elapsed());
    }

    /// Review L11: the converter's own tree is held to the bounds, whatever the gate's parser made of the page.
    #[test]
    fn review_l11_converter_tree_past_the_bounds_falls_back_to_plain_text() {
        let html = format!("{}<b>x</b>{}", "<div>".repeat(100), "</div>".repeat(100));
        let cleaned = clean_document(parse_structure(&html).unwrap());
        let converter = test_converter();
        assert_eq!(convert_bounded(&converter, &cleaned, &html, 50, MAX_HTML_NODES), html_to_plain_text(&html));
        assert_eq!(convert_bounded(&converter, &cleaned, &html, MAX_HTML_NESTING_DEPTH, 50), html_to_plain_text(&html));
        assert_eq!(convert_bounded(&converter, &cleaned, &html, MAX_HTML_NESTING_DEPTH, MAX_HTML_NODES), "**x**");
        assert_ne!(html_to_plain_text(&html), "**x**");
    }

    /// Review V1: inline code nested to the depth limit around a large text is scanned once per level, by byte.
    #[test]
    fn review_v1_nested_inline_code_converts_in_bounded_time() {
        let html = format!("{}{}{}", "<code>".repeat(500), "a ".repeat(512 * 1024), "</code>".repeat(500));
        let out = convert_timed(&html);
        assert!(out.starts_with('`') && out.len() >= 1024 * 1024, "{}", out.len());
    }

    /// Review L12: content is copied, and `<pre>`/`<code>` ancestry walked, once per ancestor level; at the depth
    /// and node limits that is bounded work.
    #[test]
    fn review_l12_deep_nesting_with_many_nodes_converts_in_bounded_time() {
        let html = format!("{}{}{}", "<div>".repeat(500), "<i>x</i>".repeat(140_000), "</div>".repeat(500));
        let out = convert_timed(&html);
        assert!(out.starts_with('*') && out.len() == 140_002, "{}", out.len());
    }

    /// Review L17: a table the handler does not turn into a pipe table renders as the stock converter renders it.
    #[test]
    fn review_l17_plain_tables_render_as_the_stock_converter_does() {
        let stock = htmd::HtmlToMarkdown::builder().skip_tags(vec!["script", "style", "noscript", "svg", "iframe", "object", "embed"]).build();
        for html in [
            "<table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>",
            "<table><tbody><tr><td>x</td></tr></tbody></table><p>after</p>",
            "<table><tr><td><table><tr><td>in</td></tr></table></td></tr></table>",
            "<table></table>",
        ] {
            assert_eq!(test_converter().convert(html).unwrap(), stock.convert(html).unwrap(), "{html}");
        }
        let source = include_str!("client.rs");
        assert!(!source.contains(concat!("handlers.", "fallback(element)")), "plain path must not enter the stock handler");
    }

    fn test_converter() -> htmd::HtmlToMarkdown {
        htmd::HtmlToMarkdown::builder()
            .skip_tags(vec![
                "script", "style", "noscript", "svg", "iframe", "object", "embed",
            ])
            .add_handler(vec!["table"], unpadded_table_handler)
            .build()
    }

    /// A response that declares a body larger than the limit is refused from its headers alone, before any of the body
    /// is downloaded. The server here sends three bytes and then stops, so reading the body to the end would fail
    /// with a transport error instead of the size error.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // plain client: the server is a loopback test server, no TLS policy applies
    async fn declared_oversized_body_is_refused_before_download() {
        let url = fuigo_test_support::counting_server::spawn_http_server(|_head| {
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2147483648\r\n\r\nabc".to_vec()
        })
        .await;
        let url = Url::parse(&format!("{url}/big.bin")).unwrap();
        // Bounded: reading the body to the end would wait on the stalled server forever
        let outcome = tokio::time::timeout(
            FALLBACK_TIME_LIMIT,
            fetch_url(&reqwest::Client::new(), &url, 1024, true),
        )
        .await
        .expect("the fetch must be refused from its headers, not wait for the body");
        assert!(
            matches!(outcome, Err(WebFetchError::ResponseTooLarge { max: 1024 })),
            "expected the size refusal, got {:?}",
            outcome.err()
        );
    }

    /// A body of unknown length is cut off at the limit rather than buffered whole.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // plain client: the server is a loopback test server, no TLS policy applies
    async fn undeclared_oversized_body_is_refused_at_the_limit() {
        let url = fuigo_test_support::counting_server::spawn_http_server(|_head| {
            let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for _ in 0..4 {
                out.extend_from_slice(b"400\r\n");
                out.extend_from_slice(&[b'x'; 0x400]);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0\r\n\r\n");
            out
        })
        .await;
        let url = Url::parse(&format!("{url}/chunked.txt")).unwrap();
        let outcome = fetch_url(&reqwest::Client::new(), &url, 2048, true).await;
        assert!(
            matches!(outcome, Err(WebFetchError::ResponseTooLarge { max: 2048 })),
            "expected the size refusal, got {:?}",
            outcome.err()
        );
        let within = fetch_url(&reqwest::Client::new(), &url, 4096, true).await;
        assert!(matches!(within, Ok(FetchResult::Content { .. })), "a body within the limit is returned");
    }

    /// A same-host redirect that leaves the allowlisted path prefix is handed back for approval
    /// instead of followed (audit S5-F10); one that stays inside is still followed.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // plain client: the server is a loopback test server, no TLS policy applies
    async fn same_host_redirect_out_of_a_path_scope_needs_approval() {
        let base = fuigo_test_support::counting_server::spawn_http_server(|head| {
            let first = head.lines().next().unwrap_or("").to_owned();
            if first.contains("/v1/docs/in") {
                b"HTTP/1.1 302 Found\r\nLocation: /v1/docs/ok\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else if first.contains("/v1/docs/out") {
                b"HTTP/1.1 302 Found\r\nLocation: /v1/private/secret\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".to_vec()
            }
        })
        .await;
        let scope = DomainMatcher::new(&["127.0.0.1/v1/docs".to_owned()]);
        // As in production: the client never follows a redirect itself.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let out = Url::parse(&format!("{base}/docs/out")).unwrap();
        assert!(scope.check(&out).is_none());
        let outcome = fetch_url_scoped(&client, &out, 4096, true, Some(&scope)).await;
        assert!(
            matches!(outcome, Ok(FetchResult::CrossHostRedirect { .. })),
            "a redirect out of the prefix must need approval, got {}",
            match &outcome {
                Ok(FetchResult::Content { final_url, status_code, .. }) => format!("content {status_code} from {final_url}"),
                Ok(FetchResult::CrossHostRedirect { .. }) => "redirect".to_owned(),
                Err(error) => error.to_string(),
            }
        );

        let inside = Url::parse(&format!("{base}/docs/in")).unwrap();
        let outcome = fetch_url_scoped(&client, &inside, 4096, true, Some(&scope)).await;
        assert!(matches!(outcome, Ok(FetchResult::Content { .. })), "inside the prefix is followed");

        let unscoped = fetch_url_scoped(&client, &out, 4096, true, None).await;
        assert!(matches!(unscoped, Ok(FetchResult::Content { .. })), "no scope: unchanged");
    }

    #[tokio::test]
    async fn oversized_html_persists_exact_pre_truncation_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let client = WebFetchClient::new(&WebFetchParams {
            context_window_tokens: Some(100),
            ..WebFetchParams::default()
        })
        .unwrap();
        let tail = "TAIL-MUST-REMAIN-RECOVERABLE";
        let html = format!(
            "<h1>Heading</h1>{}<p>{tail}</p>",
            "<p>body line</p>".repeat(1_000)
        );
        let expected = strip_base64_data_uris(html_to_markdown(&test_converter(), &html));

        let processed = client
            .process_text_content(
                html.as_bytes(),
                "text/html; charset=utf-8",
                Some(&SessionFiles::at(tmp.path())),
                RecoveryTools {
                    read: Some("ReadAsset"),
                    execute: Some("ExecuteAsset"),
                },
            )
            .await;

        assert!(processed.was_truncated);
        assert_eq!(processed.content_type, "markdown");
        assert_eq!(processed.bytes, expected.len());
        assert!(!processed.content.contains(tail));
        assert!(expected.contains(tail));
        let artifact = tmp.path().join("web_fetch/1.md");
        assert!(
            processed
                .content
                .contains(artifact.to_string_lossy().as_ref())
        );
        assert_eq!(tokio::fs::read_to_string(artifact).await.unwrap(), expected);
    }

    // ── URL validation ──────────────────────────────────────────────────

    #[test]
    fn validate_url_accepts_valid() {
        assert!(validate_url("https://docs.rs/reqwest/latest").is_ok());
        assert!(validate_url("https://github.com/seanmonstar/reqwest").is_ok());
        assert!(validate_url("http://example.com/path?q=1#frag").is_ok());
    }

    #[test]
    fn validate_url_rejects_single_label_hosts() {
        // localhost is an explicit local host; SSRF still blocks it unless
        // allow_local is set on tool params.
        assert!(validate_url("http://localhost:8080/foo").is_ok());
        assert!(validate_url("http://intranet/foo").is_err());
        assert!(validate_url("http://metadata/computeMetadata").is_err());
    }

    #[test]
    fn upgrade_to_https_skips_explicit_local_hosts() {
        let mut local = Url::parse("http://127.0.0.1:8080/").unwrap();
        upgrade_to_https(&mut local);
        assert_eq!(local.scheme(), "http");

        let mut localhost = Url::parse("http://localhost:3000/").unwrap();
        upgrade_to_https(&mut localhost);
        assert_eq!(localhost.scheme(), "http");

        let mut public = Url::parse("http://example.com/").unwrap();
        upgrade_to_https(&mut public);
        assert_eq!(public.scheme(), "https");
    }

    #[test]
    fn validate_url_rejects_credentials() {
        assert!(validate_url("https://user:pass@example.com/foo").is_err());
        assert!(validate_url("https://admin@example.com/foo").is_err());
    }

    #[test]
    fn validate_url_rejects_long_urls() {
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        assert!(validate_url(&long).is_err());
    }

    #[test]
    fn validate_url_rejects_unsupported_schemes() {
        assert!(validate_url("ftp://example.com/file.txt").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("data:text/html,<h1>hi</h1>").is_err());
    }

    #[test]
    fn validate_url_rejects_garbage() {
        assert!(validate_url("not a url").is_err());
        assert!(validate_url("").is_err());
    }

    #[test]
    fn upgrade_http_to_https() {
        let mut url = Url::parse("http://example.com/path").unwrap();
        upgrade_to_https(&mut url);
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn upgrade_https_is_noop() {
        let mut url = Url::parse("https://example.com/path").unwrap();
        upgrade_to_https(&mut url);
        assert_eq!(url.scheme(), "https");
    }

    // ── Same-host redirect check ────────────────────────────────────────

    #[test]
    fn same_host_exact_match() {
        let a = Url::parse("https://example.com/a").unwrap();
        let b = Url::parse("https://example.com/b").unwrap();
        assert!(is_same_host(&a, &b));
    }

    /// Review L10: a fetch reuses the client's allowlist matcher instead of building one per call.
    #[tokio::test]
    async fn fetches_reuse_one_domain_matcher() {
        let base = fuigo_test_support::counting_server::spawn_http_server(|_head| {
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".to_vec()
        })
        .await;
        let client = WebFetchClient::new(&WebFetchParams {
            allow_local: Some(true),
            ..WebFetchParams::default()
        })
        .unwrap();
        let built = super::super::domain::MATCHERS_BUILT.with(std::cell::Cell::get);
        for page in ["a", "b", "c"] {
            let out = client.fetch(&format!("{base}/{page}"), None, None, None).await;
            assert!(out.is_ok(), "{out:?}");
        }
        assert_eq!(
            super::super::domain::MATCHERS_BUILT.with(std::cell::Cell::get),
            built,
            "the matcher is built once with the client, not once per fetch"
        );
    }

    /// Review L10: host comparison for a redirect ignores ASCII case (a non-special scheme keeps its host as written).
    #[test]
    fn same_host_ignores_ascii_case() {
        let a = Url::parse("foo://Example.COM/a").unwrap();
        let b = Url::parse("foo://example.com/b").unwrap();
        assert!(is_same_host(&a, &b));
        let other = Url::parse("foo://other.com/b").unwrap();
        assert!(!is_same_host(&a, &other));
    }

    #[test]
    fn www_subdomain_is_cross_host() {
        let a = Url::parse("https://example.com/a").unwrap();
        let c = Url::parse("https://www.example.com/a").unwrap();
        assert!(!is_same_host(&a, &c));
        assert!(!is_same_host(&c, &a));
    }

    #[test]
    fn different_host_rejected() {
        let a = Url::parse("https://example.com/a").unwrap();
        let d = Url::parse("https://other.com/a").unwrap();
        assert!(!is_same_host(&a, &d));
    }

    #[test]
    fn same_host_redirect_location_reupgrades_http() {
        // Absolute http Location on an https origin must not stay http when
        // followed as a same-host hop (upgrade_to_https reapplied each hop).
        let origin = Url::parse("https://example.com/start").unwrap();
        let mut next = origin.join("http://example.com/next").unwrap();
        assert_eq!(next.scheme(), "http");
        assert!(is_same_host(&origin, &next));
        upgrade_to_https(&mut next);
        assert_eq!(next.scheme(), "https");
        assert_eq!(next.as_str(), "https://example.com/next");
    }

    // ── Content type detection ──────────────────────────────────────────

    #[test]
    fn is_html_detects_html_types() {
        assert!(is_html("text/html"));
        assert!(is_html("text/html; charset=utf-8"));
        assert!(is_html("application/xhtml+xml"));
    }

    #[test]
    fn is_html_rejects_non_html() {
        assert!(!is_html("text/plain"));
        assert!(!is_html("text/markdown"));
        assert!(!is_html("application/json"));
        assert!(!is_html("application/pdf"));
    }

    // ── PDF content type detection ────────────────────────────────────

    #[test]
    fn is_pdf_detects_pdf_types() {
        assert!(is_pdf("application/pdf"));
        assert!(is_pdf("application/pdf; charset=utf-8"));
    }

    #[test]
    fn is_pdf_rejects_non_pdf() {
        assert!(!is_pdf("text/html"));
        assert!(!is_pdf("text/plain"));
        assert!(!is_pdf("application/json"));
        assert!(!is_pdf("application/octet-stream"));
    }

    // ── Binary content type detection ────────────────────────────────

    #[test]
    fn binary_detects_images_and_media() {
        assert!(is_binary_content_type("image/png"));
        assert!(is_binary_content_type("image/jpeg"));
        assert!(is_binary_content_type("image/gif"));
        assert!(is_binary_content_type("audio/mpeg"));
        assert!(is_binary_content_type("video/mp4"));
        assert!(is_binary_content_type("application/octet-stream"));
        assert!(is_binary_content_type("application/zip"));
        assert!(is_binary_content_type("application/wasm"));
        assert!(is_binary_content_type("font/woff2"));
    }

    #[test]
    fn binary_allows_text_types() {
        assert!(!is_binary_content_type("text/plain"));
        assert!(!is_binary_content_type("text/html"));
        assert!(!is_binary_content_type("text/html; charset=utf-8"));
        assert!(!is_binary_content_type("text/markdown"));
        assert!(!is_binary_content_type("text/csv"));
        assert!(!is_binary_content_type("text/xml"));
    }

    #[test]
    fn binary_allows_text_like_application_types() {
        assert!(!is_binary_content_type("application/json"));
        assert!(!is_binary_content_type("application/json; charset=utf-8"));
        assert!(!is_binary_content_type("application/xml"));
        assert!(!is_binary_content_type("application/javascript"));
        assert!(!is_binary_content_type("application/xhtml+xml"));
        assert!(!is_binary_content_type("application/svg+xml"));
        assert!(!is_binary_content_type("application/ld+json"));
        assert!(!is_binary_content_type("application/yaml"));
        assert!(!is_binary_content_type("application/graphql"));
    }

    // ── HTML to markdown conversion ─────────────────────────────────────

    #[test]
    fn html_to_markdown_basic() {
        let md = html_to_markdown(&test_converter(), "<h1>Hello</h1><p>World</p>");
        assert!(md.contains("Hello"));
        assert!(md.contains("World"));
    }

    #[test]
    fn html_to_markdown_strips_script_and_style() {
        let html = r#"<h1>Title</h1>
            <script>var x = 1; alert("hi");</script>
            <style>body { color: red; }</style>
            <p>Content</p>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("Title"));
        assert!(md.contains("Content"));
        assert!(!md.contains("alert"), "script content should be stripped");
        assert!(
            !md.contains("color: red"),
            "style content should be stripped"
        );
    }

    #[test]
    fn html_to_markdown_strips_noscript() {
        let html = "<p>Visible</p><noscript>Enable JavaScript</noscript>";
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("Visible"));
        assert!(
            !md.contains("Enable JavaScript"),
            "noscript content should be stripped"
        );
    }

    #[test]
    fn html_to_markdown_strips_svg() {
        let html = r#"<p>Text</p><svg xmlns="http://www.w3.org/2000/svg"><circle r="5"/></svg>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("Text"));
        assert!(!md.contains("circle"), "SVG content should be stripped");
    }

    #[test]
    fn html_to_markdown_preserves_links() {
        let html = r#"<a href="https://example.com">Click here</a>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("[Click here]"));
        assert!(md.contains("(https://example.com)"));
    }

    #[test]
    fn html_to_markdown_preserves_code_blocks() {
        let html = "<pre><code>fn main() {}</code></pre>";
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("fn main() {}"));
    }

    #[test]
    fn html_to_markdown_preserves_lists() {
        let html = "<ul><li>One</li><li>Two</li><li>Three</li></ul>";
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("One"));
        assert!(md.contains("Two"));
        assert!(md.contains("Three"));
    }

    #[test]
    fn html_to_markdown_handles_nested_elements() {
        let html = r#"<p>This is <strong>bold <em>and italic</em></strong> text.</p>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("bold"));
        assert!(md.contains("and italic"));
    }

    #[test]
    fn html_to_markdown_handles_empty_input() {
        let md = html_to_markdown(&test_converter(), "");
        assert!(md.is_empty() || md.trim().is_empty());
    }

    #[test]
    fn html_to_markdown_strips_iframe() {
        let html = r#"<p>Content</p><iframe src="https://evil.com/embed"></iframe><p>More</p>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("Content"));
        assert!(md.contains("More"));
        assert!(!md.contains("evil.com"), "iframe should be stripped");
    }

    #[test]
    fn html_to_markdown_full_page_strips_boilerplate() {
        let html = r#"<!DOCTYPE html>
<html>
<head>
  <title>Test Page</title>
  <script>var tracking = true;</script>
  <style>body { margin: 0; }</style>
</head>
<body>
  <nav><a href="/">Home</a><a href="/about">About</a></nav>
  <main>
    <h1>Article Title</h1>
    <p>This is the main content of the article.</p>
  </main>
  <footer>Copyright 2025</footer>
  <script>analytics.track('pageview');</script>
</body>
</html>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("Article Title"), "article title should survive");
        assert!(md.contains("main content"), "article body should survive");
        assert!(
            !md.contains("tracking"),
            "head script content should be stripped"
        );
        assert!(
            !md.contains("analytics.track"),
            "body script content should be stripped"
        );
        assert!(
            !md.contains("margin: 0"),
            "style content should be stripped"
        );
    }

    #[test]
    fn html_to_markdown_handles_tables() {
        let html = r#"<table>
            <tr><th>Name</th><th>Value</th></tr>
            <tr><td>Alpha</td><td>1</td></tr>
            <tr><td>Beta</td><td>2</td></tr>
        </table>"#;
        let md = html_to_markdown(&test_converter(), html);
        assert!(md.contains("Name"));
        assert!(md.contains("Alpha"));
        assert!(md.contains("Beta"));
    }

    // ── Base64 data URI stripping ─────────────────────────────────────

    /// Golden test: verify exact output format for the most common case.
    #[test]
    fn strip_base64_output_format() {
        let result = strip_base64_data_uris(
            "Before ![logo](data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==) after".to_owned(),
        );
        assert_eq!(
            result,
            "Before ![logo]([base64 image/png data removed]) after"
        );
    }

    /// Inputs the scanner must leave untouched.
    #[test]
    fn strip_base64_rejects_invalid() {
        let cases: &[&str] = &[
            // whitespace in header (RFC 2397 forbids)
            "data: image/png ;base64,AAAA== end",
            // payload too short (< 4 chars)
            "data:image/png;base64,AA= end",
            // empty payload
            "data:image/png;base64, end",
            // no comma after data:
            "data:image/png;base64 with no comma",
            // truncated data: at EOF
            "trailing data:",
        ];
        for input in cases {
            assert_eq!(
                strip_base64_data_uris(input.to_string()),
                *input,
                "should not strip: {input:?}"
            );
        }
    }

    /// Oversized header must be rejected (can't be a static string).
    #[test]
    fn strip_base64_rejects_oversized_header() {
        let huge_mime = "x".repeat(10_000);
        let input = format!("data:{huge_mime};base64,AAAA== end");
        assert_eq!(strip_base64_data_uris(input.clone()), input);
    }

    /// Multi-param headers and case-insensitive marker — capabilities
    /// the manual scanner has beyond the original regex.
    #[test]
    fn strip_base64_extended_headers() {
        assert_eq!(
            strip_base64_data_uris("data:text/plain;charset=utf-8;base64,SGVsbG8= end".to_owned()),
            "[base64 text/plain data removed] end"
        );
        assert!(
            strip_base64_data_uris("data:image/png;Base64,AAAA==".to_owned())
                .contains("[base64 image/png data removed]")
        );
    }

    // ── Regex equivalence ──────────────────────────────────────────────

    /// Reference implementation: the original regex-based stripper.
    fn strip_base64_data_uris_regex(content: &str) -> String {
        let re = regex::Regex::new(r"data:([^;,\s]{1,80});base64,[A-Za-z0-9+/=]+")
            .expect("valid base64 data URI regex");
        re.replace_all(content, |caps: &regex::Captures| {
            let mime = caps.get(1).map_or("unknown", |m| m.as_str());
            format!("[base64 {mime} data removed]")
        })
        .into_owned()
    }

    /// Both implementations must produce identical output on all realistic
    /// inputs. Covers: markdown images, standalone URIs, multiple URIs,
    /// normal URLs, non-base64 data URIs, HTML/CSS contexts, various
    /// positions, and real-world payloads.
    #[test]
    fn strip_base64_equivalence_with_regex() {
        let cases: &[&str] = &[
            "no data URIs here",
            "![logo](data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==) after",
            "See data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0 here",
            "![a](data:image/png;base64,AAAA==) text ![b](data:image/jpeg;base64,/9j/4AAQ==)",
            "![img](https://example.com/logo.png) and [link](https://example.com)",
            "data:text/html,%3Ch1%3EHello%3C%2Fh1%3E",
            "Just normal markdown with **bold** and [link](https://x.com)",
            r#"<img src="data:image/png;base64,iVBORw0KGgo="> text"#,
            "background: url(data:image/svg+xml;base64,PHN2Zz4=) no-repeat",
            "before data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7 after",
            "data:image/png;base64,AA==",
            "data:application/octet-stream;base64,AQID",
            "x data:a/b;base64,AAAA== y data:c/d;base64,BBBB== z",
            "data:image/png;base64,AAAA== rest",
            "rest data:image/png;base64,AAAA==",
            "data:image/png;base64,AAAA==",
            "data:image/x-icon;base64,AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAA",
        ];
        for input in cases {
            let regex_out = strip_base64_data_uris_regex(input);
            let manual_out = strip_base64_data_uris(input.to_string());
            assert_eq!(manual_out, regex_out, "mismatch on input: {input:?}");
        }
    }

    /// The manual scanner correctly rejects word-internal "data:" prefixes
    /// that the regex would false-positive on.
    #[test]
    fn strip_base64_rejects_word_internal_data_prefix() {
        for input in ["metadata:foo;base64,AAAA==", "validata:bar;base64,BBBB=="] {
            let manual_out = strip_base64_data_uris(input.to_string());
            let regex_out = strip_base64_data_uris_regex(input);
            assert_eq!(
                manual_out, input,
                "manual scanner should NOT strip: {input:?}"
            );
            assert_ne!(
                regex_out, manual_out,
                "expected divergence from regex on: {input:?}"
            );
        }
    }

    // ── Proxy configs ─────────────────────────────────────

    #[test]
    fn proxy_endpoint_round_trips_through_config() {
        let json = r#"{"proxy_endpoint": "https://proxy.corp.example.com", "allowed_domains": ["example.com"]}"#;
        let params: WebFetchParams = serde_json::from_str(json).unwrap();
        assert_eq!(
            params.proxy_endpoint.as_deref(),
            Some("https://proxy.corp.example.com")
        );

        // Client builds successfully with the proxy endpoint set.
        let client = WebFetchClient::new(&params);
        assert!(client.is_ok());
    }

    #[test]
    fn proxy_endpoint_defaults_to_none() {
        let json = r#"{"allowed_domains": ["example.com"]}"#;
        let params: WebFetchParams = serde_json::from_str(json).unwrap();
        assert!(params.proxy_endpoint.is_none());
    }

    // ── HTML cleaning (scraper-based) ─────────────────────────────────

    #[test]
    fn clean_html_removes_boilerplate_tags() {
        let html = r#"<body><nav>Menu</nav><header>Header</header><main>Content</main><footer>Footer</footer></body>"#;
        let cleaned = clean_html(html);
        assert!(cleaned.contains("Content"));
        assert!(!cleaned.contains("Menu"));
        assert!(!cleaned.contains("Header"));
        assert!(!cleaned.contains("Footer"));
    }

    #[test]
    fn clean_html_removes_noisy_classes_and_ids() {
        let html = r#"<div class="cookie-banner">cookies</div><aside id="sidebar">side</aside><div class="ad-banner">ad</div>"#;
        let cleaned = clean_html(html);
        assert!(!cleaned.contains("cookie-banner"));
        assert!(!cleaned.contains("sidebar"));
        assert!(!cleaned.contains("ad-banner"));
    }

    #[test]
    fn clean_html_keeps_root_when_it_matches_selector() {
        let html =
            r#"<html class="advert"><body><nav>Menu</nav><main>Content</main></body></html>"#;
        let cleaned = clean_html(html);
        assert!(cleaned.contains("Content"));
        assert!(!cleaned.contains("Menu"));
    }

    // ── Image content type detection ──────────────────────────────────

    #[test]
    fn is_image_detects_image_types() {
        assert!(is_image("image/png"));
        assert!(is_image("image/jpeg"));
        assert!(is_image("image/gif"));
        assert!(is_image("image/webp"));
        assert!(is_image("image/bmp"));
        assert!(is_image("image/tiff"));
        assert!(is_image("image/png; charset=utf-8"));
    }

    #[test]
    fn is_image_rejects_svg() {
        assert!(!is_image("image/svg+xml"));
        assert!(!is_image("image/svg+xml; charset=utf-8"));
    }

    #[test]
    fn is_image_rejects_non_image() {
        assert!(!is_image("text/html"));
        assert!(!is_image("video/mp4"));
        assert!(!is_image("application/pdf"));
        assert!(!is_image("application/octet-stream"));
    }

    // ── Video content type detection ──────────────────────────────────

    #[test]
    fn is_video_detects_video_types() {
        assert!(is_video("video/mp4"));
        assert!(is_video("video/webm"));
        assert!(is_video("video/quicktime"));
        assert!(is_video("video/x-msvideo"));
        assert!(is_video("video/mp4; codecs=avc1"));
    }

    #[test]
    fn is_video_rejects_non_video() {
        assert!(!is_video("text/html"));
        assert!(!is_video("image/png"));
        assert!(!is_video("application/pdf"));
        assert!(!is_video("audio/mpeg"));
    }

    // ── Magic byte validation ─────────────────────────────────────────

    #[test]
    fn magic_bytes_valid_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(validate_media_magic_bytes("image/png", &png));
    }

    #[test]
    fn magic_bytes_valid_jpeg() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert!(validate_media_magic_bytes("image/jpeg", &jpeg));
    }

    #[test]
    fn magic_bytes_valid_gif() {
        assert!(validate_media_magic_bytes("image/gif", b"GIF89a\x01\x00"));
        assert!(validate_media_magic_bytes("image/gif", b"GIF87a\x01\x00"));
    }

    #[test]
    fn magic_bytes_valid_webp() {
        let mut webp = vec![0u8; 12];
        webp[..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        assert!(validate_media_magic_bytes("image/webp", &webp));
    }

    #[test]
    fn magic_bytes_valid_mp4() {
        let mut mp4 = vec![0u8; 12];
        mp4[4..8].copy_from_slice(b"ftyp");
        assert!(validate_media_magic_bytes("video/mp4", &mp4));
    }

    #[test]
    fn magic_bytes_valid_webm() {
        let webm = [0x1A, 0x45, 0xDF, 0xA3, 0x01, 0x00];
        assert!(validate_media_magic_bytes("video/webm", &webm));
    }

    #[test]
    fn magic_bytes_rejects_mismatch() {
        // HTML content masquerading as PNG
        assert!(!validate_media_magic_bytes("image/png", b"<html>"));
        // PNG bytes claimed as JPEG
        assert!(!validate_media_magic_bytes(
            "image/jpeg",
            &[0x89, 0x50, 0x4E, 0x47]
        ));
        // Empty body
        assert!(!validate_media_magic_bytes("image/png", &[]));
        // Text claimed as video
        assert!(!validate_media_magic_bytes("video/mp4", b"not video"));
    }

    #[test]
    fn magic_bytes_allows_unknown_subtypes() {
        // Unknown image/video subtypes should pass (fail-open)
        assert!(validate_media_magic_bytes("image/x-custom", b"anything"));
        assert!(validate_media_magic_bytes("video/x-custom", b"anything"));
    }

    // ── Media extension mapping ───────────────────────────────────────

    #[test]
    fn media_extension_maps_known_types() {
        assert_eq!(media_extension("image/png"), "png");
        assert_eq!(media_extension("image/jpeg"), "jpg");
        assert_eq!(media_extension("image/gif"), "gif");
        assert_eq!(media_extension("image/webp"), "webp");
        assert_eq!(media_extension("image/bmp"), "bmp");
        assert_eq!(media_extension("image/tiff"), "tiff");
        assert_eq!(media_extension("video/mp4"), "mp4");
        assert_eq!(media_extension("video/webm"), "webm");
        assert_eq!(media_extension("video/quicktime"), "mov");
        assert_eq!(media_extension("video/x-msvideo"), "avi");
    }

    #[test]
    fn media_extension_handles_params() {
        assert_eq!(media_extension("image/png; charset=utf-8"), "png");
        assert_eq!(media_extension("video/mp4; codecs=avc1"), "mp4");
    }

    #[test]
    fn media_extension_unknown_falls_back_to_bin() {
        assert_eq!(media_extension("image/x-custom"), "bin");
        assert_eq!(media_extension("video/x-custom"), "bin");
        assert_eq!(media_extension("application/octet-stream"), "bin");
    }
}
