//! Upload destination config and archive-restore metadata shared by the
//! always-on upload queue and session restore paths.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Method for uploading to object storage.
#[derive(Clone)]
pub enum UploadMethod {
    Direct {
        service_account_key: Option<String>,
    },
    Proxy {
        proxy_base_url: String,
        user_token: String,
        deployment_key: Option<String>,
        alpha_test_key: Option<String>,
    },
    S3 {
        bucket: String,
        region: String,
        credentials_file: Option<String>,
        credentials_content: Option<String>,
        endpoint_url: Option<String>,
    },
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructures are exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for UploadMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { service_account_key } => f
                .debug_struct("Direct")
                .field("service_account_key", &service_account_key.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::Proxy { proxy_base_url, user_token: _, deployment_key, alpha_test_key } => f
                .debug_struct("Proxy")
                .field("proxy_base_url", &fuigo_auth::redact_url(proxy_base_url))
                .field("user_token", &"<redacted>")
                .field("deployment_key", &deployment_key.as_ref().map(|_| "<redacted>"))
                .field("alpha_test_key", &alpha_test_key.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::S3 { bucket, region, credentials_file, credentials_content, endpoint_url } => f
                .debug_struct("S3")
                .field("bucket", bucket)
                .field("region", region)
                .field("credentials_file", credentials_file)
                .field("credentials_content", &credentials_content.as_ref().map(|_| "<redacted>"))
                .field("endpoint_url", &endpoint_url.as_deref().map(fuigo_auth::redact_url))
                .finish(),
        }
    }
}

/// Configuration for object-storage export.
#[derive(Clone)]
pub struct TraceExportConfig {
    pub bucket_url: Option<String>,
    pub service_account_key: Option<String>,
    pub upload_method: UploadMethod,
    pub prefix_dir: Option<String>,
    pub gcs_prefix: Option<String>,
    pub absolute_paths: bool,
    pub archive_name_override: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for TraceExportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            bucket_url,
            service_account_key,
            upload_method,
            prefix_dir,
            gcs_prefix,
            absolute_paths,
            archive_name_override,
        } = self;
        f.debug_struct("TraceExportConfig")
            .field("bucket_url", &bucket_url.as_deref().map(fuigo_auth::redact_url))
            .field("service_account_key", &service_account_key.as_ref().map(|_| "<redacted>"))
            .field("upload_method", upload_method)
            .field("prefix_dir", prefix_dir)
            .field("gcs_prefix", gcs_prefix)
            .field("absolute_paths", absolute_paths)
            .field("archive_name_override", archive_name_override)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobCompression {
    #[default]
    None,
    Zstd,
}

pub const SKIP_DIR_NAMES: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".output",
    ".cache",
    ".parcel-cache",
    ".turbo",
    "vendor",
    "bower_components",
    ".tox",
    ".nox",
    ".eggs",
    ".idea",
    ".vscode",
    ".gradle",
    ".dart_tool",
    "coverage",
    ".nyc_output",
    "htmlcov",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
];

pub fn skip_dir_set() -> &'static std::collections::HashSet<&'static str> {
    use std::collections::HashSet;
    use std::sync::LazyLock;
    static SET: LazyLock<HashSet<&str>> =
        LazyLock::new(|| SKIP_DIR_NAMES.iter().copied().collect());
    &SET
}

pub const SKIP_FILE_PATTERNS: &[&str] = &[
    "*.egg-info",
    "*.pyc",
    "*.pyo",
    "*.o",
    "*.so",
    "*.dylib",
    "*.class",
    "*.jar",
    ".DS_Store",
    "Thumbs.db",
    "*.swp",
    "*.swo",
    "*~",
    "*.iml",
];

pub fn default_untracked_exclude_globs() -> Vec<String> {
    let mut globs: Vec<String> = SKIP_DIR_NAMES.iter().map(|d| format!("{d}/")).collect();
    globs.extend(SKIP_FILE_PATTERNS.iter().map(|p| p.to_string()));
    globs
}

pub fn default_excludes_as_gitignore() -> String {
    default_untracked_exclude_globs().join("\n")
}

pub const ARCHIVE_SCHEMA_VERSION: &str = "v2";
pub const ARCHIVE_SCHEMA_VERSION_V3: &str = "v3";
pub const DEDUP_GCS_PREFIX: &str = "repo_changes_dedup";
pub const DEDUP_PATCH_SUBDIR: &str = "patches";
pub const DEDUP_BLOB_SUBDIR: &str = "blobs";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludedContent {
    pub path: String,
    pub reason: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DedupMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_archive_url: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub patch_references: HashMap<String, PatchReference>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub file_references: HashMap<String, FileReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<ExcludedContent>,
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    /// P70 (Astra r1): upload destinations carry the user token, deployment key and inline cloud credentials.
    #[test]
    fn upload_method_and_export_config_debug_redact() {
        let proxy = UploadMethod::Proxy {
            proxy_base_url: "https://p70.invalid".into(),
            user_token: "p70ut-FAKE-5e6f7a8b".into(),
            deployment_key: Some("p70dk-FAKE-9c0d1e2f".into()),
            alpha_test_key: Some("p70at-FAKE-3a4b5c6d".into()),
        };
        assert_redacted(&proxy, &["p70ut-FAKE-5e6f7a8b", "p70dk-FAKE-9c0d1e2f", "p70at-FAKE-3a4b5c6d"]);
        let s3 = UploadMethod::S3 {
            bucket: "b".into(),
            region: "r".into(),
            credentials_file: None,
            credentials_content: Some("p70s3-FAKE-7e8f9a0b".into()),
            endpoint_url: None,
        };
        assert_redacted(&s3, &["p70s3-FAKE-7e8f9a0b"]);
        let export = TraceExportConfig {
            bucket_url: None,
            service_account_key: Some("p70sa-FAKE-1c2d3e4f".into()),
            upload_method: UploadMethod::Direct { service_account_key: Some("p70sd-FAKE-5a6b7c8d".into()) },
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
        };
        assert_redacted(&export, &["p70sa-FAKE-1c2d3e4f", "p70sd-FAKE-5a6b7c8d"]);
    }
}
