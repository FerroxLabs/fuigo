use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error(
        "{action}: existing config at {path} is not valid TOML ({source}). Fix the file (or move it aside) and retry."
    )]
    InvalidToml {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("{section} is not a table")]
    NotATable { section: &'static str },

    #[error("{section} is not an array")]
    NotAnArray { section: String },

    #[error("{place} is not a JSON object")]
    NotAJsonObject { place: String },

    #[error("{path}: hooks.{event} is not a JSON array")]
    NotAJsonArray { path: PathBuf, event: String },

    #[error("failed to serialize MCP server {name}: {source}")]
    McpSerialize {
        name: String,
        #[source]
        source: toml::ser::Error,
    },

    #[error("failed to serialize {path}: {source}")]
    TomlSerialize {
        path: PathBuf,
        #[source]
        source: toml::ser::Error,
    },

    #[error("failed to serialize {path}: {source}")]
    JsonSerialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}
