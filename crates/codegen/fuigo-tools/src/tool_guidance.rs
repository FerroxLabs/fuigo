//! User-settable tool guidance: text appended to, or replacing, a built-in tool's description.
//!
//! The loader lives in `fuigo-workspace` (it owns the trust gate and the file locations); this
//! module holds the value types and the pure application step so `ToolRegistryBuilder::finalize`
//! can apply them to the rendered definition on every provider wire.
use serde::{Deserialize, Serialize};

/// How a guidance entry combines with the stock description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuidanceMode {
    /// Add the text after the stock description.
    Append,
    /// Use the text instead of the stock description.
    Replace,
}

/// One tool's guidance override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolGuidance {
    pub mode: GuidanceMode,
    pub text: String,
}

impl ToolGuidance {
    /// The description the model sees, given the stock (already rendered) description.
    pub fn apply(&self, stock: Option<&str>) -> String {
        match (self.mode, stock) {
            (GuidanceMode::Replace, _) | (GuidanceMode::Append, None) => self.text.clone(),
            (GuidanceMode::Append, Some(s)) => format!("{s}\n\n{}", self.text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_follows_stock_and_replace_discards_it() {
        let a = ToolGuidance {
            mode: GuidanceMode::Append,
            text: "extra".into(),
        };
        let r = ToolGuidance {
            mode: GuidanceMode::Replace,
            text: "only".into(),
        };
        assert_eq!(a.apply(Some("stock")), "stock\n\nextra");
        assert_eq!(a.apply(None), "extra");
        assert_eq!(r.apply(Some("stock")), "only");
    }
}
