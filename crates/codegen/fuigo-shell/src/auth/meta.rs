use serde::{Deserialize, Serialize};

/// Access gate from `fuigo_build_access_gate`.
///
/// Message only. It used to carry `url` and `label` for a clickable CTA on the gate screen; that
/// CTA was the competitor-subscription funnel and is gone, so the two fields were read by nothing.
/// They are not `#[serde(skip)]`-ed placeholders: an operator who still sets them would get silent
/// no-ops, and a dead field is how a funnel gets rewired. Serde ignores unknown wire keys, so a
/// server that still sends them is accepted exactly as before.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInfo {
    pub message: String,
}

/// Typed auth metadata passed from the shell to the pager via ACP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMeta {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub auth_mode: Option<String>,
    /// Team principal UUID when the session is a team login (`None` for personal).
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub team_name: Option<String>,
    #[serde(default)]
    pub is_zdr: bool,
    #[serde(default)]
    pub team_role: Option<String>,
    /// Defaults to opted-out (safer) until auth meta is populated.
    #[serde(default = "crate::auth::default_coding_data_retention_opt_out")]
    pub coding_data_retention_opt_out: bool,
    #[serde(default)]
    pub show_resolved_model: Option<bool>,
    /// `Some` means the user is blocked; `None` means the user has access.
    #[serde(default)]
    pub gate: Option<GateInfo>,
    /// Display name for the current subscription tier (e.g. "SuperGrok Heavy", "X Premium", "Free"), from CCP `/settings`.
    #[serde(default)]
    pub subscription_tier: Option<String>,
    /// Whether `/feedback` may offer a one-shot trace upload; it lives on auth meta so it refreshes with auth changes.
    #[serde(default)]
    pub feedback_trace_offer: bool,
}

impl Default for AuthMeta {
    fn default() -> Self {
        Self {
            email: None,
            auth_mode: None,
            team_id: None,
            team_name: None,
            is_zdr: false,
            team_role: None,
            coding_data_retention_opt_out: crate::auth::default_coding_data_retention_opt_out(),
            show_resolved_model: None,
            gate: None,
            subscription_tier: None,
            feedback_trace_offer: false,
        }
    }
}
