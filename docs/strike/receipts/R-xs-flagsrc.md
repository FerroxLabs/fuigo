# R-xs-flagsrc: who can turn `features.peer_messaging` on

Strip: `CAMPAIGN_STRIP_PATHS` (`crates/codegen/fuigo-config/src/config_override.rs:101`) via `strip_campaign_paths` (`:104`), called for every campaign patch in `apply_active_campaign_patches` (`crates/codegen/fuigo-config/src/campaigns.rs:112`), the single path remote, local and env-override campaigns all take (`config_layers.rs:255`).

| Source | Can set the flag after this change | Evidence |
|---|---|---|
| User `config.toml` `[features]` | yes (unchanged) | normal layer merge |
| `[[version_overrides]]` in the user's / admin's own file | yes (unchanged, their own action) | applied per file layer: `loader.rs:262,291,335,366`; `version_overrides.rs:121` |
| `FUIGO_CONFIG` overlay | yes (unchanged) | `config_override.rs` `OVERLAY_ALLOW_PATHS` keeps `["features"]` |
| Env `FUIGO_PEER_MESSAGING` | yes (unchanged) | not a campaign path |
| Admin managed config / requirements pin | yes; pin still beats everything | `config_layers.rs:256-258` `reapply_requirements` |
| Remote campaign (`RemoteSettings.campaigns`) | NO | `campaigns.rs:112` |
| Local `[[campaigns]]` in any layer | NO | `campaigns.rs:112` |
| `FUIGO_CAMPAIGNS_OVERRIDE` | NO | `campaigns.rs:112` |
| `version_overrides` from a remote/campaign source | n/a: key stripped from campaign patches (`CAMPAIGN_STRIP_KEYS`), and no remote path feeds `apply_version_overrides` | `config_override.rs:91` |
