# R-1026-model-notice: model notice banner (packet 26-6d(b))

Branch `strike/b26-6n`, base `hub/strike/stage-1026`. Local sources only; budget rule (owner decision 68) applied.

## Ported
| Piece | Fuigo location |
|---|---|
| `ModelNotice` type, meta key, `parse_model_notice_meta` (string or table form), tests | `fuigo-sampling-types/src/types/model_notice.rs`, `model_notice_tests.rs`, re-export in `types.rs` |
| `notice` on `[model.<id>]` (`ConfigModelOverride`), `ModelEntryConfig`, `ModelInfo`; override apply (blank clears); `_meta.notice` in the ACP model meta | `fuigo-shell/src/agent/config.rs`, `config_model_override_parse.rs` |
| Banner view (fixed `notice:` tag, own scrub, 4-row cap) and tests | `fuigo-pager/src/views/model_notice_banner.rs` and `_tests.rs` |
| `ModelState::current_notice` (scrubs the ACP value again) | `fuigo-pager/src/acp/model_state.rs` |
| Layout row `model_notice_height` / `model_notice` above the voice row and prompt; paint in `draw_layers`; line-viewer overlay bottom | `views/agent.rs`, `app/agent_view/render.rs` |

## Sources and trust
- Sources: `[model.<id>] notice` in the user or managed config. `[model.*]` comes from the merged global config; `find_project_configs` is used for plugins, MCP and `inspect`, not for model entries, so a project or plugin file cannot supply a notice. Nothing is fetched (remote catalog source not ported: `remote/client.rs` leaves it empty). Upstream's bundled `default_models.json` carries no notices, so none are bundled.
- Filter (`scrub_unsafe_display`, row breaks to spaces, whitespace collapsed, 160-character cap, label 24): at config parse (`config_model_override_parse.rs`), when applied (`sanitize_model_notice`), when the ACP meta is built, when the pager reads the meta (`current_notice`) and when it paints (`banner::sanitize`).
- The banner starts with the fixed `notice:` tag, uses plain styled cells (no markdown, no link, not in the transcript).

## Layout and the peer dialog
The banner is a passive row group in the layout (between the follow-ups/dock rows and the voice row/prompt), 0 rows at 16 terminal rows or less (`SHORT_TERMINAL_ROWS`), so 52x6 is unchanged and the held-row rule (`scrollback.height > 6`) still applies. The held row is cut from the scrollback after the layout, so the banner never shifts it. The dialog is still painted after `draw_layers`. `render` is not overlay-shaped, so `other_overlay_list_matches_the_draw_overlays` needs no new row; `model_notice_tests.rs` pins that the banner is painted in the layers and is absent from `other_overlay_active`.

## Not ported
Remote catalog source; welcome-screen banner (`views/welcome/mod.rs`, `app_view.rs`; moves to the next release); bundled notices.
