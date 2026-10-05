//! P133: the config notice (a refused reference to the saved API key) goes out as a session notification, and, like the
//! other intake diagnostics, leaves the first-output window open. Red first.

use super::support::*;
use super::*;

#[tokio::test]
async fn a_config_notice_reaches_the_client_as_a_session_notification() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (actor, mut gateway_rx) = build_actor().await;
            actor
                .send_fuigo_notification_transient(FuigoSessionUpdate::ConfigNotice {
                    message: "/w/repo/.fuigo/config.toml: `mcp_servers.s.env.T` names FUIGO_API_KEY".into(),
                });
            let mut seen = Vec::new();
            while let Ok(msg) = gateway_rx.try_recv() {
                if let fuigo_acp_lib::AcpClientMessage::ExtNotification(args) = msg
                    && args.request.method.as_ref() == "fuigo/session_notification"
                {
                    let params: serde_json::Value = serde_json::from_str(args.request.params.get()).unwrap();
                    if params["update"]["sessionUpdate"] == "config_notice" {
                        seen.push(params["update"]["message"].as_str().unwrap_or_default().to_owned());
                    }
                }
            }
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert!(seen[0].contains("FUIGO_API_KEY"));
        })
        .await;
}
