use super::*;
use crate::session::slash_commands::BUILTIN_COMMANDS;

fn text_block(text: &str) -> acp::ContentBlock {
    acp::ContentBlock::Text(acp::TextContent::new(text))
}

#[test]
fn model_authored_resolution_uses_exact_canonical_metadata() {
    assert!(matches!(
        resolve(
            InputAuthority::ModelAuthoredUntrusted,
            &[text_block("/compact preserve auth")],
            BUILTIN_COMMANDS,
        ),
        AuthorityResolution::StaticBuiltin(BuiltinAction::Compact {
            user_context: Some(context),
        }) if context == "preserve auth"
    ));

    for text in ["/Compact", "/COMPACT", "/yolo", "/context", "/feedback"] {
        assert!(matches!(
            resolve(
                InputAuthority::ModelAuthoredUntrusted,
                &[text_block(text)],
                BUILTIN_COMMANDS,
            ),
            AuthorityResolution::ModelAuthoredSkillCandidate { .. }
        ));
    }
}

#[test]
fn runtime_control_is_inert_and_human_intent_continues_to_dynamic_resolution() {
    assert!(matches!(
        resolve(
            InputAuthority::RuntimeControl,
            &[text_block("/compact")],
            BUILTIN_COMMANDS,
        ),
        AuthorityResolution::Inert
    ));
    assert!(matches!(
        resolve(
            InputAuthority::RuntimeControl,
            &[text_block("/available-skill")],
            BUILTIN_COMMANDS,
        ),
        AuthorityResolution::Inert
    ));
    assert!(matches!(
        resolve(
            InputAuthority::HumanIntent,
            &[text_block("/Compact keep aliases")],
            BUILTIN_COMMANDS,
        ),
        AuthorityResolution::HumanIntent {
            command_name: "Compact",
            args: "keep aliases",
        }
    ));
}

/// S1.2: a peer's leading `/` is inert for every command, including the one a parent agent may run (`/compact`),
/// every human-only builtin, and an unknown name (a skill or plugin command).
#[test]
fn s1_2_peer_untrusted_slash_is_inert_for_every_command() {
    for text in [
        "/compact", "/compact keep going", "/yolo", "/permissions", "/rename pwned", "/context", "/feedback",
        "/available-skill arg", "/plugin-command x", "/loop 1m do it", "  /yolo",
    ] {
        assert!(
            matches!(
                resolve(InputAuthority::PeerUntrusted, &[text_block(text)], BUILTIN_COMMANDS),
                AuthorityResolution::Inert
            ),
            "{text}"
        );
    }
    assert!(matches!(
        resolve(InputAuthority::PeerUntrusted, &[text_block("plain")], BUILTIN_COMMANDS),
        AuthorityResolution::NotSlash
    ));
    // every builtin name, by name
    for command in BUILTIN_COMMANDS {
        let text = format!("/{}", command.name);
        assert!(
            matches!(
                resolve(InputAuthority::PeerUntrusted, &[text_block(&text)], BUILTIN_COMMANDS),
                AuthorityResolution::Inert
            ),
            "{text}"
        );
    }
}

/// `/context-window` is a human command: neither model-authored nor peer-authored text can run it or select a window.
#[test]
fn context_window_command_is_human_only() {
    assert!(crate::session::slash_commands::PAGER_COMMAND_KEYS.contains(&"context-window"));
    assert!(
        BUILTIN_COMMANDS
            .iter()
            .all(|command| command.name != "context-window"
                || command.model_authored_eligibility == ModelAuthoredEligibility::Denied)
    );
    for text in ["/context-window 400k", "/context-window", "/Context-Window 1m"] {
        assert!(matches!(
            resolve(
                InputAuthority::ModelAuthoredUntrusted,
                &[text_block(text)],
                BUILTIN_COMMANDS,
            ),
            AuthorityResolution::ModelAuthoredSkillCandidate { .. }
        ));
        assert!(matches!(
            resolve(
                InputAuthority::PeerUntrusted,
                &[text_block(text)],
                BUILTIN_COMMANDS,
            ),
            AuthorityResolution::Inert
        ));
        assert!(matches!(
            resolve(
                InputAuthority::RuntimeControl,
                &[text_block(text)],
                BUILTIN_COMMANDS,
            ),
            AuthorityResolution::Inert
        ));
    }
    // The skill resolver has no builtin to dispatch, so the text stays plain prompt text.
    let blocks = vec![text_block("/context-window 400k")];
    let out = crate::session::slash_commands::resolve_model_authored_skill(
        blocks.clone(),
        "context-window",
        "400k",
        &[],
        crate::session::slash_commands::CommandAvailability::default(),
        true,
    );
    assert!(matches!(out, Ok(ref b) if b.len() == 1));
}
