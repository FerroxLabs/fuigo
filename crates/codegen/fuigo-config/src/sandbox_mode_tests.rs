use std::str::FromStr;

use serde::Deserialize;

use super::{
    ModeDegradation, RefusedLayers, ResolvedSandboxMode, SandboxMode, SandboxModeLayers,
    SandboxModeSource, enforce_fallback_warning,
};

fn resolve(layers: SandboxModeLayers<'_>) -> (SandboxMode, SandboxModeSource) {
    let resolved = SandboxMode::resolve(layers);
    assert_eq!(None, resolved.degraded, "the layers alone never degrade");
    (resolved.mode, resolved.source)
}

/// The sandbox ships off; observe/enforce are turned on in Settings or in
/// `workspaced.toml`.
#[test]
fn default_is_off_from_the_default_layer() {
    assert_eq!(SandboxMode::Off, SandboxMode::default());
    assert_eq!(
        ResolvedSandboxMode {
            mode: SandboxMode::Off,
            source: SandboxModeSource::Default,
            degraded: None,
        },
        SandboxMode::resolve(SandboxModeLayers::default())
    );
}

/// Decided policy: `enforce` on a host with no per-command backend never refuses to run. From any
/// layer it falls back to `off`, recorded as [`ModeDegradation::EnforceWithoutBackend`] and
/// attributed to the layer that asked for it. With a backend nothing changes.
#[test]
fn enforce_on_a_host_without_a_backend_falls_back_to_off_from_every_layer() {
    for layers in [
        SandboxModeLayers {
            env: Some("enforce"),
            ..SandboxModeLayers::default()
        },
        SandboxModeLayers {
            managed: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        },
        SandboxModeLayers {
            user: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        },
        SandboxModeLayers {
            workspace: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        },
        SandboxModeLayers {
            env: Some("enforce"),
            managed: Some(SandboxMode::Observe),
            ..SandboxModeLayers::default()
        },
    ] {
        let resolved = SandboxMode::resolve(layers);
        assert_eq!(SandboxMode::Enforce, resolved.mode, "{layers:?}");
        assert_eq!(resolved, resolved.on_host(true), "{layers:?}");
        let fallback = resolved.on_host(false);
        assert_eq!(
            ResolvedSandboxMode {
                mode: SandboxMode::Off,
                source: resolved.source,
                degraded: Some(ModeDegradation::EnforceWithoutBackend),
            },
            fallback,
            "{layers:?}"
        );
        assert!(!fallback.mode.is_wrapped(), "{layers:?}");
        assert!(!fallback.mode.uses_proxy(), "{layers:?}");
        assert_eq!(
            fallback,
            SandboxMode::resolve_on_host(layers, false),
            "{layers:?}"
        );
        assert_eq!(
            resolved,
            SandboxMode::resolve_on_host(layers, true),
            "{layers:?}"
        );
    }
    // Observe and off have nothing to degrade
    for mode in [SandboxMode::Observe, SandboxMode::Off] {
        let resolved = SandboxMode::resolve(SandboxModeLayers {
            managed: Some(mode),
            ..SandboxModeLayers::default()
        });
        assert_eq!(resolved, resolved.on_host(false), "{mode:?}");
    }
}

/// The fallback is loud: the warning text names the platform, the reason, the layer that asked and
/// the consequence, and `on_host_because` carries the probe's reason through unchanged.
#[test]
fn the_fallback_warning_names_the_platform_and_the_reason() {
    let text = enforce_fallback_warning(
        "linux",
        "no per-command sandbox backend for linux: v1 has Seatbelt on macos only",
        SandboxModeSource::UserConfig,
    );
    for needle in [
        "WARNING",
        "enforce",
        "linux",
        "v1 has Seatbelt on macos only",
        "user_config",
        "mode `off`",
        "WITHOUT per-command confinement",
    ] {
        assert!(text.contains(needle), "{needle} missing from {text}");
    }
    let resolved = ResolvedSandboxMode::new(SandboxMode::Enforce, SandboxModeSource::Env);
    assert_eq!(resolved, resolved.on_host_because(None));
    let fallback = resolved.on_host_because(Some("no sandbox-exec"));
    assert_eq!(SandboxMode::Off, fallback.mode);
    assert_eq!(
        Some(ModeDegradation::EnforceWithoutBackend),
        fallback.degraded
    );
}

/// A file layer that is refused counts as `enforce`; with no backend it leaves the readable
/// layers' mode (marked), and never runs commands more loosely than the readable layers say.
#[test]
fn a_refused_layer_without_a_backend_keeps_the_readable_mode_marked() {
    let resolved = SandboxMode::resolve_on_host(
        SandboxModeLayers {
            user: Some(SandboxMode::Observe),
            workspace: Some(SandboxMode::Enforce),
            refused: RefusedLayers {
                managed: true,
                ..RefusedLayers::default()
            },
            ..SandboxModeLayers::default()
        },
        false,
    );
    assert_eq!(
        SandboxMode::Off,
        resolved.mode,
        "workspace enforce falls back"
    );
    let resolved = SandboxMode::resolve_on_host(
        SandboxModeLayers {
            user: Some(SandboxMode::Observe),
            refused: RefusedLayers {
                managed: true,
                ..RefusedLayers::default()
            },
            ..SandboxModeLayers::default()
        },
        false,
    );
    assert_eq!(
        ResolvedSandboxMode {
            mode: SandboxMode::Observe,
            source: SandboxModeSource::Managed,
            degraded: Some(ModeDegradation::ConfigRefused),
        },
        resolved
    );
}

/// `sandbox.status` carries the degradation only when there is one, so the shape of every
/// other answer is unchanged.
#[test]
fn a_degradation_is_serialized_only_when_present() {
    let plain = ResolvedSandboxMode::new(SandboxMode::Enforce, SandboxModeSource::Managed);
    assert_eq!(
        serde_json::json!({"mode": "enforce", "source": "managed"}),
        serde_json::to_value(plain).unwrap()
    );
    assert_eq!(
        serde_json::json!({
            "mode": "off",
            "source": "managed",
            "degraded": "enforce_without_backend",
        }),
        serde_json::to_value(plain.on_host(false)).unwrap()
    );
    assert_eq!(
        "enforce_without_backend",
        <&str>::from(ModeDegradation::EnforceWithoutBackend)
    );
}

/// `Enforce`, `ENFORCE` and ` enforce ` all name the mode, from the environment as from a file
/// or the managed config; a word that is not a mode is still refused, whatever its case.
#[test]
fn modes_are_parsed_in_any_case_from_every_source() {
    for (text, mode) in [
        ("Enforce", SandboxMode::Enforce),
        ("ENFORCE", SandboxMode::Enforce),
        ("observe", SandboxMode::Observe),
        ("Observe", SandboxMode::Observe),
        ("OFF", SandboxMode::Off),
    ] {
        assert_eq!(Ok(mode), SandboxMode::from_str(text), "{text}");
        assert_eq!(
            mode,
            serde_json::from_str::<SandboxMode>(&format!("\" {text} \"")).unwrap(),
            "{text}"
        );
        assert_eq!(
            (mode, SandboxModeSource::Env),
            resolve(SandboxModeLayers {
                env: Some(text),
                ..SandboxModeLayers::default()
            }),
            "{text}"
        );
    }
    assert!(SandboxMode::from_str("Audit").is_err());
    let error = serde_json::from_str::<SandboxMode>("\"Audit\"").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expected off, observe or enforce"),
        "{error}"
    );
    assert!(
        !error.to_string().contains("Audit"),
        "the value is never echoed: {error}"
    );
    assert!(serde_json::from_str::<SandboxMode>("3").is_err());
}

/// A `workspaced.toml` layer reads the mode through the same function: a string names it, any
/// other TOML value (a datetime included) is an unset field, and the table still loads.
#[test]
fn a_file_sandbox_mode_of_any_shape_never_fails_the_table() {
    #[derive(Deserialize)]
    struct Layer {
        #[serde(default, deserialize_with = "super::optional_sandbox_mode")]
        mode: Option<SandboxMode>,
        other: bool,
    }
    for (value, mode) in [
        (r#""Observe""#, Some(SandboxMode::Observe)),
        (r#""audit""#, None),
        ("3", None),
        ("1979-05-27T07:32:00Z", None),
        (r#"["enforce"]"#, None),
        ("{ a = 1 }", None),
    ] {
        let text = format!("mode = {value}\nother = true\n");
        let layer =
            toml::from_str::<Layer>(&text).unwrap_or_else(|error| panic!("{text}: {error}"));
        assert_eq!(mode, layer.mode, "{text}");
        assert!(layer.other, "{text}");
    }
}

#[test]
fn user_config_beats_the_default() {
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::UserConfig),
        resolve(SandboxModeLayers {
            user: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        })
    );
}

#[test]
fn managed_beats_user_config() {
    assert_eq!(
        (SandboxMode::Observe, SandboxModeSource::Managed),
        resolve(SandboxModeLayers {
            managed: Some(SandboxMode::Observe),
            user: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        })
    );
}

/// A cloned repository's `.fuigo/workspaced.toml` cannot lower the user's
/// mode.
#[test]
fn workspace_config_may_only_tighten_the_user_mode() {
    let lowered = resolve(SandboxModeLayers {
        workspace: Some(SandboxMode::Off),
        user: Some(SandboxMode::Enforce),
        ..SandboxModeLayers::default()
    });
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::UserConfig),
        lowered
    );

    let raised = resolve(SandboxModeLayers {
        workspace: Some(SandboxMode::Enforce),
        user: Some(SandboxMode::Observe),
        ..SandboxModeLayers::default()
    });
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::WorkspaceConfig),
        raised
    );

    let raised_over_default = resolve(SandboxModeLayers {
        workspace: Some(SandboxMode::Enforce),
        ..SandboxModeLayers::default()
    });
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::WorkspaceConfig),
        raised_over_default
    );

    let equal = resolve(SandboxModeLayers {
        workspace: Some(SandboxMode::Observe),
        user: Some(SandboxMode::Observe),
        ..SandboxModeLayers::default()
    });
    assert_eq!((SandboxMode::Observe, SandboxModeSource::UserConfig), equal);
}

/// A folder whose file says `off` with nothing above it is set by that
/// file, not by the default; an equal user value keeps the credit.
#[test]
fn an_explicit_workspace_off_is_attributed_to_the_workspace_file() {
    assert_eq!(
        (SandboxMode::Off, SandboxModeSource::WorkspaceConfig),
        resolve(SandboxModeLayers {
            workspace: Some(SandboxMode::Off),
            ..SandboxModeLayers::default()
        })
    );
    assert_eq!(
        (SandboxMode::Off, SandboxModeSource::UserConfig),
        resolve(SandboxModeLayers {
            user: Some(SandboxMode::Off),
            workspace: Some(SandboxMode::Off),
            ..SandboxModeLayers::default()
        })
    );
}

/// The workspace layer is a tighten-only layer, so it takes no trust input: the layers carry
/// nothing about the folder's trust, and a workspace `enforce` over the default is `enforce`
/// whatever the folder's trust standing. (Gated on trust, a repository's own `.envrc` — which
/// makes the folder untrusted — would drop the mode the folder asked for.)
#[test]
fn the_workspace_layer_tightens_without_a_trust_input() {
    let layers = SandboxModeLayers {
        workspace: Some(SandboxMode::Enforce),
        ..SandboxModeLayers::default()
    };
    let SandboxModeLayers {
        env: None,
        managed: None,
        user: None,
        workspace: Some(SandboxMode::Enforce),
        refused:
            RefusedLayers {
                managed: false,
                user: false,
                workspace: false,
            },
    } = layers
    else {
        panic!(
            "the layers are the four mode sources and which files were refused, nothing else: \
             {layers:?}"
        );
    };
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::WorkspaceConfig),
        resolve(layers)
    );
}

#[test]
fn workspace_config_never_overrides_env_or_managed() {
    assert_eq!(
        (SandboxMode::Observe, SandboxModeSource::Managed),
        resolve(SandboxModeLayers {
            managed: Some(SandboxMode::Observe),
            workspace: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        })
    );
    assert_eq!(
        (SandboxMode::Off, SandboxModeSource::Env),
        resolve(SandboxModeLayers {
            env: Some("off"),
            workspace: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        })
    );
}

#[test]
fn env_beats_every_layer() {
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::Env),
        resolve(SandboxModeLayers {
            env: Some(" enforce\n"),
            managed: Some(SandboxMode::Off),
            workspace: Some(SandboxMode::Off),
            user: Some(SandboxMode::Off),
            refused: RefusedLayers {
                managed: false,
                user: true,
                workspace: true,
            },
        })
    );
}

/// A refused file layer counts as `enforce` whatever it holds and is marked when it decides (over
/// the user's file, the default, as the tightening folder layer), never over a higher layer; with
/// no backend the readable layers' mode stands, still marked.
#[test]
fn a_refused_layer_counts_as_enforce_and_is_marked_when_it_decides() {
    let refused = |mode, source| ResolvedSandboxMode {
        mode,
        source,
        degraded: Some(ModeDegradation::ConfigRefused),
    };
    let user_layers = SandboxModeLayers {
        user: Some(SandboxMode::Off),
        refused: RefusedLayers {
            managed: false,
            user: true,
            workspace: false,
        },
        ..SandboxModeLayers::default()
    };
    let user_refused = SandboxMode::resolve(user_layers);
    assert_eq!(
        refused(SandboxMode::Enforce, SandboxModeSource::UserConfig),
        user_refused
    );
    let workspace_layers = SandboxModeLayers {
        user: Some(SandboxMode::Observe),
        workspace: Some(SandboxMode::Off),
        refused: RefusedLayers {
            managed: false,
            user: false,
            workspace: true,
        },
        ..SandboxModeLayers::default()
    };
    let workspace_refused = SandboxMode::resolve(workspace_layers);
    assert_eq!(
        refused(SandboxMode::Enforce, SandboxModeSource::WorkspaceConfig),
        workspace_refused
    );
    assert_eq!(
        ResolvedSandboxMode::new(SandboxMode::Enforce, SandboxModeSource::UserConfig),
        SandboxMode::resolve(SandboxModeLayers {
            user: Some(SandboxMode::Enforce),
            refused: RefusedLayers {
                managed: false,
                user: false,
                workspace: true,
            },
            ..SandboxModeLayers::default()
        }),
        "the user's own enforce decided"
    );
    assert_eq!(
        ResolvedSandboxMode::new(SandboxMode::Observe, SandboxModeSource::Managed),
        SandboxMode::resolve(SandboxModeLayers {
            managed: Some(SandboxMode::Observe),
            refused: RefusedLayers {
                managed: false,
                user: true,
                workspace: true,
            },
            ..SandboxModeLayers::default()
        })
    );

    for (layers, readable) in [
        (user_layers, SandboxMode::Off),
        (workspace_layers, SandboxMode::Observe),
    ] {
        let resolved = SandboxMode::resolve(layers);
        assert_eq!(resolved, SandboxMode::resolve_on_host(layers, true));
        assert_eq!(resolved, resolved.on_host(true));
        assert_eq!(
            refused(readable, resolved.source),
            SandboxMode::resolve_on_host(layers, false)
        );
        assert_eq!(
            refused(SandboxMode::Off, resolved.source),
            resolved.on_host(false)
        );
    }
    assert_eq!(
        serde_json::json!({
            "mode": "enforce",
            "source": "user_config",
            "degraded": "config_refused",
        }),
        serde_json::to_value(user_refused).unwrap(),
        "`sandbox.status` says why"
    );
}

/// Over every pairing of absent, readable and refused files a refusal never lowers a readable
/// layer's mode and is marked (at the highest refused layer) only when it raised it; with no
/// backend every `enforce` runs `off`.
#[test]
fn a_refusal_never_wins_a_tie_or_lowers_a_readable_layer() {
    let refused_user_beside_workspace_enforce = SandboxMode::resolve(SandboxModeLayers {
        user: Some(SandboxMode::Off),
        workspace: Some(SandboxMode::Enforce),
        refused: RefusedLayers {
            managed: false,
            user: true,
            workspace: false,
        },
        ..SandboxModeLayers::default()
    });
    let refused_workspace_beside_user_enforce = SandboxMode::resolve(SandboxModeLayers {
        user: Some(SandboxMode::Enforce),
        workspace: Some(SandboxMode::Off),
        refused: RefusedLayers {
            managed: false,
            user: false,
            workspace: true,
        },
        ..SandboxModeLayers::default()
    });
    let fallback = |source| ResolvedSandboxMode {
        mode: SandboxMode::Off,
        source,
        degraded: Some(ModeDegradation::EnforceWithoutBackend),
    };
    for (resolved, source) in [
        (
            refused_user_beside_workspace_enforce,
            SandboxModeSource::WorkspaceConfig,
        ),
        (
            refused_workspace_beside_user_enforce,
            SandboxModeSource::UserConfig,
        ),
    ] {
        assert_eq!(
            ResolvedSandboxMode::new(SandboxMode::Enforce, source),
            resolved.on_host(true)
        );
        assert_eq!(fallback(source), resolved.on_host(false));
    }

    let values = [
        None,
        Some(SandboxMode::Off),
        Some(SandboxMode::Observe),
        Some(SandboxMode::Enforce),
    ];
    let files: Vec<(Option<SandboxMode>, bool)> = values
        .into_iter()
        .flat_map(|value| [(value, false), (value, true)])
        .collect();
    for &(managed, managed_refused) in &files {
        for &(user, user_refused) in &files {
            for &(workspace, workspace_refused) in &files {
                let layers = SandboxModeLayers {
                    managed,
                    user,
                    workspace,
                    refused: RefusedLayers {
                        managed: managed_refused,
                        user: user_refused,
                        workspace: workspace_refused,
                    },
                    ..SandboxModeLayers::default()
                };
                let readable = SandboxMode::resolve(SandboxModeLayers {
                    managed: managed.filter(|_| !managed_refused),
                    user: user.filter(|_| !user_refused),
                    workspace: workspace.filter(|_| !workspace_refused),
                    ..SandboxModeLayers::default()
                });
                let resolved = SandboxMode::resolve(layers);
                let applies = (managed_refused || user_refused || workspace_refused)
                    && readable.source != SandboxModeSource::Managed;
                assert_eq!(
                    applies && readable.mode != SandboxMode::Enforce,
                    resolved.degraded == Some(ModeDegradation::ConfigRefused),
                    "marked only when the refusal raised the mode: {layers:?}"
                );
                if resolved.degraded == Some(ModeDegradation::ConfigRefused) {
                    let highest = if managed_refused {
                        SandboxModeSource::Managed
                    } else if user_refused {
                        SandboxModeSource::UserConfig
                    } else {
                        SandboxModeSource::WorkspaceConfig
                    };
                    assert_eq!(highest, resolved.source, "{layers:?}");
                }
                for backend_available in [true, false] {
                    let resolved = SandboxMode::resolve_on_host(layers, backend_available);
                    // With no backend a readable `enforce` runs off (loudly); a refusal alone
                    // never raises the mode there
                    let expected = if applies && backend_available {
                        SandboxMode::Enforce
                    } else {
                        readable.on_host(backend_available).mode
                    };
                    assert_eq!(
                        expected, resolved.mode,
                        "{resolved:?} fails open, lowers {readable:?} or runs a mode no one \
                         chose: {layers:?}, backend_available = {backend_available}"
                    );
                    assert_eq!(
                        applies && readable.mode != SandboxMode::Enforce,
                        resolved.degraded == Some(ModeDegradation::ConfigRefused),
                        "{layers:?}, backend_available = {backend_available}"
                    );
                }
            }
        }
    }
}

#[test]
fn unrecognised_env_is_skipped_not_treated_as_off() {
    assert_eq!(
        (SandboxMode::Enforce, SandboxModeSource::UserConfig),
        resolve(SandboxModeLayers {
            env: Some("enforcee"),
            user: Some(SandboxMode::Enforce),
            ..SandboxModeLayers::default()
        })
    );
}

#[test]
fn modes_are_ordered_off_observe_enforce() {
    assert!(SandboxMode::Off < SandboxMode::Observe);
    assert!(SandboxMode::Observe < SandboxMode::Enforce);
}

#[test]
fn mode_strings_round_trip_through_serde_and_strum() {
    for (mode, text) in [
        (SandboxMode::Off, "off"),
        (SandboxMode::Observe, "observe"),
        (SandboxMode::Enforce, "enforce"),
    ] {
        assert_eq!(text, <&str>::from(mode));
        assert_eq!(
            mode,
            serde_json::from_str::<SandboxMode>(&format!("\"{text}\"")).unwrap()
        );
    }
    assert!(serde_json::from_str::<SandboxMode>("\"audit\"").is_err());
}

#[test]
fn only_enforce_wraps_and_off_never_injects_the_proxy() {
    assert!(SandboxMode::Enforce.is_wrapped());
    assert!(!SandboxMode::Observe.is_wrapped());
    assert!(!SandboxMode::Off.is_wrapped());
    assert!(SandboxMode::Enforce.uses_proxy());
    assert!(SandboxMode::Observe.uses_proxy());
    assert!(!SandboxMode::Off.uses_proxy());
}
