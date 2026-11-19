use super::*;

impl CompiledPolicy {
    /// Escalate (never auto-allow) a shell reader/writer/redirect touching a restricted path; unpinnable operands return `Ask`.
    pub fn evaluate_shell_file_access(&self, cmd: &str, cwd: &Path) -> Option<Decision> {
        self.evaluate_shell_file_access_gate(cmd, cwd)
            .map(GateDecision::into_decision)
    }

    /// [`Self::evaluate_shell_file_access`] with `Ask` provenance kept.
    /// A rule-match Ask stays binding while the manager may defer a fail-closed Ask to the auto-mode classifier.
    pub(crate) fn evaluate_shell_file_access_gate(
        &self,
        cmd: &str,
        cwd: &Path,
    ) -> Option<GateDecision> {
        if !self.has_file_restrictions {
            return None;
        }
        let base = RuleBase::new(cwd);
        self.evaluate_shell_file_access_inner(cmd, &base, MAX_INLINE_SHELL_DEPTH, false, false)
    }

    pub(super) fn evaluate_shell_file_access_inner(
        &self,
        cmd: &str,
        base: &RuleBase<'_>,
        inline_depth_remaining: usize,
        cwd_unpinned: bool,
        entered_inline: bool,
    ) -> Option<GateDecision> {
        let Some(tree) = try_parse_shell(cmd) else {
            return entered_inline.then_some(GateDecision::AskFailClosed);
        };
        let root = tree.root_node();
        let parse_failed = root.has_error();
        // WHY: only recursively entered scripts gain a general malformed-script Ask floor.
        let mut forced_ask = entered_inline && parse_failed;
        let mut decision: Option<GateDecision> = None;

        let invocations = shell_command_invocations(root, cmd);

        // We don't track cwd across `cd`/`pushd`/`env -C`; a relative operand after one is unpinnable and must Ask
        // Managed denies are `**/` basename globs, so they still match; only exact-path rules are affected
        let cwd_changes = cwd_poison_positions(root, cmd);

        for redirect in shell_redirect_targets(root, cmd) {
            if redirect.ambiguous {
                forced_ask = true;
            }
            if let Some(path) = redirect.path {
                let path_cwd_unpinned = cwd_unpinned
                    || cwd_unpinned_before(&cwd_changes, redirect.start_byte, redirect.scope);
                decision = combine_gate_decisions(
                    decision,
                    self.evaluate_shell_path(&path, base, redirect.mode, path_cwd_unpinned),
                );
            }
        }

        for invocation in &invocations {
            let peeled = unwrap_invocation_checked(invocation);
            let words = peeled.words;
            let invocation_cwd_unpinned = cwd_unpinned
                || cwd_unpinned_before(&cwd_changes, invocation.start_byte, invocation.scope)
                || peeled.has_chdir;
            forced_ask |= peeled.exhausted;
            forced_ask |= peeled.has_split_string;
            forced_ask |= peeled.env_options_uncertain;
            forced_ask |= peeled.transparent_ambiguous;
            let shell_words = words.shell_words();
            let inline_script = shell_dash_c_script(&shell_words);
            if parse_failed && !matches!(inline_script, InlineShellScript::NotInline) {
                forced_ask = true;
            }
            match inline_script {
                InlineShellScript::Literal(index) => {
                    if inline_depth_remaining == 0 {
                        forced_ask = true;
                    } else if let ShellWord::Literal(inner) = shell_words[index] {
                        decision = combine_gate_decisions(
                            decision,
                            self.evaluate_shell_file_access_inner(
                                inner,
                                base,
                                inline_depth_remaining - 1,
                                invocation_cwd_unpinned,
                                true,
                            ),
                        );
                    }
                }
                // Potential -c (Untrusted) and unmodeled options without -c (Unrecognized) both fail closed; only Literal may recurse
                InlineShellScript::Untrusted | InlineShellScript::Unrecognized => {
                    forced_ask = true;
                }
                InlineShellScript::NotInline => {}
            }
            let literal_words = words.literal_words();
            let has_ambiguous_word = words
                .words
                .iter()
                .any(|word| matches!(word, InvocationWord::Untrusted));
            let Some(InvocationWord::Literal(program)) = words.words.first() else {
                continue;
            };
            let program = shell_program_name(program);
            let program_lower = program.to_ascii_lowercase();
            if matches!(program_lower.as_str(), "cd" | "pushd" | "popd") {
                continue;
            }
            let candidates = shell_file_candidates(&literal_words);
            let path_operands = shell_path_command_operands(&program_lower, &literal_words);
            let is_known = program_lower == "dd"
                || shell_file_mode(&program_lower).is_some()
                || path_operands.is_some();
            if is_known && (invocation_cwd_unpinned || has_ambiguous_word || parse_failed) {
                forced_ask = true;
            }
            for (path, mode) in special_file_operands(&program_lower, &literal_words) {
                decision = combine_gate_decisions(
                    decision,
                    self.evaluate_shell_operand(
                        &invocation.globs,
                        &path,
                        base,
                        mode,
                        invocation_cwd_unpinned,
                    ),
                );
            }
            if program_lower == "dd" {
                continue;
            }
            if let Some(operands) = path_operands {
                for (path, mode) in operands {
                    decision = combine_gate_decisions(
                        decision,
                        self.evaluate_shell_operand(
                            &invocation.globs,
                            path,
                            base,
                            mode,
                            invocation_cwd_unpinned,
                        ),
                    );
                }
                continue;
            }
            let modes: &[ShellFileMode] = match shell_file_mode(&program_lower) {
                Some(_) if program_lower == "sed" && shell_sed_in_place(&literal_words) => {
                    &[ShellFileMode::Read, ShellFileMode::Write]
                }
                Some(ShellFileMode::Read) => &[ShellFileMode::Read],
                Some(ShellFileMode::Write) => &[ShellFileMode::Write],
                Some(ShellFileMode::Create) | None => continue,
            };
            for &token in &candidates {
                for &mode in modes {
                    decision = combine_gate_decisions(
                        decision,
                        self.evaluate_shell_operand(
                            &invocation.globs,
                            token,
                            base,
                            mode,
                            invocation_cwd_unpinned,
                        ),
                    );
                }
            }
            if shell_reader_can_recurse(&program_lower, &literal_words, &candidates) {
                forced_ask = true;
            }
        }
        combine_gate_decisions(decision, forced_ask.then_some(GateDecision::AskFailClosed))
    }

    /// One file operand: a literal path is matched as before; an unquoted glob is matched as written (bash passes an
    /// unmatched pattern through literally) and also as a pattern ([`Self::evaluate_shell_glob`]); undecoded glob
    /// characters fail closed.
    pub(super) fn evaluate_shell_operand(
        &self,
        globs: &InvocationGlobs,
        token: &str,
        base: &RuleBase<'_>,
        mode: ShellFileMode,
        cwd_unpinned: bool,
    ) -> Option<GateDecision> {
        let literal = self.evaluate_shell_path(token, base, mode, cwd_unpinned);
        let extra = match globs.operand(token) {
            OperandGlob::Literal => None,
            OperandGlob::Pattern => self.evaluate_shell_glob(token, base, mode, cwd_unpinned),
            OperandGlob::Ambiguous => Some(GateDecision::AskFailClosed),
        };
        combine_gate_decisions(literal, extra)
    }

    /// An unquoted glob operand: it requires approval when the pattern could match a path a deny or ask rule restricts
    /// for this access, judged pattern against pattern so a file created later is covered, and when any path it
    /// matches now (followed through symlinks, as a literal operand is) hits a rule.
    pub(super) fn evaluate_shell_glob(
        &self,
        token: &str,
        base: &RuleBase<'_>,
        mode: ShellFileMode,
        cwd_unpinned: bool,
    ) -> Option<GateDecision> {
        let pattern = normalize_shell_path(token);
        let is_absolute = is_absolute_shell_path(&pattern);
        // `..` after a wildcard walks out of whatever directory matched; an unknown cwd anchors nothing.
        if path_has_parent_dir(Path::new(&normalize_shell_path_raw(token)))
            || (cwd_unpinned && !is_absolute)
        {
            return Some(GateDecision::AskFailClosed);
        }
        let mut spellings = vec![pattern.clone()];
        if !is_absolute {
            spellings.push(normalize_shell_path(
                &base.lexical.join(&pattern).to_string_lossy(),
            ));
            if let Some(physical) = base.resolved_physical() {
                spellings.push(normalize_shell_path(
                    &physical.join(&pattern).to_string_lossy(),
                ));
            }
        }
        let probe = shell_access(mode, String::new());
        if spellings
            .iter()
            .any(|spelling| self.restricted_pattern_may_match(&probe, spelling))
        {
            return Some(GateDecision::AskFailClosed);
        }
        // What the pattern matches now: each match is a literal operand (symlinks followed, rules matched).
        const MAX_GLOB_MATCHES: usize = 256;
        let anchored = if let Some(rest) = pattern.strip_prefix("~/") {
            let Some(home) = fuigo_dirs::home_dir() else {
                return Some(GateDecision::AskFailClosed);
            };
            home.join(rest).to_string_lossy().into_owned()
        } else if pattern.starts_with('~') {
            return Some(GateDecision::AskFailClosed);
        } else if is_absolute {
            pattern.clone()
        } else {
            base.lexical.join(&pattern).to_string_lossy().into_owned()
        };
        let Ok(paths) = glob::glob_with(
            &anchored,
            fuigo_tools::util::path_match::path_glob_options(),
        ) else {
            return Some(GateDecision::AskFailClosed);
        };
        let mut decision = None;
        for (count, entry) in paths.enumerate() {
            let Ok(path) = entry else {
                return Some(GateDecision::AskFailClosed);
            };
            if count >= MAX_GLOB_MATCHES {
                return Some(GateDecision::AskFailClosed);
            }
            decision = combine_gate_decisions(
                decision,
                self.evaluate_shell_path(&path.to_string_lossy(), base, mode, false),
            );
        }
        decision
    }

    pub(super) fn evaluate_shell_path(
        &self,
        token: &str,
        base: &RuleBase<'_>,
        mode: ShellFileMode,
        cwd_unpinned: bool,
    ) -> Option<GateDecision> {
        let cwd = base.lexical;
        let path = normalize_shell_path(token);
        let raw = normalize_shell_path_raw(token);
        let is_absolute = is_absolute_shell_path(&path);
        // Cwd-aware rule match mirrors the direct Read/Edit tool gate
        // A rooted rule like `Read(src/**)` also keys on the same file spelled absolutely
        // An unpinned cwd anchors nothing: relative operands then keep text-only matching (absolute operands are cwd-independent)
        let rule_base = (is_absolute || !cwd_unpinned).then_some(base);
        // As for a native `..` path, the collapsed text gets physical-cwd forms only from the resolved re-check
        let has_parent_dir = path_has_parent_dir(Path::new(&raw));
        let lexical_base = has_parent_dir.then(|| base.without_physical());
        let path_rule_base = rule_base.map(|base| lexical_base.as_ref().unwrap_or(base));
        // Escalate only: drop Allow so a file allow-rule can't auto-approve here.
        let escalate = |access: &AccessKind, rule_base: Option<&RuleBase<'_>>| match self
            .evaluate_rules_with_base(access, rule_base)
        {
            Some(Decision::Reject(reason)) => Some(GateDecision::Reject(reason)),
            Some(Decision::Ask) => Some(GateDecision::AskRuleMatch),
            _ => None,
        };
        // Also re-check the resolved symlink target so a deny keyed on the real path can't be dodged via an in-workspace symlink (`ln -s /etc x`)
        // Resolve the *uncollapsed* operand so a `..` after a link is applied physically, not erased textually before the link is followed
        let raw_absolute = if is_absolute_shell_path(&raw) {
            Some(raw)
        } else if cwd_unpinned {
            None
        } else {
            Some(normalize_shell_path_raw(&cwd.join(&raw).to_string_lossy()))
        };
        let resolved_decision = raw_absolute.and_then(|raw_absolute| {
            let absolute = if is_absolute {
                path.clone()
            } else {
                normalize_shell_path(&cwd.join(&path).to_string_lossy())
            };
            match follow_absolute_symlink(&raw_absolute, &absolute) {
                SymlinkFollow::Target(resolved) => {
                    escalate(&shell_access(mode, resolved), rule_base)
                }
                SymlinkFollow::None if has_parent_dir => {
                    escalate(&shell_access(mode, absolute), rule_base)
                }
                SymlinkFollow::Unresolvable => Some(GateDecision::AskFailClosed),
                SymlinkFollow::None => None,
            }
        });
        let path_decision = escalate(&shell_access(mode, path.clone()), path_rule_base);
        // WHY: unknown cwd permits text matches only, never original-cwd resolution.
        let anchored_decision = if cwd_unpinned && !is_absolute {
            None
        } else {
            let absolute = if is_absolute {
                path.clone()
            } else {
                normalize_shell_path(&cwd.join(&path).to_string_lossy())
            };
            combine_gate_decisions(
                escalate(&shell_access(mode, absolute), path_rule_base),
                resolved_decision,
            )
        };
        let decision = combine_gate_decisions(path_decision, anchored_decision);
        combine_gate_decisions(
            decision,
            (cwd_unpinned && !is_absolute).then_some(GateDecision::AskFailClosed),
        )
    }
}
