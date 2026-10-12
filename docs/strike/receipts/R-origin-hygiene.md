# R-origin-hygiene

Packet: origin-hygiene (1.0.25). Base 4c907ab9.

## Changed
1. `PromptOrigin::hook_origin_tag()` (exhaustive match, next to the enum). The `UserPromptSubmit` payload `origin`
   is `None` only for `User`; every other origin has a tag. Tags (12): `task_completed`, `subagent_completed`,
   `parent_agent_message`, `peer_message`, `workflow_completed`, `notification`, `goal_summary`,
   `goal_classifier_nudge`, `scheduled`, `plan_resume`, `subagent_task`, `unverified_scheduled`.
   Doc in `fuigo-hooks/src/event.rs` updated. Which origins run the hook and block enforcement: unchanged.
2. Stored item kind: NOT changed (see report: the new reasons would alter compaction anchoring and several
   consumers of `synthetic_reason.is_none()`).
3. `SessionCommand::Prompt.origin` and `HumanPromptContent.origin` are now `PromptOrigin` (no `Option`, no
   fallback). 7 production/test constructors updated; 3 test assertions adjusted. No other crate touched.
4. `prompt_queue.rs` interjection authority match: `User` alone maps to `InterjectionAuthority::User`; the runtime
   origins map to the non-human (parent-agent) authority; no wildcard.

## Tests
- `session::tests::hook_origin_tag_is_none_only_for_a_typed_prompt`
- `prompt_gate_tests::hook_payload_tags_a_runtime_origin`
- `prompt_gate_tests::hook_payload_has_no_origin_for_a_typed_prompt`
- Item 3 is enforced by the compiler.
