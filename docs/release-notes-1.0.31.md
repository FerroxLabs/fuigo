# Fuigo 1.0.31 release notes

This release follows 1.0.30. It fixes problems with switching model providers in the middle of a session, with `/remember`, with session rules after a model switch and with MCP tool progress, adds tests for untrusted folders, corrects the user guide on subfolder rules, and renews the README, brand and community files.

## Fixes

- Switching with `/model` from one provider to another in the middle of a session no longer sends the earlier model's reasoning back in a form the new provider rejects. Before, a session that had used an Anthropic model could fail on the next OpenAI turn with `400 Invalid 'input[k].id': ''`, because a reasoning item with an empty id was replayed. Fuigo now leaves out reasoning items that came from the other provider, and no longer sends an empty id.
- `/remember` now tells you the file it actually wrote, which is the memory file for the current project. Before, it always printed the global memory path, even when the note went somewhere else. When the note cannot be saved, for example because the folder is under a temporary directory where project memory is not kept, it says `Memory note NOT saved` and gives the reason, instead of reporting success. A note that is empty after cleanup, or a reply that does not confirm the save, is reported the same way.
- Rules passed when a session is created (`_meta.rules`) and a system-prompt override now survive a model switch and a reload. Before, they were dropped when the model changed. The override is saved with the session, so it also survives closing Fuigo and loading the session again, and switching models repeatedly never duplicates the rules block, even when a custom agent template has its own `<human_rules>` section. (#19)
- Progress from MCP tools now reaches the client as a `tool_call_update` with `_meta.progress`. Progress always arrives after the tool call it belongs to, progress sent before the call is fully registered or just before it finishes is no longer lost, and two calls that happen to use the same progress token across an MCP server reconnect no longer receive each other's updates. (#20)
- End-to-end tests now confirm that untrusted folders do not load project instructions on the headless and stdio paths, and the nested discovery root is now trust-gated; new tests check this through the real session builder and with a nested `AGENTS.md`. (#18)

## Documentation

- The user guide page on project rules (`12-project-rules.md`) said that AGENTS.md files in subfolders below the working directory apply when Fuigo works there. They do not. Fuigo loads rules only from the repo root down to the directory you start it in. The page now says so, and says that to get a subfolder's rules you start Fuigo in that subfolder.

## README, brand and community files

- The README is rewritten: install steps come first, then why Fuigo, the three ways to work, features, model routes, memory and a documentation index. It uses real screenshots and a demo recording from Fuigo 1.0.30. The provider recipes that used to be in the README are now in `docs/connect-a-model.md`.
- The Fuigo mark is now the Wind icon (a fuigo is a forge bellows), with light and dark banners and a social preview image. The brand notes are in `docs/brand/BRAND.md`. The old galaxy images are removed.
- `SECURITY.md` now sends vulnerability reports to Ferrox Labs by email. Before, it pointed to a programme inherited from another project.
- New files: `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue templates for bugs and feature requests, and a pull request template.

## Other

- Lint cleanup: the whole workspace now passes `cargo clippy --workspace --all-targets -D warnings`, and the release gate checks every crate. The fixes change no behaviour.
- The version is 1.0.31 in the Rust crate and in all seven npm packages.
