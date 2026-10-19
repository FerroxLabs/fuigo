<!--
Fuigo is developed internally by Ferrox Labs. External pull requests are not accepted (see CONTRIBUTING.md);
an unsolicited PR will be closed with a pointer to the issue tracker. If you are a maintainer, fill in the
sections below. Security fixes follow SECURITY.md and are not discussed in a public PR.
-->

## What changes

<!-- One paragraph: the user-visible behaviour before and after. Link the issue if there is one. -->

## Surfaces affected

- [ ] Terminal UI
- [ ] Headless CLI (`-p`)
- [ ] ACP agent (`fuigo agent`)
- [ ] npm launcher / install
- [ ] Documentation only

## Verification

<!-- Commands run and their result. Name the crates tested, e.g. `cargo test --locked -p fuigo-memory --lib`. -->

## Documentation and release notes

- [ ] User guide pages under `crates/codegen/fuigo-pager/docs/user-guide/` updated, or no user-visible change
- [ ] `docs/release-notes-<version>.md` has an entry, or the change is not user-visible
- [ ] Known limits of the change are written down in the same entry

## Checklist

- [ ] No secrets, tokens or private paths in the diff
- [ ] Dependencies changed in the per-crate manifest, not the generated root `Cargo.toml`
- [ ] Third-party code or assets added carry their licence and a NOTICE entry
