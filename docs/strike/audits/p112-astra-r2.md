# P112 Astra round 2 report (gpt-6-astra, read-only, coordinator run on 2f985608)

Raw transcript sha256: e48a0ab882f30458a7cdcc82045c550906e1033875f2fed5de9b5bc00b5a91d2

**FIXED — the R1 registry-selection HIGH is closed for the reviewed release job at `2f985608`.**

- **All release-fetch npm calls are wrapped.** Both `view` and `pack` use `public_npm` at [registry-release-inputs.sh:77](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/scripts/release/registry-release-inputs.sh:77). The wrapper isolates project/user/global configuration and pins both default and `@fuigo` registries. `env -i` removes inherited npm configuration, `NODE_OPTIONS`, proxy variables, and Node TLS overrides.
- **Built-in configuration and executable trust remain boundaries.** At [registry-release-inputs.sh:66](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/scripts/release/registry-release-inputs.sh:66), PATH is retained and npm’s built-in npmrc remains readable. CLI registry pins override its registry entries, but malicious built-in proxy/TLS settings—or a substituted npm executable—could still defeat provenance. The actual caller uses hosted Ubuntu and [setup-node](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/.github/workflows/release.yml:666); no checkout-controlled route to those toolchain changes was found. These are not confirmed new defects.
- **`NODE_OPTIONS` isolation is limited to npm.** Subsequent [Node invocations](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/scripts/release/registry-release-inputs.sh:81) inherit the original environment. Arbitrary Node preload injection therefore remains outside this wrapper’s protection; no such injection path is established in the calling job.
- **No trap collision.** The [EXIT trap](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/scripts/release/registry-release-inputs.sh:64) is the script’s only trap. The workflow [executes the script](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/.github/workflows/release.yml:686), rather than sourcing it, preserving the parent shell’s traps.

**Existing limitation:** R1’s additional request to bind release downloads to native-verification digests remains unimplemented. The verifier’s [npm download](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/crates/codegen/fuigo-pager/npm/fuigo/scripts/verify-published-platform.js:19) remains unisolated, and its [digests are only logged](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/crates/codegen/fuigo-pager/npm/fuigo/scripts/verify-published-platform.js:43). Cross-job byte equality is therefore not independently enforced. This previously identified limitation does not reopen the corrected release-registry selection path.

No NEW defects confirmed. Static review only; no builds, tests, network commands, or file modifications.

LAND-OK
