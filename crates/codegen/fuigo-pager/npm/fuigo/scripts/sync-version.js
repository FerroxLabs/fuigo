#!/usr/bin/env node
// Stamp every npm package version from the Rust source of truth.
//
// The product version lives in ONE place: crates/codegen/fuigo-version's
// `version` field, which becomes `fuigo_version::VERSION` through
// CARGO_PKG_VERSION and is what `fuigo --version` prints. Everything else --
// the npm meta package, its six optionalDependency pins, and the six
// per-platform packages -- is derived from it here.
//
// WHY THIS EXISTS
// The meta package version was hand-maintained and had drifted to
// `0.1.220-alpha.4` (copied from an unrelated internal crate) while the binary
// reported `1.0.1`. npm publishes the meta package's number, so users would
// have installed "0.1.220-alpha.4" and been greeted by a binary calling itself
// 1.0.1 -- and an alpha-looking version for a release build.
//
// A number that has to be kept in sync by hand eventually will not be, so the
// fix is to stop maintaining it: derive it, and have `assemble-platform-
// packages.js` refuse to build if the derived value ever disagrees.
//
//   node scripts/sync-version.js           # stamp
//   node scripts/sync-version.js --check   # verify only, non-zero on drift
//
// `--check` is the CI form: it fails the build rather than quietly publishing
// a mismatched pair.

const fs = require('fs');
const path = require('path');

const NPM_ROOT = path.resolve(__dirname, '..', '..');
const META_PKG = path.join(NPM_ROOT, 'fuigo', 'package.json');
const VERSION_CRATE = path.resolve(
    NPM_ROOT, '..', '..', 'fuigo-version', 'Cargo.toml');

const PLATFORMS = [
    'darwin-arm64', 'darwin-x64',
    'linux-arm64', 'linux-x64',
    'win32-arm64', 'win32-x64',
];

// Platform packages publish scoped: @fuigo/<platform>-<arch>. The meta package
// stays unscoped. See bin/postinstall.js for why the scope is load-bearing.
// The DIRECTORY stays fuigo-<platform>-<arch>; only the npm name is scoped.
const packageNameFor = (p) => `@fuigo/${p}`;

// Unscoped. `fuigo` and the six `fuigo-<platform>` names are ours on npm;
// the `@fuigo-official` scope this once used is not an org that exists.
const PREFIX = 'fuigo';

/**
 * The product version, read from fuigo-version's Cargo.toml.
 *
 * Deliberately a narrow regex over the [package] section rather than a TOML
 * parse: this script must run with no dependencies, before `npm install` has
 * necessarily happened. The crate is tiny and its shape is stable.
 */
function rustVersion() {
    const toml = fs.readFileSync(VERSION_CRATE, 'utf8');
    const pkg = toml.split(/^\[/m)[1]; // the [package] section
    const m = /^version\s*=\s*"([^"]+)"/m.exec(pkg || '');
    if (!m) {
        throw new Error(`could not read version from ${VERSION_CRATE}`);
    }
    return m[1];
}

/** Refuse anything that is not a plain release version. */
function assertReleaseVersion(v) {
    if (!/^\d+\.\d+\.\d+$/.test(v)) {
        throw new Error(
            `version "${v}" is not a plain release version (x.y.z).\n` +
            `Publishing a prerelease is a deliberate act: set it in\n` +
            `crates/codegen/fuigo-version/Cargo.toml and pass --allow-prerelease.`,
        );
    }
}

function readJson(p) {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function writeJson(p, obj) {
    fs.writeFileSync(p, JSON.stringify(obj, null, 4) + '\n');
}

function main() {
    const check = process.argv.includes('--check');
    const allowPrerelease = process.argv.includes('--allow-prerelease');

    const version = rustVersion();
    if (!allowPrerelease) assertReleaseVersion(version);

    const drift = [];
    const note = (what, from, to) => {
        if (from !== to) drift.push(`${what}: ${from} -> ${to}`);
    };

    // Meta package: its own version, plus the six pins. npm resolves an
    // optionalDependency by exact version, so a stale pin means the platform
    // package is silently skipped and postinstall reports "unsupported
    // platform" on a platform that is in fact supported.
    const meta = readJson(META_PKG);
    note('meta version', meta.version, version);
    meta.version = version;

    // Rebuilt from scratch, not merged: a renamed package must not leave its
    // old pin behind, or npm resolves a name that will never exist again.
    const priorPins = meta.optionalDependencies || {};
    meta.optionalDependencies = {};
    for (const p of PLATFORMS) {
        const name = packageNameFor(p);
        note(`  pin ${name}`, priorPins[name], version);
        meta.optionalDependencies[name] = version;
    }
    if (!check) writeJson(META_PKG, meta);

    // Per-platform packages. `assemble-platform-packages.js` also stamps
    // these, but only for targets whose binary is present -- so a partial
    // build would leave the others stale in git.
    for (const p of PLATFORMS) {
        const pkgPath = path.join(NPM_ROOT, `fuigo-${p}`, 'package.json');
        if (!fs.existsSync(pkgPath)) {
            console.error(`[sync-version] missing package: ${pkgPath}`);
            process.exit(1);
        }
        const pkg = readJson(pkgPath);
        note(`  fuigo-${p}`, pkg.version, version);
        pkg.version = version;
        if (!check) writeJson(pkgPath, pkg);
    }

    if (check) {
        if (drift.length) {
            console.error(`[sync-version] DRIFT from Rust version ${version}:`);
            for (const d of drift) console.error(`  ${d}`);
            console.error('\nRun: node scripts/sync-version.js');
            process.exit(1);
        }
        console.log(`[sync-version] ok — everything at ${version}`);
        return;
    }

    if (drift.length) {
        console.log(`[sync-version] stamped ${version}:`);
        for (const d of drift) console.log(`  ${d}`);
    } else {
        console.log(`[sync-version] already at ${version}; nothing to do`);
    }
}

try {
    main();
} catch (e) {
    console.error(`[sync-version] ${e.message}`);
    process.exit(1);
}
