#!/usr/bin/env node
// Resolves the fuigo binary and runs it, in order of preference:
//   1. $FUIGO_HOME/bin/fuigo, when its stamp says it was installed from this
//      exact package payload
//   2. install it (fuigo-install.js, loaded only then) from the per-platform
//      @fuigo/<platform> package: decompress into $FUIGO_HOME/bin, link, write
//      config. This replaces an npm postinstall script, which npm 11 warns about.
//   3. decompress in place under node_modules (no resolvable version, an
//      unwritable home, or a package that is not a global install)
//
// Only a GLOBAL install (npm's prefix, or a pnpm/yarn/bun global store) manages
// $FUIGO_HOME/bin and config.toml. A project-local or npx copy runs its own packaged
// binary and touches nothing under $FUIGO_HOME, so two installs of different versions
// never take turns re-swapping the user's binary. A launch also never moves
// $FUIGO_HOME/bin to an OLDER version than it already points at.
//
// FUIGO_INSTALL_ONLY=1 is the setup step Fuigo's own updater runs after `npm i -g`
// (npm no longer runs an install script): do the install above synchronously, do not
// exec the binary, and exit non-zero unless $FUIGO_HOME/bin/fuigo now points at this
// package's version. It installs even when that is a downgrade (an explicit request).
//
// Binaries ship brotli-compressed to stay under npm's tarball size limit.
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { installStamp, STAMP_NAME, globalInstallKind, compareVersions, canonicalVersion } = require('./fuigo-replace.js');

const pkgName = 'fuigo';
const IS_WINDOWS = process.platform === 'win32';
const EXE = IS_WINDOWS ? '.exe' : '';
const BIN_NAME = `fuigo${EXE}`;
// $FUIGO_HOME/bin (else ~/.fuigo/bin), matching the Rust fuigo_home():
// a symlinked $HOME resolves the same way.
function defaultFuigoHome() {
    const home = os.homedir();
    try { return path.join(fs.realpathSync(home), '.fuigo'); } catch { return path.join(home, '.fuigo'); }
}
const INSTALL_ONLY = process.env.FUIGO_INSTALL_ONLY === '1';
const FUIGO_HOME = process.env.FUIGO_HOME ?? defaultFuigoHome();
const CANONICAL_DIR = path.join(FUIGO_HOME, 'bin');
const CANONICAL_PATH = path.join(CANONICAL_DIR, BIN_NAME);

function readLocalVersion() {
    try { return require('../package.json').version; } catch { return undefined; }
}

// The platform packages are scoped under the `fuigo` npm org: @fuigo/<platform>-<arch>.
// The meta package stays unscoped -- it is the name users install, and this is
// the same split @next, @anthropic-ai and @vscode use for native sidecars.
//
// Scoping is not cosmetic. npm's spam filter refuses to CREATE an unscoped
// package name containing the token `win32-arm64` (403 "Package name triggered
// spam detection"), which is why fuigo-win32-arm64 never existed at any version
// and Windows ARM shipped without a binary until 1.0.3. Measured: the refused
// name fails even when published ALONE ten minutes after a successful sibling,
// while the same binary under a different name publishes fine. A scope removes
// that entire class of failure for every platform, not just the one that hit it.
//
// The DIRECTORY is still fuigo-<platform>-<arch>; only the npm name is scoped.
const platformPackageName = (k) => `@fuigo/${k}`;

// Returns null when npm skipped the matching optional dependency
// (unsupported platform, or --no-optional).
function resolvePlatformPackageDir() {
    const platformPkg = platformPackageName(`${process.platform}-${process.arch}`);
    try {
        return path.dirname(require.resolve(`${platformPkg}/package.json`));
    } catch {
        return null;
    }
}

// The cheap check made on every node launch: the canonical binary exists and
// the stamp says it was installed from exactly this package's vendored payload
// (version, package location, payload size and mtime). A reinstall of the same
// version with a changed binary changes the payload stat, so it is picked up.
function isCurrent(stamp) {
    try {
        return fs.existsSync(CANONICAL_PATH)
            && fs.readFileSync(path.join(CANONICAL_DIR, STAMP_NAME), 'utf8') === stamp;
    } catch {
        return false;
    }
}

function failSetup(why) {
    console.error(`${pkgName}: setup failed: ${why}`);
    process.exit(2);
}

function resolveBinary() {
    const platformDir = resolvePlatformPackageDir();
    if (!platformDir) {
        // No payload to install from: an existing binary is still better than nothing.
        if (INSTALL_ONLY) failSetup(`no platform package for ${process.platform}-${process.arch}`);
        if (fs.existsSync(CANONICAL_PATH)) return CANONICAL_PATH;
        console.error(`${pkgName}: no platform binary installed for ${process.platform}-${process.arch}.`);
        console.error(`  Expected sibling package ${platformPackageName(`${process.platform}-${process.arch}`)}.`);
        console.error(`  This usually means npm skipped optionalDependencies (e.g. --no-optional)`);
        console.error(`  or the platform is not supported.`);
        process.exit(1);
    }

    const binaryPath = path.join(platformDir, 'bin', BIN_NAME);
    const brotliPath = binaryPath + '.br';
    const version = readLocalVersion();

    const managed = INSTALL_ONLY || globalInstallKind(__dirname) !== null;
    if (INSTALL_ONLY && !version) failSetup('the package has no readable version');
    if (version && managed) {
        const stamp = installStamp(version, __dirname, brotliPath, binaryPath);
        if (isCurrent(stamp)) return CANONICAL_PATH;
        const linked = canonicalVersion(CANONICAL_PATH);
        const wouldDowngrade = !INSTALL_ONLY && linked !== null && compareVersions(linked, version) > 0;
        if (wouldDowngrade) {
            // A launch never moves ~/.fuigo/bin backwards: run this package's own binary in place.
            if (process.env.FUIGO_BOOTSTRAP_DEBUG) {
                console.error(`fuigo-bootstrap: ${CANONICAL_PATH} is at ${linked}, newer than ${version}; not downgrading`);
            }
        } else {
            // First run after an install or upgrade: do what a postinstall script used to.
            const installed = require('./fuigo-install.js').installCanonical({
                fuigoHome: FUIGO_HOME, version, brotliPath, binaryPath, stamp,
                pkgBinDir: __dirname, argv1: process.argv[1], installOnly: INSTALL_ONLY,
            });
            if (installed) return installed;
            if (INSTALL_ONLY) failSetup('the install did not complete');
        }
    } else if (!version && fs.existsSync(CANONICAL_PATH)) {
        return CANONICAL_PATH;
    }

    if (!fs.existsSync(binaryPath)
        && !require('./fuigo-install.js').writeVendorBinary(brotliPath, binaryPath, binaryPath)) {
        if (fs.existsSync(CANONICAL_PATH)) return CANONICAL_PATH;
        console.error(`${pkgName}: missing binary at ${binaryPath}`);
        process.exit(1);
    }
    return binaryPath;
}

const execPath = resolveBinary();
if (INSTALL_ONLY) process.exit(0); // setup only: resolveBinary exits non-zero on failure
const childEnv = { ...process.env, FUIGO_MANAGED_BY_NPM: '1' };
const child = spawn(execPath, process.argv.slice(2), { stdio: 'inherit', env: childEnv });
child.on('exit', (code, signal) => {
    if (signal) {
        process.kill(process.pid, signal);
    } else {
        process.exit(code ?? 0);
    }
});
