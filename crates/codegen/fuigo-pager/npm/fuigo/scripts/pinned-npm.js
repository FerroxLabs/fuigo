'use strict';
// Run npm against the PUBLIC npm registry and nothing else.
//
// This is the Node twin of `public_npm` in scripts/release/registry-release-inputs.sh, which lays
// out the GitHub Release from the registry tarballs. verify-published-platform.js must download
// through the same isolation, otherwise it could execute and attest bytes from a different
// registry than the ones the release ships (Astra P112 r2). scripts/test-pinned-npm.js asserts
// the two stay equal.
//
// Isolation: npm runs from an empty directory with an EMPTY environment (PATH, a HOME pointing at
// that directory, and on Windows only the system variables listed in WIN32_SYSTEM_VARS, with
// APPDATA, LOCALAPPDATA and USERPROFILE also pointed at that directory), the global and user npmrc
// pointed at files that do not exist, no project .npmrc in reach, and both the default registry
// and the @fuigo scope pinned on the command line. Nothing in the caller's environment
// (npm_config_*, NODE_AUTH_TOKEN, proxies, registry overrides) reaches npm.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {execFileSync} = require('child_process');

const REGISTRY = 'https://registry.npmjs.org/';

// npm is a .cmd shim on Windows, not an executable for execFileSync.
// setup-node installs npm's JS entry beside node.exe; invoke it without a shell.
const npmCommand = process.platform === 'win32' ? process.execPath : 'npm';
const npmPrefix = process.platform === 'win32'
    ? [path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')] : [];

/** Pinned command-line flags; the same two the shell script passes. */
const pinnedFlags = () => [`--registry=${REGISTRY}`, `--@fuigo:registry=${REGISTRY}`];

/**
 * A fresh isolation home: an empty directory that is both npm's cwd and its HOME.
 * Returns {home, cleanup}.
 */
function makeHome() {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-public-npm-'));
    return {home, cleanup: () => fs.rmSync(home, {recursive: true, force: true, maxRetries: 5, retryDelay: 200})};
}

// The ONLY variables copied from the caller, and only on win32. Everything else is dropped.
//  - SystemRoot (often spelled SYSTEMROOT) / windir: the Windows directory. Node (winsock,
//    crypto, DNS) and cmd.exe fail to start or resolve hosts without it (Microsoft
//    "Environment variables" docs).
//  - ComSpec: the command interpreter, used when npm runs a lifecycle script or `.cmd` shim.
//  - PATHEXT: which extensions count as executable when a bare command name is resolved.
//  - TEMP / TMP: the system temp directory; os.tmpdir() reads them (node `os.tmpdir` docs).
// They name system locations, not npm configuration, so none of them can choose a registry.
const WIN32_SYSTEM_VARS = ['SystemRoot', 'windir', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP'];
// User-profile variables npm and libuv consult for npmrc, cache and the home directory
// (libuv uv_os_homedir reads USERPROFILE on Windows; npm's cache lives under LOCALAPPDATA, its
// global prefix under APPDATA). They are NEVER copied: on win32 they all point into the private
// home, so every user-level lookup lands in an empty directory.
const WIN32_PROFILE_VARS = ['APPDATA', 'LOCALAPPDATA', 'USERPROFILE'];
const NPM_CONFIG_KEY = /^npm_config_/i;

/**
 * The complete environment npm gets. `extraEnv` is for lifecycle scripts (e.g. FUIGO_HOME) and
 * may not carry npm configuration. `platform` and `source` default to the real process and exist
 * so the builder can be unit-tested for both platforms.
 */
function pinnedEnv(home, extraEnv = {}, platform = process.platform, source = process.env) {
    for (const k of Object.keys(extraEnv)) {
        if (NPM_CONFIG_KEY.test(k)) throw new Error(`extraEnv may not set ${k}: npm configuration is pinned`);
    }
    const env = {
        PATH: source.PATH || source.Path || '',
        HOME: home,
        NPM_CONFIG_GLOBALCONFIG: path.join(home, 'no-global-npmrc'),
        NPM_CONFIG_USERCONFIG: path.join(home, 'no-user-npmrc'),
    };
    if (platform === 'win32') {
        // Windows names are case-insensitive; find the caller's spelling.
        const byLower = new Map(Object.keys(source).map(k => [k.toLowerCase(), k]));
        for (const k of WIN32_SYSTEM_VARS) {
            const real = byLower.get(k.toLowerCase());
            if (real !== undefined && source[real] !== undefined) env[k] = source[real];
        }
        for (const k of WIN32_PROFILE_VARS) env[k] = home;
    }
    return {...env, ...extraEnv};
}

/**
 * Run `npm <args>` with the pinned registry and an empty environment.
 * `cwd` defaults to `home`; `extraEnv` is added on top of the isolated environment.
 */
function publicNpm(home, args, {cwd = home, extraEnv = {}, ...options} = {}) {
    return execFileSync(npmCommand, [...npmPrefix, ...pinnedFlags(), ...args],
        {...options, cwd, env: pinnedEnv(home, extraEnv)});
}

const sha512Integrity = bytes => 'sha512-' + crypto.createHash('sha512').update(bytes).digest('base64');

/**
 * Download `spec` (e.g. `@fuigo/linux-x64@1.0.20`) through the public npm into `dest` and
 * check the tarball against the registry's separately read `dist.integrity`.
 * Returns {filename, path, integrity, bytes}.
 */
function fetchFromPublicRegistry(home, spec, dest) {
    const integrity = publicNpm(home, ['view', spec, 'dist.integrity'], {encoding: 'utf8'}).trim();
    if (!integrity) throw new Error(`${spec} has no dist.integrity on the registry`);
    const [packed] = JSON.parse(publicNpm(home, ['pack', spec, '--ignore-scripts', '--json',
        '--pack-destination', dest], {encoding: 'utf8'}));
    const file = path.join(dest, packed.filename);
    const bytes = fs.readFileSync(file);
    const got = sha512Integrity(bytes);
    if (got !== integrity) throw new Error(`${packed.filename} is ${got}, the registry says ${integrity}`);
    return {filename: packed.filename, path: file, integrity: got, bytes};
}

module.exports = {REGISTRY, WIN32_SYSTEM_VARS, WIN32_PROFILE_VARS, pinnedFlags, pinnedEnv, makeHome, publicNpm, sha512Integrity, fetchFromPublicRegistry};
