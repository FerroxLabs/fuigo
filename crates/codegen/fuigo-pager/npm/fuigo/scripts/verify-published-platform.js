#!/usr/bin/env node
// Download one published platform package from the PUBLIC npm registry, run its binary natively,
// and record its digests.
//
//   node verify-published-platform.js <platform> [--digest-out <file>]
//
// Every npm call goes through pinned-npm.js: the same isolation as `public_npm` in
// scripts/release/registry-release-inputs.sh (empty environment, no npmrc, both registries
// pinned), so the bytes executed here are the bytes the GitHub Release is laid out from.
// `--digest-out` writes the digests as JSON; the github-release job uploads them and
// scripts/release/verify-release-digests.js compares them with the release assets.
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const assert = require('assert/strict');
const {execFileSync} = require('child_process');
const {makeHome, publicNpm, fetchFromPublicRegistry} = require('./pinned-npm');
const {repositoryProblems} = require('./release-metadata');
const args = process.argv.slice(2);
const platform = args[0];
assert(['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'].includes(platform));
const digestFlag = args.indexOf('--digest-out');
const digestOut = digestFlag === -1 ? null : args[digestFlag + 1];
assert(digestFlag === -1 || digestOut, '--digest-out needs a file');
const version = require('../package.json').version;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-published-check-'));
const npmHome = makeHome();
try {
    const packed = fetchFromPublicRegistry(npmHome.home, `@fuigo/${platform}@${version}`, dir);
    execFileSync('tar', ['-xzf', packed.filename], {cwd: dir});
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package/package.json')));
    const [targetOs, arch] = platform.split('-');
    assert.equal(manifest.name, `@fuigo/${platform}`);
    assert.equal(manifest.version, version);
    const problems = repositoryProblems(manifest, `fuigo-${platform}`, process.env.GITHUB_REPOSITORY);
    assert.deepEqual(problems, [], problems.join('\n'));
    assert.deepEqual(manifest.os, [targetOs]);
    assert.deepEqual(manifest.cpu, [arch]);
    const name = targetOs === 'win32' ? 'fuigo.exe' : 'fuigo';
    const raw = zlib.brotliDecompressSync(fs.readFileSync(path.join(dir, 'package/bin', `${name}.br`)),
        {maxOutputLength: 512 * 1024 * 1024});
    const binary = path.join(dir, name);
    fs.writeFileSync(binary, raw, {mode: 0o755});
    const description = execFileSync('file', ['-b', binary], {encoding: 'utf8'}).trim();
    assert.match(description, arch === 'arm64' ? /arm64|aarch64/i : /x86[-_]64/i);
    const result = execFileSync(binary, ['--version'], {timeout: 60000, encoding: 'utf8',
        env: {...process.env, HOME: dir, USERPROFILE: dir, FUIGO_HOME: path.join(dir, 'home')}}).trim();
    assert(result.includes(` ${version} `), `Unexpected version: ${result}`);
    const expectedCommit = process.env.FUIGO_EXPECTED_RELEASE_COMMIT || process.env.GITHUB_SHA;
    if (expectedCommit) assert(result.includes(expectedCommit.slice(0, 12)), `Wrong source stamp: ${result}`);
    // The github-release job lays out the raw binary from this same registry
    // tarball; logging its sha256 lets the release be matched to this run.
    const sha256 = crypto.createHash('sha256').update(raw).digest('hex');
    console.log(JSON.stringify({name: manifest.name, version, description, result, integrity: packed.integrity,
        sha256}));
    if (digestOut) {
        fs.writeFileSync(digestOut, JSON.stringify({platform, name: manifest.name, version,
            integrity: packed.integrity, sha256}, null, 2) + '\n');
    }
    if (platform === 'linux-x64' || platform === 'darwin-arm64') {
        const prefix = path.join(dir, 'installed');
        const env = {...process.env, HOME: dir, FUIGO_HOME: path.join(dir, 'installed-home')};
        // npm itself stays pinned; only its lifecycle scripts see the scratch HOME/FUIGO_HOME.
        const install = v => publicNpm(npmHome.home, ['install', '--prefix', prefix,
            '--no-audit', '--no-fund', `fuigo@${v}`],
        {extraEnv: {HOME: dir, FUIGO_HOME: env.FUIGO_HOME}, stdio: 'inherit'});
        const entry = path.join(prefix, 'node_modules/.bin/fuigo');
        if (platform === 'linux-x64') {
            install('1.0.5');
            assert(execFileSync(entry, ['--version'], {env, encoding: 'utf8', timeout: 60000}).includes(' 1.0.5 '));
        }
        install(version);
        const installed = execFileSync(entry, ['--version'], {env, encoding: 'utf8', timeout: 60000}).trim();
        assert(installed.includes(` ${version} `), installed);
        console.log(JSON.stringify({metaPackageInstall: 'PASS', platform, installed,
            upgradeFrom: platform === 'linux-x64' ? '1.0.5' : null}));
    }
} finally {
    npmHome.cleanup();
    fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5, retryDelay: 200});
}
