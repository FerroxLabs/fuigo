#!/usr/bin/env node
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const assert = require('assert/strict');
const {execFileSync} = require('child_process');
const platform = process.argv[2];
assert(['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'].includes(platform));
const version = require('../package.json').version;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-published-check-'));
try {
    const [packed] = JSON.parse(execFileSync('npm', ['pack', `@fuigo/${platform}@${version}`,
        '--ignore-scripts', '--json'], {cwd: dir, encoding: 'utf8'}));
    execFileSync('tar', ['-xzf', packed.filename], {cwd: dir});
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package/package.json')));
    const [targetOs, arch] = platform.split('-');
    assert.equal(manifest.name, `@fuigo/${platform}`);
    assert.equal(manifest.version, version);
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
    if (process.env.GITHUB_SHA) assert(result.includes(process.env.GITHUB_SHA.slice(0, 12)), `Wrong source stamp: ${result}`);
    console.log(JSON.stringify({name: manifest.name, version, description, result, integrity: packed.integrity}));
    if (platform === 'linux-x64' || platform === 'darwin-arm64') {
        const prefix = path.join(dir, 'installed');
        const env = {...process.env, HOME: dir, FUIGO_HOME: path.join(dir, 'installed-home')};
        const install = v => execFileSync('npm', ['install', '--prefix', prefix,
            '--no-audit', '--no-fund', `fuigo@${v}`], {env, stdio: 'inherit'});
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
    fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5, retryDelay: 200});
}
