#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');
const {execFileSync} = require('child_process');
const {packageNotices} = require('./package-notices');
const npmRoot = path.resolve(__dirname, '../..');
const output = path.resolve(process.argv[2] || path.join(npmRoot, 'release-packages'));
fs.mkdirSync(output, {recursive: true});
packageNotices(true);
const platforms = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'];
const notices = ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES', 'THIRD_PARTY_NOTICES.md',
    'vendor-notices/NOTICE', 'vendor-notices/ordered_hashmap/LICENCE',
    'vendor-notices/graphlib_rust/LICENCE', 'vendor-notices/dagre_rust/LICENCE',
    'vendor-notices/mermaid-to-svg/LICENSE', 'vendor-notices/mermaid-to-svg/THIRD_PARTY_NOTICES'];
const version = JSON.parse(fs.readFileSync(path.join(npmRoot, 'fuigo/package.json'))).version;
const manifest = [];
for (const platform of [...platforms, null]) {
    const directory = path.join(npmRoot, platform ? `fuigo-${platform}` : 'fuigo');
    const [packed] = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json',
        '--pack-destination', output], {cwd: directory, encoding: 'utf8'}));
    assert.equal(packed.name, platform ? `@fuigo/${platform}` : 'fuigo');
    assert.equal(packed.version, version);
    const files = new Set(packed.files.map(f => f.path));
    const executable = platform ? `bin/${platform.startsWith('win32') ? 'fuigo.exe' : 'fuigo'}.br` : 'bin/fuigo';
    assert(files.has(executable), `Missing executable in ${packed.name}`);
    assert(packed.files.find(f => f.path === executable).size > 0, 'Empty executable');
    for (const notice of notices) {
        assert(files.has(notice), `${packed.name} omits ${notice}`);
        const actual = execFileSync('tar', ['-xOf', path.join(output, packed.filename), `package/${notice}`]);
        assert(actual.equals(fs.readFileSync(path.join(directory, notice))), `Stale ${notice}`);
    }
    manifest.push({name: packed.name, version, filename: packed.filename,
        integrity: packed.integrity, shasum: packed.shasum, size: packed.size});
}
fs.writeFileSync(path.join(output, 'release-manifest.json'), JSON.stringify({
    sourceCommit: process.env.GITHUB_SHA || null, version, packages: manifest,
}, null, 2) + '\n');
console.log(`Verified ${manifest.length} release archives at ${version}: executable and 70 attribution files.`);
