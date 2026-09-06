#!/usr/bin/env node
// Preserve repository, vendored and tool attribution in every npm package.
const fs = require('fs');
const path = require('path');
const npmRoot = path.resolve(__dirname, '../..');
const repoRoot = path.resolve(npmRoot, '../../../..');
const packages = ['fuigo', ...['darwin-arm64', 'darwin-x64', 'linux-arm64',
    'linux-x64', 'win32-arm64', 'win32-x64'].map(p => `fuigo-${p}`)];
const notices = ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES'].map(name => [name, name]);
notices.push(['crates/codegen/fuigo-tools/THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_NOTICES.md']);
for (const name of ['NOTICE', 'ordered_hashmap/LICENCE', 'graphlib_rust/LICENCE',
    'dagre_rust/LICENCE', 'mermaid-to-svg/LICENSE', 'mermaid-to-svg/THIRD_PARTY_NOTICES']) {
    notices.push([`third_party/${name}`, `vendor-notices/${name}`]);
}

function packageNotices(check = false) {
    // Read every required source before writing anything; missing attribution is fatal.
    const sources = notices.map(([source, destination]) =>
        [destination, fs.readFileSync(path.join(repoRoot, source))]);
    for (const pkg of packages) {
        const pkgDir = path.join(npmRoot, pkg);
        for (const [destination, bytes] of sources) {
            const target = path.join(pkgDir, destination);
            if (check) {
                if (!fs.existsSync(target) || !fs.readFileSync(target).equals(bytes)) {
                    throw new Error(`Missing or stale packaged attribution: ${pkg}/${destination}`);
                }
            } else {
                fs.mkdirSync(path.dirname(target), {recursive: true});
                fs.writeFileSync(target, bytes);
            }
        }
    }
}

module.exports = {packageNotices};
if (require.main === module) {
    packageNotices(process.argv.includes('--check'));
    console.log('Attribution checked for all seven npm packages.');
}
