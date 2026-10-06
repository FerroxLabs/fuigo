#!/usr/bin/env node
// Tests for npm provenance readiness and the pinned post-publish verifier (packet P126).
//
//   node scripts/test-release-provenance.js
//
// Needs only node, tar and npm (for `npm pack` of local directories). Nothing is published and
// the network is never touched: the registry is a fake `npm` shim placed first on PATH, and
// the release workflow is checked as text.

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const {execFileSync, spawnSync} = require('child_process');
const assert = require('assert/strict');

const SCRIPTS = __dirname;
const NPM_ROOT = path.resolve(SCRIPTS, '..', '..');
const REPO_ROOT = path.resolve(NPM_ROOT, '../../../..');
const PLATFORMS = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'];
const posixOnly = process.platform !== 'win32';

let passed = 0, failed = 0, skipped = 0;
function test(name, fn, {skip = false} = {}) {
    if (skip) { console.log(`  - ${name} (skipped)`); skipped++; return; }
    try { fn(); console.log(`  ✓ ${name}`); passed++; }
    catch (e) { console.error(`  ✗ ${name}\n    ${String(e.message).split('\n').join('\n    ')}`); failed++; }
}

const tmpDirs = [];
const tmp = (label = 't') => { const d = fs.mkdtempSync(path.join(os.tmpdir(), `fuigo-p126-${label}-`)); tmpDirs.push(d); return d; };
const write = (file, data, mode) => { fs.mkdirSync(path.dirname(file), {recursive: true}); fs.writeFileSync(file, data, mode ? {mode} : undefined); };
const readJson = f => JSON.parse(fs.readFileSync(f, 'utf8'));
const cleanEnv = extra => {
    const env = {...process.env};
    delete env.GITHUB_REPOSITORY; delete env.GITHUB_SHA; delete env.FUIGO_EXPECTED_RELEASE_COMMIT;
    return {...env, ...extra};
};
const run = (cmd, args, options = {}) => spawnSync(cmd, args, {encoding: 'utf8', ...options, env: cleanEnv(options.env)});
const sha = (algo, bytes, enc = 'hex') => crypto.createHash(algo).update(bytes).digest(enc);

const meta = require('./release-metadata');
const pinned = require('./pinned-npm');
const {verifyDigests, ASSET_PLATFORM} = require(path.join(REPO_ROOT, 'scripts/release/verify-release-digests.js'));
const version = readJson(path.join(NPM_ROOT, 'fuigo/package.json')).version;
const dirOf = p => (p ? `fuigo-${p}` : 'fuigo');

/** A copy of the npm package tree (scripts, bin, package.json files) plus the repo files it reads. */
function makeTree() {
    const root = tmp('tree');
    const npm = path.join(root, 'crates/codegen/fuigo-pager/npm');
    fs.cpSync(NPM_ROOT, npm, {recursive: true, filter: s => !s.includes('node_modules') && !s.endsWith('.tgz')});
    write(path.join(root, 'crates/codegen/fuigo-version/Cargo.toml'), `[package]\nname = "fuigo-version"\nversion = "${version}"\n`);
    for (const f of ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES', 'crates/codegen/fuigo-tools/THIRD_PARTY_NOTICES.md',
        'third_party/NOTICE', 'third_party/ordered_hashmap/LICENCE', 'third_party/graphlib_rust/LICENCE',
        'third_party/dagre_rust/LICENCE', 'third_party/mermaid-to-svg/LICENSE', 'third_party/mermaid-to-svg/THIRD_PARTY_NOTICES']) {
        write(path.join(root, f), `fixture ${f}\n`);
    }
    for (const p of PLATFORMS) {
        write(path.join(npm, `fuigo-${p}`, 'bin', p.startsWith('win32') ? 'fuigo.exe.br' : 'fuigo.br'), 'x');
    }
    execFileSync('node', [path.join(npm, 'fuigo/scripts/package-notices.js')], {cwd: npm});
    return {root, npm, scripts: path.join(npm, 'fuigo/scripts')};
}
const pkgJsonOf = (tree, p) => path.join(tree.npm, dirOf(p), 'package.json');

console.log('repository field on the committed packages');
test('all seven committed package.json files name this repository, with their own directory', () => {
    for (const p of [...PLATFORMS, null]) {
        const m = readJson(path.join(NPM_ROOT, dirOf(p), 'package.json'));
        assert.deepEqual(meta.repositoryProblems(m, dirOf(p)), [], dirOf(p));
        assert.equal(m.repository.url, 'git+https://github.com/FerroxLabs/fuigo.git');
        assert.equal(m.repository.directory, `crates/codegen/fuigo-pager/npm/${dirOf(p)}`);
    }
});
test('repositoryProblems rejects missing, wrong url, wrong directory and a foreign publisher', () => {
    const good = {name: 'x', repository: meta.repositoryFor('fuigo')};
    assert.deepEqual(meta.repositoryProblems(good, 'fuigo'), []);
    assert.deepEqual(meta.repositoryProblems(good, 'fuigo', 'FerroxLabs/fuigo'), []);
    assert.match(meta.repositoryProblems({name: 'x'}, 'fuigo')[0], /no "repository" field/);
    assert.match(meta.repositoryProblems({name: 'x', repository: 'github:FerroxLabs/fuigo'}, 'fuigo')[0], /expected/);
    assert.match(meta.repositoryProblems({name: 'x', repository: {...good.repository, url: 'git+https://github.com/a/b.git'}}, 'fuigo')[0], /expected/);
    assert.match(meta.repositoryProblems({name: 'x', repository: {...good.repository, directory: 'nope'}}, 'fuigo')[0], /expected/);
    assert.match(meta.repositoryProblems(good, 'fuigo', 'someone/fork').join('\n'), /not the publishing repository/);
});

console.log('sync-version requires and stamps repository');
test('--check fails when a package has no repository, the stamp adds it, then --check passes', () => {
    const t = makeTree();
    const target = pkgJsonOf(t, 'linux-x64');
    const m = readJson(target); delete m.repository;
    write(target, JSON.stringify(m, null, 4) + '\n');
    const bad = run('node', [path.join(t.scripts, 'sync-version.js'), '--check']);
    assert.equal(bad.status, 1, bad.stdout + bad.stderr);
    assert.match(bad.stderr, /fuigo-linux-x64 repository/);
    const stamp = run('node', [path.join(t.scripts, 'sync-version.js')]);
    assert.equal(stamp.status, 0, stamp.stderr);
    assert.deepEqual(readJson(target).repository, meta.repositoryFor('fuigo-linux-x64'));
    assert.equal(run('node', [path.join(t.scripts, 'sync-version.js'), '--check']).status, 0);
});
test('--check fails on the meta package with a wrong repository url', () => {
    const t = makeTree();
    const target = pkgJsonOf(t, null);
    const m = readJson(target); m.repository = {type: 'git', url: 'git+https://github.com/other/repo.git'};
    write(target, JSON.stringify(m, null, 4) + '\n');
    const bad = run('node', [path.join(t.scripts, 'sync-version.js'), '--check']);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /meta repository/);
});

console.log('verify-package-archives requires repository in the packed manifest');
test('passes on a complete tree and writes the manifest', () => {
    const t = makeTree();
    const out = path.join(tmp('out'), 'pk');
    const r = run('node', [path.join(t.scripts, 'verify-package-archives.js'), out]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(readJson(path.join(out, 'release-manifest.json')).packages.length, 7);
});
test('fails when one package lacks repository', () => {
    const t = makeTree();
    const target = pkgJsonOf(t, 'win32-arm64');
    const m = readJson(target); delete m.repository;
    write(target, JSON.stringify(m, null, 4) + '\n');
    const r = run('node', [path.join(t.scripts, 'verify-package-archives.js'), path.join(tmp('out'), 'pk')]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /@fuigo\/win32-arm64: package\.json has no "repository" field/);
});
test('fails under Actions when repository does not name the publishing repository', () => {
    const t = makeTree();
    const r = run('node', [path.join(t.scripts, 'verify-package-archives.js'), path.join(tmp('out'), 'pk')],
        {env: {GITHUB_REPOSITORY: 'someone/fork'}});
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not the publishing repository/);
    const ok = run('node', [path.join(t.scripts, 'verify-package-archives.js'), path.join(tmp('out'), 'pk2')],
        {env: {GITHUB_REPOSITORY: 'FerroxLabs/fuigo'}});
    assert.equal(ok.status, 0, ok.stderr);
});

/** A fake `npm` first on PATH. It logs argv, cwd and environment, and serves fixtures. */
function makeShim(fixtures) {
    const bin = tmp('shim');
    const log = path.join(bin, 'calls.jsonl');
    write(path.join(bin, 'fixtures.json'), JSON.stringify(fixtures));
    write(path.join(bin, 'npm'), `#!${process.execPath}
const fs = require('fs'), path = require('path');
const [, , ...argv] = process.argv;
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({argv, cwd: process.cwd(), env: process.env}) + '\\n');
const fx = JSON.parse(fs.readFileSync(${JSON.stringify(path.join(bin, 'fixtures.json'))}, 'utf8'));
const args = argv.filter(a => !a.startsWith('--registry=') && !a.startsWith('--@fuigo:registry='));
const spec = args[1];
const f = fx[spec];
if (!f) { console.error('fake registry: E404 ' + spec); process.exit(1); }
if (args[0] === 'view') { console.log(f.viewIntegrity || f.integrity); process.exit(0); }
if (args[0] === 'pack') {
    const dest = argv[argv.indexOf('--pack-destination') + 1];
    fs.copyFileSync(f.tgz, path.join(dest, f.filename));
    console.log(JSON.stringify([{filename: f.filename}]));
    process.exit(0);
}
console.error('fake registry: unsupported ' + args.join(' ')); process.exit(1);
`, 0o755);
    return {bin, calls: () => fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l))};
}

/** A platform tarball like the registry serves. `shell` is the 'native' executable the verifier runs. */
function makeFixtureTarball(platform, {repository, shell} = {}) {
    const dir = tmp('pkg');
    const [os_, arch] = platform.split('-');
    const m = {name: `@fuigo/${platform}`, version, os: [os_], cpu: [arch]};
    if (repository !== null) m.repository = repository || meta.repositoryFor(`fuigo-${platform}`);
    write(path.join(dir, 'package/package.json'), JSON.stringify(m));
    const exe = shell || `#!/bin/sh\necho "fuigo ${version} (abcdef123456)"\n`;
    write(path.join(dir, 'package/bin', `${os_ === 'win32' ? 'fuigo.exe' : 'fuigo'}.br`), zlib.brotliCompressSync(Buffer.from(exe)));
    const tgz = path.join(tmp('tgz'), `fuigo-${platform}-${version}.tgz`);
    execFileSync('tar', ['-czf', tgz, '-C', dir, 'package']);
    const integrity = 'sha512-' + sha('sha512', fs.readFileSync(tgz), 'base64');
    return {tgz, filename: path.basename(tgz), integrity, exeSha256: sha('sha256', exe)};
}

// A file(1) stand-in so the architecture assertion sees what a real binary would say.
function makeFileShim(bin, text) {
    write(path.join(bin, 'file'), `#!/bin/sh\necho "${text}"\n`, 0o755);
}

const POISON = {npm_config_registry: 'https://evil.example/', NPM_CONFIG_REGISTRY: 'https://evil.example/',
    NODE_AUTH_TOKEN: 'sekret-token', HTTPS_PROXY: 'http://evil.example:3128', npm_config__authtoken: 'sekret-token'};

console.log('pinned npm (fake registry)');
test('publicNpm runs from an empty directory with only the pinned environment', () => {
    const fx = makeFixtureTarball('linux-x64');
    const shim = makeShim({[`@fuigo/linux-x64@${version}`]: fx});
    const home = tmp('home'); write(path.join(home, '.npmrc'), 'registry=https://evil.example/\n');
    const cwd = tmp('cwd'); write(path.join(cwd, '.npmrc'), 'registry=https://evil.example/\n');
    const saved = {...process.env};
    try {
        Object.assign(process.env, POISON, {PATH: `${shim.bin}${path.delimiter}${process.env.PATH}`, HOME: home});
        process.chdir(cwd);
        const iso = pinned.makeHome();
        try { pinned.publicNpm(iso.home, ['view', `@fuigo/linux-x64@${version}`, 'dist.integrity'], {encoding: 'utf8'}); }
        finally { iso.cleanup(); }
    } finally {
        for (const k of Object.keys(POISON)) delete process.env[k];
        Object.assign(process.env, saved);
        process.chdir(SCRIPTS);
    }
    const [call] = shim.calls();
    assert(call.argv.includes('--registry=https://registry.npmjs.org/'), call.argv.join(' '));
    assert(call.argv.includes('--@fuigo:registry=https://registry.npmjs.org/'), call.argv.join(' '));
    for (const k of Object.keys(POISON)) assert.equal(call.env[k], undefined, `${k} leaked into npm`);
    assert.match(call.env.NPM_CONFIG_GLOBALCONFIG, /no-global-npmrc$/);
    assert.match(call.env.NPM_CONFIG_USERCONFIG, /no-user-npmrc$/);
    assert(!fs.existsSync(call.env.NPM_CONFIG_GLOBALCONFIG) && !fs.existsSync(call.env.NPM_CONFIG_USERCONFIG));
    const strip = d => d.replace(/^\/private/, '');
    assert.equal(strip(call.cwd), strip(call.env.HOME), 'npm must run from its empty HOME');
    assert.notEqual(call.env.HOME, home);
    assert.deepEqual(Object.keys(call.env).sort().filter(k => !['PATH', 'HOME', 'NPM_CONFIG_GLOBALCONFIG',
        'NPM_CONFIG_USERCONFIG', 'PWD', 'OLDPWD', 'SHLVL', '_', 'LC_CTYPE', 'LANG', '__CF_USER_TEXT_ENCODING'].includes(k)), []);
}, {skip: !posixOnly});
const WIN_SRC = {Path: 'C:\\node', SystemRoot: 'C:\\Windows', windir: 'C:\\Windows', ComSpec: 'C:\\Windows\\system32\\cmd.exe',
    PATHEXT: '.COM;.EXE;.CMD', Temp: 'C:\\t', TMP: 'C:\\t', APPDATA: 'C:\\Users\\r\\AppData\\Roaming',
    LOCALAPPDATA: 'C:\\Users\\r\\AppData\\Local', USERPROFILE: 'C:\\Users\\r', HOME: 'C:\\Users\\r',
    ProgramData: 'C:\\PD', GITHUB_TOKEN: 'ghs_x', ...POISON};
const CONFIG_ENV = ['NPM_CONFIG_GLOBALCONFIG', 'NPM_CONFIG_USERCONFIG'];
test('pinnedEnv on win32 passes exactly the system variables, points profile dirs at the private home', () => {
    const env = pinned.pinnedEnv('H', {}, 'win32', WIN_SRC);
    assert.deepEqual(Object.keys(env).sort(), ['APPDATA', 'ComSpec', 'HOME', 'LOCALAPPDATA', 'NPM_CONFIG_GLOBALCONFIG',
        'NPM_CONFIG_USERCONFIG', 'PATH', 'PATHEXT', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE', 'windir'].sort());
    assert.equal(env.PATH, 'C:\\node');
    assert.equal(env.SystemRoot, 'C:\\Windows'); assert.equal(env.windir, 'C:\\Windows');
    assert.equal(env.ComSpec, WIN_SRC.ComSpec); assert.equal(env.PATHEXT, WIN_SRC.PATHEXT);
    assert.equal(env.TEMP, 'C:\\t', 'case-insensitive pick of Temp'); assert.equal(env.TMP, 'C:\\t');
    for (const k of ['APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'HOME']) assert.equal(env[k], 'H', `${k} must be the private home`);
    for (const k of Object.keys(POISON)) assert.equal(env[k], undefined, `${k} leaked`);
    for (const k of ['GITHUB_TOKEN', 'ProgramData']) assert.equal(env[k], undefined, `${k} leaked`);
    assert(CONFIG_ENV.every(k => env[k].startsWith('H')));
    assert.deepEqual(pinned.WIN32_SYSTEM_VARS.sort(),
        ['ComSpec', 'PATHEXT', 'SystemRoot', 'TEMP', 'TMP', 'windir'].sort());
});
test('pinnedEnv on win32 tolerates absent system variables', () => {
    const env = pinned.pinnedEnv('H', {}, 'win32', {Path: 'p'});
    assert.deepEqual(Object.keys(env).sort(), ['APPDATA', 'HOME', 'LOCALAPPDATA', 'NPM_CONFIG_GLOBALCONFIG',
        'NPM_CONFIG_USERCONFIG', 'PATH', 'USERPROFILE']);
});
test('pinnedEnv on posix is PATH, HOME and the two npmrc pins only', () => {
    for (const platform of ['linux', 'darwin']) {
        const env = pinned.pinnedEnv('H', {}, platform, {...WIN_SRC, PATH: '/bin'});
        assert.deepEqual(Object.keys(env).sort(), ['HOME', 'NPM_CONFIG_GLOBALCONFIG', 'NPM_CONFIG_USERCONFIG', 'PATH']);
        assert.equal(env.PATH, '/bin');
    }
});
test('pinnedEnv defaults follow process.platform and process.env at call time', () => {
    const real = Object.getOwnPropertyDescriptor(process, 'platform');
    const saved = process.env.SystemRoot;
    try {
        Object.defineProperty(process, 'platform', {value: 'win32'});
        process.env.SystemRoot = 'C:\\W';
        const env = pinned.pinnedEnv('H');
        assert.equal(env.USERPROFILE, 'H'); assert(env.SystemRoot === 'C:\\W' || env.SYSTEMROOT === 'C:\\W');
    } finally {
        Object.defineProperty(process, 'platform', real);
        if (saved === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = saved;
    }
    assert.equal(pinned.pinnedEnv('H', {}).USERPROFILE, process.platform === 'win32' ? 'H' : undefined);
});
test('pinnedEnv refuses npm configuration in extraEnv and keeps lifecycle variables', () => {
    for (const platform of ['win32', 'linux']) {
        for (const k of ['npm_config_registry', 'NPM_CONFIG_REGISTRY', 'Npm_Config_Userconfig']) {
            assert.throws(() => pinned.pinnedEnv('H', {[k]: 'x'}, platform, {}), /pinned/);
        }
        assert.equal(pinned.pinnedEnv('H', {FUIGO_HOME: 'F'}, platform, {}).FUIGO_HOME, 'F');
    }
});
test('both registries stay pinned on the command line, and the module is the only env source', () => {
    assert.deepEqual(pinned.pinnedFlags(), ['--registry=https://registry.npmjs.org/', '--@fuigo:registry=https://registry.npmjs.org/']);
    const src = fs.readFileSync(path.join(SCRIPTS, 'pinned-npm.js'), 'utf8');
    assert(/pinnedEnv\(home, extraEnv\)/.test(src), 'publicNpm must pass pinnedEnv(home, extraEnv)');
    assert(!/\.\.\.process\.env/.test(src), 'pinned-npm.js must never spread process.env');
});
test('fetchFromPublicRegistry accepts a matching dist.integrity and rejects a different one', () => {
    const fx = makeFixtureTarball('linux-x64');
    const spec = `@fuigo/linux-x64@${version}`;
    const shim = makeShim({[spec]: fx});
    const saved = process.env.PATH;
    try {
        process.env.PATH = `${shim.bin}${path.delimiter}${saved}`;
        const iso = pinned.makeHome();
        try {
            const got = pinned.fetchFromPublicRegistry(iso.home, spec, tmp('dl'));
            assert.equal(got.integrity, fx.integrity);
            const bad = makeShim({[spec]: {...fx, viewIntegrity: 'sha512-AAAA'}});
            process.env.PATH = `${bad.bin}${path.delimiter}${saved}`;
            assert.throws(() => pinned.fetchFromPublicRegistry(iso.home, spec, tmp('dl')), /the registry says sha512-AAAA/);
        } finally { iso.cleanup(); }
    } finally { process.env.PATH = saved; }
}, {skip: !posixOnly});
test('the JavaScript pin matches public_npm in registry-release-inputs.sh', () => {
    const sh = fs.readFileSync(path.join(REPO_ROOT, 'scripts/release/registry-release-inputs.sh'), 'utf8');
    assert(sh.includes(`REGISTRY=${pinned.REGISTRY}`), 'registry differs');
    assert(sh.includes('npm --registry="$REGISTRY" --@fuigo:registry="$REGISTRY"'));
    assert(sh.includes('env -i PATH="$PATH" HOME="$NPM_HOME"'));
    assert(sh.includes('NPM_CONFIG_GLOBALCONFIG="$NPM_HOME/no-global-npmrc"'));
    assert(sh.includes('NPM_CONFIG_USERCONFIG="$NPM_HOME/no-user-npmrc"'));
    assert.deepEqual(pinned.pinnedFlags(), [`--registry=${pinned.REGISTRY}`, `--@fuigo:registry=${pinned.REGISTRY}`]);
});

console.log('verify-published-platform.js (fake registry)');
function runVerifier(platform, fixture, extraArgs = [], extraEnv = {}) {
    const spec = `@fuigo/${platform}@${version}`;
    const shim = makeShim({[spec]: fixture});
    makeFileShim(shim.bin, platform.endsWith('arm64') ? 'Mach-O 64-bit arm64 executable' : 'Mach-O 64-bit x86_64 executable');
    const r = run(process.execPath, [path.join(SCRIPTS, 'verify-published-platform.js'), platform, ...extraArgs],
        {env: {...POISON, PATH: `${shim.bin}${path.delimiter}${process.env.PATH}`, ...extraEnv}});
    return {r, shim};
}
test('downloads through the pinned npm and writes digests that match the tarball and executable', () => {
    const fx = makeFixtureTarball('darwin-x64');
    const out = path.join(tmp('d'), 'verified.json');
    const {r, shim} = runVerifier('darwin-x64', fx, ['--digest-out', out]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(readJson(out), {platform: 'darwin-x64', name: '@fuigo/darwin-x64', version,
        integrity: fx.integrity, sha256: fx.exeSha256});
    const calls = shim.calls();
    assert(calls.some(c => c.argv.includes('view')) && calls.some(c => c.argv.includes('pack')));
    for (const c of calls) {
        assert(c.argv.includes('--registry=https://registry.npmjs.org/'), c.argv.join(' '));
        assert(c.argv.includes('--@fuigo:registry=https://registry.npmjs.org/'));
        for (const k of Object.keys(POISON)) assert.equal(c.env[k], undefined, `${k} leaked into npm`);
        assert.match(c.env.NPM_CONFIG_USERCONFIG, /no-user-npmrc$/);
    }
}, {skip: !posixOnly});
test('fails when the registry tarball differs from the integrity the registry advertises', () => {
    const fx = makeFixtureTarball('darwin-x64');
    const {r} = runVerifier('darwin-x64', {...fx, viewIntegrity: 'sha512-AAAA'});
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /the registry says sha512-AAAA/);
}, {skip: !posixOnly});
test('fails when the published package.json has no repository', () => {
    const fx = makeFixtureTarball('darwin-x64', {repository: null});
    const {r} = runVerifier('darwin-x64', fx);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /no "repository" field/);
}, {skip: !posixOnly});
test('fails when the published repository is not the publishing repository', () => {
    const fx = makeFixtureTarball('darwin-x64');
    const {r} = runVerifier('darwin-x64', fx, [], {GITHUB_REPOSITORY: 'someone/fork'});
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not the publishing repository/);
}, {skip: !posixOnly});

console.log('verify-release-digests.js');
function makeRelease(opts = {}) {
    const release = tmp('release'), verified = tmp('verified');
    const packages = [];
    const sums = [];
    for (const [p, ap] of Object.entries(ASSET_PLATFORM)) {
        const tgzBytes = Buffer.from(`tarball ${p}`), rawBytes = Buffer.from(`binary ${p}`);
        write(path.join(release, `fuigo-${p}-${version}.tgz`), tgzBytes);
        write(path.join(release, `fuigo-${version}-${ap}`), rawBytes);
        const integrity = 'sha512-' + sha('sha512', tgzBytes, 'base64');
        packages.push({name: `@fuigo/${p}`, version, filename: `fuigo-${p}-${version}.tgz`, integrity});
        sums.push([`fuigo-${p}-${version}.tgz`, sha('sha256', tgzBytes, 'hex')], [`fuigo-${version}-${ap}`, sha('sha256', rawBytes, 'hex')]);
        write(path.join(verified, `verified-${p}.json`), JSON.stringify({platform: p, name: `@fuigo/${p}`, version,
            integrity, sha256: sha('sha256', rawBytes, 'hex')}));
    }
    write(path.join(release, 'release-manifest.json'), JSON.stringify({version, packages}));
    write(path.join(release, 'SHA256SUMS'), sums.map(([n, h]) => `${h}  ${n}\n`).join(''));
    return {release, verified};
}
test('accepts release assets equal to what the verifiers executed', () => {
    const {release, verified} = makeRelease();
    assert.deepEqual(verifyDigests(version, verified, release), []);
    const r = run(process.execPath, [path.join(REPO_ROOT, 'scripts/release/verify-release-digests.js'), version, verified, release]);
    assert.equal(r.status, 0, r.stderr);
});
test('rejects a raw binary that differs from the verified executable', () => {
    const {release, verified} = makeRelease();
    fs.appendFileSync(path.join(release, `fuigo-${version}-linux-x86_64`), 'x');
    const e = verifyDigests(version, verified, release).join('\n');
    assert.match(e, /fuigo-.*-linux-x86_64 is sha256/);
    const r = run(process.execPath, [path.join(REPO_ROOT, 'scripts/release/verify-release-digests.js'), version, verified, release]);
    assert.equal(r.status, 1);
});
test('rejects a tarball that differs from the verified integrity', () => {
    const {release, verified} = makeRelease();
    fs.appendFileSync(path.join(release, `fuigo-win32-x64-${version}.tgz`), 'x');
    assert.match(verifyDigests(version, verified, release).join('\n'), /fuigo-win32-x64-.*\.tgz is sha512-/);
});
test('rejects SHA256SUMS and release-manifest.json entries that disagree with the verifier', () => {
    const a = makeRelease();
    const sumsFile = path.join(a.release, 'SHA256SUMS');
    fs.writeFileSync(sumsFile, fs.readFileSync(sumsFile, 'utf8').replace(/^[0-9a-f]{64}( {2}fuigo-[^ ]*-macos-aarch64)$/m, `${'0'.repeat(64)}$1`));
    assert.match(verifyDigests(version, a.verified, a.release).join('\n'), /SHA256SUMS says .* for fuigo-.*-macos-aarch64/);
    const b = makeRelease();
    const mf = path.join(b.release, 'release-manifest.json');
    const m = readJson(mf); m.packages[0].integrity = 'sha512-BBBB'; write(mf, JSON.stringify(m));
    assert.match(verifyDigests(version, b.verified, b.release).join('\n'), /release-manifest\.json says sha512-BBBB/);
});
test('rejects a missing verifier record, a wrong version and an unknown platform', () => {
    const a = makeRelease();
    fs.rmSync(path.join(a.verified, 'verified-linux-arm64.json'));
    assert.match(verifyDigests(version, a.verified, a.release).join('\n'), /no verified digests for linux-arm64/);
    const b = makeRelease();
    assert.match(verifyDigests('9.9.9', b.verified, b.release).join('\n'), /verified version/);
    const c = makeRelease();
    write(path.join(c.verified, 'verified-plan9-x64.json'), JSON.stringify({platform: 'plan9-x64'}));
    assert.match(verifyDigests(version, c.verified, c.release).join('\n'), /unknown platform plan9-x64/);
});
test('the asset platform names equal the ones github-release-assets.sh lays out', () => {
    const sh = fs.readFileSync(path.join(REPO_ROOT, 'scripts/release/github-release-assets.sh'), 'utf8');
    for (const [p, ap] of Object.entries(ASSET_PLATFORM)) assert(sh.includes(`${p}) asset_platform=${ap} ;;`), p);
});

console.log('release workflow');
const wf = fs.readFileSync(path.join(REPO_ROOT, '.github/workflows/release.yml'), 'utf8');
const jobs = (() => {
    const body = wf.slice(wf.indexOf('\njobs:\n') + 7);
    const out = {};
    let name = null;
    for (const line of body.split('\n')) {
        const m = /^ {2}([a-z][a-z0-9-]*):\s*$/.exec(line);
        if (m) { name = m[1]; out[name] = ''; } else if (name) out[name] += line + '\n';
    }
    return out;
})();
test('every npm publish asks for provenance', () => {
    const lines = wf.split('\n').filter(l => /npm publish\b/.test(l) && !l.trim().startsWith('#'));
    assert.equal(lines.length, 2, lines.join('\n'));
    for (const l of lines) assert(l.includes('--provenance'), l);
});
test('only the publish job holds id-token: write, and the workflow default does not', () => {
    const top = wf.slice(0, wf.indexOf('\njobs:\n'));
    assert(!/id-token/.test(top), 'workflow-level id-token');
    assert(/^ {4}permissions:\n(?: {6}.*\n)*? {6}id-token: write$/m.test(jobs.publish), 'publish job lacks id-token: write');
    for (const [n, body] of Object.entries(jobs)) {
        if (n !== 'publish') assert(!/^\s*id-token:\s*write/m.test(body), `${n} has id-token: write`);
    }
});
test('verify-published records digests and github-release compares them with the assets', () => {
    assert(/verify-published-platform\.js[^\n]*\\\n\s*--digest-out /.test(jobs['verify-published']));
    assert(/name: verified-\$\{\{ matrix\.platform \}\}/.test(jobs['verify-published']));
    const rel = jobs['github-release'];
    assert(/pattern: verified-\*/.test(rel));
    const layout = rel.indexOf('registry-release-inputs.sh'), cmp = rel.indexOf('verify-release-digests.js'),
        create = rel.indexOf('name: Create or complete the release');
    assert(layout > 0 && layout < cmp && cmp < create, 'compare must run after layout and before the release is created');
});

for (const d of tmpDirs) fs.rmSync(d, {recursive: true, force: true});
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
process.exit(failed ? 1 : 0);
