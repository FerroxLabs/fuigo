#!/usr/bin/env node
// Tests for bin/fuigo-replace.js: same-version reinstall replaces a differing binary.
// Run with:  node scripts/test-reinstall.js   (node built-ins only, temp dirs only)
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const assert = require('assert');
const { spawnSync } = require('child_process');
const { installVendorBinary } = require('../bin/fuigo-replace.js');

const isWin = process.platform === 'win32';
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
let passed = 0, failed = 0, skipped = 0;
function test(name, fn, skip) {
    if (skip) { console.log(`  - SKIP ${name}: ${skip}`); skipped++; return; }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-reinstall-'));
    try { fn(dir); console.log(`  ok ${name}`); passed++; }
    catch (e) { console.error(`  FAIL ${name}\n    ${e.message}`); failed++; }
    finally { try { fs.chmodSync(path.join(dir, 'bin'), 0o755); } catch {} fs.rmSync(dir, { recursive: true, force: true }); }
}
function setup(dir, vendored, installed) {
    const vendor = path.join(dir, 'vendor'), bin = path.join(dir, 'bin');
    fs.mkdirSync(vendor); fs.mkdirSync(bin);
    const br = path.join(vendor, 'fuigo.br');
    fs.writeFileSync(br, zlib.brotliCompressSync(Buffer.from(vendored)));
    const dest = path.join(bin, 'fuigo-1.0.25');
    if (installed !== undefined) fs.writeFileSync(dest, installed, { mode: 0o755 });
    return { br, raw: path.join(vendor, 'fuigo'), dest, bin };
}

console.log('\nreinstall tests\n');
test('fresh install writes the file with mode 0755', (d) => {
    const s = setup(d, 'NEW');
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'NEW');
    if (!isWin) assert.strictEqual(fs.statSync(s.dest).mode & 0o777, 0o755);
});
test('same content: no write (inode and mtime unchanged)', (d) => {
    const s = setup(d, 'SAME', 'SAME');
    const old = new Date(2020, 0, 1); fs.utimesSync(s.dest, old, old);
    const before = fs.statSync(s.dest);
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    const after = fs.statSync(s.dest);
    assert.strictEqual(after.ino, before.ino);
    assert.strictEqual(after.mtimeMs, before.mtimeMs);
});
test('different content, same size: replaced', (d) => {
    const s = setup(d, 'AAAA', 'BBBB');
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'AAAA');
});
test('different content: replaced by rename (new inode), mode 0755, no temp left', (d) => {
    const s = setup(d, 'NEWER-CONTENT', 'old');
    fs.chmodSync(s.dest, 0o644);
    const ino = fs.statSync(s.dest).ino;
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'NEWER-CONTENT');
    assert.strictEqual(fs.statSync(s.dest).mode & 0o777, 0o755);
    assert.notStrictEqual(fs.statSync(s.dest).ino, ino);
    assert.deepStrictEqual(fs.readdirSync(s.bin), ['fuigo-1.0.25']);
}, isWin && 'unix inode/mode semantics');
test('uncompressed vendored binary also replaces', (d) => {
    const s = setup(d, 'x', 'old');
    fs.rmSync(s.br); fs.writeFileSync(s.raw, 'RAW');
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'RAW');
});
test('destination is a symlink: untouched', (d) => {
    const s = setup(d, 'NEW');
    const target = path.join(d, 'elsewhere'); fs.writeFileSync(target, 'KEEP');
    fs.symlinkSync(target, s.dest);
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.ok(fs.lstatSync(s.dest).isSymbolicLink());
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'KEEP');
}, isWin && 'symlinks need privileges');
test('replace fails (read-only dir): old file kept, launch continues', (d) => {
    const s = setup(d, 'NEW', 'OLD');
    fs.chmodSync(s.bin, 0o555);
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'OLD');
}, isWin ? 'unix permissions' : isRoot && 'running as root: a read-only dir does not stop root');
test('missing vendored binary with an existing file: kept; with none: false', (d) => {
    const s = setup(d, 'x', 'OLD'); fs.rmSync(s.br);
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'OLD');
    fs.rmSync(s.dest);
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), false);
});
test('empty vendored binary never replaces a good one; with none installed: false', (d) => {
    const s = setup(d, '', 'OLD');
    const ino = fs.statSync(s.dest).ino;
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'OLD');
    assert.strictEqual(fs.statSync(s.dest).ino, ino);
    fs.rmSync(s.br); fs.writeFileSync(s.raw, '');
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), true);
    assert.strictEqual(fs.readFileSync(s.dest, 'utf8'), 'OLD');
    fs.rmSync(s.dest);
    assert.strictEqual(installVendorBinary(s.br, s.raw, s.dest), false);
    assert.strictEqual(fs.existsSync(s.dest), false);
});
const pending = [];
(() => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-reinstall-'));
    const big = Buffer.alloc(8 * 1024 * 1024, 7); big[5] = 9;
    const s = setup(d, big, 'old'); // paths only, rewritten below
    const code = `require(${JSON.stringify(path.resolve(__dirname, '../bin/fuigo-replace.js'))}).installVendorBinary(${JSON.stringify(s.br)},${JSON.stringify(s.raw)},${JSON.stringify(s.dest)})`;
    // the temp dir must outlive this callback: keep it and check after the children exit
    const keep = fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-reinstall-c-'));
    const s2 = setup(keep, big, 'old');
    const code2 = code.split(s.br).join(s2.br).split(s.dest).join(s2.dest);
    const { spawn } = require('child_process');
    pending.push(Promise.all(Array.from({ length: 6 }, () => new Promise((r) => spawn(process.execPath, ['-e', code2]).on('exit', r)))).then((codes) => {
        try {
            assert.ok(codes.every((c) => c === 0), `exit codes ${codes}`);
            assert.ok(fs.readFileSync(s2.dest).equals(big), 'file incomplete');
            assert.deepStrictEqual(fs.readdirSync(s2.bin), ['fuigo-1.0.25']);
            console.log('  ok two concurrent replaces leave a complete file (6 processes)'); passed++;
        } catch (e) { console.error(`  FAIL concurrent: ${e.message}`); failed++; }
        fs.rmSync(keep, { recursive: true, force: true });
    }));
    fs.rmSync(d, { recursive: true, force: true });
})();
Promise.all(pending).then(() => {
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
process.exit(failed > 0 ? 1 : 0);
});
