#!/usr/bin/env node
// Tests for the versioned-binary + symlink installation logic used by
// bin/fuigo-install.js and bin/fuigo-bootstrap.js (there is no npm postinstall script).
//
// Run with:  node scripts/test-fuigo-install.js
//
// Uses only Node.js built-in modules (no test framework needed).

const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const assert = require('assert');

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  ✓ ${name}`);
        passed++;
    } catch (e) {
        console.error(`  ✗ ${name}`);
        console.error(`    ${e.message}`);
        failed++;
    }
}

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'fuigo-test-'));
}

function cleanup(dir) {
    fs.rmSync(dir, { recursive: true, force: true });
}

// ─── Extracted logic (mirrors bin/fuigo-install.js and bin/fuigo-bootstrap.js) ─

/** Comparator: sort "<prefix>X.Y.Z" filenames by version, newest first. */
function byVersionDescending(prefix) {
    return (a, b) => {
        const pa = a.slice(prefix.length).split('.').map(Number);
        const pb = b.slice(prefix.length).split('.').map(Number);
        for (let i = 0; i < 3; i++) {
            if ((pa[i] || 0) !== (pb[i] || 0)) return (pb[i] || 0) - (pa[i] || 0);
        }
        return 0;
    };
}

/** Install a versioned binary + atomic symlink (same as fuigo-install.js). */
function installVersionedBinary(vendoredBinPath, version, canonicalDir) {
    const canonicalPath = path.join(canonicalDir, 'fuigo');
    fs.mkdirSync(canonicalDir, { recursive: true });

    const versionedName = `fuigo-${version}`;
    const versionedPath = path.join(canonicalDir, versionedName);

    if (!fs.existsSync(versionedPath)) {
        const tmpPath = versionedPath + `.tmp.${process.pid}`;
        try {
            fs.copyFileSync(vendoredBinPath, tmpPath);
            fs.chmodSync(tmpPath, 0o755);
            fs.renameSync(tmpPath, versionedPath);
        } finally {
            try { fs.unlinkSync(tmpPath); } catch {}
        }
    }

    const tmpLink = canonicalPath + `.link.${process.pid}`;
    try { fs.unlinkSync(tmpLink); } catch {}
    fs.symlinkSync(versionedName, tmpLink);
    fs.renameSync(tmpLink, canonicalPath);

    return { canonicalPath, versionedPath, versionedName };
}

/** Cleanup old versioned binaries (same as fuigo-install.js). */
function cleanupOldVersions(canonicalDir, currentVersionedName) {
    const entries = fs.readdirSync(canonicalDir);
    const versionedBinaries = entries
        .filter(e => e.startsWith('fuigo-') && !e.includes('.tmp.') && !e.includes('.link.') && e !== currentVersionedName)
        .sort(byVersionDescending('fuigo-'));
    // Keep the most recent old version, remove anything older.
    for (const old of versionedBinaries.slice(1)) {
        try { fs.unlinkSync(path.join(canonicalDir, old)); } catch {}
    }
    return versionedBinaries;
}

/** Fuigo bin dir resolution (mirrors bin/fuigo-install.js and bin/fuigo-bootstrap.js). */
function resolveFuigoBinDir(env, homedir) {
    const fuigoHome = env.FUIGO_HOME ?? path.join(homedir, '.fuigo');
    return path.join(fuigoHome, 'bin');
}

/** Write the shipped binary to destPath (mirrors writeVendorBinary). */
function writeVendorBinary(brotliPath, binaryPath, destPath) {
    const tmp = destPath + `.tmp.${process.pid}`;
    try {
        if (fs.existsSync(brotliPath)) {
            fs.writeFileSync(tmp, zlib.brotliDecompressSync(fs.readFileSync(brotliPath)));
        } else if (fs.existsSync(binaryPath)) {
            fs.copyFileSync(binaryPath, tmp);
        } else {
            return false;
        }
        fs.chmodSync(tmp, 0o755);
        fs.renameSync(tmp, destPath);
        return true;
    } catch {
        return false;
    } finally {
        try { fs.unlinkSync(tmp); } catch {}
    }
}

/** Decompress a compressed binary into the bin dir (mirrors installBinary). */
function installBinaryFromBrotli(brotliPath, version, canonicalDir) {
    fs.mkdirSync(canonicalDir, { recursive: true });
    const versionedName = `fuigo-${version}`;
    const versionedPath = path.join(canonicalDir, versionedName);
    const canonicalPath = path.join(canonicalDir, 'fuigo');

    if (!fs.existsSync(versionedPath)) {
        const tmpPath = versionedPath + `.tmp.${process.pid}`;
        try {
            const decompressed = zlib.brotliDecompressSync(fs.readFileSync(brotliPath));
            fs.writeFileSync(tmpPath, decompressed);
            fs.chmodSync(tmpPath, 0o755);
            fs.renameSync(tmpPath, versionedPath);
        } finally {
            try { fs.unlinkSync(tmpPath); } catch {}
        }
    }

    const tmpLink = canonicalPath + `.link.${process.pid}`;
    try { fs.unlinkSync(tmpLink); } catch {}
    fs.symlinkSync(versionedName, tmpLink);
    fs.renameSync(tmpLink, canonicalPath);

    return { canonicalPath, versionedPath, versionedName };
}

/** Install the shipped binary into the bin dir (same as bin/fuigo-bootstrap.js). */
function bootstrapCanonical(vendoredBinPath, version, canonicalDir) {
    const canonicalPath = path.join(canonicalDir, 'fuigo');
    try {
        fs.mkdirSync(canonicalDir, { recursive: true });
        const versionedName = `fuigo-${version}`;
        const versionedPath = path.join(canonicalDir, versionedName);
        if (!fs.existsSync(versionedPath)) {
            const tmpPath = versionedPath + `.tmp.${process.pid}`;
            fs.copyFileSync(vendoredBinPath, tmpPath);
            fs.chmodSync(tmpPath, 0o755);
            fs.renameSync(tmpPath, versionedPath);
        }
        const tmpLink = canonicalPath + `.link.${process.pid}`;
        try { fs.unlinkSync(tmpLink); } catch {}
        fs.symlinkSync(versionedName, tmpLink);
        fs.renameSync(tmpLink, canonicalPath);
        return canonicalPath;
    } catch {
        return vendoredBinPath;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Install + Symlink Tests
// ═══════════════════════════════════════════════════════════════════════

console.log('install + symlink tests\n');

test('creates versioned binary and symlink on fresh install', () => {
    const dir = makeTmpDir();
    try {
        const vendored = path.join(dir, 'vendored-fuigo');
        fs.writeFileSync(vendored, 'binary-content-v1');

        const binDir = path.join(dir, 'bin');
        const result = installVersionedBinary(vendored, '0.1.140', binDir);

        // Versioned file should exist
        assert.ok(fs.existsSync(result.versionedPath), 'versioned binary should exist');
        assert.strictEqual(fs.readFileSync(result.versionedPath, 'utf8'), 'binary-content-v1');

        // Canonical path should be a symlink
        const stat = fs.lstatSync(result.canonicalPath);
        assert.ok(stat.isSymbolicLink(), 'canonical path should be a symlink');

        // Symlink should point to the versioned name (relative)
        const target = fs.readlinkSync(result.canonicalPath);
        assert.strictEqual(target, 'fuigo-0.1.140');

        // Reading through the symlink should return the binary content
        assert.strictEqual(fs.readFileSync(result.canonicalPath, 'utf8'), 'binary-content-v1');
    } finally {
        cleanup(dir);
    }
});

test('upgrade swaps symlink and preserves old binary', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');

        // Install v1
        const vendored_v1 = path.join(dir, 'vendored-v1');
        fs.writeFileSync(vendored_v1, 'v1-content');
        installVersionedBinary(vendored_v1, '0.1.140', binDir);

        // Install v2
        const vendored_v2 = path.join(dir, 'vendored-v2');
        fs.writeFileSync(vendored_v2, 'v2-content');
        const result = installVersionedBinary(vendored_v2, '0.1.141', binDir);

        // Symlink now points to v2
        assert.strictEqual(fs.readlinkSync(result.canonicalPath), 'fuigo-0.1.141');
        assert.strictEqual(fs.readFileSync(result.canonicalPath, 'utf8'), 'v2-content');

        // Old v1 binary MUST still exist on disk (this is the key safety property)
        const oldBinary = path.join(binDir, 'fuigo-0.1.140');
        assert.ok(fs.existsSync(oldBinary), 'old versioned binary must not be deleted');
        assert.strictEqual(fs.readFileSync(oldBinary, 'utf8'), 'v1-content');
    } finally {
        cleanup(dir);
    }
});

test('idempotent: reinstalling same version does not re-copy', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');

        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'original');
        installVersionedBinary(vendored, '0.1.140', binDir);

        // Modify vendored source (simulate npm replacing it)
        fs.writeFileSync(vendored, 'replaced-by-npm');

        // Re-run postinstall with same version
        installVersionedBinary(vendored, '0.1.140', binDir);

        // Versioned binary should NOT have been replaced (existsSync guard)
        const versionedPath = path.join(binDir, 'fuigo-0.1.140');
        assert.strictEqual(fs.readFileSync(versionedPath, 'utf8'), 'original');
    } finally {
        cleanup(dir);
    }
});

test('symlink swap is atomic (no intermediate missing state)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const canonicalPath = path.join(binDir, 'fuigo');

        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'v1');
        installVersionedBinary(vendored, '0.1.140', binDir);
        assert.ok(fs.existsSync(canonicalPath), 'should exist after first install');

        // Upgrade
        fs.writeFileSync(vendored, 'v2');
        installVersionedBinary(vendored, '0.1.141', binDir);
        assert.ok(fs.existsSync(canonicalPath), 'should exist after upgrade');

        // No temp files left behind
        const entries = fs.readdirSync(binDir);
        const tempFiles = entries.filter(e => e.includes('.tmp.') || e.includes('.link.'));
        assert.strictEqual(tempFiles.length, 0, `temp files should be cleaned up, found: ${tempFiles}`);
    } finally {
        cleanup(dir);
    }
});

test('handles upgrade from old-style regular file to versioned symlink', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const canonicalPath = path.join(binDir, 'fuigo');
        fs.mkdirSync(binDir, { recursive: true });

        // Simulate old installation: fuigo is a regular file
        fs.writeFileSync(canonicalPath, 'old-style-binary');
        assert.ok(!fs.lstatSync(canonicalPath).isSymbolicLink(), 'should be regular file initially');

        // Run new-style install
        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'v2-content');
        installVersionedBinary(vendored, '0.1.141', binDir);

        // Should now be a symlink
        assert.ok(fs.lstatSync(canonicalPath).isSymbolicLink(), 'should be symlink after install');
        assert.strictEqual(fs.readFileSync(canonicalPath, 'utf8'), 'v2-content');
    } finally {
        cleanup(dir);
    }
});

test('handles broken symlink (target deleted externally)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // Create a broken symlink (points to a file that doesn't exist)
        const canonicalPath = path.join(binDir, 'fuigo');
        fs.symlinkSync('fuigo-0.1.99', canonicalPath);
        assert.ok(!fs.existsSync(canonicalPath), 'broken symlink should not "exist"');

        // Install should work and fix the broken symlink
        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'fixed-content');
        const result = installVersionedBinary(vendored, '0.1.141', binDir);

        assert.ok(fs.existsSync(result.canonicalPath), 'symlink should now resolve');
        assert.strictEqual(fs.readFileSync(result.canonicalPath, 'utf8'), 'fixed-content');
    } finally {
        cleanup(dir);
    }
});

test('three sequential upgrades: v1 -> v2 -> v3 all coexist', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');

        fs.writeFileSync(vendored, 'content-v1');
        installVersionedBinary(vendored, '0.1.1', binDir);

        fs.writeFileSync(vendored, 'content-v2');
        installVersionedBinary(vendored, '0.1.2', binDir);

        fs.writeFileSync(vendored, 'content-v3');
        installVersionedBinary(vendored, '0.1.3', binDir);

        // Symlink points to latest
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo')), 'fuigo-0.1.3');

        // All three versioned binaries still exist (no cleanup yet)
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.1')));
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.2')));
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.3')));
    } finally {
        cleanup(dir);
    }
});

test('file permissions are preserved (0o755)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'binary');

        const result = installVersionedBinary(vendored, '0.1.140', binDir);

        const mode = fs.statSync(result.versionedPath).mode & 0o777;
        assert.strictEqual(mode, 0o755, `expected 0755, got ${mode.toString(8)}`);
    } finally {
        cleanup(dir);
    }
});

// ═══════════════════════════════════════════════════════════════════════
// Cleanup / Semver Sort Tests
// ═══════════════════════════════════════════════════════════════════════

console.log('\ncleanup + semver sort tests\n');

test('cleanup keeps N-1 version and removes older ones', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // Create three old versioned binaries
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.138'), 'v138');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.139'), 'v139');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.140'), 'v140');
        // fuigo-0.1.141 is the current version (excluded from cleanup)
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.141'), 'v141');

        cleanupOldVersions(binDir, 'fuigo-0.1.141');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'current should exist');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.140')), 'N-1 should be kept');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.139')), 'N-2 should be removed');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.138')), 'N-3 should be removed');
    } finally {
        cleanup(dir);
    }
});

test('cleanup with only one old version keeps it', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.140'), 'v140');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.141'), 'v141');

        cleanupOldVersions(binDir, 'fuigo-0.1.141');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.140')), 'single old version should be kept');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'current should exist');
    } finally {
        cleanup(dir);
    }
});

test('cleanup with no old versions is a no-op', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // Only the current version exists
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.141'), 'v141');

        cleanupOldVersions(binDir, 'fuigo-0.1.141');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'current should still exist');
        const entries = fs.readdirSync(binDir).filter(e => e.startsWith('fuigo-'));
        assert.strictEqual(entries.length, 1, 'should only have current version');
    } finally {
        cleanup(dir);
    }
});

test('cleanup ignores .tmp. and .link. files', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.141'), 'current');
        // Leftover temp files from a crashed install
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.140.tmp.12345'), 'crashed-tmp');
        fs.writeFileSync(path.join(binDir, 'fuigo.link.12345'), 'crashed-link');

        cleanupOldVersions(binDir, 'fuigo-0.1.141');

        // Temp files should not be touched by cleanup (they're filtered out)
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.140.tmp.12345')), 'tmp file should not be touched');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo.link.12345')), 'link file should not be touched');
    } finally {
        cleanup(dir);
    }
});

test('semver sort: 0.1.9 vs 0.1.10 (digit boundary)', () => {
    // Regression test: lexical sort puts '0.1.9' after '0.1.10' because '9' > '1'
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.8'), 'v8');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.9'), 'v9');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.10'), 'v10');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.11'), 'v11');

        cleanupOldVersions(binDir, 'fuigo-0.1.11');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.11')), 'current should exist');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.10')), '0.1.10 should be kept (N-1)');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.9')), '0.1.9 should be removed');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.8')), '0.1.8 should be removed');
    } finally {
        cleanup(dir);
    }
});

test('semver sort: major version boundary (0.x vs 1.x)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        fs.writeFileSync(path.join(binDir, 'fuigo-0.9.99'), 'old');
        fs.writeFileSync(path.join(binDir, 'fuigo-1.0.0'), 'v1');
        fs.writeFileSync(path.join(binDir, 'fuigo-1.0.1'), 'current');

        cleanupOldVersions(binDir, 'fuigo-1.0.1');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-1.0.0')), '1.0.0 should be kept (N-1)');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.9.99')), '0.9.99 should be removed');
    } finally {
        cleanup(dir);
    }
});

test('semver sort: minor version boundary (0.1.x vs 0.2.x)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.999'), 'old');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.2.0'), 'v2');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.2.1'), 'current');

        cleanupOldVersions(binDir, 'fuigo-0.2.1');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.2.0')), '0.2.0 should be kept (N-1)');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.999')), '0.1.999 should be removed');
    } finally {
        cleanup(dir);
    }
});

test('byVersionDescending: unit test comparator directly', () => {
    const input = ['fuigo-0.1.9', 'fuigo-0.1.10', 'fuigo-0.1.2', 'fuigo-1.0.0', 'fuigo-0.2.0'];
    const sorted = [...input].sort(byVersionDescending('fuigo-'));
    assert.deepStrictEqual(sorted, [
        'fuigo-1.0.0',
        'fuigo-0.2.0',
        'fuigo-0.1.10',
        'fuigo-0.1.9',
        'fuigo-0.1.2',
    ]);
});

// ═══════════════════════════════════════════════════════════════════════
// Bootstrap Tests
// ═══════════════════════════════════════════════════════════════════════

console.log('\nbootstrap tests\n');

test('bootstrapCanonical creates versioned binary from vendored', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored-fuigo');
        fs.writeFileSync(vendored, 'vendored-content');

        const result = bootstrapCanonical(vendored, '0.1.140', binDir);

        assert.strictEqual(result, path.join(binDir, 'fuigo'));
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.140')), 'versioned binary should exist');
        assert.ok(fs.lstatSync(result).isSymbolicLink(), 'canonical should be symlink');
        assert.strictEqual(fs.readFileSync(result, 'utf8'), 'vendored-content');
    } finally {
        cleanup(dir);
    }
});

test('bootstrapCanonical is idempotent', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored-fuigo');
        fs.writeFileSync(vendored, 'original-content');

        bootstrapCanonical(vendored, '0.1.140', binDir);

        // Change vendored content (simulating npm update)
        fs.writeFileSync(vendored, 'npm-replaced-content');

        // Second bootstrap should not overwrite existing versioned binary
        const result = bootstrapCanonical(vendored, '0.1.140', binDir);

        assert.strictEqual(
            fs.readFileSync(path.join(binDir, 'fuigo-0.1.140'), 'utf8'),
            'original-content',
            'should keep original, not npm-replaced version'
        );
    } finally {
        cleanup(dir);
    }
});

test('bootstrapCanonical returns vendored path on failure', () => {
    // If the canonical dir can't be created (e.g. permission denied),
    // bootstrap should gracefully fall back to the vendored binary.
    const dir = makeTmpDir();
    try {
        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'fallback');

        // Create a regular file where the dir should be — mkdirSync will fail.
        const blockerFile = path.join(dir, 'blocked');
        fs.writeFileSync(blockerFile, 'I am a file, not a directory');
        const impossibleDir = path.join(blockerFile, 'subdir');

        const result = bootstrapCanonical(vendored, '0.1.140', impossibleDir);

        assert.strictEqual(result, vendored, 'should fall back to vendored path');
    } finally {
        cleanup(dir);
    }
});

test('bootstrapCanonical works when canonical already exists (different version)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');

        // Install v1 via postinstall
        const vendored1 = path.join(dir, 'vendored-v1');
        fs.writeFileSync(vendored1, 'v1');
        installVersionedBinary(vendored1, '0.1.140', binDir);

        // Bootstrap with v2 (simulates the launcher running a newer vendored binary)
        const vendored2 = path.join(dir, 'vendored-v2');
        fs.writeFileSync(vendored2, 'v2');
        const result = bootstrapCanonical(vendored2, '0.1.141', binDir);

        assert.strictEqual(result, path.join(binDir, 'fuigo'));
        // Symlink should now point to v2
        assert.strictEqual(fs.readlinkSync(result), 'fuigo-0.1.141');
        // v1 should still exist
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.140')), 'old version should still exist');
    } finally {
        cleanup(dir);
    }
});

// ═══════════════════════════════════════════════════════════════════════
// End-to-end Scenario Tests
// ═══════════════════════════════════════════════════════════════════════

console.log('\nend-to-end scenario tests\n');

test('full lifecycle: install, upgrade, cleanup', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');

        // v1: fresh install
        fs.writeFileSync(vendored, 'v1');
        installVersionedBinary(vendored, '0.1.140', binDir);

        // v2: upgrade
        fs.writeFileSync(vendored, 'v2');
        installVersionedBinary(vendored, '0.1.141', binDir);

        // v3: another upgrade
        fs.writeFileSync(vendored, 'v3');
        installVersionedBinary(vendored, '0.1.142', binDir);
        cleanupOldVersions(binDir, 'fuigo-0.1.142');

        // Current (v3) + N-1 (v2) should exist; v1 removed
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.142')), 'v3 should exist');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'v2 should be kept (N-1)');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.140')), 'v1 should be removed');

        // Canonical symlink points to v3
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo')), 'fuigo-0.1.142');
        assert.strictEqual(fs.readFileSync(path.join(binDir, 'fuigo'), 'utf8'), 'v3');
    } finally {
        cleanup(dir);
    }
});

test('downgrade: installing older version than current', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');

        // Install v2 first
        fs.writeFileSync(vendored, 'v2');
        installVersionedBinary(vendored, '0.1.141', binDir);

        // Downgrade to v1
        fs.writeFileSync(vendored, 'v1');
        installVersionedBinary(vendored, '0.1.140', binDir);

        // Symlink should now point to v1
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo')), 'fuigo-0.1.140');
        assert.strictEqual(fs.readFileSync(path.join(binDir, 'fuigo'), 'utf8'), 'v1');

        // v2 should still exist (never delete old binaries during install)
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'v2 should still exist');
    } finally {
        cleanup(dir);
    }
});

test('non-fuigo files in bin dir are not touched by cleanup', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // Non-fuigo files
        fs.writeFileSync(path.join(binDir, 'other-tool'), 'should-stay');
        fs.writeFileSync(path.join(binDir, 'README.md'), 'should-stay');

        // Fuigo versions
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.138'), 'old1');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.139'), 'old2');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.140'), 'current');

        cleanupOldVersions(binDir, 'fuigo-0.1.140');

        assert.ok(fs.existsSync(path.join(binDir, 'other-tool')), 'non-fuigo file should not be touched');
        assert.ok(fs.existsSync(path.join(binDir, 'README.md')), 'non-fuigo file should not be touched');
    } finally {
        cleanup(dir);
    }
});

// ═══════════════════════════════════════════════════════════════════════
// fuigo vs fuigo-pager Isolation Tests
// ═══════════════════════════════════════════════════════════════════════

console.log('\nfuigo vs fuigo-pager isolation tests\n');

/**
 * Cleanup for a named binary (mirrors fuigo-install.js cleanupOldVersions).
 * Uses prefix + leading digit to avoid fuigo-* matching fuigo-pager-*.
 */
function cleanupOldVersionsNamed(canonicalDir, binName, version) {
    const prefix = `${binName}-`;
    const currentVersioned = `${binName}-${version}`;
    const entries = fs.readdirSync(canonicalDir);
    const versionedBinaries = entries
        .filter(e => {
            if (!e.startsWith(prefix)) return false;
            if (e.includes('.tmp.') || e.includes('.link.')) return false;
            if (e === currentVersioned) return false;
            const suffix = e.slice(prefix.length);
            return /^\d/.test(suffix);
        })
        .sort(byVersionDescending(prefix));
    for (const old of versionedBinaries.slice(1)) {
        try { fs.unlinkSync(path.join(canonicalDir, old)); } catch {}
    }
    return versionedBinaries;
}

/** Install a named binary (mirrors fuigo-install.js installBinary). */
function installNamedBinary(vendoredBinPath, binName, version, canonicalDir) {
    fs.mkdirSync(canonicalDir, { recursive: true });
    const versionedName = `${binName}-${version}`;
    const versionedPath = path.join(canonicalDir, versionedName);
    const canonicalPath = path.join(canonicalDir, binName);

    if (!fs.existsSync(versionedPath)) {
        const tmpPath = versionedPath + `.tmp.${process.pid}`;
        try {
            fs.copyFileSync(vendoredBinPath, tmpPath);
            fs.chmodSync(tmpPath, 0o755);
            fs.renameSync(tmpPath, versionedPath);
        } finally {
            try { fs.unlinkSync(tmpPath); } catch {}
        }
    }

    const tmpLink = canonicalPath + `.link.${process.pid}`;
    try { fs.unlinkSync(tmpLink); } catch {}
    fs.symlinkSync(versionedName, tmpLink);
    fs.renameSync(tmpLink, canonicalPath);

    return { canonicalPath, versionedPath, versionedName };
}

test('installing both fuigo and fuigo-pager creates independent symlinks', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'fuigo-binary');
        const vendoredPager = path.join(dir, 'vendored-pager');
        fs.writeFileSync(vendoredPager, 'pager-binary');

        installNamedBinary(vendored, 'fuigo', '0.1.141', binDir);
        installNamedBinary(vendoredPager, 'fuigo-pager', '0.1.141', binDir);

        // Both symlinks exist and point to correct targets
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo')), 'fuigo-0.1.141');
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo-pager')), 'fuigo-pager-0.1.141');

        // Both versioned files exist with correct content
        assert.strictEqual(fs.readFileSync(path.join(binDir, 'fuigo-0.1.141'), 'utf8'), 'fuigo-binary');
        assert.strictEqual(fs.readFileSync(path.join(binDir, 'fuigo-pager-0.1.141'), 'utf8'), 'pager-binary');
    } finally {
        cleanup(dir);
    }
});

test('cleanup of fuigo-* does not remove fuigo-pager-*', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // Old fuigo versions
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.138'), 'old-grok-1');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.139'), 'old-grok-2');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.140'), 'old-grok-3');
        // Current fuigo
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.141'), 'current-fuigo');

        // fuigo-pager versions (should not be touched)
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.138'), 'old-pager-1');
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.139'), 'old-pager-2');
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.141'), 'current-pager');

        cleanupOldVersionsNamed(binDir, 'fuigo', '0.1.141');

        // fuigo cleanup: current + N-1 kept, older removed
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'current fuigo should exist');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.140')), 'N-1 fuigo should be kept');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.139')), 'N-2 fuigo should be removed');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.138')), 'N-3 fuigo should be removed');

        // ALL fuigo-pager versions must be untouched
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.138')), 'fuigo-pager-0.1.138 must survive fuigo cleanup');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.139')), 'fuigo-pager-0.1.139 must survive fuigo cleanup');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.141')), 'fuigo-pager-0.1.141 must survive fuigo cleanup');
    } finally {
        cleanup(dir);
    }
});

test('cleanup of fuigo-pager-* does not remove fuigo-*', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // fuigo versions (should not be touched)
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.138'), 'old-grok-1');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.139'), 'old-grok-2');
        fs.writeFileSync(path.join(binDir, 'fuigo-0.1.141'), 'current-fuigo');

        // Old fuigo-pager versions
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.138'), 'old-pager-1');
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.139'), 'old-pager-2');
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.140'), 'old-pager-3');
        // Current pager
        fs.writeFileSync(path.join(binDir, 'fuigo-pager-0.1.141'), 'current-pager');

        cleanupOldVersionsNamed(binDir, 'fuigo-pager', '0.1.141');

        // fuigo-pager cleanup: current + N-1 kept, older removed
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.141')), 'current pager should exist');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.140')), 'N-1 pager should be kept');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.139')), 'N-2 pager should be removed');
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.138')), 'N-3 pager should be removed');

        // ALL fuigo versions must be untouched
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.138')), 'fuigo-0.1.138 must survive pager cleanup');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.139')), 'fuigo-0.1.139 must survive pager cleanup');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')), 'fuigo-0.1.141 must survive pager cleanup');
    } finally {
        cleanup(dir);
    }
});

test('full dual-binary lifecycle: install, upgrade, cleanup both', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');
        const vendoredPager = path.join(dir, 'vendored-pager');

        // v1
        fs.writeFileSync(vendored, 'fuigo-v1');
        fs.writeFileSync(vendoredPager, 'pager-v1');
        installNamedBinary(vendored, 'fuigo', '0.1.140', binDir);
        installNamedBinary(vendoredPager, 'fuigo-pager', '0.1.140', binDir);

        // v2
        fs.writeFileSync(vendored, 'fuigo-v2');
        fs.writeFileSync(vendoredPager, 'pager-v2');
        installNamedBinary(vendored, 'fuigo', '0.1.141', binDir);
        installNamedBinary(vendoredPager, 'fuigo-pager', '0.1.141', binDir);

        // v3
        fs.writeFileSync(vendored, 'fuigo-v3');
        fs.writeFileSync(vendoredPager, 'pager-v3');
        installNamedBinary(vendored, 'fuigo', '0.1.142', binDir);
        installNamedBinary(vendoredPager, 'fuigo-pager', '0.1.142', binDir);

        // Cleanup both independently
        cleanupOldVersionsNamed(binDir, 'fuigo', '0.1.142');
        cleanupOldVersionsNamed(binDir, 'fuigo-pager', '0.1.142');

        // Current + N-1 for each
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.142')));
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.141')));
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-0.1.140')));

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.142')));
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.141')));
        assert.ok(!fs.existsSync(path.join(binDir, 'fuigo-pager-0.1.140')));

        // Symlinks correct
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo')), 'fuigo-0.1.142');
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo-pager')), 'fuigo-pager-0.1.142');
    } finally {
        cleanup(dir);
    }
});

// ═══════════════════════════════════════════════════════════════════════
// macOS-only Pager Platform Split Tests
// ═══════════════════════════════════════════════════════════════════════

console.log('\nmacOS-only pager platform split tests\n');

test('fuigo installs normally regardless of platform key', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored-fuigo');
        fs.writeFileSync(vendored, 'fuigo-binary');

        for (const platform of ['darwin-arm64', 'linux-x64', 'linux-arm64']) {
            const result = installNamedBinary(vendored, 'fuigo', '0.1.150', binDir);
            assert.ok(fs.existsSync(result.versionedPath), `fuigo should install for ${platform}`);
            assert.strictEqual(fs.readlinkSync(result.canonicalPath), 'fuigo-0.1.150');
        }
    } finally {
        cleanup(dir);
    }
});

test('fuigo-pager installs when vendored binary exists (darwin-arm64 path)', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendoredPager = path.join(dir, 'vendored-pager');
        fs.writeFileSync(vendoredPager, 'pager-binary');

        const result = installNamedBinary(vendoredPager, 'fuigo-pager', '0.1.150', binDir);
        assert.ok(fs.existsSync(result.versionedPath), 'pager versioned binary should exist');
        assert.strictEqual(fs.readlinkSync(result.canonicalPath), 'fuigo-pager-0.1.150');
        assert.strictEqual(fs.readFileSync(result.canonicalPath, 'utf8'), 'pager-binary');
    } finally {
        cleanup(dir);
    }
});

test('Linux pager vendor files are not required for fuigo install', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendorBase = path.join(dir, 'vendor');

        // Only darwin-arm64 pager exists (mirrors npm tarball)
        fs.mkdirSync(path.join(vendorBase, 'darwin-arm64'), { recursive: true });
        fs.writeFileSync(path.join(vendorBase, 'darwin-arm64', 'fuigo-pager'), 'mac-pager');

        // Linux pager vendor dirs exist but without pager binaries
        fs.mkdirSync(path.join(vendorBase, 'linux-x64'), { recursive: true });
        fs.mkdirSync(path.join(vendorBase, 'linux-arm64'), { recursive: true });

        // Verify no Linux pager binaries
        assert.ok(!fs.existsSync(path.join(vendorBase, 'linux-x64', 'fuigo-pager')));
        assert.ok(!fs.existsSync(path.join(vendorBase, 'linux-arm64', 'fuigo-pager')));

        // fuigo install should succeed independently
        const fuigoVendored = path.join(dir, 'vendored-fuigo');
        fs.writeFileSync(fuigoVendored, 'fuigo-linux');
        const result = installNamedBinary(fuigoVendored, 'fuigo', '0.1.150', binDir);
        assert.ok(fs.existsSync(result.versionedPath), 'fuigo should install without Linux pager');
    } finally {
        cleanup(dir);
    }
});

test('skipping pager install on Linux does not affect fuigo cleanup', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        const vendored = path.join(dir, 'vendored');

        // Install fuigo across two versions
        fs.writeFileSync(vendored, 'fuigo-v1');
        installNamedBinary(vendored, 'fuigo', '0.1.149', binDir);
        fs.writeFileSync(vendored, 'fuigo-v2');
        installNamedBinary(vendored, 'fuigo', '0.1.150', binDir);

        // Simulate Linux: only run fuigo cleanup, skip pager entirely
        cleanupOldVersionsNamed(binDir, 'fuigo', '0.1.150');

        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.150')), 'current fuigo should exist');
        assert.ok(fs.existsSync(path.join(binDir, 'fuigo-0.1.149')), 'N-1 fuigo should be kept');
        assert.strictEqual(fs.readlinkSync(path.join(binDir, 'fuigo')), 'fuigo-0.1.150');

        // No pager files should exist at all
        const entries = fs.readdirSync(binDir);
        const pagerEntries = entries.filter(e => e.includes('pager'));
        assert.strictEqual(pagerEntries.length, 0, 'no pager artifacts on Linux');
    } finally {
        cleanup(dir);
    }
});

test('canonical pager from non-npm install is preserved on Linux', () => {
    const dir = makeTmpDir();
    try {
        const binDir = path.join(dir, 'bin');
        fs.mkdirSync(binDir, { recursive: true });

        // Simulate pager installed by install-fuigo.sh (not npm)
        const pagerVersioned = path.join(binDir, 'fuigo-pager-0.1.150');
        fs.writeFileSync(pagerVersioned, 'installer-pager-binary');
        fs.chmodSync(pagerVersioned, 0o755);
        const pagerCanonical = path.join(binDir, 'fuigo-pager');
        fs.symlinkSync('fuigo-pager-0.1.150', pagerCanonical);

        // Run fuigo-only install + cleanup (simulating Linux postinstall)
        const vendored = path.join(dir, 'vendored');
        fs.writeFileSync(vendored, 'fuigo-binary');
        installNamedBinary(vendored, 'fuigo', '0.1.150', binDir);
        cleanupOldVersionsNamed(binDir, 'fuigo', '0.1.150');

        // Pager installed by other means must be untouched
        assert.ok(fs.existsSync(pagerCanonical), 'canonical pager should survive');
        assert.ok(fs.existsSync(pagerVersioned), 'versioned pager should survive');
        assert.strictEqual(fs.readlinkSync(pagerCanonical), 'fuigo-pager-0.1.150');
    } finally {
        cleanup(dir);
    }
});

console.log('\nfuigo home + brotli install tests\n');

test('resolveFuigoBinDir honors $FUIGO_HOME, else falls back to <home>/.fuigo/bin', () => {
    assert.strictEqual(
        resolveFuigoBinDir({ FUIGO_HOME: '/fast/local/.fuigo' }, '/home/alice'),
        path.join('/fast/local/.fuigo', 'bin'),
    );
    assert.strictEqual(
        resolveFuigoBinDir({}, '/home/alice'),
        path.join('/home/alice', '.fuigo', 'bin'),
    );
    assert.strictEqual(resolveFuigoBinDir({ FUIGO_HOME: '' }, '/home/alice'), path.join('', 'bin'));
});

test('writeVendorBinary returns false (not true) when the destination cannot be written', () => {
    const dir = makeTmpDir();
    try {
        const brotliPath = path.join(dir, 'fuigo.br');
        fs.writeFileSync(brotliPath, zlib.brotliCompressSync(Buffer.from('binary')));

        // A non-empty directory at destPath makes the final rename fail.
        const dest = path.join(dir, 'dest');
        fs.mkdirSync(dest);
        fs.writeFileSync(path.join(dest, 'child'), 'x');

        assert.strictEqual(writeVendorBinary(brotliPath, path.join(dir, 'raw'), dest), false);
        assert.ok(!fs.existsSync(`${dest}.tmp.${process.pid}`), 'temp file is cleaned up on failure');
    } finally {
        cleanup(dir);
    }
});

test('decompresses brotli into the canonical dir without duplicating into node_modules', () => {
    const dir = makeTmpDir();
    try {
        const vendorBin = path.join(dir, 'node_modules', 'bin');
        fs.mkdirSync(vendorBin, { recursive: true });
        const brotliPath = path.join(vendorBin, 'fuigo.br');
        fs.writeFileSync(brotliPath, zlib.brotliCompressSync(Buffer.from('native-binary-bytes')));

        const binDir = path.join(dir, '.fuigo', 'bin');
        const result = installBinaryFromBrotli(brotliPath, '0.1.220', binDir);

        assert.ok(fs.lstatSync(result.canonicalPath).isSymbolicLink());
        assert.strictEqual(fs.readFileSync(result.canonicalPath, 'utf8'), 'native-binary-bytes');
        assert.ok(!fs.existsSync(path.join(vendorBin, 'fuigo')), 'no uncompressed binary in node_modules');
        assert.ok(fs.existsSync(brotliPath), 'compressed .br payload is preserved');
    } finally {
        cleanup(dir);
    }
});

if (process.platform !== 'win32') {
    console.log('\nbin link tests\n');

    const { spawnSync } = require('child_process');

    /** Extract the native binary beside the entry and link to it (mirrors installBinLink). */
    function installBinLink(pkgBinDir, vendorBinary) {
        const nativePath = path.join(pkgBinDir, 'fuigo-native');
        if (!writeVendorBinary(vendorBinary + '.br', vendorBinary, nativePath)) {
            return;
        }
        const entryPath = path.join(pkgBinDir, 'fuigo');
        const tmp = entryPath + `.link.${process.pid}`;
        try { fs.unlinkSync(tmp); } catch {}
        fs.symlinkSync('./fuigo-native', tmp);
        fs.renameSync(tmp, entryPath);
    }

    test('bin entry links to the sibling native binary and launches with args', () => {
        const dir = makeTmpDir();
        try {
            const vendorBinary = path.join(dir, 'platform', 'bin', 'fuigo');
            fs.mkdirSync(path.dirname(vendorBinary), { recursive: true });
            fs.writeFileSync(vendorBinary, '#!/bin/sh\necho "REAL|$@"\n');

            // npm-style layout: the PATH entry is a symlink to the package entry.
            const pkgBinDir = path.join(dir, 'pkg-bin');
            const entryPath = path.join(pkgBinDir, 'fuigo');
            fs.mkdirSync(pkgBinDir, { recursive: true });
            fs.writeFileSync(entryPath, '#!/usr/bin/env node\n');
            const pathEntry = path.join(dir, 'npm-bin', 'fuigo');
            fs.mkdirSync(path.dirname(pathEntry), { recursive: true });
            fs.symlinkSync(entryPath, pathEntry);

            installBinLink(pkgBinDir, vendorBinary);

            assert.ok(fs.lstatSync(entryPath).isSymbolicLink(), 'entry should be a symlink');
            assert.strictEqual(fs.readlinkSync(entryPath), './fuigo-native');
            const res = spawnSync(pathEntry, ['hello', 'a b'], { encoding: 'utf8' });
            assert.strictEqual(res.status, 0, `launch failed: ${res.stderr}`);
            assert.strictEqual(res.stdout.trim(), 'REAL|hello a b');

            // Entry and binary share one lifetime: deleting unrelated state
            // (the fuigo home) cannot dangle the entry.
            const res2 = spawnSync(pathEntry, ['x'], { encoding: 'utf8' });
            assert.strictEqual(res2.stdout.trim(), 'REAL|x');
        } finally {
            cleanup(dir);
        }
    });

    test('replacing the entry twice leaves one valid link and no temp files', () => {
        const dir = makeTmpDir();
        try {
            const vendorBinary = path.join(dir, 'vendor', 'fuigo');
            fs.mkdirSync(path.dirname(vendorBinary), { recursive: true });
            fs.writeFileSync(vendorBinary, 'binary');
            const entryPath = path.join(dir, 'fuigo');
            fs.writeFileSync(entryPath, '#!/usr/bin/env node\n');

            installBinLink(dir, vendorBinary);
            installBinLink(dir, vendorBinary);

            assert.ok(fs.lstatSync(entryPath).isSymbolicLink());
            assert.strictEqual(fs.readFileSync(entryPath, 'utf8'), 'binary');
            assert.strictEqual(fs.readdirSync(dir).filter(e => e.includes('.link.') || e.includes('.tmp.')).length, 0, 'no temp files left');
        } finally {
            cleanup(dir);
        }
    });

    test('mirrored link matches fuigo-install.js and the shipped entry wires the bootstrap', () => {
        const pkgRoot = path.join(__dirname, '..');
        const installer = fs.readFileSync(path.join(pkgRoot, 'bin', 'fuigo-install.js'), 'utf8');
        for (const line of [
            "if (agent && !agent.startsWith('npm/')) return;",
            "fs.symlinkSync('./fuigo-native', tmp);",
        ]) {
            assert.ok(installer.includes(line), `fuigo-install.js lost link line: ${line}`);
        }
        const launcher = fs.readFileSync(path.join(pkgRoot, 'bin', 'fuigo'), 'utf8');
        assert.ok(launcher.startsWith('#!/usr/bin/env node'), 'shipped entry must stay a node script for Windows cmd shims');
        assert.ok(launcher.includes("require('./fuigo-bootstrap.js')"), 'entry must run the bootstrap');
        assert.ok(fs.existsSync(path.join(pkgRoot, 'bin', 'fuigo-bootstrap.js')), 'bootstrap must ship in bin/');
        assert.ok(fs.existsSync(path.join(pkgRoot, 'bin', 'fuigo-install.js')), 'installer must ship in bin/');
    });
}

test('package.json declares no install script (npm 11 warns about every package that has one)', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
        assert.strictEqual(manifest.scripts[hook], undefined, `scripts.${hook} must not exist`);
    }
    assert.ok(!fs.existsSync(path.join(__dirname, '..', 'bin', 'post' + 'install.js')), 'the postinstall script must be gone');
    assert.ok(manifest.files.includes('bin/'), 'bin/ (launcher + installer) must ship');
});

// ─── First-run install (runs the real bin/fuigo-bootstrap.js) ───────────

if (process.platform !== 'win32') {
    console.log('\nfirst-run install tests\n');

    const { spawnSync } = require('child_process');
    const platformKey = `${process.platform}-${process.arch}`;
    const supported = ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64'].includes(platformKey);
    const pkgRoot = path.join(__dirname, '..');

    /**
     * Lay out an installed package around the shipped bin/: the platform package with a
     * brotli stub binary, and a stub @iarna/toml (the release job does not `npm install`).
     * The npm-style PATH entry is a symlink to bin/fuigo, as npm makes it.
     */
    function sandboxPackage(dir, { version = '1.2.3', payload = 'v1', local = false, nmDir = null } = {}) {
        // A global npm install lives under <prefix>/lib/node_modules; a project-local one under <project>/node_modules.
        const nm = nmDir ?? (local ? path.join(dir, 'node_modules') : path.join(dir, 'lib', 'node_modules'));
        const pkg = path.join(nm, 'fuigo');
        fs.mkdirSync(path.join(pkg, 'bin'), { recursive: true });
        for (const f of ['fuigo', 'fuigo-bootstrap.js', 'fuigo-install.js', 'fuigo-replace.js']) {
            fs.copyFileSync(path.join(pkgRoot, 'bin', f), path.join(pkg, 'bin', f));
        }
        fs.chmodSync(path.join(pkg, 'bin', 'fuigo'), 0o755);
        fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'fuigo', version }));
        const toml = path.join(nm, '@iarna', 'toml');
        fs.mkdirSync(toml, { recursive: true });
        fs.writeFileSync(path.join(toml, 'package.json'), '{"name":"@iarna/toml","main":"index.js"}');
        fs.writeFileSync(path.join(toml, 'index.js'),
            'module.exports = { parse: (t) => JSON.parse(t.replace(/^#.*$/m, "") || "{}"), stringify: (o) => "# stub\\n" + JSON.stringify(o) };');
        const platform = path.join(nm, '@fuigo', platformKey);
        fs.mkdirSync(path.join(platform, 'bin'), { recursive: true });
        fs.writeFileSync(path.join(platform, 'package.json'), `{"name":"@fuigo/${platformKey}","version":"${version}"}`);
        setPayload(nm, payload);
        const pathEntry = path.join(dir, 'bin', 'fuigo');
        fs.mkdirSync(path.dirname(pathEntry), { recursive: true });
        fs.symlinkSync(path.join(pkg, 'bin', 'fuigo'), pathEntry);
        // A default-layout global sandbox is named as npm's prefix, as `npm config get prefix` would be.
        return { pkg, pathEntry, prefix: local || nmDir ? null : dir };
    }

    /** Replace the vendored binary (a same-version reinstall with a different build). */
    function setPayload(nm, payload) {
        const br = path.join(nm, '@fuigo', platformKey, 'bin', 'fuigo.br');
        fs.writeFileSync(br, zlib.brotliCompressSync(Buffer.from(`#!/bin/sh\necho "${payload} $*"\n`)));
        const future = new Date(Date.now() + 5000 * (setPayload.n = (setPayload.n || 0) + 1));
        fs.utimesSync(br, future, future);
    }

    function run(sb, home, args = ['arg'], extraEnv = {}, opts = {}) {
        const env = { ...process.env, HOME: home, FUIGO_HOME: path.join(home, '.fuigo'),
            FUIGO_NPM_REGISTRY: 'https://registry.invalid/', ...extraEnv };
        delete env.FUIGO_INSTALL_COMPLETIONS;
        if (sb.prefix && !('FUIGO_NPM_PREFIX' in extraEnv)) env.FUIGO_NPM_PREFIX = sb.prefix;
        // The launch environment of a real run: no package-manager variables.
        for (const k of ['npm_config_user_agent', 'npm_config_prefix', 'FUIGO_INSTALL_ONLY']) {
            if (!(k in extraEnv)) delete env[k];
        }
        return spawnSync(sb.pathEntry, args, { encoding: 'utf8', env, ...opts });
    }

    test('first run installs like postinstall did: versioned binary, symlink, config, bin link, clean stdout', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const sb = sandboxPackage(dir);
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            const res = run(sb, home, ['hello', 'a b']);
            assert.strictEqual(res.status, 0, res.stderr);
            assert.strictEqual(res.stdout, 'v1 hello a b\n', 'stdout must be only the program output');
            const bin = path.join(home, '.fuigo', 'bin');
            assert.ok(fs.statSync(path.join(bin, 'fuigo-1.2.3')).mode & 0o100, 'versioned binary is executable');
            assert.strictEqual(fs.readlinkSync(path.join(bin, 'fuigo')), 'fuigo-1.2.3');
            assert.strictEqual(fs.readlinkSync(path.join(sb.pkg, 'bin', 'fuigo')), './fuigo-native');
            const cfg = fs.readFileSync(path.join(home, '.fuigo', 'config.toml'), 'utf8');
            assert.ok(cfg.includes('"installer":"npm"'), `installer not recorded: ${cfg}`);
            assert.ok(cfg.includes('registry.invalid'), `registry not recorded: ${cfg}`);
            // Second run goes through the symlinked native binary.
            const res2 = run(sb, home, ['again']);
            assert.strictEqual(res2.stdout, 'v1 again\n');
        } finally { cleanup(dir); }
    });

    test('node launcher stays when the entry is not reached through a symlink (non-npm wrappers)', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const sb = sandboxPackage(dir);
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            const env = { ...process.env, HOME: home, FUIGO_HOME: path.join(home, '.fuigo'), FUIGO_NPM_REGISTRY: 'https://registry.invalid/' };
            const res = spawnSync(process.execPath, [path.join(sb.pkg, 'bin', 'fuigo'), 'x'], { encoding: 'utf8', env });
            assert.strictEqual(res.stdout, 'v1 x\n', res.stderr);
            assert.ok(!fs.lstatSync(path.join(sb.pkg, 'bin', 'fuigo')).isSymbolicLink(), 'entry must be left alone');
            assert.ok(!fs.existsSync(path.join(sb.pkg, 'bin', 'fuigo-native')));
        } finally { cleanup(dir); }
    });

    test('other package managers (user agent) keep the node launcher', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const sb = sandboxPackage(dir);
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            const res = run(sb, home, ['x'], { npm_config_user_agent: 'pnpm/9.0.0 npm/? node/v22' });
            assert.strictEqual(res.stdout, 'v1 x\n', res.stderr);
            assert.ok(!fs.lstatSync(path.join(sb.pkg, 'bin', 'fuigo')).isSymbolicLink());
        } finally { cleanup(dir); }
    });

    test('upgrade: a canonical binary from an older version is replaced on first run', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            const old = sandboxPackage(dir, { version: '1.2.2', payload: 'old' });
            assert.strictEqual(run(old, home).stdout, 'old arg\n');
            cleanup(path.join(dir, 'lib')); cleanup(path.join(dir, 'bin'));
            const next = sandboxPackage(dir, { version: '1.2.3', payload: 'new' });
            assert.strictEqual(run(next, home).stdout, 'new arg\n', 'must not keep running the old canonical binary');
            const bin = path.join(home, '.fuigo', 'bin');
            assert.strictEqual(fs.readlinkSync(path.join(bin, 'fuigo')), 'fuigo-1.2.3');
            assert.ok(fs.existsSync(path.join(bin, 'fuigo-1.2.2')), 'previous version is kept');
        } finally { cleanup(dir); }
    });

    test('same-version reinstall with a changed binary is picked up', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            let sb = sandboxPackage(dir, { payload: 'build-a' });
            assert.strictEqual(run(sb, home).stdout, 'build-a arg\n');
            cleanup(path.join(dir, 'lib')); cleanup(path.join(dir, 'bin'));
            sb = sandboxPackage(dir, { payload: 'build-b' });
            assert.strictEqual(run(sb, home).stdout, 'build-b arg\n');
            assert.strictEqual(fs.readFileSync(path.join(home, '.fuigo', 'bin', 'fuigo-1.2.3'), 'utf8'), '#!/bin/sh\necho "build-b $*"\n');
        } finally { cleanup(dir); }
    });

    test('a current install is not rewritten by later node launches (stamp fast path)', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const sb = sandboxPackage(dir);
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            const env = { ...process.env, HOME: home, FUIGO_HOME: path.join(home, '.fuigo'), FUIGO_NPM_REGISTRY: 'https://registry.invalid/', FUIGO_NPM_PREFIX: sb.prefix };
            const boot = path.join(sb.pkg, 'bin', 'fuigo-bootstrap.js');
            spawnSync(process.execPath, [boot], { encoding: 'utf8', env });
            const bin = path.join(home, '.fuigo', 'bin');
            const cfg = path.join(home, '.fuigo', 'config.toml');
            const before = [fs.statSync(path.join(bin, 'fuigo-1.2.3')).ino, fs.lstatSync(path.join(bin, 'fuigo')).ino,
                fs.statSync(cfg).mtimeMs];
            const res = spawnSync(process.execPath, [boot, 'z'], { encoding: 'utf8', env });
            assert.strictEqual(res.stdout, 'v1 z\n');
            const after = [fs.statSync(path.join(bin, 'fuigo-1.2.3')).ino, fs.lstatSync(path.join(bin, 'fuigo')).ino,
                fs.statSync(cfg).mtimeMs];
            assert.deepStrictEqual(after, before);
        } finally { cleanup(dir); }
    });

    test('a fresh Fuigo home is 0700 under umask 002; an existing 775 home is left alone', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        const oldMask = process.umask(0o002);
        try {
            const sb = sandboxPackage(dir);
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            assert.strictEqual(run(sb, home).status, 0);
            assert.strictEqual(fs.statSync(path.join(home, '.fuigo')).mode & 0o777, 0o700, 'fresh home must be 0700');
            const dir2 = path.join(dir, 'twox');
            fs.mkdirSync(dir2);
            const sb2 = sandboxPackage(dir2);
            const home2 = path.join(dir, 'home2');
            fs.mkdirSync(path.join(home2, '.fuigo'), { recursive: true });
            fs.chmodSync(path.join(home2, '.fuigo'), 0o775);
            assert.strictEqual(run(sb2, home2).status, 0);
            assert.strictEqual(fs.statSync(path.join(home2, '.fuigo')).mode & 0o777, 0o775, 'an existing home must not be changed');
        } finally { process.umask(oldMask); cleanup(dir); }
    });

    test('P150: config.toml is created owner-only (0600) and an existing file keeps its mode', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = path.join(dir, 'home');
            fs.mkdirSync(home);
            let sb = sandboxPackage(dir, { payload: 'a' });
            assert.strictEqual(run(sb, home).status, 0);
            const configPath = path.join(home, '.fuigo', 'config.toml');
            assert.strictEqual(fs.statSync(configPath).mode & 0o777, 0o600);
            fs.chmodSync(configPath, 0o644);
            cleanup(path.join(dir, 'lib')); cleanup(path.join(dir, 'bin'));
            sb = sandboxPackage(dir, { payload: 'b', version: '1.2.4' });
            assert.strictEqual(run(sb, home).stdout, 'b arg\n');
            assert.strictEqual(fs.statSync(configPath).mode & 0o777, 0o644, 'an existing config.toml must keep its mode');
        } finally { cleanup(dir); }
    });
    // ─── P29-NPM-R2 ─────────────────────────────────────────────────────

    const linkOf = (home, name = 'fuigo') => fs.readlinkSync(path.join(home, '.fuigo', 'bin', name));
    const mkHome = (dir, name = 'home') => { const h = path.join(dir, name); fs.mkdirSync(h, { recursive: true }); return h; };

    test('F5: a local/npx install of another version does not touch ~/.fuigo and runs its own binary', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const global = sandboxPackage(path.join(dir, 'g'), { version: '1.2.3', payload: 'global' });
            assert.strictEqual(run(global, home).stdout, 'global arg\n');
            const cfgPath = path.join(home, '.fuigo', 'config.toml');
            const binDir = path.join(home, '.fuigo', 'bin');
            const snap = () => JSON.stringify([fs.readlinkSync(path.join(binDir, 'fuigo')), fs.readdirSync(binDir).sort(),
                fs.readFileSync(path.join(binDir, '.fuigo-npm-stamp'), 'utf8'), fs.readFileSync(cfgPath, 'utf8')]);
            const before = snap();
            // Older and newer project-local installs, launched repeatedly, alternate with the global one.
            for (const [version, payload] of [['1.2.2', 'local-old'], ['2.0.0', 'local-new']]) {
                const sb = sandboxPackage(path.join(dir, `p-${version}`), { version, payload, local: true });
                for (let n = 0; n < 2; n++) {
                    assert.strictEqual(run(sb, home).stdout, `${payload} arg\n`);
                    assert.strictEqual(run(global, home).stdout, 'global arg\n', 'the global install still runs ITS binary');
                }
                assert.strictEqual(snap(), before, `a local ${version} install must not change ~/.fuigo`);
                assert.ok(!fs.lstatSync(path.join(sb.pkg, 'bin', 'fuigo')).isSymbolicLink(), 'no bin link swap for a local install');
            }
        } finally { cleanup(dir); }
    });

    test('F5: a local install on a fresh machine creates nothing under ~/.fuigo', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const sb = sandboxPackage(dir, { local: true });
            assert.strictEqual(run(sb, home).stdout, 'v1 arg\n');
            assert.ok(!fs.existsSync(path.join(home, '.fuigo')), '~/.fuigo must not be created by a local install');
        } finally { cleanup(dir); }
    });

    test('F5: a launch never downgrades ~/.fuigo/bin, an older global package runs in place', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const newer = sandboxPackage(path.join(dir, 'a'), { version: '1.2.3', payload: 'new' });
            assert.strictEqual(run(newer, home).stdout, 'new arg\n');
            const older = sandboxPackage(path.join(dir, 'b'), { version: '1.2.2', payload: 'old' });
            assert.strictEqual(run(older, home).stdout, 'old arg\n', 'the older package still runs its own binary');
            assert.strictEqual(linkOf(home), 'fuigo-1.2.3', 'launch must not move the link back');
            assert.ok(!fs.existsSync(path.join(home, '.fuigo', 'bin', 'fuigo-1.2.2')));
            // A prerelease of the same core is older than the release.
            const pre = sandboxPackage(path.join(dir, 'c'), { version: '1.2.3-alpha.1', payload: 'pre' });
            assert.strictEqual(run(pre, home).stdout, 'pre arg\n');
            assert.strictEqual(linkOf(home), 'fuigo-1.2.3');
        } finally { cleanup(dir); }
    });

    test('F5: a project .npmrc registry is not written to the global config.toml', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const project = mkHome(dir, 'project');
            fs.writeFileSync(path.join(project, '.npmrc'), 'registry=https://evil.invalid/\n');
            // A stand-in `npm` that answers like the real one: the project .npmrc of the CURRENT directory wins.
            const stub = path.join(dir, 'stub-bin');
            fs.mkdirSync(stub);
            fs.writeFileSync(path.join(stub, 'npm'),
                '#!/bin/sh\nif [ -f .npmrc ]; then sed -n "s/^registry=//p" .npmrc; else echo https://user.example/; fi\n', { mode: 0o755 });
            fs.writeFileSync(path.join(home, '.npmrc'), 'registry=https://user.example/\n');
            const sb = sandboxPackage(dir);
            const env = { PATH: `${stub}${path.delimiter}${process.env.PATH}` };
            // No FUIGO_NPM_REGISTRY, so the `npm config get registry` lookup is actually exercised.
            const e2 = { ...process.env, ...env, HOME: home, FUIGO_HOME: path.join(home, '.fuigo'), FUIGO_NPM_PREFIX: sb.prefix };
            delete e2.FUIGO_NPM_REGISTRY;
            const r2 = spawnSync(sb.pathEntry, ['x'], { encoding: 'utf8', env: e2, cwd: project });
            assert.strictEqual(r2.status, 0, r2.stderr);
            const cfg = fs.readFileSync(path.join(home, '.fuigo', 'config.toml'), 'utf8');
            assert.ok(!cfg.includes('evil.invalid'), `project registry leaked into config: ${cfg}`);
            assert.ok(cfg.includes('user.example'), `user registry expected: ${cfg}`);
        } finally { cleanup(dir); }
    });

    test('F6: an unparsable config.toml is left untouched; the install still completes', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            fs.mkdirSync(path.join(home, '.fuigo'));
            const cfgPath = path.join(home, '.fuigo', 'config.toml');
            const broken = '[cli\nauto_update = = tru\n# my settings\n';
            fs.writeFileSync(cfgPath, broken, { mode: 0o640 });
            const sb = sandboxPackage(dir);
            const res = run(sb, home);
            assert.strictEqual(res.stdout, 'v1 arg\n', res.stderr);
            assert.strictEqual(fs.readFileSync(cfgPath, 'utf8'), broken, 'settings must not be wiped');
            assert.strictEqual(fs.statSync(cfgPath).mode & 0o777, 0o640);
            assert.strictEqual(linkOf(home), 'fuigo-1.2.3', 'the binary install is independent of the config step');
            assert.deepStrictEqual(fs.readdirSync(path.join(home, '.fuigo')).filter((f) => f.includes('.tmp.')), []);
        } finally { cleanup(dir); }
    });

    test('F6: config.toml is written through a temp file and renamed (no partial file, no temp left)', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const sb = sandboxPackage(dir);
            assert.strictEqual(run(sb, home).status, 0);
            const files = fs.readdirSync(path.join(home, '.fuigo'));
            assert.deepStrictEqual(files.filter((f) => f.includes('.tmp.')), []);
            const cfg = path.join(home, '.fuigo', 'config.toml');
            assert.strictEqual(fs.statSync(cfg).mode & 0o777, 0o600);
            // Keep the existing keys when adding ours.
            fs.writeFileSync(cfg, '# keep\n{"cli":{"channel":"alpha"},"x":1}'.replace('# keep\n', '# keep\n'));
            cleanup(path.join(dir, 'lib')); cleanup(path.join(dir, 'bin'));
            const sb2 = sandboxPackage(dir, { version: '1.2.4', payload: 'v2' });
            assert.strictEqual(run(sb2, home).stdout, 'v2 arg\n');
            const after = fs.readFileSync(cfg, 'utf8');
            assert.ok(after.includes('"channel":"alpha"') && after.includes('"installer":"npm"') && after.includes('"x":1'), after);
        } finally { cleanup(dir); }
    });

    test('F7: no user agent at launch: the bin link is still npm-only (npm global yes; pnpm/yarn stores and projects no)', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const npm = sandboxPackage(path.join(dir, 'n'), { payload: 'n' });
            assert.strictEqual(run(npm, home).stdout, 'n arg\n');
            assert.strictEqual(fs.readlinkSync(path.join(npm.pkg, 'bin', 'fuigo')), './fuigo-native');
            for (const [name, rel] of [['pnpm', 'pnpm/global/5/node_modules'], ['yarn', 'yarn/global/node_modules'], ['project', 'proj/node_modules']]) {
                const d = path.join(dir, name);
                const sb = sandboxPackage(d, { payload: name, nmDir: path.join(d, rel) });
                const h = mkHome(dir, `home-${name}`);
                assert.strictEqual(run(sb, h).stdout, `${name} arg\n`, name);
                assert.ok(!fs.lstatSync(path.join(sb.pkg, 'bin', 'fuigo')).isSymbolicLink(), `${name}: stays on the node launcher`);
            }
        } finally { cleanup(dir); }
    });

    test('F2: pnpm/yarn global stores still manage ~/.fuigo; a project does not', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            for (const [name, rel, managed] of [['pnpm', 'pnpm/global/5/node_modules', true], ['yarn', 'yarn/global/node_modules', true],
                ['project', 'proj/node_modules', false]]) {
                const d = path.join(dir, name);
                const sb = sandboxPackage(d, { nmDir: path.join(d, rel) });
                const h = mkHome(dir, `home-${name}`);
                assert.strictEqual(run(sb, h).status, 0);
                assert.strictEqual(fs.existsSync(path.join(h, '.fuigo', 'bin', 'fuigo')), managed, name);
            }
        } finally { cleanup(dir); }
    });

    // The setup step Fuigo's own updater runs after `npm i -g` (crates/codegen/fuigo-update).
    const setupStep = (sb, home, extraEnv = {}) => spawnSync(process.execPath, [path.join(sb.pkg, 'bin', 'fuigo-bootstrap.js')], {
        encoding: 'utf8', env: { ...process.env, HOME: home, FUIGO_HOME: path.join(home, '.fuigo'), FUIGO_INSTALL_ONLY: '1',
            FUIGO_NPM_REGISTRY: 'https://registry.invalid/', ...(sb.prefix ? { FUIGO_NPM_PREFIX: sb.prefix } : {}), ...extraEnv },
    });

    test('P30: a local/npx copy is not npm-managed: FUIGO_NPM_LOCAL, no FUIGO_MANAGED_BY_NPM, ~/.fuigo untouched', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const local = sandboxPackage(path.join(dir, 'proj'), { local: true, payload: 'L=$FUIGO_NPM_LOCAL M=$FUIGO_MANAGED_BY_NPM' });
            const res = run(local, home, ['x'], { FUIGO_MANAGED_BY_NPM: '1' });
            assert.strictEqual(res.stdout, 'L=1 M= x\n', res.stderr);
            assert.ok(!fs.existsSync(path.join(home, '.fuigo', 'bin')), 'a local copy must not create ~/.fuigo/bin');
            assert.ok(!fs.existsSync(path.join(home, '.fuigo', 'config.toml')));
            const global = sandboxPackage(path.join(dir, 'g'), { payload: 'L=$FUIGO_NPM_LOCAL M=$FUIGO_MANAGED_BY_NPM' });
            assert.strictEqual(run(global, home, ['x']).stdout, 'L= M=1 x\n');
        } finally { cleanup(dir); }
    });

    test('P30: a project whose root dir is named lib is local, not global', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const sb = sandboxPackage(dir, { payload: 'L=$FUIGO_NPM_LOCAL', nmDir: path.join(dir, 'lib', 'node_modules') });
            fs.writeFileSync(path.join(dir, "lib", "package.json"), "{}");
            assert.strictEqual(run(sb, home, ['x']).stdout, 'L=1 x\n');
            assert.ok(!fs.existsSync(path.join(home, '.fuigo', 'bin')));
        } finally { cleanup(dir); }
    });

    test('P30: the setup step writes the FUIGO_INSTALL_REPORT file (version and package dir)', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const sb = sandboxPackage(dir, { version: '1.2.3' });
            const report = path.join(dir, 'report.json');
            const res = setupStep(sb, home, { FUIGO_INSTALL_REPORT: report });
            assert.strictEqual(res.status, 0, res.stderr);
            const got = JSON.parse(fs.readFileSync(report, 'utf8'));
            assert.strictEqual(got.version, '1.2.3');
            assert.strictEqual(fs.realpathSync(got.dir), fs.realpathSync(sb.pkg));
        } finally { cleanup(dir); }
    });

    test('F2: the setup step moves ~/.fuigo/bin to the new version without running the binary', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const old = sandboxPackage(dir, { version: '1.2.2', payload: 'old' });
            assert.strictEqual(run(old, home).stdout, 'old arg\n');
            assert.strictEqual(linkOf(home), 'fuigo-1.2.2');
            // `npm i -g fuigo@1.2.3` replaces the package; no install script runs.
            cleanup(path.join(dir, 'lib')); cleanup(path.join(dir, 'bin'));
            const next = sandboxPackage(dir, { version: '1.2.3', payload: 'new' });
            const res = setupStep(next, home);
            assert.strictEqual(res.status, 0, res.stderr);
            assert.strictEqual(res.stdout, '', 'the binary is not run and nothing is printed');
            assert.strictEqual(linkOf(home), 'fuigo-1.2.3', '~/.fuigo/bin/fuigo points at the new version');
            assert.strictEqual(fs.readlinkSync(path.join(next.pkg, 'bin', 'fuigo')), './fuigo-native', 'bin link set up for later launches');
            // The next launch goes straight to the new binary, no further install work.
            assert.strictEqual(run(next, home).stdout, 'new arg\n');
            assert.strictEqual(spawnSync(path.join(home, '.fuigo', 'bin', 'fuigo'), ['q'], { encoding: 'utf8' }).stdout, 'new q\n');
        } finally { cleanup(dir); }
    });

    test('F2: the setup step is an explicit request, so it may move to an older version', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const newer = sandboxPackage(path.join(dir, 'a'), { version: '1.2.3', payload: 'new' });
            assert.strictEqual(run(newer, home).stdout, 'new arg\n');
            const older = sandboxPackage(path.join(dir, 'b'), { version: '1.2.2', payload: 'old' });
            assert.strictEqual(setupStep(older, home).status, 0);
            assert.strictEqual(linkOf(home), 'fuigo-1.2.2');
        } finally { cleanup(dir); }
    });

    test('F2: the setup step fails loudly (non-zero, stderr) when nothing can be installed', () => {
        if (!supported) return;
        const dir = makeTmpDir();
        try {
            const home = mkHome(dir);
            const sb = sandboxPackage(dir);
            cleanup(path.join(dir, 'lib', 'node_modules', '@fuigo'));
            const res = setupStep(sb, home);
            assert.notStrictEqual(res.status, 0);
            assert.ok(/setup failed/.test(res.stderr), res.stderr);
            assert.ok(!fs.existsSync(path.join(home, '.fuigo', 'bin', 'fuigo')));
        } finally { cleanup(dir); }
    });

}

// ─── Global-install detection and the Windows downgrade guard (P30) ─────

console.log('\nglobal install detection\n');
{
    const { classifyGlobal, globalPrefixes, npmrcPrefix, canonicalVersion } = require('../bin/fuigo-replace.js');
    const detect = (platform, pkgBin, env = {}, extra = {}) => {
        const ctx = { platform, env, home: platform === 'win32' ? 'C:\\Users\\sean' : '/home/sean', ...extra };
        // extra.pkgJson lists directories that contain a package.json (a project root).
        const pj = new Set((extra.pkgJson || []).map((d) => d.replace(/[\\/]+$/, '')));
        ctx.exists = (f) => pj.has(f.replace(/[\\/]package\.json$/, ''));
        ctx.prefixes = globalPrefixes({ ...ctx, execPaths: ctx.execPaths || [] });
        if (extra.globalRoots) ctx.globalRoots = extra.globalRoots;
        return classifyGlobal(pkgBin, ctx);
    };
    const W = 'win32';
    const winCases = [
        ['default %APPDATA%\\npm', 'C:\\Users\\sean\\AppData\\Roaming\\npm\\node_modules\\fuigo\\bin', { APPDATA: 'C:\\Users\\sean\\AppData\\Roaming' }, {}, 'npm'],
        ['custom prefix via npm_config_prefix', 'D:\\tools\\npm-global\\node_modules\\fuigo\\bin', { npm_config_prefix: 'D:\\tools\\npm-global' }, {}, 'npm'],
        ['custom prefix from npmrc', 'D:\\tools\\npm-global\\node_modules\\fuigo\\bin', {}, { npmrcPrefixes: ['D:\\tools\\npm-global'] }, 'npm'],
        ['case-insensitive prefix', 'd:\\Tools\\NPM-Global\\node_modules\\fuigo\\bin', { npm_config_prefix: 'D:\\tools\\npm-global\\' }, {}, 'npm'],
        ['prefix next to node.exe', 'C:\\Program Files\\nodejs\\node_modules\\fuigo\\bin', {}, { execPaths: ['C:\\Program Files\\nodejs\\node.exe'] }, 'npm'],
        ['nvm-windows, running under another node version', 'C:\\Users\\sean\\AppData\\Roaming\\nvm\\v18.19.0\\node_modules\\fuigo\\bin',
            {}, { execPaths: ['C:\\Users\\sean\\AppData\\Roaming\\nvm\\v20.11.0\\node.exe'] }, 'npm'],
        ['Scoop nodejs, current\\bin', 'C:\\Users\\sean\\scoop\\apps\\nodejs\\current\\bin\\node_modules\\fuigo\\bin', {}, { execPaths: ['C:\\Users\\sean\\scoop\\apps\\nodejs\\current\\node.exe'] }, 'npm'],
        ['Scoop nodejs, persist layout', 'C:\\Users\\sean\\scoop\\persist\\nodejs\\bin\\node_modules\\fuigo\\bin', { SCOOP: 'C:\\Users\\sean\\scoop' }, {}, 'npm'],
        ['Scoop nodejs, versioned app dir, custom SCOOP', 'E:\\apps-root\\apps\\nodejs\\21.6.0\\bin\\node_modules\\fuigo\\bin', { SCOOP: 'E:\\apps-root' }, {}, 'npm'],
        ['Volta', 'C:\\Users\\sean\\AppData\\Local\\Volta\\tools\\image\\packages\\fuigo\\lib\\node_modules\\fuigo\\bin', { LOCALAPPDATA: 'C:\\Users\\sean\\AppData\\Local' }, {}, 'other'],
        ['Volta, VOLTA_HOME', 'F:\\v\\tools\\image\\packages\\fuigo\\node_modules\\fuigo\\bin', { VOLTA_HOME: 'F:\\v' }, {}, 'other'],
        ['Yarn classic', 'C:\\Users\\sean\\AppData\\Local\\Yarn\\Data\\global\\node_modules\\fuigo\\bin', { LOCALAPPDATA: 'C:\\Users\\sean\\AppData\\Local' }, {}, 'other'],
        ['pnpm via PNPM_HOME', 'D:\\pn\\global\\5\\node_modules\\.pnpm\\fuigo@1.0.30\\node_modules\\fuigo\\bin', { PNPM_HOME: 'D:\\pn' }, {}, 'other'],
        ['pnpm default', 'C:\\Users\\sean\\AppData\\Local\\pnpm\\global\\5\\node_modules\\fuigo\\bin', {}, {}, 'other'],
        ['project-local', 'C:\\work\\app\\node_modules\\fuigo\\bin', { npm_config_prefix: 'D:\\tools\\npm-global' }, { execPaths: ['C:\\Program Files\\nodejs\\node.exe'], pkgJson: ['C:\\work\\app'] }, null],
        ['project named npm', 'C:\\work\\npm\\node_modules\\fuigo\\bin', { APPDATA: 'C:\\Users\\sean\\AppData\\Roaming' }, { pkgJson: ['C:\\work\\npm'] }, null],
        ['project called scoop-like but not nodejs', 'C:\\work\\scoop\\apps\\other\\bin\\node_modules\\fuigo\\bin', {}, { pkgJson: ['C:\\work\\scoop\\apps\\other\\bin'] }, null],
        ['pnpm project (.pnpm)', 'C:\\work\\app\\node_modules\\.pnpm\\fuigo@1.0.30\\node_modules\\fuigo\\bin', {}, {}, null],
        ['yarn berry project (.yarn)', 'C:\\work\\app\\.yarn\\unplugged\\fuigo-npm-abc\\node_modules\\fuigo\\bin', {}, {}, null],
        ['M4: plain APPDATA\\npm with no env and no npmrc', 'C:\\Users\\sean\\AppData\\Roaming\\npm\\node_modules\\fuigo\\bin', {}, {}, 'npm'],
        ['M4: unknown prefix drive, nothing set', 'Z:\\weird\\prefix\\node_modules\\fuigo\\bin', {}, {}, 'npm'],
        ['npx cache', 'C:\\Users\\sean\\AppData\\Local\\npm-cache\\_npx\\abc123\\node_modules\\fuigo\\bin', { APPDATA: 'C:\\Users\\sean\\AppData\\Roaming' }, {}, null],
        ['not under node_modules', 'C:\\src\\fuigo\\bin', {}, {}, null],
    ];
    for (const [name, p, env, extra, want] of winCases) {
        test(`windows: ${name} -> ${want}`, () => assert.strictEqual(detect(W, p, env, extra), want));
    }
    const U = 'linux';
    const unixCases = [
        ['/usr/local prefix', '/usr/local/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['prefix from node location', '/opt/node-22/lib/node_modules/fuigo/bin', {}, { execPaths: ['/opt/node-22/bin/node'] }, 'npm'],
        ['npm_config_prefix', '/data/g/lib/node_modules/fuigo/bin', { npm_config_prefix: '/data/g' }, {}, 'npm'],
        ['PREFIX', '/data/p/lib/node_modules/fuigo/bin', { PREFIX: '/data/p' }, {}, 'npm'],
        ['~/.npm-global', '/home/sean/.npm-global/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['npmrc prefix', '/srv/x/lib/node_modules/fuigo/bin', {}, { npmrcPrefixes: ['/srv/x'] }, 'npm'],
        ['nvm, another node version', '/home/sean/.nvm/versions/node/v18.20.0/lib/node_modules/fuigo/bin', {}, { execPaths: ['/home/sean/.nvm/versions/node/v22.1.0/bin/node'] }, 'npm'],
        ['Yarn classic ~/.config/yarn/global', '/home/sean/.config/yarn/global/node_modules/fuigo/bin', {}, {}, 'other'],
        ['Yarn classic, XDG_CONFIG_HOME', '/cfg/yarn/global/node_modules/fuigo/bin', { XDG_CONFIG_HOME: '/cfg' }, {}, 'other'],
        ['pnpm global store', '/home/sean/.local/share/pnpm/global/5/node_modules/.pnpm/fuigo@1/node_modules/fuigo/bin', {}, {}, 'other'],
        ['pnpm, PNPM_HOME', '/pn/global/5/node_modules/fuigo/bin', { PNPM_HOME: '/pn' }, {}, 'other'],
        ['bun', '/home/sean/.bun/install/global/node_modules/fuigo/bin', {}, {}, 'other'],
        ['Volta', '/home/sean/.volta/tools/image/packages/fuigo/lib/node_modules/fuigo/bin', {}, {}, 'other'],
        ['a project whose root dir is named lib', '/home/sean/work/lib/node_modules/fuigo/bin', {}, { execPaths: ['/usr/local/bin/node'], pkgJson: ['/home/sean/work/lib'] }, null],
        ['project-local', '/home/sean/work/app/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/work/app'] }, null],
        ['known prefix /usr/local with a stray package.json beside node_modules is still global (r3)', '/usr/local/lib/node_modules/fuigo/bin', {}, { pkgJson: ['/usr/local/lib'] }, 'npm'],
        ['project-local, not lib-shaped, no package.json', '/home/sean/work/app/node_modules/fuigo/bin', {}, {}, null],
        ['pnpm project (.pnpm)', '/home/sean/work/app/node_modules/.pnpm/fuigo@1.0.30/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/work/app'] }, null],
        ['pnpm project (.pnpm), package.json absent', '/home/sean/work/app/node_modules/.pnpm/fuigo@1.0.30/node_modules/fuigo/bin', {}, {}, null],
        ['yarn berry project (.yarn)', '/home/sean/work/app/.yarn/unplugged/fuigo-npm-abc/node_modules/fuigo/bin', {}, {}, null],
        ['nested dependency of a package', '/home/sean/work/app/node_modules/other/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/work/app/node_modules/other'] }, null],
        ['M4: asdf legacy <ver>/.npm prefix', '/home/sean/.asdf/installs/nodejs/20.11.0/.npm/lib/node_modules/fuigo/bin', {}, { execPaths: ['/home/sean/.asdf/installs/nodejs/20.11.0/bin/node'] }, 'npm'],
        ['M4: env prefix not inherited (shell from a GUI app)', '/data/g/lib/node_modules/fuigo/bin', {}, { execPaths: ['/opt/node/bin/node'] }, 'npm'],
        ['M4: prefix only in npm builtin npmrc', '/srv/builtin/lib/node_modules/fuigo/bin', {}, { execPaths: ['/opt/node/bin/node'] }, 'npm'],
        ['M4: nvm with non-default NVM_DIR under another version', '/data/nvmdir/versions/node/v18.20.0/lib/node_modules/fuigo/bin', { NVM_DIR: '/data/nvmdir' }, { execPaths: ['/data/nvmdir/versions/node/v22.1.0/bin/node'] }, 'npm'],
        ['Homebrew /opt/homebrew', '/opt/homebrew/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['Homebrew Cellar realpath', '/opt/homebrew/Cellar/node/22.1.0/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['mise', '/home/sean/.local/share/mise/installs/node/22.1.0/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['linuxbrew', '/home/linuxbrew/.linuxbrew/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['/usr prefix', '/usr/lib/node_modules/fuigo/bin', {}, {}, 'npm'],
        ['npx cache', '/home/sean/.npm/_npx/9f8e/node_modules/fuigo/bin', {}, {}, null],
        ['npx cache with a package.json inside', '/home/sean/.npm/_npx/9f8e/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/.npm/_npx/9f8e'] }, null],
    ];
    for (const [name, p, env, extra, want] of unixCases) {
        test(`unix: ${name} -> ${want}`, () => assert.strictEqual(detect(U, p, env, extra), want));
    }
    // A global prefix with a package.json beside its node_modules is global when npm says so.
    const rootsOf = (...r) => ({ globalRoots: () => r });
    const failing = { globalRoots: () => { throw new Error('npm: not found'); } };
    test('windows: prefix = home dir with ~\\package.json beside node_modules is global (npm root -g matches)', () => {
        assert.strictEqual(detect(W, 'C:\\Users\\sean\\node_modules\\fuigo\\bin', { npm_config_prefix: 'C:\\Users\\sean' },
            { pkgJson: ['C:\\Users\\sean'], ...rootsOf('C:\\Users\\sean\\node_modules') }), 'npm');
    });
    test('windows: root compare is case-insensitive and separator-normalised', () => {
        assert.strictEqual(detect(W, 'c:\\users\\SEAN\\node_modules\\fuigo\\bin', {}, { pkgJson: ['c:\\users\\SEAN'], ...rootsOf('C:/Users/sean/node_modules/') }), 'npm');
    });
    test('unix: ~/.local prefix with a stray package.json is global (npm root -g matches)', () => {
        assert.strictEqual(detect(U, '/home/sean/.local/lib/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/.local/lib'], ...rootsOf('/home/sean/.local/lib/node_modules') }), 'npm');
    });
    test('unix: project with package.json stays local when npm root -g names another dir', () => {
        assert.strictEqual(detect(U, '/home/sean/work/app/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/work/app'], ...rootsOf('/usr/local/lib/node_modules') }), null);
    });
    test('unix: masked `***` global root matches exactly one segment per star', () => {
        const bin = '/home/u/3f2b9c1e-8d4a-4f6b-9a7c-1e2d3f4a5b6c/g/lib/node_modules/fuigo/bin';
        assert.strictEqual(detect(U, bin, {}, { pkgJson: ['/home/u/3f2b9c1e-8d4a-4f6b-9a7c-1e2d3f4a5b6c/g/lib'], ...rootsOf('/home/u/***/g/lib/node_modules') }), 'npm');
        // a different tail, or a different depth, is not the same root
        assert.strictEqual(detect(U, bin, {}, { pkgJson: ['/home/u/3f2b9c1e-8d4a-4f6b-9a7c-1e2d3f4a5b6c/g/lib'], ...rootsOf('/home/u/***/h/lib/node_modules') }), null);
        assert.strictEqual(detect(U, bin, {}, { pkgJson: ['/home/u/3f2b9c1e-8d4a-4f6b-9a7c-1e2d3f4a5b6c/g/lib'], ...rootsOf('/home/***/lib/node_modules') }), null);
    });
    test('npm missing or failing falls back to the package.json rule (local)', () => {
        assert.strictEqual(detect(U, '/srv/zz/lib/node_modules/fuigo/bin', {}, { pkgJson: ['/srv/zz/lib'], ...failing }), null);
        assert.strictEqual(detect(U, '/srv/zz/lib/node_modules/fuigo/bin', {}, { pkgJson: ['/srv/zz/lib'], ...rootsOf() }), null);
        assert.strictEqual(detect(U, '/srv/zz/lib/node_modules/fuigo/bin', {}, { pkgJson: ['/srv/zz/lib'] }), null);
    });
    test('npm is consulted only in the ambiguous package.json case', () => {
        let calls = 0;
        const spy = { globalRoots: () => { calls++; return []; } };
        detect(U, '/usr/local/lib/node_modules/fuigo/bin', {}, { ...spy });
        detect(U, '/home/sean/.npm/_npx/9f8e/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/.npm/_npx/9f8e'], ...spy });
        assert.strictEqual(calls, 0);
        detect(U, '/home/sean/work/app/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/work/app'], ...spy });
        assert.strictEqual(calls, 1);
    });
    test('a known prefix resolves the ambiguous case without asking npm (home prefix, ~/.local)', () => {
        let calls = 0;
        const spy = { globalRoots: () => { calls++; return []; } };
        assert.strictEqual(detect(W, 'C:\\Users\\sean\\node_modules\\fuigo\\bin', { npm_config_prefix: 'C:\\Users\\sean' }, { pkgJson: ['C:\\Users\\sean'], ...spy }), 'npm');
        assert.strictEqual(detect(W, 'c:\\users\\SEAN\\node_modules\\fuigo\\bin', { npm_config_prefix: 'C:\\Users\\sean\\' }, { pkgJson: ['c:\\users\\SEAN'], ...spy }), 'npm');
        assert.strictEqual(detect(U, '/home/sean/.local/lib/node_modules/fuigo/bin', {}, { pkgJson: ['/home/sean/.local/lib'], ...spy }), 'npm');
        assert.strictEqual(calls, 0);
    });
    test('real globalInstallKind: read-only package dir -> per-user cache, one npm spawn over 3 launches, no ~/.fuigo', () => {
        const dir = makeTmpDir();
        const saved = { HOME: process.env.HOME, XDG: process.env.XDG_CACHE_HOME, LA: process.env.LOCALAPPDATA };
        const cpm = require('child_process');
        const orig = cpm.execFileSync;
        try {
            const home = path.join(dir, 'home');
            fs.mkdirSync(home, { recursive: true });
            process.env.HOME = home;
            process.env.XDG_CACHE_HOME = path.join(home, 'xdg');
            process.env.LOCALAPPDATA = path.join(home, 'lad');
            const pkg = path.join(dir, 'proj', 'node_modules', 'fuigo');
            const bin = path.join(pkg, 'bin');
            fs.mkdirSync(bin, { recursive: true });
            fs.writeFileSync(path.join(dir, 'proj', 'package.json'), '{"name":"proj"}');
            fs.writeFileSync(path.join(pkg, 'package.json'), '{"name":"fuigo","version":"1.0.30"}');
            // a directory squatting on the cache name makes the package-dir write fail even as root
            fs.mkdirSync(path.join(pkg, '.fuigo-npm-root.json'));
            let calls = 0;
            cpm.execFileSync = () => { calls++; return '/some/other/lib/node_modules\n'; };
            const { globalInstallKind } = require('../bin/fuigo-replace.js');
            for (let i = 0; i < 3; i++) assert.strictEqual(globalInstallKind(bin), null);
            assert.strictEqual(calls, 1, 'second and third launch hit the user cache');
            const files = [];
            (function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const f = path.join(d, e.name); if (e.isDirectory()) walk(f); else files.push(f); } })(home);
            assert.ok(files.some((f) => path.basename(f) === 'fuigo-npm-root.json'), 'user cache written: ' + files.join(','));
            assert.ok(!fs.existsSync(path.join(home, '.fuigo')), '~/.fuigo must not be created');
            // a version bump re-asks, then is cached too
            fs.writeFileSync(path.join(pkg, 'package.json'), '{"name":"fuigo","version":"1.0.31"}');
            assert.strictEqual(globalInstallKind(bin), null);
            assert.strictEqual(calls, 2);
            assert.strictEqual(globalInstallKind(bin), null);
            assert.strictEqual(calls, 2);
            // a failed (timed out) npm is not cached
            fs.writeFileSync(path.join(pkg, 'package.json'), '{"name":"fuigo","version":"1.0.32"}');
            cpm.execFileSync = () => { calls++; throw new Error('ETIMEDOUT'); };
            assert.strictEqual(globalInstallKind(bin), null);
            assert.strictEqual(globalInstallKind(bin), null);
            assert.strictEqual(calls, 4, 'failures stay uncached');
        } finally {
            cpm.execFileSync = orig;
            for (const [k, v] of [['HOME', saved.HOME], ['XDG_CACHE_HOME', saved.XDG], ['LOCALAPPDATA', saved.LA]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
            cleanup(dir);
        }
    });
    for (const attack of ['other-owner', 'group-writable', 'symlinked-dir', 'planted-file-other-owner']) {
        test(`user npm-root cache ignored when untrusted: ${attack}`, () => {
            if (process.platform === 'win32') return;
            const dir = makeTmpDir();
            const saved = { HOME: process.env.HOME, XDG: process.env.XDG_CACHE_HOME, TMPDIR: process.env.TMPDIR };
            const cpm = require('child_process');
            const orig = cpm.execFileSync;
            const { globalInstallKind, npmRootCacheHooks } = require('../bin/fuigo-replace.js');
            const origLstat = npmRootCacheHooks.lstat;
            try {
                process.env.HOME = path.join(dir, 'home');
                process.env.XDG_CACHE_HOME = path.join(dir, 'xdg');
                process.env.TMPDIR = path.join(dir, 'tmp');
                fs.mkdirSync(process.env.TMPDIR, { recursive: true });
                const proj = path.join(dir, 'proj');
                const pkg = path.join(proj, 'node_modules', 'fuigo');
                const bin = path.join(pkg, 'bin');
                fs.mkdirSync(bin, { recursive: true });
                fs.writeFileSync(path.join(proj, 'package.json'), '{"name":"proj"}');
                fs.writeFileSync(path.join(pkg, 'package.json'), '{"name":"fuigo","version":"1.0.30"}');
                fs.mkdirSync(path.join(pkg, '.fuigo-npm-root.json')); // package dir not writable
                const cdir = path.join(dir, 'xdg', 'fuigo');
                const cfile = path.join(cdir, 'fuigo-npm-root.json');
                const key = [fs.realpathSync(pkg), '1.0.30', fs.realpathSync(process.execPath)].join('|');
                // the attacker's file claims the victim project's node_modules is the global root
                const plant = JSON.stringify({ [key]: [path.join(proj, 'node_modules')] });
                if (attack === 'symlinked-dir') {
                    const real = path.join(dir, 'evil'); fs.mkdirSync(real, { mode: 0o700 });
                    fs.writeFileSync(path.join(real, 'fuigo-npm-root.json'), plant);
                    fs.mkdirSync(path.dirname(cdir), { recursive: true });
                    fs.symlinkSync(real, cdir);
                } else {
                    fs.mkdirSync(cdir, { recursive: true, mode: 0o700 });
                    fs.writeFileSync(cfile, plant);
                    if (attack === 'group-writable') fs.chmodSync(cdir, 0o770);
                    if (attack === 'other-owner') npmRootCacheHooks.lstat = (f) => { const st = fs.lstatSync(f); return f === cdir ? Object.create(st, { uid: { value: process.getuid() + 1 }, isDirectory: { value: () => true }, isSymbolicLink: { value: () => false } }) : st; };
                    if (attack === 'planted-file-other-owner') npmRootCacheHooks.lstat = (f) => { const st = fs.lstatSync(f); return f === cfile ? Object.create(st, { uid: { value: process.getuid() + 1 }, isFile: { value: () => true }, isSymbolicLink: { value: () => false } }) : st; };
                }
                let calls = 0;
                cpm.execFileSync = () => { calls++; return '/some/other/lib/node_modules\n'; };
                assert.strictEqual(globalInstallKind(bin), null, 'planted root must not make the project copy global');
                assert.strictEqual(calls, 1, 'untrusted cache is ignored, npm asked');
                if (attack === 'symlinked-dir') assert.strictEqual(fs.readFileSync(path.join(dir, 'evil', 'fuigo-npm-root.json'), 'utf8'), plant, 'nothing written through the symlink');
            } finally {
                npmRootCacheHooks.lstat = origLstat;
                cpm.execFileSync = orig;
                for (const [k, v] of [['HOME', saved.HOME], ['XDG_CACHE_HOME', saved.XDG], ['TMPDIR', saved.TMPDIR]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
                cleanup(dir);
            }
        });
    }
    test('real globalInstallKind: a project-local copy spawns nothing on repeat launches (npm output cached)', () => {
        const dir = makeTmpDir();
        try {
            const bin = path.join(dir, 'proj', 'node_modules', 'fuigo', 'bin');
            fs.mkdirSync(bin, { recursive: true });
            fs.writeFileSync(path.join(dir, 'proj', 'package.json'), '{"name":"proj"}');
            fs.writeFileSync(path.join(dir, 'proj', 'node_modules', 'fuigo', 'package.json'), '{"name":"fuigo","version":"1.0.30"}');
            const cp = require('child_process');
            const orig = cp.execFileSync;
            let calls = 0;
            cp.execFileSync = () => { calls++; return '/some/other/lib/node_modules\n'; };
            try {
                const { globalInstallKind } = require('../bin/fuigo-replace.js');
                assert.strictEqual(globalInstallKind(bin), null);
                assert.strictEqual(calls, 1, 'first launch asks npm once');
                assert.strictEqual(globalInstallKind(bin), null);
                assert.strictEqual(globalInstallKind(bin), null);
                assert.strictEqual(calls, 1, 'later launches use the cache');
                // a new installed version re-asks
                fs.writeFileSync(path.join(dir, 'proj', 'node_modules', 'fuigo', 'package.json'), '{"name":"fuigo","version":"1.0.31"}');
                assert.strictEqual(globalInstallKind(bin), null);
                assert.strictEqual(calls, 2);
                // and the cached npm-only answer still resolves a global copy
                const gbin = path.join(dir, 'g', 'lib', 'node_modules', 'fuigo', 'bin');
                fs.mkdirSync(gbin, { recursive: true });
                fs.writeFileSync(path.join(dir, 'g', 'lib', 'package.json'), '{}');
                fs.writeFileSync(path.join(dir, 'g', 'lib', 'node_modules', 'fuigo', 'package.json'), '{"name":"fuigo","version":"1.0.30"}');
                cp.execFileSync = () => { calls++; return fs.realpathSync(path.join(dir, 'g', 'lib', 'node_modules')) + '\n'; };
                assert.strictEqual(globalInstallKind(gbin), 'npm');
            } finally { cp.execFileSync = orig; }
        } finally { cleanup(dir); }
    });
    test('a normal global install (no package.json beside node_modules) never spawns npm', () => {
        const dir = makeTmpDir();
        try {
            const gbin = path.join(dir, 'g', 'lib', 'node_modules', 'fuigo', 'bin');
            fs.mkdirSync(gbin, { recursive: true });
            const cp = require('child_process');
            const orig = cp.execFileSync;
            let calls = 0;
            cp.execFileSync = () => { calls++; return ''; };
            try {
                assert.strictEqual(require('../bin/fuigo-replace.js').globalInstallKind(gbin), 'npm');
                assert.strictEqual(calls, 0);
            } finally { cp.execFileSync = orig; }
        } finally { cleanup(dir); }
    });
    test('npmrcPrefix reads prefix=, expands ${VAR} and ~, ignores comments, last one wins', () => {
        assert.strictEqual(npmrcPrefix('; prefix=/no\nregistry=x\nprefix = "D:\\\\npm"\n', {}, '/h'), 'D:\\\\npm');
        assert.strictEqual(npmrcPrefix('prefix=${APPDATA}\\npm', { APPDATA: 'C:\\Users\\s\\AppData\\Roaming' }, 'C:\\h'), 'C:\\Users\\s\\AppData\\Roaming\\npm');
        assert.strictEqual(npmrcPrefix('prefix=~/.npm-global', {}, '/home/s'), '/home/s/.npm-global');
        assert.strictEqual(npmrcPrefix('registry=x', {}, '/h'), null);
    });

    console.log('\nWindows downgrade guard (canonicalVersion)\n');
    const winBin = (dir, files, stamp) => {
        for (const [n, c] of Object.entries(files)) fs.writeFileSync(path.join(dir, n), c);
        if (stamp !== undefined) fs.writeFileSync(path.join(dir, '.fuigo-npm-stamp'), JSON.stringify([stamp, 'C:\\pkg', '1:2']));
        return path.join(dir, 'fuigo.exe');
    };
    test('windows: the stamp names the version of the fuigo.exe copy', () => {
        const dir = makeTmpDir();
        try {
            const exe = winBin(dir, { 'fuigo.exe': 'BBBB', 'fuigo-1.0.29.exe': 'AAAA', 'fuigo-1.0.30.exe': 'BBBB' }, '1.0.30');
            assert.strictEqual(canonicalVersion(exe, 'win32'), '1.0.30');
        } finally { cleanup(dir); }
    });
    test('windows: no stamp -> the newest versioned exe with the same size', () => {
        const dir = makeTmpDir();
        try {
            const exe = winBin(dir, { 'fuigo.exe': 'BBBB', 'fuigo-1.0.9.exe': 'BBBB', 'fuigo-1.0.10.exe': 'BBBB', 'fuigo-1.0.11.exe': 'CCCCCC' });
            assert.strictEqual(canonicalVersion(exe, 'win32'), '1.0.10');
        } finally { cleanup(dir); }
    });
    test('windows: a stamp for a version that is not on disk is ignored', () => {
        const dir = makeTmpDir();
        try {
            const exe = winBin(dir, { 'fuigo.exe': 'AAAA', 'fuigo-1.0.28.exe': 'AAAA' }, '1.0.99');
            assert.strictEqual(canonicalVersion(exe, 'win32'), '1.0.28');
        } finally { cleanup(dir); }
    });
    test('windows: missing fuigo.exe, a garbage stamp and a non-win32 platform all give null/fallback', () => {
        const dir = makeTmpDir();
        try {
            assert.strictEqual(canonicalVersion(path.join(dir, 'fuigo.exe'), 'win32'), null);
            const exe = winBin(dir, { 'fuigo.exe': 'AAAA', 'fuigo-1.0.28.exe': 'AAAA', '.fuigo-npm-stamp': 'not json' });
            assert.strictEqual(canonicalVersion(exe, 'win32'), '1.0.28');
            assert.strictEqual(canonicalVersion(exe, 'linux'), null, 'a Unix regular file stays unknown');
        } finally { cleanup(dir); }
    });
}

// ─── Summary ───────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
