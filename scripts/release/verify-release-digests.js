#!/usr/bin/env node
// Compare what the post-publish verifiers executed with the GitHub Release assets.
//
//   verify-release-digests.js <version> <verified-dir> <release-dir>
//
// <verified-dir>  the six JSON files verify-published-platform.js wrote with --digest-out, one
//                 per platform: {platform, name, version, integrity (sha512 of the registry
//                 tarball), sha256 (of the decompressed executable it ran)}
// <release-dir>   the laid-out assets (github-release-assets.sh): the tarballs, the raw
//                 binaries, release-manifest.json and SHA256SUMS
//
// For every platform the release tarball's sha512 must equal the verified integrity (in the
// file itself and in release-manifest.json) and the raw binary's sha256 must equal the verified
// sha256 (in the file itself and in SHA256SUMS). A release asset that differs from what was
// executed fails the job. Digests are recomputed from the asset bytes, never trusted from a
// listing.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Pinned against github-release-assets.sh by scripts/release/test-release-scripts.sh.
const ASSET_PLATFORM = {
    'darwin-arm64': 'macos-aarch64', 'darwin-x64': 'macos-x86_64',
    'linux-arm64': 'linux-aarch64', 'linux-x64': 'linux-x86_64',
    'win32-arm64': 'windows-aarch64', 'win32-x64': 'windows-x86_64',
};

function verifyDigests(version, verifiedDir, releaseDir) {
    const errors = [];
    const hash = (algo, file, enc) => crypto.createHash(algo).update(fs.readFileSync(file)).digest(enc);
    const readJson = f => JSON.parse(fs.readFileSync(f, 'utf8'));
    const sums = new Map();
    const sumsFile = path.join(releaseDir, 'SHA256SUMS');
    if (!fs.existsSync(sumsFile)) errors.push('release has no SHA256SUMS');
    else {
        for (const line of fs.readFileSync(sumsFile, 'utf8').split('\n')) {
            const m = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line);
            if (m) sums.set(m[2], m[1]);
        }
    }
    const manifestFile = path.join(releaseDir, 'release-manifest.json');
    const manifest = fs.existsSync(manifestFile) ? readJson(manifestFile) : null;
    if (!manifest) errors.push('release has no release-manifest.json');

    const records = new Map();
    for (const f of fs.existsSync(verifiedDir) ? fs.readdirSync(verifiedDir).sort() : []) {
        if (!f.endsWith('.json')) continue;
        const r = readJson(path.join(verifiedDir, f));
        if (records.has(r.platform)) errors.push(`two verified records for ${r.platform}`);
        records.set(r.platform, r);
    }
    for (const p of records.keys()) {
        if (!(p in ASSET_PLATFORM)) errors.push(`verified record for unknown platform ${p}`);
    }

    for (const [p, assetPlatform] of Object.entries(ASSET_PLATFORM)) {
        const r = records.get(p);
        if (!r) { errors.push(`no verified digests for ${p}: its verify-published job did not report`); continue; }
        if (r.version !== version) errors.push(`${p}: verified version ${r.version}, release is ${version}`);
        if (r.name !== `@fuigo/${p}`) errors.push(`${p}: verified package is ${r.name}`);
        if (!/^sha512-/.test(r.integrity || '') || !/^[0-9a-f]{64}$/.test(r.sha256 || '')) {
            errors.push(`${p}: malformed verified digests`); continue;
        }
        const tgz = `fuigo-${p}-${version}.tgz`;
        const raw = `fuigo-${version}-${assetPlatform}`;
        for (const f of [tgz, raw]) {
            if (!fs.existsSync(path.join(releaseDir, f))) errors.push(`release asset ${f} is missing`);
        }
        if (fs.existsSync(path.join(releaseDir, tgz))) {
            const got = 'sha512-' + hash('sha512', path.join(releaseDir, tgz), 'base64');
            if (got !== r.integrity) errors.push(`${tgz} is ${got}, the verifier ran ${r.integrity}`);
            const entry = manifest && manifest.packages.find(x => x.filename === tgz);
            if (!entry) errors.push(`release-manifest.json has no entry for ${tgz}`);
            else if (entry.integrity !== r.integrity) {
                errors.push(`release-manifest.json says ${entry.integrity} for ${tgz}, the verifier ran ${r.integrity}`);
            }
        }
        if (fs.existsSync(path.join(releaseDir, raw))) {
            const got = hash('sha256', path.join(releaseDir, raw), 'hex');
            if (got !== r.sha256) errors.push(`${raw} is sha256 ${got}, the verifier ran ${r.sha256}`);
            if (sums.get(raw) !== r.sha256) {
                errors.push(`SHA256SUMS says ${sums.get(raw)} for ${raw}, the verifier ran ${r.sha256}`);
            }
        }
    }
    return errors;
}

if (require.main === module) {
    const [version, verifiedDir, releaseDir] = process.argv.slice(2);
    if (!version || !verifiedDir || !releaseDir) {
        console.error('usage: verify-release-digests.js <version> <verified-dir> <release-dir>');
        process.exit(2);
    }
    const errors = verifyDigests(version, verifiedDir, releaseDir);
    if (errors.length) {
        for (const e of errors) console.error(`error: ${e}`);
        process.exit(1);
    }
    console.log(`release assets match the bytes verify-published executed on all ${Object.keys(ASSET_PLATFORM).length} platforms`);
}
module.exports = {verifyDigests, ASSET_PLATFORM};
