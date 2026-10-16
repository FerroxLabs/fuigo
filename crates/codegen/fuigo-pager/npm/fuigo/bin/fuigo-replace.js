// Shared by fuigo-bootstrap.js and fuigo-install.js: put the vendored binary at
// destPath, replacing an existing file only when its content differs.
//
// Rule: decode the vendored binary, compare its length with the installed file,
// and only when the lengths are equal compare the bytes (Buffer.equals, exact).
// Same content: nothing is written (inode and mtime stay). Different content: a
// uniquely named temp file is written (mode 0755 on unix) and renamed over the
// destination, never an in-place write (macOS kills a running binary that is
// overwritten in place with exit 137). Windows cannot rename over a binary that
// is in use: that failure keeps the existing file and the launch goes on.
// A destination that is a symlink or not a regular file is left alone.
//
// Returns true when destPath holds a usable binary afterwards.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

function debug(msg) {
    if (process.env.FUIGO_BOOTSTRAP_DEBUG) console.error(`fuigo-bootstrap: ${msg}`);
}

function readVendored(brotliPath, binaryPath) {
    if (fs.existsSync(brotliPath)) return zlib.brotliDecompressSync(fs.readFileSync(brotliPath));
    if (fs.existsSync(binaryPath)) return fs.readFileSync(binaryPath);
    return null;
}

function installVendorBinary(brotliPath, binaryPath, destPath) {
    let st = null;
    try { st = fs.lstatSync(destPath); } catch {}
    if (st && !st.isFile()) {
        debug(`${destPath} is not a regular file, left as is`);
        return true;
    }
    let data;
    try { data = readVendored(brotliPath, binaryPath); } catch { return st !== null; }
    if (data === null) return st !== null;
    // An empty vendored file is a broken package, never a newer binary: it must not replace a good one.
    if (data.length === 0) {
        debug(`vendored binary is empty, ${st ? 'keeping the existing file' : 'nothing installed'}`);
        return st !== null;
    }
    if (st && st.size === data.length) {
        try {
            if (fs.readFileSync(destPath).equals(data)) return true;
        } catch {}
    }
    const tmp = `${destPath}.tmp.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
    let created = false;
    try {
        fs.writeFileSync(tmp, data, { flag: 'wx', mode: 0o755 });
        created = true;
        if (process.platform !== 'win32') fs.chmodSync(tmp, 0o755);
        fs.renameSync(tmp, destPath);
        return true;
    } catch (e) {
        debug(`could not replace ${destPath} (${e.code ?? e.message}), keeping the existing file`);
        return st !== null;
    } finally {
        // Only a temp file this call created is removed ('wx' fails when the name already exists).
        if (created) { try { fs.unlinkSync(tmp); } catch {} }
    }
}

// Create the Fuigo home (the parent of `<home>/bin`) with mode 0700 whatever the
// umask (mkdir's mode is masked only downward, so 0700 survives umask 002), but
// ONLY when it does not exist yet: an existing home is never chmod-ed. Parents
// are created with default modes; `bin` and anything below it are made later
// with default modes. Windows: no mode semantics, plain mkdir.
function ensureFuigoHome(home) {
    if (fs.existsSync(home)) return;
    fs.mkdirSync(path.dirname(home), { recursive: true });
    try {
        fs.mkdirSync(home, { mode: 0o700 });
    } catch (e) {
        if (e.code !== 'EEXIST') throw e;
    }
}

// The marker written last by a completed install and compared by every node launch.
// It names the version, the package location and the stat of the vendored payload,
// so a same-version reinstall that changed the binary no longer matches.
const STAMP_NAME = '.fuigo-npm-stamp';
function installStamp(version, pkgBinDir, brotliPath, binaryPath) {
    let payload = 'none';
    for (const p of [brotliPath, binaryPath]) {
        try { const st = fs.statSync(p); payload = `${st.size}:${Math.floor(st.mtimeMs)}`; break; } catch {}
    }
    let where = pkgBinDir;
    try { where = fs.realpathSync(pkgBinDir); } catch {}
    return JSON.stringify([version, where, payload]);
}

// Which kind of global install, if any, `pkgBinDir` (the package's bin/) belongs to:
//   'npm'   -- npm's global prefix: <prefix>/lib/node_modules/fuigo (Unix), or
//              <prefix>/node_modules/fuigo where <prefix> is the Windows default
//              (%APPDATA%\npm), the directory of the running node, or $npm_config_prefix
//   'other' -- a pnpm / yarn / bun global store
//   null    -- anything else: a project-local install, an npx cache, a checkout
// Only a global install may manage $FUIGO_HOME/bin and config.toml: a project-local or
// npx copy of another version must never swap the user's installed binary. This is a
// cheap path check (no npm call, no cwd-dependent lookup).
function globalInstallKind(pkgBinDir) {
    let real = pkgBinDir;
    try { real = fs.realpathSync(pkgBinDir); } catch {}
    const norm = (p) => (process.platform === 'win32' ? p.toLowerCase() : p);
    const marked = norm(real).split(path.sep).join('/');
    if (/\/(pnpm|yarn)\/global\//.test(marked) || marked.includes('/.bun/install/global/')) return 'other';
    const nodeModules = path.dirname(path.dirname(real));
    if (path.basename(nodeModules) !== 'node_modules') return null;
    const prefixRoot = path.dirname(nodeModules);
    const realOf = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
    const sameDir = (a, b) => norm(realOf(a)) === norm(realOf(b));
    if (process.platform !== 'win32') {
        if (path.basename(prefixRoot) === 'lib') return 'npm';
        const prefixes = [process.env.npm_config_prefix, path.dirname(path.dirname(process.execPath))];
        return prefixes.some((p) => p && sameDir(path.join(p, 'lib'), prefixRoot)) ? 'npm' : null;
    }
    const prefixes = [process.env.npm_config_prefix, path.dirname(process.execPath)];
    if (norm(path.basename(prefixRoot)) === 'npm') return 'npm';
    return prefixes.some((p) => p && sameDir(p, prefixRoot)) ? 'npm' : null;
}

// "X.Y.Z[-pre]" -> comparable parts, or null when it is not a version.
function parseVersion(v) {
    const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(String(v));
    return m ? { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? null } : null;
}

// Negative, zero or positive like a comparator; null when either side is not a version.
function compareVersions(a, b) {
    const pa = parseVersion(a);
    const pb = parseVersion(b);
    if (!pa || !pb) return null;
    for (let i = 0; i < 3; i++) if (pa.core[i] !== pb.core[i]) return pa.core[i] - pb.core[i];
    if (pa.pre === pb.pre) return 0;
    if (pa.pre === null) return 1;
    if (pb.pre === null) return -1;
    const xs = pa.pre.split('.');
    const ys = pb.pre.split('.');
    for (let i = 0; i < Math.max(xs.length, ys.length); i++) {
        if (xs[i] === undefined) return -1;
        if (ys[i] === undefined) return 1;
        const nx = /^\d+$/.test(xs[i]);
        const ny = /^\d+$/.test(ys[i]);
        if (nx && ny) { if (Number(xs[i]) !== Number(ys[i])) return Number(xs[i]) - Number(ys[i]); }
        else if (nx !== ny) return nx ? -1 : 1;
        else if (xs[i] !== ys[i]) return xs[i] < ys[i] ? -1 : 1;
    }
    return 0;
}

// The version the canonical link `<bin>/fuigo` points at (Unix symlink to fuigo-<version>),
// or null when unknown (missing, not a symlink, Windows copy).
function canonicalVersion(canonicalPath) {
    try {
        const m = /^fuigo-(\d.*)$/.exec(path.basename(fs.readlinkSync(canonicalPath)));
        return m && parseVersion(m[1]) ? m[1] : null;
    } catch {
        return null;
    }
}

module.exports = {
    installVendorBinary, ensureFuigoHome, installStamp, STAMP_NAME,
    globalInstallKind, compareVersions, canonicalVersion,
};
