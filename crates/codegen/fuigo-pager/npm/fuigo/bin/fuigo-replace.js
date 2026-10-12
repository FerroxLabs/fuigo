// Shared by postinstall.js and fuigo-bootstrap.js: put the vendored binary at
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

module.exports = { installVendorBinary, ensureFuigoHome };
