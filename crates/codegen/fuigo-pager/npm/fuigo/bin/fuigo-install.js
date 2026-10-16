// The slow path of the launcher, loaded by fuigo-bootstrap.js only when the
// installed binary is missing or stale. It does everything the old npm
// `postinstall` script did, so that no install script is needed (npm 11 warns
// about every package with one):
//   - extract the platform binary into $FUIGO_HOME/bin as fuigo-<version>[.exe]
//     (replacing a same-version file whose content differs, see fuigo-replace.js)
//   - point fuigo[.exe] at it: an atomic symlink on Unix, a copy on Windows
//   - prune old versioned binaries
//   - record `cli.installer = "npm"` and the npm registry in config.toml
//   - on Unix, replace the package's bin/fuigo with a symlink to a sibling
//     native binary so later launches are a single exec, with no node
//   - optionally generate shell completions (FUIGO_INSTALL_COMPLETIONS=1)
// Only a global install gets here (see fuigo-bootstrap.js). Fuigo's own updater runs it
// with FUIGO_INSTALL_ONLY=1 after `npm i -g`, since npm runs no install script.
// Nothing here writes to stdout: the launcher's stdout belongs to the user's command.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync, spawnSync } = require('child_process');
const os = require('os');
const { installVendorBinary, ensureFuigoHome, STAMP_NAME, globalInstallKind } = require('./fuigo-replace.js');

const IS_WINDOWS = process.platform === 'win32';
const EXE = IS_WINDOWS ? '.exe' : '';

function debug(msg) {
    if (process.env.FUIGO_BOOTSTRAP_DEBUG) console.error(`fuigo-bootstrap: ${msg}`);
}

// Extract a vendored binary (brotli, else plain) to destPath via temp + rename.
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
        // An empty vendored file is a broken package: never put it in place of a binary.
        if (fs.statSync(tmp).size === 0) return false;
        if (!IS_WINDOWS) fs.chmodSync(tmp, 0o755);
        fs.renameSync(tmp, destPath);
        return true;
    } catch {
        return false;
    } finally {
        try { fs.unlinkSync(tmp); } catch {}
    }
}

// Unix: atomic symlink swap. Windows: symlinks need elevation, so copy; if the
// exe is locked by a running process, rename it aside and retry.
function swapCanonical(canonicalPath, versionedName, versionedPath) {
    if (!IS_WINDOWS) {
        const tmpLink = canonicalPath + `.link.${process.pid}`;
        try { fs.unlinkSync(tmpLink); } catch {}
        fs.symlinkSync(versionedName, tmpLink);
        fs.renameSync(tmpLink, canonicalPath);
        return;
    }
    const oldPath = canonicalPath + '.old';
    try { fs.unlinkSync(oldPath); } catch {}
    try {
        try { fs.unlinkSync(canonicalPath); } catch {}
        fs.copyFileSync(versionedPath, canonicalPath);
    } catch {
        fs.renameSync(canonicalPath, oldPath);
        try {
            fs.copyFileSync(versionedPath, canonicalPath);
        } catch {
            try { fs.renameSync(oldPath, canonicalPath); } catch {}
            throw new Error('locked');
        }
    }
}

// Comparator: sort "<prefix>X.Y.Z" filenames by version, newest first.
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

// Best-effort cleanup of old versioned binaries for a given binary name. Keeps
// the current version and the previous one (a process may still be running it).
// Exact prefix + hyphen + digit, so fuigo-* never matches fuigo-pager-*.
function cleanupOldVersions(canonicalDir, binName, version) {
    try {
        const prefix = `${binName}-`;
        const currentVersioned = `${binName}-${version}${EXE}`;
        const old = fs.readdirSync(canonicalDir)
            .filter((e) => {
                if (!e.startsWith(prefix)) return false;
                if (e.includes('.tmp.') || e.includes('.link.')) return false;
                if (e === currentVersioned) return false;
                return /^\d/.test(e.slice(prefix.length));
            })
            .sort(byVersionDescending(prefix));
        for (const name of old.slice(1)) {
            try { fs.unlinkSync(path.join(canonicalDir, name)); } catch {}
        }
    } catch {}
}

// Record that npm installed this, and which registry `fuigo update` should use.
// Rewrites the file only when a value changes, via a temp file + rename, owner-only (0600).
// A config.toml that does not parse is left untouched (never replaced by a bare `[cli]`).
function writeInstallerConfig(fuigoHome) {
    let TOML;
    try { TOML = require('@iarna/toml'); } catch { debug('@iarna/toml unavailable, config.toml not written'); return; }
    const configPath = path.join(fuigoHome, 'config.toml');
    let obj = {};
    let exists = false;
    try {
        const text = fs.readFileSync(configPath, 'utf8');
        exists = true;
        obj = TOML.parse(text);
    } catch (e) {
        if (exists || (e && e.code !== 'ENOENT')) {
            debug(`config.toml unreadable or not valid TOML, left untouched: ${e.message}`);
            return;
        }
    }
    const before = JSON.stringify(obj);
    obj.cli ??= {};
    obj.cli.installer = 'npm';
    const registry = process.env.FUIGO_NPM_REGISTRY || (() => {
        try {
            // cwd is the user's home, never the launch directory: a project .npmrc there must not
            // decide the registry recorded in the user's global config.
            const resolved = execSync('npm config get registry',
                { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'], cwd: os.homedir() }).trim();
            if (resolved && resolved !== 'undefined') return resolved;
        } catch {}
        return null;
    })();
    if (registry) obj.cli.npm_registry = registry;
    if (JSON.stringify(obj) === before && fs.existsSync(configPath)) return;
    // 0600 for a new file; an existing file keeps the mode its owner gave it.
    let mode = 0o600;
    try { mode = fs.statSync(configPath).mode & 0o777; } catch {}
    const tmp = `${configPath}.tmp.${process.pid}`;
    try {
        fs.writeFileSync(tmp, TOML.stringify(obj), { encoding: 'utf8', mode, flag: 'w' });
        if (!IS_WINDOWS) fs.chmodSync(tmp, mode);
        fs.renameSync(tmp, configPath);
    } finally {
        try { fs.unlinkSync(tmp); } catch {}
    }
}

// Unix, launched through a symlink (npm's bin link): swap the package's bin/fuigo
// for a symlink to a sibling native binary, so every later launch is one exec.
// Windows keeps the node launcher (npm builds its cmd shims from it). A wrapper
// that is not a plain symlink (pnpm's shell shim) would run `node <binary>`, so
// it is left alone, as is any non-npm package manager. The launch environment has
// usually no npm_config_user_agent, so npm-only is decided by where the package
// lives (npm's global prefix, not a pnpm/yarn/bun store or a project) and by argv[1]
// being a symlink to the package's own bin/fuigo, which is what npm's bin link is.
function installBinLink(pkgBinDir, brotliPath, binaryPath, argv1) {
    if (IS_WINDOWS) return;
    if (globalInstallKind(pkgBinDir) !== 'npm') return;
    const agent = process.env.npm_config_user_agent;
    if (agent && !agent.startsWith('npm/')) return;
    const entryPath = path.join(pkgBinDir, 'fuigo');
    const nativePath = path.join(pkgBinDir, 'fuigo-native');
    const tmp = entryPath + `.link.${process.pid}`;
    try {
        if (fs.lstatSync(entryPath).isSymbolicLink()) return;
        if (!argv1 || !fs.lstatSync(argv1).isSymbolicLink()
            || fs.realpathSync(argv1) !== fs.realpathSync(entryPath)) return;
        if (!writeVendorBinary(brotliPath, binaryPath, nativePath)) return;
        try { fs.unlinkSync(tmp); } catch {}
        fs.symlinkSync('./fuigo-native', tmp);
        fs.renameSync(tmp, entryPath);
    } catch (e) {
        // Losing the link only costs latency; the node launcher still works.
        debug(`bin link not installed: ${e.message}`);
        try { fs.unlinkSync(tmp); } catch {}
    }
}

function generateCompletions(fuigoHome, fuigoPath) {
    if (process.env.FUIGO_INSTALL_COMPLETIONS !== '1' || IS_WINDOWS) return;
    try {
        const dir = path.join(fuigoHome, 'completions');
        const targets = [['bash', path.join(dir, 'bash', 'fuigo.bash')], ['zsh', path.join(dir, 'zsh', '_fuigo')]];
        for (const [shell, out] of targets) {
            fs.mkdirSync(path.dirname(out), { recursive: true });
            const res = spawnSync(fuigoPath, ['completions', shell], { encoding: 'utf8' });
            if (res.status === 0) fs.writeFileSync(out, res.stdout);
        }
    } catch {}
}

// The setup step runs `node fuigo-bootstrap.js`, so argv[1] is not npm's bin link; the link
// the user's PATH holds is <prefix>/bin/fuigo for <prefix>/lib/node_modules/fuigo.
function npmBinLinkFor(pkgBinDir) {
    try {
        const pkgDir = path.dirname(fs.realpathSync(pkgBinDir));
        return path.join(path.dirname(path.dirname(path.dirname(pkgDir))), 'bin', 'fuigo');
    } catch {
        return null;
    }
}

// Install for `version` from the platform package; returns the canonical path,
// or null when the caller should launch in place instead.
function installCanonical({ fuigoHome, version, brotliPath, binaryPath, stamp, pkgBinDir, argv1, installOnly }) {
    try {
        const canonicalDir = path.join(fuigoHome, 'bin');
        ensureFuigoHome(fuigoHome);
        fs.mkdirSync(canonicalDir, { recursive: true });
        const versionedName = `fuigo-${version}${EXE}`;
        const versionedPath = path.join(canonicalDir, versionedName);
        const canonicalPath = path.join(canonicalDir, `fuigo${EXE}`);
        if (!installVendorBinary(brotliPath, binaryPath, versionedPath)) return null;
        swapCanonical(canonicalPath, versionedName, versionedPath);
        if (!fs.existsSync(canonicalPath)) return null; // a broken wire-up is not success
        if (installOnly && !IS_WINDOWS && fs.readlinkSync(canonicalPath) !== versionedName) return null;
        cleanupOldVersions(canonicalDir, 'fuigo', version);
        cleanupOldVersions(canonicalDir, 'fuigo-pager', version);
        try { writeInstallerConfig(fuigoHome); } catch (e) { debug(`config.toml not written: ${e.message}`); }
        installBinLink(pkgBinDir, brotliPath, binaryPath, installOnly ? npmBinLinkFor(pkgBinDir) : argv1);
        generateCompletions(fuigoHome, canonicalPath);
        // Last: a stamp only ever describes a completed install.
        try { fs.writeFileSync(path.join(canonicalDir, STAMP_NAME), stamp); } catch {}
        return canonicalPath;
    } catch (e) {
        debug(`install failed: ${e.message}`);
        return null;
    }
}

module.exports = { installCanonical, writeVendorBinary, cleanupOldVersions, byVersionDescending };
