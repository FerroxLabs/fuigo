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
const os = require('os');
const cp = require('child_process');

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
//   'npm'   -- the package sits directly under npm's global root: <prefix>/lib/node_modules
//              (Unix) or <prefix>\node_modules (Windows) for a prefix we can name (see
//              globalPrefixes), a version manager's global root (nvm, nvm-windows, nodenv,
//              asdf, n, fnm), or Scoop's nodejs `bin\node_modules`
//   'other' -- a pnpm / yarn classic / bun / Volta global store
//   null    -- anything else: a project-local install, an npx cache, a checkout
// Only a global install may manage $FUIGO_HOME/bin and config.toml (and so mark itself
// FUIGO_MANAGED_BY_NPM for the global updater): a project-local or npx copy of another
// version must never swap the user's installed binary or run `npm i -g`.
//
// The decision never calls npm: `npm root -g` / `npm prefix -g` print path segments that
// look like UUIDs as `***` on npm 11, so they cannot be compared. A copy is LOCAL only on
// positive evidence (package.json beside its node_modules, an npx cache, a pnpm/yarn project
// store); otherwise a `lib/node_modules` (Unix) / `node_modules` (Windows) copy is global,
// whatever the prefix (asdf `.npm`, builtin npmrc, an env the shell did not inherit).
// FUIGO_NPM_PREFIX names the prefix explicitly for setups none of the sources reveal.
//
// classifyGlobal is the pure core (platform, env, paths and the realpath function are
// inputs), so every layout is unit-tested with Windows paths as plain strings.
function classifyGlobal(pkgBinDir, ctx) {
    const win = ctx.platform === 'win32';
    const p = win ? path.win32 : path.posix;
    const env = ctx.env || {};
    const real = ctx.realpath || ((x) => x);
    const home = ctx.home || '';
    const norm = (x) => {
        let r = p.normalize(String(x)).replace(/[\\/]+$/, '');
        if (win) r = r.toLowerCase();
        return r;
    };
    const fwd = (x) => norm(x).split(p.sep).join('/');
    const within = (child, root) => {
        if (!root) return false;
        const c = norm(child);
        const r = norm(root);
        return c === r || c.startsWith(r + p.sep);
    };
    const join = (...xs) => p.join(...xs);
    const pkgBin = String(pkgBinDir);
    const variants = (x) => { const r = real(x); return r === x ? [x] : [x, r]; };
    const locations = variants(pkgBin);

    // Is this node_modules dir the one `npm root -g` names? ctx.globalRoots() lazily returns
    // that output (and any real global dir). npm 11 masks UUID-like segments as `***`, so a
    // root containing `***` matches segment by segment with `***` standing for exactly one.
    let rootsCache = null;
    const isGlobalRoot = (nodeModules) => {
        if (!ctx.globalRoots) return false;
        if (rootsCache === null) {
            try { rootsCache = (ctx.globalRoots() || []).filter(Boolean).map(String); } catch { rootsCache = []; }
        }
        const mine = new Set(variants(nodeModules).map(fwd));
        for (const root of rootsCache) {
            const rs = fwd(root).split('/');
            for (const m of mine) {
                const ms = m.split('/');
                if (ms.length === rs.length && rs.every((seg, i) => seg === '***' || seg === ms[i])) return true;
            }
        }
        return false;
    };

    // Package-manager global stores that are not npm's. Realpath-ed locations point INTO
    // the store (pnpm: <store>/global/5/node_modules/.pnpm/...), so test containment.
    const local = env.LOCALAPPDATA || (home ? join(home, 'AppData', 'Local') : '');
    const xdgConfig = env.XDG_CONFIG_HOME || (home ? join(home, '.config') : '');
    const xdgData = env.XDG_DATA_HOME || (home ? join(home, '.local', 'share') : '');
    const voltaHome = env.VOLTA_HOME || (win ? local && join(local, 'Volta') : home && join(home, '.volta'));
    const others = [
        // Yarn classic: `yarn global dir`
        win ? local && join(local, 'Yarn', 'Data', 'global') : xdgConfig && join(xdgConfig, 'yarn', 'global'),
        !win && home && join(home, '.yarn', 'global'),
        // pnpm: $PNPM_HOME, else the per-OS default
        env.PNPM_HOME,
        win ? local && join(local, 'pnpm') : (ctx.platform === 'darwin' && home ? join(home, 'Library', 'pnpm') : xdgData && join(xdgData, 'pnpm')),
        // bun
        env.BUN_INSTALL ? join(env.BUN_INSTALL, 'install', 'global') : home && join(home, '.bun', 'install', 'global'),
        // Volta keeps each global package in its own image
        voltaHome && join(voltaHome, 'tools', 'image', 'packages'),
    ].filter(Boolean);
    const marked = locations.map(fwd);
    if (locations.some((l) => others.some((o) => within(l, o)))
        || marked.some((m) => /\/(pnpm|yarn)\/global\//.test(m) || /\/yarn\/data\/global\//.test(m)
            || m.includes('/.bun/install/global/') || m.includes('/volta/tools/image/packages/'))) {
        return 'other';
    }

    // POSITIVE evidence of a local copy wins over every global-shaped guess below. Real global
    // prefixes are not reliably nameable (asdf's `<ver>/.npm`, a prefix only in npm's builtin
    // npmrc, an env that a GUI-started shell did not inherit), so the default for a
    // `lib/node_modules` (Unix) or `node_modules` (Windows) copy is global and only these mark
    // it local: an npx cache, a pnpm/yarn project store, or a project root (a package.json
    // beside the node_modules). A global npm prefix has no package.json beside its node_modules.
    const exists = ctx.exists || (() => false);
    for (const loc of locations) {
        const segs = fwd(loc).split('/');
        if (segs.includes('_npx') || segs.includes('.pnpm') || segs.includes('.yarn')) return null;
        const nodeModules = p.dirname(p.dirname(loc));
        if (p.basename(nodeModules).toLowerCase() === 'node_modules'
            && exists(join(p.dirname(nodeModules), 'package.json'))) {
            // Ambiguous: a project root, OR a global prefix that happens to hold a package.json
            // (Windows prefix = the home dir, a Unix `~/.local` with a stray file). Ask npm
            // positively, and only here, so a normal startup never spawns it.
            // Cheap first: a known prefix (env, npmrc, node location) already names this root.
            const nmv = new Set(variants(nodeModules).map(norm));
            for (const prefix of ctx.prefixes || []) {
                if (!prefix) continue;
                const root = win ? join(prefix, 'node_modules') : join(prefix, 'lib', 'node_modules');
                if (variants(root).some((r) => nmv.has(norm(r)))) return 'npm';
            }
            if (isGlobalRoot(nodeModules)) return 'npm';
            return null;
        }
    }

    // The node_modules directory the package sits directly in.
    for (const loc of locations) {
        const nodeModules = p.dirname(p.dirname(loc));
        if (p.basename(nodeModules).toLowerCase() !== 'node_modules') continue;
        const nm = norm(nodeModules);
        const nmVariants = new Set(variants(nodeModules).map(norm));
        const roots = [];
        for (const prefix of ctx.prefixes || []) {
            if (!prefix) continue;
            const root = win ? join(prefix, 'node_modules') : join(prefix, 'lib', 'node_modules');
            for (const r of variants(root)) roots.push(norm(r));
        }
        if (roots.some((r) => nmVariants.has(r))) return 'npm';
        // Version managers keep one global root per Node version, and a copy installed under
        // one version may run under another (two nvm-windows versions).
        const f = nm.split(p.sep).join('/');
        if (win) {
            if (/\/nvm\/v?\d+\.\d+\.\d+\/node_modules$/.test(f)
                || (env.NVM_HOME && within(nodeModules, env.NVM_HOME) && /\/v?\d+\.\d+\.\d+\/node_modules$/.test(f))) return 'npm';
            // Scoop's nodejs: <scoop>\apps\nodejs\<current|ver>\bin\node_modules, persisted
            // under <scoop>\persist\nodejs\bin\node_modules.
            const scoops = [env.SCOOP, env.SCOOP_GLOBAL].filter(Boolean);
            const scoopish = f.includes('/scoop/') || scoops.some((s) => within(nodeModules, s));
            if (scoopish && /\/(apps\/nodejs[^/]*\/[^/]+|persist\/nodejs[^/]*)\/bin\/node_modules$/.test(f)) return 'npm';
        } else if (/\/(\.nvm\/versions\/node|\.nodenv\/versions|\.asdf\/installs\/nodejs|\/n\/versions\/node|\.?fnm\/node-versions)\/[^/]+(\/installation)?\/lib\/node_modules$/.test(f)) {
            return 'npm';
        }
    }
    // No named prefix matched, no local evidence: npm's global layout shape is `<prefix>/lib/
    // node_modules` on Unix and `<prefix>\\node_modules` on Windows, whatever the prefix is.
    for (const loc of locations) {
        const nodeModules = p.dirname(p.dirname(loc));
        if (p.basename(nodeModules).toLowerCase() !== 'node_modules') continue;
        if (win || p.basename(p.dirname(nodeModules)) === 'lib') return 'npm';
    }
    return null;
}

// npm's global prefix candidates for this process, none of them from running npm.
function globalPrefixes(ctx) {
    const win = ctx.platform === 'win32';
    const p = win ? path.win32 : path.posix;
    const env = ctx.env || {};
    const out = [env.FUIGO_NPM_PREFIX, env.npm_config_prefix, env.NPM_CONFIG_PREFIX, env.PREFIX, ...(ctx.npmrcPrefixes || [])];
    const exes = ctx.execPaths || [];
    for (const exe of exes) {
        if (win) {
            out.push(p.dirname(exe), p.join(p.dirname(exe), 'bin')); // node.exe next to npm; Scoop's current\bin
        } else {
            out.push(p.dirname(p.dirname(exe))); // <prefix>/bin/node
        }
    }
    if (win) {
        if (env.APPDATA) out.push(p.join(env.APPDATA, 'npm'));
    } else {
        out.push('/usr', '/usr/local', '/opt/homebrew', '/opt/local');
        if (ctx.home) out.push(p.join(ctx.home, '.npm-global'), p.join(ctx.home, '.npm-packages'), p.join(ctx.home, '.local'));
    }
    return out.filter(Boolean);
}

// `prefix=` from an npmrc text (comments and quotes stripped, ${VAR} and a leading ~ expanded).
function npmrcPrefix(text, env, home) {
    let found = null;
    for (const raw of String(text).split(/\r?\n/)) {
        const m = /^\s*prefix\s*=\s*(.*?)\s*$/.exec(raw);
        if (!m) continue;
        let v = m[1].replace(/^(["'])(.*)\1$/, '$2');
        v = v.replace(/\$\{([^}]+)\}/g, (_, k) => env[k] ?? '');
        if (v === '~' || /^~[\\/]/.test(v)) v = home + v.slice(1);
        if (v) found = v;
    }
    return found;
}

const NPM_ROOT_TIMEOUT_MS = 5000;
const NPM_ROOT_CACHE_MAX = 64;

// Per-user cache files outside the package, most preferred first. Never under ~/.fuigo: a
// project-local copy must not create Fuigo's home.
function userNpmRootCacheFiles() {
    const env = process.env;
    const dirs = [];
    if (process.platform === 'win32') {
        if (env.LOCALAPPDATA) dirs.push(path.join(env.LOCALAPPDATA, 'fuigo'));
    } else {
        if (env.XDG_CACHE_HOME && path.isAbsolute(env.XDG_CACHE_HOME)) dirs.push(path.join(env.XDG_CACHE_HOME, 'fuigo'));
        else { try { dirs.push(path.join(os.homedir(), '.cache', 'fuigo')); } catch {} }
    }
    let uid = 'u';
    try { uid = typeof process.getuid === 'function' ? String(process.getuid()) : os.userInfo().username; } catch {}
    // The tmpdir is shared and world-writable: only usable where we can verify ownership.
    if (typeof process.getuid === 'function') dirs.push(path.join(os.tmpdir(), `fuigo-${uid}`));
    return dirs.map((d) => path.join(d, 'fuigo-npm-root.json'));
}

// lstat is injectable so tests can simulate another owner without needing root.
const npmRootCacheHooks = { lstat: (f) => fs.lstatSync(f) };

// A cache location is trusted only if it is a real (non-symlink) entry of the right kind, owned
// by this user and, for directories, not group/world-writable. Where there is no getuid
// (Windows) the per-user LOCALAPPDATA dir is trusted as a real, non-symlink entry.
function secureEntry(f, wantDir) {
    try {
        const st = npmRootCacheHooks.lstat(f);
        if (st.isSymbolicLink()) return false;
        if (wantDir ? !st.isDirectory() : !st.isFile()) return false;
        if (typeof process.getuid === 'function') {
            if (st.uid !== process.getuid()) return false;
            if (wantDir && (st.mode & 0o022) !== 0) return false;
        }
        return true;
    } catch { return false; }
}

function readNpmRootCache(pkgDir, key) {
    try {
        const c = JSON.parse(fs.readFileSync(path.join(pkgDir, '.fuigo-npm-root.json'), 'utf8'));
        if (c && c.key === key && Array.isArray(c.roots)) return c.roots;
    } catch {}
    for (const f of userNpmRootCacheFiles()) {
        try {
            if (!secureEntry(path.dirname(f), true) || !secureEntry(f, false)) continue;
            const m = JSON.parse(fs.readFileSync(f, 'utf8'));
            const r = m && m[key];
            if (Array.isArray(r)) return r;
        } catch {}
    }
    return null;
}

function writeNpmRootCache(pkgDir, key, roots) {
    try { fs.writeFileSync(path.join(pkgDir, '.fuigo-npm-root.json'), JSON.stringify({ key, roots })); return true; } catch {}
    for (const f of userNpmRootCacheFiles()) {
        try {
            fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
            if (!secureEntry(path.dirname(f), true)) continue;
            let m = {};
            let exists = true;
            try { npmRootCacheHooks.lstat(f); } catch { exists = false; }
            if (exists && !secureEntry(f, false)) continue;
            try { const old = JSON.parse(fs.readFileSync(f, 'utf8')); if (old && typeof old === 'object' && !Array.isArray(old)) m = old; } catch {}
            delete m[key];
            m[key] = roots;
            const keys = Object.keys(m);
            for (const k of keys.slice(0, Math.max(0, keys.length - NPM_ROOT_CACHE_MAX))) delete m[k];
            const tmp = `${f}.${process.pid}.tmp`;
            try { fs.unlinkSync(tmp); } catch {}
            fs.writeFileSync(tmp, JSON.stringify(m), { flag: 'wx', mode: 0o600 });
            fs.renameSync(tmp, f);
            return true;
        } catch {}
    }
    return false;
}

function globalInstallKind(pkgBinDir) {
    const realOf = (x) => { try { return fs.realpathSync(x); } catch { return x; } };
    const env = process.env;
    const home = os.homedir();
    const win = process.platform === 'win32';
    const execPaths = [process.execPath];
    const execReal = realOf(process.execPath);
    if (execReal !== process.execPath) execPaths.push(execReal);
    const npmrcFiles = [env.npm_config_userconfig, path.join(home, '.npmrc'), env.npm_config_globalconfig,
        ...execPaths.map((e) => (win ? path.join(path.dirname(e), 'etc', 'npmrc') : path.join(path.dirname(path.dirname(e)), 'etc', 'npmrc')))];
    const npmrcPrefixes = [];
    for (const f of npmrcFiles) {
        if (!f) continue;
        try {
            const v = npmrcPrefix(fs.readFileSync(f, 'utf8'), env, home);
            if (v) npmrcPrefixes.push(v);
        } catch {}
    }
    const ctx = { platform: process.platform, env, home, realpath: realOf, execPaths, npmrcPrefixes, exists: fs.existsSync };
    ctx.prefixes = globalPrefixes(ctx);
    // `npm root -g` is spawned only when the cheap prefixes could not answer, and its output is
    // cached (keyed by the package's realpath, version and node binary), so a project-local copy
    // pays for it once per installed version, not on every launch. The cache lives next to the
    // package; when that dir is read-only (root-owned `npm ci`, Nix store, read-only mount) it
    // falls back to a per-user cache file outside the package. Only a successful answer is
    // cached; with nothing writable npm is still asked at most once per process.
    ctx.globalRoots = () => {
        const pkgDir = path.dirname(pkgBinDir);
        let version = '';
        try { version = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version || ''; } catch {}
        const key = [realOf(pkgDir), version, execReal].join('|');
        const cached = readNpmRootCache(pkgDir, key);
        if (cached) return cached;
        let out = '';
        try {
            out = cp.execFileSync(win ? 'npm.cmd' : 'npm', ['root', '-g'], {
                encoding: 'utf8', timeout: NPM_ROOT_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'], shell: win,
            }).trim().split(/\r?\n/).pop();
        } catch { return []; }
        if (!out) return [];
        writeNpmRootCache(pkgDir, key, [out]);
        return [out];
    };
    return classifyGlobal(pkgBinDir, ctx);
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

// The version `<bin>/fuigo[.exe]` runs, or null when unknown. Unix: the symlink target
// fuigo-<version>. Windows has no symlink (it is a copy of fuigo-<version>.exe), so read the
// stamp a completed install writes last (its first element is the version); without a usable
// stamp, the newest fuigo-<version>.exe whose size equals the copy's. That is what lets a
// starting older global copy see a newer fuigo.exe and not overwrite it.
function canonicalVersion(canonicalPath, platform = process.platform) {
    try {
        const m = /^fuigo-(\d.*)$/.exec(path.basename(fs.readlinkSync(canonicalPath)));
        return m && parseVersion(m[1]) ? m[1] : null;
    } catch {}
    if (platform !== 'win32') return null;
    try {
        const dir = path.dirname(canonicalPath);
        const size = fs.statSync(canonicalPath).size;
        const versioned = (v) => {
            try { return fs.statSync(path.join(dir, `fuigo-${v}.exe`)).size === size; } catch { return false; }
        };
        try {
            const v = JSON.parse(fs.readFileSync(path.join(dir, STAMP_NAME), 'utf8'))[0];
            if (typeof v === 'string' && parseVersion(v) && versioned(v)) return v;
        } catch {}
        let best = null;
        for (const e of fs.readdirSync(dir)) {
            const m = /^fuigo-(\d.*)\.exe$/i.exec(e);
            if (!m || !parseVersion(m[1]) || !versioned(m[1])) continue;
            if (best === null || compareVersions(m[1], best) > 0) best = m[1];
        }
        return best;
    } catch {
        return null;
    }
}

module.exports = {
    installVendorBinary, ensureFuigoHome, installStamp, STAMP_NAME,
    globalInstallKind, npmRootCacheHooks, classifyGlobal, globalPrefixes, npmrcPrefix, compareVersions, canonicalVersion,
};
