#!/usr/bin/env node
// Runs once after npm install/update. Reads the fuigo binary from the
// matching per-platform optional dependency (fuigo-<platform>)
// and installs it to ~/.fuigo/bin/ using versioned filenames:
//
//   Unix:    fuigo-<version>  +  fuigo  (symlink)
//   Windows: fuigo-<version>.exe  +  fuigo.exe  (copy)
//
// Versioned files ensure running processes are never disrupted on macOS
// (replacing a binary that a running process has mmap'd causes SIGKILL
// because the kernel can no longer verify the code signature).
const path = require('path');
const fs = require('fs');
const os = require('os');
const zlib = require('zlib');
const { execSync } = require('child_process');
const TOML = require('@iarna/toml');

// $FUIGO_HOME (else ~/.fuigo), matching the Rust fuigo_home(): a symlinked
// $HOME resolves the same way. Lets fleets relocate the binary off a slow $HOME
// (NFS); old code hardcoded os.homedir().
function defaultFuigoHome() {
    const home = os.homedir();
    try { return path.join(fs.realpathSync(home), '.fuigo'); } catch { return path.join(home, '.fuigo'); }
}
const FUIGO_HOME = process.env.FUIGO_HOME ?? defaultFuigoHome();
const CANONICAL_DIR = path.join(FUIGO_HOME, 'bin');

const key = `${process.platform}-${process.arch}`;
const SUPPORTED = new Set([
    'darwin-arm64',
    'darwin-x64',
    'linux-x64',
    'linux-arm64',
    'win32-x64',
    'win32-arm64',
]);
if (!SUPPORTED.has(key)) {
    console.error(`fuigo: unsupported platform ${key}`);
    process.exit(0);
}

// Resolve the per-platform sibling package's directory. The matching
// optionalDependency is installed by npm based on `os`/`cpu` filters; the
// other five are silently skipped. If the matching one is missing, npm was
// likely invoked with --no-optional or the platform is unsupported.
function resolvePlatformPackageDir() {
    const platformPkg = `fuigo-${key}`;
    try {
        return path.dirname(require.resolve(`${platformPkg}/package.json`));
    } catch {
        return null;
    }
}

let version;
try { version = require('../package.json').version; } catch {}
if (!version) {
    console.error('fuigo: unable to determine version');
    process.exit(0);
}

const IS_WINDOWS = process.platform === 'win32';
const EXE = IS_WINDOWS ? '.exe' : '';

fs.mkdirSync(CANONICAL_DIR, { recursive: true });

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
        if (!IS_WINDOWS) fs.chmodSync(tmp, 0o755);
        fs.renameSync(tmp, destPath);
        return true;
    } catch {
        return false;
    } finally {
        try { fs.unlinkSync(tmp); } catch {}
    }
}

function installBinary(binName, sourceDir, vendorSubpath) {
    const brotliPath = path.join(sourceDir, 'bin', vendorSubpath + '.br');
    const binaryPath = path.join(sourceDir, 'bin', vendorSubpath);

    const versionedName = `${binName}-${version}${EXE}`;
    const versionedPath = path.join(CANONICAL_DIR, versionedName);
    const canonicalName = `${binName}${EXE}`;
    const canonicalPath = path.join(CANONICAL_DIR, canonicalName);

    // Skip if this exact version is already installed.
    if (!fs.existsSync(versionedPath) && !writeVendorBinary(brotliPath, binaryPath, versionedPath)) {
        console.error(`fuigo: missing binary at ${brotliPath}`);
        return false;
    }

    if (IS_WINDOWS) {
        // Symlinks need elevation on Windows; copy instead. If the exe is
        // locked by a running process, rename it aside then retry.
        const oldPath = canonicalPath + '.old';
        try { fs.unlinkSync(oldPath); } catch {} // stale backup from prior update
        try {
            try { fs.unlinkSync(canonicalPath); } catch {}
            fs.copyFileSync(versionedPath, canonicalPath);
        } catch (e) {
            try {
                fs.renameSync(canonicalPath, oldPath);
                try {
                    fs.copyFileSync(versionedPath, canonicalPath);
                } catch (copyErr) {
                    // Rollback: restore the old binary so the install isn't broken.
                    try { fs.renameSync(oldPath, canonicalPath); } catch {}
                    throw copyErr;
                }
            } catch (e2) {
                console.error(`fuigo: failed to update ${canonicalPath}: ${e2.message}`);
                console.error('Close all running fuigo processes and try again.');
                return false;
            }
        }
    } else {
        // Atomic symlink swap.
        const tmpLink = canonicalPath + `.link.${process.pid}`;
        try { fs.unlinkSync(tmpLink); } catch {}
        fs.symlinkSync(versionedName, tmpLink);
        fs.renameSync(tmpLink, canonicalPath);
    }

    // Don't report a broken wire-up as success.
    if (!fs.existsSync(canonicalPath)) {
        console.error(`fuigo: ${canonicalName} did not resolve after install`);
        return false;
    }

    console.log(`${binName} ${version} installed to ${canonicalPath} -> ${versionedName}`);
    return true;
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

// Best-effort cleanup of old versioned binaries for a given binary name.
// Keeps the current version and the previous one (in case a process is still
// running the old binary and hasn't fully loaded all pages yet).
// Uses an exact prefix match + hyphen + digit to avoid fuigo-* matching fuigo-pager-*.
function cleanupOldVersions(binName) {
    try {
        const prefix = `${binName}-`;
        const currentVersioned = `${binName}-${version}${EXE}`;
        const entries = fs.readdirSync(CANONICAL_DIR);
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
            try { fs.unlinkSync(path.join(CANONICAL_DIR, old)); } catch {}
        }
    } catch {}
}

const platformDir = resolvePlatformPackageDir();
if (!platformDir) {
    console.error(`fuigo: platform package fuigo-${key} not installed.`);
    console.error('  This usually means npm was invoked with --no-optional, or the install failed.');
    console.error('  Try: npm install -g fuigo');
    process.exit(0);
}

// Point the bin entry at a binary extracted beside it: launches become one
// process, and the link can only dangle if the package itself is broken.
// Windows keeps the node launcher; npm generates its command shims from it.
function installBinLink(platformDir) {
    if (IS_WINDOWS) return;
    // Other package managers wrap the entry's `#!` line in their own launchers.
    if (!(process.env.npm_config_user_agent ?? '').startsWith('npm/')) return;
    const brotliPath = path.join(platformDir, 'bin', `fuigo${EXE}.br`);
    const binaryPath = path.join(platformDir, 'bin', `fuigo${EXE}`);
    const nativePath = path.join(__dirname, 'fuigo-native');
    const entryPath = path.join(__dirname, 'fuigo');
    const tmp = entryPath + `.link.${process.pid}`;
    try {
        if (!writeVendorBinary(brotliPath, binaryPath, nativePath)) {
            return;
        }
        try { fs.unlinkSync(tmp); } catch {}
        fs.symlinkSync('./fuigo-native', tmp);
        fs.renameSync(tmp, entryPath);
    } catch (e) {
        // Losing the link only costs latency; the node launcher still works.
        console.error(`fuigo: bin link not installed: ${e.message}`);
        try { fs.unlinkSync(tmp); } catch {}
    }
}

if (installBinary('fuigo', platformDir, `fuigo${EXE}`)) {
    installBinLink(platformDir);
}
cleanupOldVersions('fuigo');
cleanupOldVersions('fuigo-pager');

// Write installer config
const configDir = FUIGO_HOME;
const configPath = path.join(configDir, 'config.toml');
let obj = {};
try { obj = TOML.parse(fs.readFileSync(configPath, 'utf8')); } catch { }
obj.cli ??= {};
obj.cli.installer = 'npm';

// Persist the npm registry so `fuigo update` and the launcher use the same one.
const npmRegistry = process.env.FUIGO_NPM_REGISTRY
    || (() => {
        try {
            const resolved = execSync(
                'npm config get registry',
                { encoding: 'utf8', timeout: 5000 }
            ).trim();
            if (resolved && resolved !== 'undefined') return resolved;
        } catch {}
        return null;
    })();

if (npmRegistry) {
    obj.cli.npm_registry = npmRegistry;
}

fs.writeFileSync(configPath, TOML.stringify(obj), 'utf8');

// Shell completions: print setup hints (no silent shell config mutation).
// Set FUIGO_INSTALL_COMPLETIONS=1 to auto-generate to ~/.fuigo/completions.
const FUIGO_PATH = path.join(CANONICAL_DIR, `fuigo${EXE}`);
if (process.env.FUIGO_INSTALL_COMPLETIONS === '1' && !IS_WINDOWS) {
    try {
        const { spawnSync } = require('child_process');
        const completionsDir = path.join(FUIGO_HOME, 'completions');
        const bashPath = path.join(completionsDir, 'bash', 'fuigo.bash');
        const zshPath = path.join(completionsDir, 'zsh', '_fuigo');
        fs.mkdirSync(path.dirname(bashPath), { recursive: true });
        fs.mkdirSync(path.dirname(zshPath), { recursive: true });
        const bashRes = spawnSync(FUIGO_PATH, ['completions', 'bash'], { encoding: 'utf8' });
        if (bashRes.status === 0) fs.writeFileSync(bashPath, bashRes.stdout);
        const zshRes = spawnSync(FUIGO_PATH, ['completions', 'zsh'], { encoding: 'utf8' });
        if (zshRes.status === 0) fs.writeFileSync(zshPath, zshRes.stdout);
        console.log('Completions generated to ~/.fuigo/completions (bash/zsh)');
    } catch {}
} else if (!IS_WINDOWS) {
    console.log('Tip: fuigo completions bash > ~/.local/share/bash-completion/completions/fuigo');
    console.log('     fuigo completions zsh  > ~/.zsh/completions/_fuigo');
}
