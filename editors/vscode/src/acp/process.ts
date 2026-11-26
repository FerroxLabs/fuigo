import { execFile, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import type { Transport } from './connection';

export const INSTALL_COMMAND = 'npm install -g fuigo';

function isExecutable(p: string): boolean {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) return false;
    if (process.platform === 'win32') return true;
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** PATH lookup for `fuigo` (with PATHEXT on Windows). */
export function findOnPath(env: NodeJS.ProcessEnv = process.env, platform = process.platform): string | undefined {
  const dirs = (env.PATH ?? env.Path ?? '').split(path.delimiter).filter(Boolean);
  const exts = platform === 'win32' ? (env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';').filter(Boolean) : [''];
  for (const d of dirs) for (const e of exts) {
    const p = path.join(d, 'fuigo' + e);
    if (isExecutable(p)) return p;
  }
  return undefined;
}

function npmGlobalPrefix(): Promise<string | undefined> {
  return new Promise((resolve) => {
    execFile(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['prefix', '-g'], { timeout: 5000, shell: process.platform === 'win32' },
      (err, stdout) => resolve(err ? undefined : stdout.trim() || undefined));
  });
}

/**
 * `fuigo.path` from user (or remote machine) settings only. A workspace or folder value is ignored: it comes from the
 * repository (`.vscode/settings.json`), and honouring it would let a cloned repo pick the binary this extension runs.
 * package.json scopes the setting `machine` for the same reason; this also covers forks that do not enforce scopes.
 */
export function userSetting(i: { globalValue?: string } | undefined): string | undefined {
  return i?.globalValue;
}

/** Setting `fuigo.path`, then PATH, then the npm global install of the `fuigo` package. */
export async function resolveBinary(configured: string | undefined): Promise<string | undefined> {
  const c = configured?.trim();
  if (c) return isExecutable(c) ? c : undefined;
  const onPath = findOnPath();
  if (onPath) return onPath;
  const prefix = await npmGlobalPrefix();
  if (!prefix) return undefined;
  const candidates = process.platform === 'win32' ? [path.join(prefix, 'fuigo.cmd')] : [path.join(prefix, 'bin', 'fuigo')];
  return candidates.find(isExecutable);
}

/** Spawn `<bin> agent stdio` and expose its stdio as a line transport. */
export function spawnAgent(bin: string, cwd: string, log: (s: string) => void): Transport {
  // npm's Windows shim is a .cmd, which needs cmd.exe; quote the path so spaces or & in it stay one argument.
  const shell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(bin);
  const child = spawn(shell ? `"${bin}"` : bin, ['agent', 'stdio'], { cwd, stdio: ['pipe', 'pipe', 'pipe'], shell });
  const lineCbs: ((l: string) => void)[] = [];
  const closeCbs: ((r: string) => void)[] = [];
  let closed = false;
  const fire = (r: string) => {
    if (closed) return;
    closed = true;
    closeCbs.forEach((cb) => cb(r));
  };
  readline.createInterface({ input: child.stdout }).on('line', (l) => lineCbs.forEach((cb) => cb(l)));
  child.stderr.on('data', (d) => log(String(d)));
  child.on('error', (e) => fire(e.message));
  child.on('exit', (code, sig) => fire(sig ? `signal ${sig}` : `code ${code}`));
  child.stdin.on('error', () => {}); // EPIPE after exit is reported through 'exit'
  return {
    send: (line) => {
      if (!closed) child.stdin.write(line + '\n');
    },
    onLine: (cb) => void lineCbs.push(cb),
    onClose: (cb) => void closeCbs.push(cb),
    close: () => {
      child.stdin.end();
      child.kill('SIGTERM');
    },
  };
}
