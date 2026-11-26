import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { downloadAndUnzipVSCode, resolveCliArgsFromVSCodeExecutablePath, runTests } from '@vscode/test-electron';

// usage: node runTest.js download          (needs network; caches VS Code in .vscode-test)
//        node runTest.js run <workspace>   (offline; run inside `unshare -n`)
// env:   VSCODE_VERSION  VS Code build to test on (default: 1.94.2, the engines.vscode floor)
//        VSIX            test the packaged extension: install this .vsix into a private extensions dir and run the
//                        suite against that copy instead of the dev folder
const VERSION = process.env.VSCODE_VERSION || '1.94.2';

async function main() {
  const [cmd, workspace] = process.argv.slice(2);
  const vscodeExecutablePath = await downloadAndUnzipVSCode(VERSION);
  if (cmd === 'download') return;
  const home = process.env.HOME ?? '/tmp';
  const root = path.resolve(__dirname, '../../..');
  const env = { ...process.env } as Record<string, string>;
  let extensionDevelopmentPath = root;
  const launchArgs = [workspace, '--no-sandbox', '--disable-gpu', '--disable-workspace-trust', '--user-data-dir', path.join(home, 'vscode-user')];
  if (process.env.VSIX) {
    const extDir = path.join(home, 'vscode-extensions');
    const [cli, ...cliArgs] = resolveCliArgsFromVSCodeExecutablePath(vscodeExecutablePath);
    const r = spawnSync(cli, [...cliArgs, '--extensions-dir', extDir, '--install-extension', path.resolve(process.env.VSIX), '--force'], { stdio: 'inherit' });
    if (r.status !== 0) throw new Error('installing the VSIX failed');
    // A stub dev extension: the test host needs one, and it must not be the dev folder under test.
    extensionDevelopmentPath = path.join(home, 'vsix-smoke-host');
    fs.mkdirSync(extensionDevelopmentPath, { recursive: true });
    fs.writeFileSync(path.join(extensionDevelopmentPath, 'package.json'),
      JSON.stringify({ name: 'vsix-smoke-host', publisher: 'test', version: '0.0.0', engines: { vscode: '*' } }));
    launchArgs.push('--extensions-dir', extDir);
    env.FUIGO_EXPECT_EXT_DIR = extDir;
  } else {
    launchArgs.push('--disable-extensions');
  }
  await runTests({ vscodeExecutablePath, extensionDevelopmentPath, extensionTestsPath: path.join(__dirname, 'suite', 'index.js'), launchArgs, extensionTestsEnv: env });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
