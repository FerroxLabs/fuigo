import * as os from 'node:os';
import * as vscode from 'vscode';
import { AgentController } from './acp/agent';
import { AcpConnection } from './acp/connection';
import { ToolCallCache } from './acp/permission';
import { INSTALL_COMMAND, resolveBinary, spawnAgent, userSetting } from './acp/process';
import { onDidShowPrompt, registerPromptUi } from './acp/ui';
import { IDE_MCP_SERVERS, IDE_SERVER_NAME, registerIdeTools } from './context';
import { registerEdits } from './edits';
import { ChatPanel } from './panel/ChatPanel';

class BinaryNotFound extends Error {}

const LAST_SESSION_KEY = 'fuigo.lastSessionId';

const cwd = () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir();

async function findBinary(): Promise<string | undefined> {
  const configured = userSetting(vscode.workspace.getConfiguration('fuigo').inspect<string>('path'));
  const bin = await resolveBinary(configured);
  if (!bin) void showInstallNotice(!!configured?.trim());
  return bin;
}

async function showInstallNotice(configured: boolean) {
  const msg = configured
    ? 'Fuigo: the binary set in "fuigo.path" does not exist or is not executable.'
    : `Fuigo: the fuigo binary was not found on PATH or in the npm global install. Install it with: ${INSTALL_COMMAND}`;
  onDidShowPrompt.fire({ kind: 'install', title: msg });
  const pick = await vscode.window.showErrorMessage(msg, 'Copy install command', 'Set fuigo.path');
  if (pick === 'Copy install command') await vscode.env.clipboard.writeText(INSTALL_COMMAND);
  if (pick === 'Set fuigo.path') await vscode.commands.executeCommand('workbench.action.openSettings', 'fuigo.path');
}

export function activate(context: vscode.ExtensionContext) {
  const out = vscode.window.createOutputChannel('Fuigo');
  const conn = new AcpConnection();
  const agent = new AgentController(
    conn,
    async () => {
      const bin = await findBinary();
      if (!bin) throw new BinaryNotFound('fuigo binary not found');
      out.appendLine(`starting ${bin} agent stdio in ${cwd()}`);
      return spawnAgent(bin, cwd(), (s) => out.append(s));
    },
    cwd,
    String(context.extension.packageJSON.version ?? '0.0.0'),
    IDE_MCP_SERVERS,
    {
      get: () => context.workspaceState.get<string>(LAST_SESSION_KEY),
      set: (id) => void context.workspaceState.update(LAST_SESSION_KEY, id),
    },
  );
  const cache = new ToolCallCache();
  context.subscriptions.push(out, conn.onSessionUpdate((_sid, u) => cache.apply(u)), { dispose: () => agent.stop() });

  registerPromptUi(context, conn, cache);
  registerEdits(context, conn); // also serves fs/read_text_file + fs/write_text_file
  registerIdeTools(context, conn);

  const panel = new ChatPanel(context.extensionUri, agent, (e) => {
    if (!(e instanceof BinaryNotFound)) out.appendLine(`error: ${String((e as Error)?.message ?? e)}`);
  });
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(ChatPanel.viewId, panel, { webviewOptions: { retainContextWhenHidden: true } }),
    vscode.commands.registerCommand('fuigo.focus', () => vscode.commands.executeCommand(`${ChatPanel.viewId}.focus`)),
    vscode.commands.registerCommand('fuigo.newSession', () => panel.startSession(true)),
    vscode.commands.registerCommand('fuigo.stop', () => agent.cancel()),
    vscode.commands.registerCommand('fuigo.openInTerminal', async () => {
      const bin = await findBinary();
      if (!bin) return;
      vscode.window.createTerminal({ name: 'Fuigo', shellPath: bin, cwd: cwd() }).show();
    }),
  );

  // Test/automation surface (the integration test drives the real agent through this).
  return { client: conn, agent, panel, onDidShowPrompt: onDidShowPrompt.event, ideServerName: IDE_SERVER_NAME };
}

export function deactivate() {}
