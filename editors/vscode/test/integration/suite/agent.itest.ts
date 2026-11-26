// Drives the real `fuigo agent stdio` (FUIGO path from the user setting; the workspace sets a decoy) against the scripted mock model.
import * as assert from 'assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vscode from 'vscode';

const MOCK = process.env.MOCK_ADMIN!;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const queue = (turns: unknown[]) => fetch(MOCK + '/admin/queue', { method: 'POST', body: JSON.stringify(turns) });
const edit = (old_string: string, new_string: string) => ({ name: 'search_replace', args: { file_path: 'hello.txt', old_string, new_string } });

async function until<T>(what: string, fn: () => T | undefined, ms = 60000): Promise<T> {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(100)) {
    const v = fn();
    if (v) return v;
  }
  throw new Error('timed out waiting for ' + what);
}

const heldDiffOpen = () =>
  vscode.window.tabGroups.all.flatMap((g) => g.tabs).some((t) => t.input instanceof vscode.TabInputTextDiff && t.input.modified.scheme === 'fuigo-edit');

describe('Fuigo extension against the real agent', function () {
  let api: any;
  let updates: any[];
  let prompts: { kind: string; title: string }[];
  const ws = vscode.workspace.workspaceFolders![0].uri.fsPath;
  const hello = path.join(ws, 'hello.txt');

  before(async () => {
    const ext = vscode.extensions.getExtension('ferroxlabs.fuigo')!;
    // VSIX smoke: the extension under test must be the installed package, not the dev folder.
    const extDir = process.env.FUIGO_EXPECT_EXT_DIR;
    if (extDir) assert.ok(ext.extensionPath.startsWith(extDir + path.sep), `extension loaded from ${ext.extensionPath}, not ${extDir}`);
    api = await ext.activate();
    updates = [];
    prompts = [];
    api.client.onSessionUpdate((_s: string, u: any) => updates.push(u));
    api.onDidShowPrompt((e: any) => prompts.push(e));
    const info = await api.agent.ensureSession();
    assert.ok(info.sessionId, 'session/new returned a session id');
    assert.deepStrictEqual(info.modes.map((m: any) => m.id).slice(0, 2), ['default', 'plan']);
  });

  after(() => api?.agent.stop());

  it('edit in ask mode: reads the dirty buffer, holds the write in a diff, Accept writes buffer and disk', async () => {
    const doc = await vscode.workspace.openTextDocument(hello);
    const ed = await vscode.window.showTextDocument(doc);
    await ed.edit((e) => e.insert(doc.lineAt(1).range.end, ' (unsaved)'));
    assert.ok(doc.isDirty);
    await queue([{ tool_calls: [edit('hello', 'howdy')] }, { text: 'edited' }]);
    updates.length = 0;
    const turn = api.panel.send('change hello to howdy in hello.txt');
    await until('held diff', heldDiffOpen);
    assert.strictEqual(fs.readFileSync(hello, 'utf8'), 'hello world\nsecond line\n', 'nothing written before Accept');
    await vscode.commands.executeCommand('fuigo.edits.accept', { path: hello });
    await turn;
    assert.strictEqual(doc.getText(), 'howdy world\nsecond line (unsaved)\n');
    assert.strictEqual(fs.readFileSync(hello, 'utf8'), 'howdy world\nsecond line (unsaved)\n');
    assert.ok(updates.some((u) => u.sessionUpdate === 'agent_message_chunk' && u.content?.text === 'edited'), 'agent text streamed');
    assert.ok(updates.some((u) => u.sessionUpdate === 'tool_call_update' && u.status === 'completed'));
    assert.deepStrictEqual(prompts.filter((p) => p.kind === 'permission'), [], 'edit permission went to the diff, not a QuickPick');
  });

  it('Reject in the diff fails only that edit; the turn continues', async () => {
    await vscode.commands.executeCommand('workbench.action.closeAllEditors');
    await queue([{ tool_calls: [edit('world', 'there')] }, { text: 'after reject' }]);
    updates.length = 0;
    const turn = api.panel.send('change world to there');
    await until('held diff', heldDiffOpen);
    await vscode.commands.executeCommand('fuigo.edits.reject', { path: hello });
    await turn;
    assert.strictEqual(fs.readFileSync(hello, 'utf8'), 'howdy world\nsecond line (unsaved)\n');
    assert.ok(updates.some((u) => u.sessionUpdate === 'tool_call_update' && u.status === 'failed'), 'edit failed');
    assert.ok(updates.some((u) => u.sessionUpdate === 'agent_message_chunk' && u.content?.text === 'after reject'), 'turn went on');
  });

  it('IDE tools are auto-allowed and served over fuigo/mcp/sdk_call', async () => {
    await queue([
      { tool_calls: [{ name: 'search_tool', args: { query: 'ide selection' } }] },
      { tool_calls: [{ name: 'use_tool', args: { tool_name: `${api.ideServerName}__ide_get_workspace_folders`, tool_input: {} } }] },
      { text: 'got folders' },
    ]);
    updates.length = 0;
    prompts.length = 0;
    await api.panel.send('which folders are open?');
    const done = updates.filter((u) => u.sessionUpdate === 'tool_call_update' && u.status === 'completed');
    assert.ok(done.some((u) => JSON.stringify(u.rawOutput ?? '').includes(ws)), 'tool output carries the workspace folder: ' + JSON.stringify(done));
    assert.deepStrictEqual(prompts, [], 'no prompt for our own IDE tools');
  });

  it('plan mode: exit_plan_mode is answered through the QuickPick and returns to default', async () => {
    await api.agent.setMode('plan');
    await queue([{ tool_calls: [{ name: 'exit_plan_mode', args: {} }] }, { text: 'plan approved, done' }]);
    const sub = api.onDidShowPrompt(async (e: any) => {
      if (e.kind !== 'plan') return;
      await sleep(500);
      await vscode.commands.executeCommand('workbench.action.acceptSelectedQuickOpenItem'); // first item: Approve
    });
    try {
      await api.panel.send('plan a change');
    } finally {
      sub.dispose();
    }
    assert.ok(prompts.some((p) => p.kind === 'plan'), 'plan approval prompt shown');
    assert.strictEqual(api.agent.info.currentModeId, 'default');
  });

  it('session/load: a restarted agent resumes the same session and replays its history', async () => {
    const sid = api.agent.info.sessionId;
    const closed = new Promise((r) => api.client.onClose(r));
    api.agent.stop();
    await closed;
    updates.length = 0;
    const info = await api.agent.ensureSession();
    assert.strictEqual(info.sessionId, sid, 'same session id after restart');
    assert.strictEqual(info.resumed, true);
    const text = updates.filter((u) => u.sessionUpdate === 'agent_message_chunk').map((u) => u.content?.text).join('');
    assert.ok(text.includes('plan approved, done'), 'earlier agent text replayed: ' + text);
    assert.ok(updates.some((u) => u.sessionUpdate === 'user_message_chunk'), 'user messages replayed');
    await queue([{ text: 'still here' }]);
    updates.length = 0;
    await api.panel.send('are you there?');
    assert.ok(updates.some((u) => u.sessionUpdate === 'agent_message_chunk' && u.content?.text === 'still here'), 'resumed session takes prompts');
  });

  it('terminal fallback: "Open in Terminal" runs the configured fuigo in an integrated terminal', async () => {
    const bin = process.env.FUIGO_BIN;
    assert.ok(bin && fs.existsSync(path.join(ws, 'decoy-fuigo')));
    const opened = new Promise<vscode.Terminal>((r) => vscode.window.onDidOpenTerminal(r));
    await vscode.commands.executeCommand('fuigo.openInTerminal');
    const term = await opened;
    try {
      assert.strictEqual(term.name, 'Fuigo');
      // The user-settings binary, not the decoy that the workspace's .vscode/settings.json names.
      assert.strictEqual((term.creationOptions as vscode.TerminalOptions).shellPath, bin);
      assert.strictEqual((term.creationOptions as vscode.TerminalOptions).cwd, ws);
    } finally {
      term.dispose();
    }
  });

  it('binary missing: shows the notice and opens no terminal', async () => {
    const cfg = vscode.workspace.getConfiguration('fuigo');
    const bin = cfg.get<string>('path');
    await cfg.update('path', path.join(ws, 'no-such-fuigo'), vscode.ConfigurationTarget.Global);
    prompts.length = 0;
    const before = vscode.window.terminals.length;
    try {
      await vscode.commands.executeCommand('fuigo.openInTerminal');
      const notice = await until('install notice', () => prompts.find((p) => p.kind === 'install'), 10000);
      assert.match(notice.title, /fuigo\.path/);
      assert.strictEqual(vscode.window.terminals.length, before, 'no terminal opened');
    } finally {
      await cfg.update('path', bin, vscode.ConfigurationTarget.Global);
    }
  });
});
