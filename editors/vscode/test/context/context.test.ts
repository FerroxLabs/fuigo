import * as assert from 'assert';
import { registerIdeTools, ADD_SELECTION_COMMAND, getPendingContext, consumePendingContext, clearPendingContext } from '../../src/context';
import { MAX_DIAGNOSTICS, MAX_SELECTION_CHARS } from '../../src/context/tools';
import type { FuigoClient, VsLike } from '../../src/context/types';

const uri = (p: string, scheme = 'file') => ({ fsPath: p, scheme, toString: () => `${scheme}://${p}` });
const P = (line: number, character: number) => ({ line, character });

function fake(over: Partial<{ text: string; sel: any; diags: any[]; tabs: any[]; folders: any[]; noEditor: boolean }> = {}) {
  const sel = over.sel ?? { start: P(4, 2), end: P(6, 3), isEmpty: false };
  const text = over.text ?? 'selected';
  const cmds = new Map<string, (...a: any[]) => unknown>();
  const msgs: string[] = [];
  const vs: VsLike = {
    window: {
      activeTextEditor: over.noEditor ? undefined : { selection: sel, document: { uri: uri('/w/a.ts'), languageId: 'typescript', isDirty: false, getText: () => text } },
      tabGroups: { all: [{ tabs: over.tabs ?? [
        { input: { uri: uri('/w/a.ts') }, isActive: true, isDirty: false },
        { input: { uri: uri('/w/b.ts') }, isActive: false, isDirty: true },
        { input: { uri: uri('/w/x', 'untitled') }, isActive: false, isDirty: false },
        { input: {}, isActive: false, isDirty: false },
      ] }] },
      showInformationMessage: (m: string) => { msgs.push(m); },
    },
    workspace: {
      workspaceFolders: over.folders ?? [{ name: 'w', uri: uri('/w') }],
      asRelativePath: (p: any) => String(p.fsPath ?? p).replace('/w/', ''),
    },
    languages: { getDiagnostics: () => over.diags ?? [] },
    commands: { registerCommand: (id, cb) => { cmds.set(id, cb); return { dispose() {} }; } },
    Uri: { file: uri },
  };
  const handlers = new Map<string, (p: any) => Promise<any>>();
  const client: FuigoClient = {
    request: async () => undefined as any, notify() {}, sessionId: 's',
    onSessionUpdate: () => ({ dispose() {} }),
    onRequest: (m, h) => { handlers.set(m, h); return { dispose() {} }; },
  };
  const ctx = { subscriptions: [] as any[] };
  registerIdeTools(ctx, client, vs);
  const call = async (message: any, serverId = 'srv_ide') => handlers.get('fuigo/mcp/sdk_call')!({ serverId, message });
  const tool = async (name: string, args: any = {}) => {
    const r = await call({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name, arguments: args } });
    return { r, body: r.result?.content && !r.result.isError ? JSON.parse(r.result.content[0].text) : undefined };
  };
  return { vs, cmds, msgs, handlers, call, tool, ctx };
}

describe('L3 ide tools over sdk_call', () => {
  beforeEach(clearPendingContext);

  it('registers both method spellings and the command', () => {
    const f = fake();
    assert.deepStrictEqual([...f.handlers.keys()].sort(), ['_fuigo/mcp/sdk_call', 'fuigo/mcp/sdk_call']);
    assert.ok(f.cmds.has(ADD_SELECTION_COMMAND));
    assert.strictEqual(f.ctx.subscriptions.length, 3);
  });

  it('answers the L0 handshake: initialize, tools/list, notification, discover', async () => {
    const f = fake();
    const init = await f.call({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2026-07-28' } });
    assert.strictEqual(init.id, 0);
    assert.strictEqual(init.result.protocolVersion, '2026-07-28');
    assert.deepStrictEqual(init.result.capabilities, { tools: {} });
    const list = await f.call({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
    assert.deepStrictEqual(list.result.tools.map((t: any) => t.name), ['ide_get_selection', 'ide_get_open_editors', 'ide_get_diagnostics', 'ide_get_workspace_folders']);
    assert.ok(list.result.tools.every((t: any) => t.annotations.readOnlyHint === true && t.inputSchema.type === 'object'));
    assert.deepStrictEqual(await f.call({ jsonrpc: '2.0', method: 'notifications/initialized' }), {});
    assert.strictEqual((await f.call({ jsonrpc: '2.0', id: 2, method: 'server/discover', params: {} })).error.code, -32601);
  });

  it('rejects an unknown serverId and an unknown tool', async () => {
    const f = fake();
    await assert.rejects(f.call({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, 'srv_other'), /unknown serverId/);
    assert.strictEqual((await f.tool('nope')).r.error.code, -32602);
  });

  it('selection: 1-based range and text', async () => {
    const { body } = await fake().tool('ide_get_selection');
    assert.deepStrictEqual(body.range, { start: { line: 5, character: 3 }, end: { line: 7, character: 4 } });
    assert.strictEqual(body.file, '/w/a.ts');
    assert.strictEqual(body.text, 'selected');
  });

  it('selection: truncates with a note; no editor is not an error', async () => {
    const { body } = await fake({ text: 'x'.repeat(MAX_SELECTION_CHARS + 5) }).tool('ide_get_selection');
    assert.strictEqual(body.text.length, MAX_SELECTION_CHARS);
    assert.strictEqual(body.truncated, true);
    assert.deepStrictEqual((await fake({ noEditor: true }).tool('ide_get_selection')).body.selection, null);
  });

  it('open editors: file tabs only, with active and dirty', async () => {
    const { body } = await fake().tool('ide_get_open_editors');
    assert.deepStrictEqual(body.editors, [{ path: '/w/a.ts', active: true, dirty: false }, { path: '/w/b.ts', active: false, dirty: true }]);
  });

  it('diagnostics: all, per file (relative path), severity names, cap', async () => {
    const d = (sev: number, m = 'bad') => ({ range: { start: P(0, 0), end: P(0, 1) }, message: m, severity: sev, source: 'ts', code: { value: 2322, target: {} } });
    const f = fake({ diags: [[uri('/w/a.ts'), [d(0), d(1)]], [uri('/w/b.ts'), [d(3)]], [uri('/w/c.ts'), []]] });
    const all = (await f.tool('ide_get_diagnostics')).body;
    assert.deepStrictEqual(all.files.map((x: any) => x.file), ['/w/a.ts', '/w/b.ts']);
    assert.deepStrictEqual(all.files[0].diagnostics.map((x: any) => x.severity), ['error', 'warning']);
    assert.strictEqual(all.files[0].diagnostics[0].code, 2322);
    const one = (await f.tool('ide_get_diagnostics', { path: 'b.ts' })).body;
    assert.deepStrictEqual(one.files.map((x: any) => x.file), ['/w/b.ts']);

    const many = fake({ diags: [[uri('/w/a.ts'), Array.from({ length: MAX_DIAGNOSTICS + 7 }, () => d(0, 'm'.repeat(900)))]] });
    const cap = (await many.tool('ide_get_diagnostics')).body;
    assert.strictEqual(cap.files[0].diagnostics.length, MAX_DIAGNOSTICS);
    assert.strictEqual(cap.files[0].diagnostics[0].message.length, 500);
    assert.match(cap.note, /7 more/);
  });

  it('diagnostics: bad path arg is a tool error, not a protocol error', async () => {
    const { r } = await fake().tool('ide_get_diagnostics', { path: 5 });
    assert.strictEqual(r.result.isError, true);
  });

  it('workspace folders', async () => {
    assert.deepStrictEqual((await fake().tool('ide_get_workspace_folders')).body.folders, [{ name: 'w', path: '/w' }]);
    assert.deepStrictEqual((await fake({ folders: [] }).tool('ide_get_workspace_folders')).body.folders, []);
  });

  it('add-selection command queues a mention + resource, consumed once', () => {
    const f = fake({ text: 'abc' });
    f.cmds.get(ADD_SELECTION_COMMAND)!();
    assert.strictEqual(getPendingContext().length, 1);
    assert.strictEqual(getPendingContext()[0].startLine, 5);
    assert.strictEqual(getPendingContext().length, 1); // peek does not clear
    const blocks = consumePendingContext() as any[];
    assert.deepStrictEqual(blocks[0], { type: 'text', text: '@a.ts#L5-7' });
    assert.deepStrictEqual(blocks[1], { type: 'resource', resource: { uri: 'file:///w/a.ts#L5-7', mimeType: 'text/plain', text: 'abc' } });
    assert.deepStrictEqual(consumePendingContext(), []);
  });

  it('add-selection: empty selection warns, queues nothing; end at column 0 excludes that line', () => {
    const e = fake({ sel: { start: P(1, 0), end: P(1, 0), isEmpty: true } });
    e.cmds.get(ADD_SELECTION_COMMAND)!();
    assert.strictEqual(getPendingContext().length, 0);
    assert.strictEqual(e.msgs.length, 1);
    const f = fake({ sel: { start: P(1, 0), end: P(3, 0), isEmpty: false } });
    f.cmds.get(ADD_SELECTION_COMMAND)!();
    assert.strictEqual(getPendingContext()[0].endLine, 3);
  });
});
