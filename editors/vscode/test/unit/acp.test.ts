import * as assert from 'assert';
import { AgentController, CLIENT_ID, initializeParams } from '../../src/acp/agent';
import { AcpConnection, RpcError, Transport } from '../../src/acp/connection';
import {
  autoPermission, buildPermissionPrompt, permissionOutcome, PLAN_APPROVE, PLAN_REVISE, planOutcome, proposedText, SHOW_DIFF_LABEL, ToolCallCache,
} from '../../src/acp/permission';
import { userSetting } from '../../src/acp/process';
import { IDE_SERVER_NAME, IDE_TOOL_NAMES } from '../../src/context/mcp';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** In-memory transport: records what the client sends; `agent` (if set) answers client requests. */
class FakeTransport implements Transport {
  sent: any[] = [];
  private lineCb: (l: string) => void = () => {};
  private closeCb: (r: string) => void = () => {};
  closed = false;
  constructor(private agent?: (m: any) => any) {}
  send(line: string) {
    const m = JSON.parse(line);
    this.sent.push(m);
    if (this.agent && m.id !== undefined && m.method) {
      const result = this.agent(m);
      queueMicrotask(() => this.deliver({ jsonrpc: '2.0', id: m.id, result }));
    }
  }
  onLine(cb: (l: string) => void) { this.lineCb = cb; }
  onClose(cb: (r: string) => void) { this.closeCb = cb; }
  close() { this.closed = true; this.closeCb('closed'); }
  deliver(m: object) { this.lineCb(JSON.stringify(m)); }
  exit(r = 'code 1') { this.closeCb(r); }
}

const tick = () => new Promise((r) => setImmediate(r));

describe('AcpConnection', () => {
  it('correlates responses and maps errors to RpcError', async () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    const a = c.request('session/new', { cwd: '/w' });
    const b = c.request('session/prompt', {});
    t.deliver({ jsonrpc: '2.0', id: t.sent[1].id, error: { code: -32602, message: 'bad' } });
    t.deliver({ jsonrpc: '2.0', id: t.sent[0].id, result: { sessionId: 's1' } });
    assert.deepStrictEqual(await a, { sessionId: 's1' });
    await assert.rejects(b, (e: any) => e instanceof RpcError && e.code === -32602);
  });

  it('puts the wire underscore on fuigo/* methods, and not on ACP core methods', () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    void c.request('fuigo/hunk-tracker/get-hunks', {});
    void c.request('_fuigo/rewind/points', {});
    c.notify('session/cancel', { sessionId: 's' });
    assert.deepStrictEqual(t.sent.map((m) => m.method), ['_fuigo/hunk-tracker/get-hunks', '_fuigo/rewind/points', 'session/cancel']);
    assert.strictEqual(t.sent[2].id, undefined);
  });

  it('dispatches _fuigo/* agent requests to handlers registered without the underscore, result unchanged', async () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    const envelope = { jsonrpc: '2.0', id: 7, result: { tools: [] } };
    let got: any;
    c.onRequest('fuigo/mcp/sdk_call', async (p) => { got = p; return envelope; });
    t.deliver({ jsonrpc: '2.0', id: 'a1', method: '_fuigo/mcp/sdk_call', params: { serverId: 'srv_ide', message: { id: 7, method: 'tools/list' } } });
    await tick();
    assert.deepStrictEqual(got, { serverId: 'srv_ide', message: { id: 7, method: 'tools/list' } });
    assert.deepStrictEqual(t.sent[0], { jsonrpc: '2.0', id: 'a1', result: envelope });
  });

  it('answers unknown methods with -32601, and handler errors with their code', async () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    c.onRequest('fs/write_text_file', async () => { throw new RpcError(-32002, 'nope'); });
    c.onRequest('fs/read_text_file', async () => { throw new Error('boom'); });
    t.deliver({ jsonrpc: '2.0', id: 1, method: 'terminal/create', params: {} });
    t.deliver({ jsonrpc: '2.0', id: 2, method: 'fs/write_text_file', params: {} });
    t.deliver({ jsonrpc: '2.0', id: 3, method: 'fs/read_text_file', params: {} });
    await tick();
    const byId = Object.fromEntries(t.sent.map((m) => [m.id, m.error]));
    assert.strictEqual(byId[1].code, -32601);
    assert.deepStrictEqual(byId[2], { code: -32002, message: 'nope' });
    assert.deepStrictEqual(byId[3], { code: -32603, message: 'boom' });
  });

  it('latest handler wins; disposing it restores the previous one', async () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    c.onRequest('fs/write_text_file', async () => 'base');
    const top = c.onRequest('fs/write_text_file', async () => 'override');
    t.deliver({ jsonrpc: '2.0', id: 1, method: 'fs/write_text_file', params: {} });
    await tick();
    top.dispose();
    t.deliver({ jsonrpc: '2.0', id: 2, method: 'fs/write_text_file', params: {} });
    await tick();
    assert.deepStrictEqual(t.sent.map((m) => m.result), ['override', 'base']);
  });

  it('fans out session/update and other notifications; ignores junk lines', () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    const ups: any[] = []; const done: any[] = [];
    c.onSessionUpdate((sid, u) => ups.push([sid, u.sessionUpdate]));
    c.onNotification('fuigo/session/prompt_complete', (p) => done.push(p.stopReason));
    (t as any).lineCb('not json');
    t.deliver({ jsonrpc: '2.0', method: 'session/update', params: { sessionId: 's1', update: { sessionUpdate: 'agent_message_chunk' } } });
    t.deliver({ jsonrpc: '2.0', method: '_fuigo/session/prompt_complete', params: { stopReason: 'end_turn' } });
    assert.deepStrictEqual(ups, [['s1', 'agent_message_chunk']]);
    assert.deepStrictEqual(done, ['end_turn']);
  });

  it('rejects pending requests and clears the session when the agent exits', async () => {
    const c = new AcpConnection(); const t = new FakeTransport(); c.attach(t);
    c.setSessionId('s1');
    const p = c.request('session/prompt', {});
    t.exit('signal SIGKILL');
    await assert.rejects(p, /exited \(signal SIGKILL\)/);
    assert.strictEqual(c.sessionId, undefined);
    assert.strictEqual(c.running, false);
    await assert.rejects(c.request('session/new', {}), /not running/);
  });
});

describe('AgentController', () => {
  const agentReplies = (m: any) => (m.method === 'session/new'
    ? { sessionId: 'sid-1', modes: { currentModeId: 'default', availableModes: [{ id: 'default', name: 'Default' }, { id: 'plan', name: 'Plan' }] } }
    : {});

  it('initialize: clientIdentifier in the top-level _meta, hunk tracker agent_only, fs read+write', () => {
    const p = initializeParams('0.1.0');
    assert.strictEqual(p._meta.clientIdentifier, CLIENT_ID);
    assert.strictEqual(CLIENT_ID, 'fuigo-code-extension');
    assert.strictEqual(p._meta['fuigo/permissionPrompts'], true);
    assert.deepStrictEqual(p.clientCapabilities._meta['fuigo/hunkTracker'], { mode: 'agent_only' });
    assert.deepStrictEqual(p.clientCapabilities.fs, { readTextFile: true, writeTextFile: true });
    assert.ok(!('clientIdentifier' in p.clientCapabilities._meta));
  });

  it('starts once for concurrent callers, then initialize + session/new with the IDE MCP server', async () => {
    const c = new AcpConnection(); let spawns = 0; let t!: FakeTransport;
    c.onRequest('fuigo/mcp/sdk_call', async () => ({}));
    const a = new AgentController(c, async () => { spawns++; return (t = new FakeTransport(agentReplies)); }, () => '/w', '0.1.0', [{ name: 'ide', serverId: 'srv_ide' }]);
    const [s1, s2] = await Promise.all([a.ensureSession(), a.ensureSession()]);
    assert.strictEqual(spawns, 1);
    assert.strictEqual(s1, s2);
    assert.deepStrictEqual(t.sent.map((m) => m.method), ['initialize', 'session/new']);
    assert.deepStrictEqual(t.sent[1].params, { cwd: '/w', mcpServers: [], _meta: { 'fuigo/mcp/servers': [{ name: 'ide', serverId: 'srv_ide' }] } });
    assert.strictEqual(c.sessionId, 'sid-1');
    assert.deepStrictEqual(s1.modes.map((m) => m.id), ['default', 'plan']);
  });

  it('omits fuigo/mcp/servers when nothing serves sdk_call; tracks mode; cancel is a notification', async () => {
    const c = new AcpConnection(); let t!: FakeTransport;
    const a = new AgentController(c, async () => (t = new FakeTransport(agentReplies)), () => '/w', '0.1.0', [{ name: 'ide', serverId: 'srv_ide' }]);
    await a.ensureSession();
    assert.deepStrictEqual(t.sent[1].params._meta, {});
    await a.setMode('plan');
    assert.deepStrictEqual(t.sent[2], { jsonrpc: '2.0', id: t.sent[2].id, method: 'session/set_mode', params: { sessionId: 'sid-1', modeId: 'plan' } });
    t.deliver({ jsonrpc: '2.0', method: 'session/update', params: { sessionId: 'sid-1', update: { sessionUpdate: 'current_mode_update', currentModeId: 'default' } } });
    assert.strictEqual(a.info!.currentModeId, 'default');
    a.cancel();
    assert.deepStrictEqual(t.sent[3], { jsonrpc: '2.0', method: 'session/cancel', params: { sessionId: 'sid-1' } });
  });

  it('restarts the agent after it exits', async () => {
    const c = new AcpConnection(); let spawns = 0; let t!: FakeTransport;
    const a = new AgentController(c, async () => { spawns++; return (t = new FakeTransport(agentReplies)); }, () => '/w', '0.1.0');
    await a.ensureSession();
    t.exit();
    assert.strictEqual(a.info, undefined);
    await a.ensureSession();
    assert.strictEqual(spawns, 2);
  });

  it('session/load: resumes the stored session when the agent advertises loadSession; history updates count as current', async () => {
    const c = new AcpConnection(); let t!: FakeTransport; const ids: (string | undefined)[] = []; const seen: boolean[] = []; let cleared = 0;
    const replies = (m: any) => (m.method === 'initialize' ? { agentCapabilities: { loadSession: true } }
      : m.method === 'session/load' ? (t.deliver({ jsonrpc: '2.0', method: 'session/update', params: { sessionId: 'old', update: { sessionUpdate: 'agent_message_chunk' } } }),
        { modes: { currentModeId: 'plan', availableModes: [{ id: 'default', name: 'Default' }] } })
      : agentReplies(m));
    const a = new AgentController(c, async () => (t = new FakeTransport(replies)), () => '/w', '0.1.0', [], { get: () => 'old', set: (id) => ids.push(id) });
    a.onWillLoad = () => cleared++;
    c.onSessionUpdate((sid) => seen.push(a.isCurrent(sid)));
    const s = await a.ensureSession();
    assert.deepStrictEqual(t.sent.map((m) => m.method), ['initialize', 'session/load']);
    assert.deepStrictEqual(t.sent[1].params, { sessionId: 'old', cwd: '/w', mcpServers: [], _meta: {} });
    assert.deepStrictEqual([s.sessionId, s.currentModeId, s.resumed, c.sessionId], ['old', 'plan', true, 'old']);
    assert.deepStrictEqual([seen, cleared, ids], [[true], 1, ['old']]);
    await a.newSession();
    assert.deepStrictEqual(ids, ['old', 'sid-1'], 'New Session replaces the stored id');
  });

  it('session/load: falls back to session/new when the load fails or the agent cannot load', async () => {
    const c = new AcpConnection(); let t!: FakeTransport;
    const failing = new FakeTransport((m) => (m.method === 'initialize' ? { agentCapabilities: { loadSession: true } } : agentReplies(m)));
    const send = failing.send.bind(failing);
    failing.send = (line: string) => {
      const m = JSON.parse(line);
      if (m.method !== 'session/load') return send(line);
      failing.sent.push(m);
      queueMicrotask(() => failing.deliver({ jsonrpc: '2.0', id: m.id, error: { code: -32602, message: 'session not found' } }));
    };
    const a = new AgentController(c, async () => (t = failing), () => '/w', '0.1.0', [], { get: () => 'gone', set: () => {} });
    const s = await a.ensureSession();
    assert.deepStrictEqual(t.sent.map((m) => m.method), ['initialize', 'session/load', 'session/new']);
    assert.deepStrictEqual([s.sessionId, s.resumed], ['sid-1', false]);

    const c2 = new AcpConnection(); let t2!: FakeTransport; // no loadSession capability: never tries
    const b = new AgentController(c2, async () => (t2 = new FakeTransport(agentReplies)), () => '/w', '0.1.0', [], { get: () => 'old', set: () => {} });
    await b.ensureSession();
    assert.deepStrictEqual(t2.sent.map((m) => m.method), ['initialize', 'session/new']);
  });

  it('New before any session never resumes the stored one; New during a resume follows it with session/new', async () => {
    const loadable = (m: any) => (m.method === 'initialize' ? { agentCapabilities: { loadSession: true } }
      : m.method === 'session/load' ? { modes: { currentModeId: 'default', availableModes: [] } } : agentReplies(m));
    const c = new AcpConnection(); let t!: FakeTransport;
    const a = new AgentController(c, async () => (t = new FakeTransport(loadable)), () => '/w', '0.1.0', [], { get: () => 'old', set: () => {} });
    const s = await a.newSession();
    assert.deepStrictEqual(t.sent.map((m) => m.method), ['initialize', 'session/new']);
    assert.deepStrictEqual([s.sessionId, s.resumed], ['sid-1', false]);

    const c2 = new AcpConnection(); let t2!: FakeTransport;
    const b = new AgentController(c2, async () => (t2 = new FakeTransport(loadable)), () => '/w', '0.1.0', [], { get: () => 'old', set: () => {} });
    const resuming = b.ensureSession(); // e.g. the panel opened and is resuming
    const fresh = await b.newSession(); // the user clicks New meanwhile
    await resuming;
    assert.deepStrictEqual(t2.sent.map((m) => m.method), ['initialize', 'session/load', 'session/cancel', 'session/new']);
    assert.deepStrictEqual([fresh.sessionId, fresh.resumed, b.info!.sessionId], ['sid-1', false, 'sid-1']);
  });

  it('a failed spawn does not wedge later attempts', async () => {
    const c = new AcpConnection(); let n = 0;
    const a = new AgentController(c, async () => { if (n++ === 0) throw new Error('fuigo binary not found'); return new FakeTransport(agentReplies); }, () => '/w', '0.1.0');
    await assert.rejects(a.ensureSession(), /not found/);
    assert.strictEqual((await a.ensureSession()).sessionId, 'sid-1');
  });
});

// Shapes recorded by the L0 probe (coord-notes/1048-vscode-l0-evidence/default_mode.acp.jsonl).
const L0_TOOL_CALL = { sessionUpdate: 'tool_call', toolCallId: 'call_1_0', title: 'search_replace', rawInput: { file_path: 'hello.txt', old_string: 'hello', new_string: 'howdy' } };
const L0_TOOL_UPDATE = {
  sessionUpdate: 'tool_call_update', toolCallId: 'call_1_0', kind: 'edit', title: 'Edit `hello.txt`',
  content: [{ type: 'diff', path: '/abs/hello.txt', oldText: 'hello', newText: 'howdy', _meta: { old_line: 1, new_line: 1 } }], locations: [{ path: 'hello.txt' }],
};
const L0_PERMISSION = {
  sessionId: 's', toolCall: { toolCallId: 'call_1_0', kind: 'edit', title: 'Edit `hello.txt`', rawInput: { variant: 'SearchReplace', file_path: 'hello.txt', old_string: 'hello', new_string: 'howdy', replace_all: false } },
  options: [
    { optionId: 'allow-edits-session', name: 'Allow edits this session', kind: 'allow_always' },
    { optionId: 'allow-once', name: 'Allow once', kind: 'allow_once' },
    { optionId: 'reject-once', name: 'Reject', kind: 'reject_once' },
  ],
};

describe('permission mapping', () => {
  it('finds the diff for a permission request by toolCallId from the preceding tool_call_update', () => {
    const cache = new ToolCallCache();
    cache.apply(L0_TOOL_CALL); cache.apply(L0_TOOL_UPDATE);
    const p = buildPermissionPrompt(L0_PERMISSION, cache);
    assert.strictEqual(p.title, 'Edit `hello.txt`');
    assert.deepStrictEqual(p.diffs, [{ path: '/abs/hello.txt', oldText: 'hello', newText: 'howdy' }]);
    assert.match(p.detail, /\/abs\/hello\.txt: −hello {2}\+howdy/);
    assert.deepStrictEqual(p.items.map((i) => i.optionId), ['allow-edits-session', 'allow-once', 'reject-once', undefined]);
    assert.strictEqual(p.items[3].label, SHOW_DIFF_LABEL);
  });

  it('falls back to rawInput when no diff is cached, and offers no diff button', () => {
    const p = buildPermissionPrompt({ toolCall: { toolCallId: 'x', title: 'Run `ls`', rawInput: { command: 'ls' } }, options: L0_PERMISSION.options }, new ToolCallCache());
    assert.strictEqual(p.detail, '{"command":"ls"}');
    assert.strictEqual(p.items.length, 3);
  });

  it('maps picks to ACP outcomes; Escape is cancelled', () => {
    assert.deepStrictEqual(permissionOutcome({ label: 'x', optionId: 'allow-once' }), { outcome: { outcome: 'selected', optionId: 'allow-once' } });
    assert.deepStrictEqual(permissionOutcome(undefined), { outcome: { outcome: 'cancelled' } });
    assert.deepStrictEqual(permissionOutcome({ label: SHOW_DIFF_LABEL }), { outcome: { outcome: 'cancelled' } });
  });

  it('drops finished tool calls from the cache', () => {
    const cache = new ToolCallCache();
    cache.apply(L0_TOOL_CALL); cache.apply({ sessionUpdate: 'tool_call_update', toolCallId: 'call_1_0', status: 'completed' });
    cache.apply({ sessionUpdate: 'agent_message_chunk' });
    assert.strictEqual(cache.size, 0);
  });

  it('auto-allows (once) only the exact tools of our own per-activation server, prompts for everything else', () => {
    const opts = [{ optionId: 'always-allow', kind: 'allow_always' }, { optionId: 'allow-once', kind: 'allow_once' }, { optionId: 'reject-once', kind: 'reject_once' }];
    const use = (tool_name: string, variant = 'UseTool') => ({ toolCall: { rawInput: { variant, tool_name } }, options: opts });
    const own = `${IDE_SERVER_NAME}__ide_get_selection`;
    assert.match(IDE_SERVER_NAME, /^ide-[0-9a-f]{8}$/);
    assert.ok(IDE_TOOL_NAMES.includes(own) && IDE_TOOL_NAMES.length === 4);
    assert.deepStrictEqual(autoPermission(use(own), IDE_TOOL_NAMES), { outcome: { outcome: 'selected', optionId: 'allow-once' } });
    // A configured MCP server named `ide` (user config or a project .mcp.json) shares the old fixed namespace: no auto-allow.
    assert.strictEqual(autoPermission(use('ide__ide_get_selection'), IDE_TOOL_NAMES), undefined);
    assert.strictEqual(autoPermission(use('ide__run_shell'), IDE_TOOL_NAMES), undefined);
    assert.strictEqual(autoPermission(use(`${IDE_SERVER_NAME}__other`), IDE_TOOL_NAMES), undefined);
    assert.strictEqual(autoPermission(use(own, 'Bash'), IDE_TOOL_NAMES), undefined);
    assert.strictEqual(autoPermission({ ...use(own), options: [opts[0]] }, IDE_TOOL_NAMES), undefined, 'never answers allow-always');
    assert.strictEqual(autoPermission({ toolCall: { rawInput: { tool_name: 'github__create_issue' } }, options: opts }, IDE_TOOL_NAMES), undefined);
    assert.strictEqual(autoPermission(L0_PERMISSION, IDE_TOOL_NAMES), undefined);
  });

  it('fuigo.path is a user setting: machine scope, off in untrusted workspaces, workspace values ignored', () => {
    const pkg = JSON.parse(fs.readFileSync(path.resolve('package.json'), 'utf8')); // cwd = editors/vscode
    assert.strictEqual(pkg.contributes.configuration.properties['fuigo.path'].scope, 'machine');
    assert.strictEqual(pkg.capabilities.untrustedWorkspaces.supported, false);
    assert.strictEqual(userSetting({ globalValue: '/usr/bin/fuigo', workspaceValue: './evil' } as any), '/usr/bin/fuigo');
    assert.strictEqual(userSetting({ workspaceValue: './evil', workspaceFolderValue: './evil' } as any), undefined);
    assert.strictEqual(userSetting(undefined), undefined);
  });

  it('builds the whole-file proposal from a snippet diff', () => {
    assert.strictEqual(proposedText('hello world\nhello\n', { path: 'p', oldText: 'hello', newText: 'howdy' }), 'howdy world\nhello\n');
    assert.strictEqual(proposedText('old', { path: 'p', oldText: '', newText: 'new' }), 'new');
    assert.strictEqual(proposedText('abc', { path: 'p', oldText: 'zzz', newText: 'y' }), 'abc');
  });

  it('maps plan approval picks to exit_plan_mode outcomes', () => {
    assert.deepStrictEqual(planOutcome(PLAN_APPROVE), { outcome: 'approved' });
    assert.deepStrictEqual(planOutcome(PLAN_REVISE, 'smaller'), { outcome: 'cancelled', feedback: 'smaller' });
    assert.deepStrictEqual(planOutcome(PLAN_REVISE), { outcome: 'cancelled' });
    assert.deepStrictEqual(planOutcome(undefined), { outcome: 'abandoned' });
  });
});
