// Replays the L0 transcripts (coord-notes/1048-vscode-l0-evidence, trimmed to edit traffic in l0-edits.jsonl) through EditController.
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { EditController, EditHost } from '../../src/edits/controller';

type Rec = { run: string; dir: string; msg: any };
const FIX: Rec[] = fs.readFileSync(path.resolve('test/edits/l0-edits.jsonl') /* cwd = editors/vscode */, 'utf8').trim().split('\n').map(l => JSON.parse(l));
const HELLO = '/work/hello.txt';

const updates = (run: string, toolCallId?: string) =>
  FIX.filter(r => r.run === run && r.msg.method === 'session/update' && (!toolCallId || r.msg.params.update.toolCallId === toolCallId)).map(r => r.msg.params.update);
const recorded = (run: string, method: string) => {
  const req = FIX.find(r => r.run === run && r.msg.method === method)!;
  return FIX.find(r => r.run === run && r.dir === 'in' && r.msg.id === req.msg.id && 'result' in r.msg)!.msg.result;
};

function setup(responses: Record<string, (p: any) => any> = {}) {
  const calls: { method: string; params: any }[] = [];
  const log: string[] = [];
  const files = new Map<string, string>([[HELLO, 'hello world\nsecond line\n']]);
  const client = {
    sessionId: 'sid' as string | undefined,
    request: async (method: string, params: any) => {
      calls.push({ method, params });
      log.push(`request ${method}`);
      return (responses[method] ?? (() => ({ result: { success: true, hunks: [] } })))(params);
    },
    notify() {},
    onSessionUpdate: () => ({ dispose() {} }),
    onRequest: () => ({ dispose() {} }),
  };
  const diffs: { path: string; left: string; right?: string }[] = [];
  const host: EditHost = {
    readText: async p => files.get(p),
    writeText: async (p, c) => { files.set(p, c); log.push(`write ${p}`); },
    flush: async p => { log.push(`flush ${p}`); },
    openDiff: (p, left, right) => diffs.push({ path: p, left, right }),
    changed: () => {},
  };
  const ctl = new EditController(client as any, host, 5);
  return { ctl, client, calls, log, files, diffs };
}
const tick = (ms = 20) => new Promise(r => setTimeout(r, ms));

describe('EditController', () => {
  it('serves reads from the buffer, honours line/limit, and returns -32002 for a missing file', async () => {
    const { ctl } = setup();
    assert.deepStrictEqual(await ctl.readTextFile({ path: HELLO }), { content: 'hello world\nsecond line\n' });
    assert.deepStrictEqual(await ctl.readTextFile({ path: HELLO, line: 2, limit: 1 }), { content: 'second line' });
    await assert.rejects(ctl.readTextFile({ path: '/nope/plan.md' }), (e: any) => e.code === -32002);
  });

  it('auto mode: the write lands, completion triggers one debounced get-hunks, and the diff opens from the baseline', async () => {
    const hunks = recorded('auto_mode', '_fuigo/hunk-tracker/get-hunks');
    const { ctl, calls, files, diffs } = setup({
      '_fuigo/hunk-tracker/get-hunks': p => (p.path ? { result: { ...hunks.result, baseline: { status: 'full', content: 'hello world\nsecond line\n' } } } : hunks),
    });
    const write = FIX.find(r => r.run === 'auto_mode' && r.msg.method === 'fs/write_text_file')!.msg.params;
    for (const u of updates('auto_mode', 'call_1_0')) {
      if (u.status === 'completed') assert.strictEqual(await ctl.writeTextFile(write), null);
      ctl.onUpdate(u);
      ctl.onUpdate(u); // a repeat inside the debounce window must not cost a second poll
    }
    assert.strictEqual(files.get(HELLO), 'howdy world\nsecond line\n');
    await tick();
    assert.deepStrictEqual(calls.map(c => c.method), ['_fuigo/hunk-tracker/get-hunks', '_fuigo/hunk-tracker/get-hunks']);
    assert.deepStrictEqual(calls[0].params, { sessionId: 'sid', source: 'agent' });
    assert.strictEqual(ctl.hunks.length, 1);
    assert.strictEqual(ctl.hunks[0].oldText, 'hello world\n');
    assert.deepStrictEqual(diffs, [{ path: HELLO, left: 'hello world\nsecond line\n', right: undefined }]);
  });

  it('reject saves the buffer before the tracker writes disk, then re-polls', async () => {
    const hunks = recorded('auto_mode', '_fuigo/hunk-tracker/get-hunks');
    const action = recorded('auto_mode', '_fuigo/hunk-tracker/file-action');
    const { ctl, calls, log } = setup({ '_fuigo/hunk-tracker/hunk-action': () => action, '_fuigo/hunk-tracker/get-hunks': () => hunks });
    await ctl.refresh();
    await ctl.act('reject', { hunk: ctl.hunks[0] });
    assert.deepStrictEqual(log.slice(1), [`flush ${HELLO}`, 'request _fuigo/hunk-tracker/hunk-action', 'request _fuigo/hunk-tracker/get-hunks']);
    assert.deepStrictEqual(calls[1].params, { sessionId: 'sid', hunkId: hunks.result.hunks[0].id, action: 'reject' });
  });

  it('accept does not touch the buffer; file and all targets use file-action / all-action', async () => {
    const { ctl, calls, log } = setup();
    await ctl.act('accept', { path: HELLO });
    await ctl.act('accept', { all: true });
    assert.ok(!log.some(l => l.startsWith('flush')));
    assert.deepStrictEqual(calls.filter(c => !c.method.endsWith('get-hunks')).map(c => [c.method, c.params]), [
      ['_fuigo/hunk-tracker/file-action', { sessionId: 'sid', path: HELLO, action: 'accept' }],
      ['_fuigo/hunk-tracker/all-action', { sessionId: 'sid', action: 'accept' }],
    ]);
  });

  it('surfaces a tracker failure', async () => {
    const { ctl } = setup({ '_fuigo/hunk-tracker/file-action': () => ({ result: { success: false, error: 'no such file' } }) });
    await assert.rejects(ctl.act('accept', { path: HELLO }), /no such file/);
  });

  it('ask mode: the edit permission is answered allow-once and the write waits in the diff; reject fails only the write', async () => {
    const { ctl, files, diffs, log } = setup();
    const perm = FIX.find(r => r.run === 'default_mode' && r.msg.method === 'session/request_permission')!.msg.params;
    updates('default_mode', perm.toolCall.toolCallId).filter(u => u.status !== 'completed').forEach(u => ctl.onUpdate(u));
    assert.deepStrictEqual(ctl.reviewPermission(perm), { outcome: { outcome: 'selected', optionId: 'allow-once' } });

    const pending = ctl.writeTextFile({ path: HELLO, content: 'howdy world\nsecond line\n' });
    await tick(1);
    assert.deepStrictEqual(diffs, [{ path: HELLO, left: 'hello world\nsecond line\n', right: 'howdy world\nsecond line\n' }]);
    assert.deepStrictEqual(ctl.paths(), [HELLO]);
    await ctl.act('reject', { path: HELLO });
    await assert.rejects(pending, (e: any) => e.code === -32603 && /rejected the edit/.test(e.message));
    assert.strictEqual(files.get(HELLO), 'hello world\nsecond line\n');
    assert.ok(!log.some(l => l.startsWith('write') || l.startsWith('request')));
    assert.deepStrictEqual(ctl.paths(), []);
  });

  it('ask mode accept writes the proposed content; a non-edit or unknown tool call is left to the normal prompt', async () => {
    const { ctl, files } = setup();
    const perm = FIX.find(r => r.run === 'default_mode' && r.msg.method === 'session/request_permission')!.msg.params;
    updates('default_mode', perm.toolCall.toolCallId).filter(u => u.status !== 'completed').forEach(u => ctl.onUpdate(u));
    ctl.reviewPermission(perm);
    const pending = ctl.writeTextFile({ path: HELLO, content: 'howdy world\nsecond line\n' });
    await tick(1);
    await ctl.act('accept', { path: HELLO });
    assert.strictEqual(await pending, null);
    assert.strictEqual(files.get(HELLO), 'howdy world\nsecond line\n');
    assert.strictEqual(ctl.reviewPermission({ ...perm, toolCall: { ...perm.toolCall, kind: 'other' } }), undefined);
    assert.strictEqual(ctl.reviewPermission({ ...perm, toolCall: { ...perm.toolCall, toolCallId: 'unknown' } }), undefined);
  });

  it('two edits of one file in a turn are both held, one diff at a time; the second never lands unreviewed', async () => {
    const { ctl, files, diffs } = setup();
    const perm = (id: string) => ({ toolCall: { toolCallId: id, kind: 'edit' }, options: [{ optionId: 'allow-once', kind: 'allow_once' }] });
    for (const id of ['e1', 'e2']) {
      ctl.onUpdate({ sessionUpdate: 'tool_call_update', toolCallId: id, content: [{ type: 'diff', path: HELLO, oldText: 'a', newText: 'b' }] });
      assert.ok(ctl.reviewPermission(perm(id)));
    }
    const w1 = ctl.writeTextFile({ path: HELLO, content: 'one\n' });
    const w2 = ctl.writeTextFile({ path: HELLO, content: 'two\n' });
    await tick(1);
    assert.deepStrictEqual(diffs.map(d => d.right), ['one\n'], 'only the first is shown; the second waits');
    assert.strictEqual(files.get(HELLO), 'hello world\nsecond line\n', 'nothing written yet');
    await ctl.act('accept', { path: HELLO });
    assert.strictEqual(await w1, null);
    await tick(1);
    assert.deepStrictEqual(diffs.map(d => [d.left, d.right]), [['hello world\nsecond line\n', 'one\n'], ['one\n', 'two\n']]);
    assert.strictEqual(files.get(HELLO), 'one\n');
    await ctl.act('reject', { path: HELLO });
    await assert.rejects(w2, (e: any) => e.code === -32603);
    assert.strictEqual(files.get(HELLO), 'one\n');
  });

  it('a failed edit clears its pending review, so a later write to the same file is not held', async () => {
    const { ctl, files } = setup();
    const perm = FIX.find(r => r.run === 'default_mode' && r.msg.method === 'session/request_permission')!.msg.params;
    updates('default_mode', perm.toolCall.toolCallId).filter(u => u.status !== 'completed').forEach(u => ctl.onUpdate(u));
    ctl.reviewPermission(perm);
    ctl.onUpdate({ sessionUpdate: 'tool_call_update', toolCallId: perm.toolCall.toolCallId, status: 'failed' });
    assert.strictEqual(await ctl.writeTextFile({ path: HELLO, content: 'x\n' }), null);
    assert.strictEqual(files.get(HELLO), 'x\n');
  });

  it('does not poll without a session', async () => {
    const { ctl, client, calls } = setup();
    client.sessionId = undefined;
    await ctl.refresh();
    assert.strictEqual(calls.length, 0);
  });
});
