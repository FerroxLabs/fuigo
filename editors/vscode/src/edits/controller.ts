// Edit state and protocol logic, kept free of the vscode runtime so it unit-tests with a fake client and host.
import * as nodePath from 'path';
import type { FuigoClient } from '../acp/types';

export interface Hunk {
  id: string;
  path: string;
  lineInfo: { oldStart: number; oldCount: number; newStart: number; newCount: number };
  oldText: string | null;
  newText: string;
}

export interface HeldWrite {
  before: string;
  content: string;
  resolve: (accepted: boolean) => void;
}

/** What the controller needs from the editor. index.ts implements it with the VS Code API. */
export interface EditHost {
  /** Open buffer text if the file is open (unsaved edits win), else disk; undefined when the file does not exist. */
  readText(path: string): Promise<string | undefined>;
  /** Apply content to the buffer (stays undoable) and save, so tools that read disk see it. */
  writeText(path: string, content: string): Promise<void>;
  /** Save a dirty buffer, so a tracker disk write cannot conflict with it. */
  flush(path: string): Promise<void>;
  /** Native diff: left text against `right`, or against the real file when `right` is undefined. */
  openDiff(path: string, left: string, right?: string): void;
  changed(): void;
}

export type Action = 'accept' | 'reject';
export type Target = { hunk: Hunk } | { path: string } | { all: true };

const HT = '_fuigo/hunk-tracker/';

/** One key per file for review/held state: the diff path, the write path and the editor's fsPath may differ in form. */
const norm = (p: string) => nodePath.normalize(p);

export function rpcError(code: number, message: string): Error {
  return Object.assign(new Error(message), { code });
}

/** Ext methods answer inside an `{result}` envelope; accept a bare value too in case the client unwraps it. */
function unwrap(r: any): any {
  if (r && typeof r === 'object' && 'result' in r) return r.result;
  if (r && typeof r === 'object' && 'error' in r) throw new Error(String(r.error));
  return r;
}

export class EditController {
  hunks: Hunk[] = [];
  readonly held = new Map<string, HeldWrite>();
  /**
   * path -> toolCallIds whose permission we answered on the promise of a held diff, oldest first. Each one holds one
   * write. A list, not one id: two edits of one file in a turn must both be reviewed (one id let the second write land unseen).
   */
  private readonly review = new Map<string, string[]>();
  /** path -> the previous held write (decision and write), so a file shows one held diff at a time. */
  private readonly holdChain = new Map<string, Promise<unknown>>();
  /** toolCallId -> diff paths, from tool_call_update content (the permission request carries none). */
  private readonly toolPaths = new Map<string, string[]>();
  private readonly toShow = new Set<string>();
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(private readonly client: FuigoClient, private readonly host: EditHost, private readonly debounceMs = 250) {}

  // ── fs/* reverse requests ──────────────────────────────────────────────

  async readTextFile(p: { path: string; line?: number; limit?: number }): Promise<{ content: string }> {
    const text = await this.host.readText(p.path);
    // The agent handles -32002 for a missing file (L0: plan file outside the workspace).
    if (text === undefined) throw rpcError(-32002, `Resource not found: ${p.path}`);
    if (p.line == null && p.limit == null) return { content: text };
    const lines = text.split('\n');
    const from = Math.max((p.line ?? 1) - 1, 0);
    return { content: lines.slice(from, p.limit == null ? undefined : from + p.limit).join('\n') };
  }

  async writeTextFile(p: { path: string; content: string }): Promise<null> {
    const key = norm(p.path);
    const queue = this.review.get(key);
    if (queue?.length) {
      queue.shift();
      if (!queue.length) this.review.delete(key);
      // Chained per file, write included, so the next held diff starts from what this one wrote.
      const mine = (this.holdChain.get(key) ?? Promise.resolve()).then(async () => {
        // An error here fails only this tool call and the turn goes on; rejecting the permission would cancel the turn (L0).
        if (!(await this.hold(key, p.content))) throw rpcError(-32603, 'User rejected the edit in the editor');
        await this.host.writeText(p.path, p.content);
      });
      this.holdChain.set(key, mine.catch(() => undefined));
      await mine;
      return null;
    }
    await this.host.writeText(p.path, p.content);
    return null;
  }

  private async hold(key: string, content: string): Promise<boolean> {
    const before = (await this.host.readText(key)) ?? '';
    const accepted = await new Promise<boolean>(resolve => {
      this.held.set(key, { before, content, resolve });
      this.host.openDiff(key, before, content);
      this.host.changed();
    });
    this.held.delete(key);
    this.host.changed();
    return accepted;
  }

  // ── session updates ───────────────────────────────────────────────────

  onUpdate(update: any): void {
    if (update?.sessionUpdate !== 'tool_call_update') return;
    const id: string = update.toolCallId;
    const paths = (update.content ?? []).filter((c: any) => c?.type === 'diff' && c.path).map((c: any) => c.path as string);
    if (paths.length) this.toolPaths.set(id, paths);
    if (update.status === 'completed' || update.status === 'failed') {
      for (const [path, ids] of this.review) {
        const left = ids.filter(t => t !== id);
        if (left.length) this.review.set(path, left);
        else this.review.delete(path);
      }
      this.toolPaths.delete(id);
      if (update.status === 'completed' && paths.length) {
        paths.forEach((p: string) => this.toShow.add(p));
        this.scheduleRefresh();
      }
    }
  }

  /**
   * For PermissionUI: an edit permission is answered allow-once and the write is held in the diff instead, so the user
   * decides once, sees the whole file, and a reject keeps the turn going. Returns undefined when this is not an edit we can hold.
   */
  reviewPermission(params: any): { outcome: { outcome: 'selected'; optionId: string } } | undefined {
    const call = params?.toolCall;
    const paths = call && this.toolPaths.get(call.toolCallId);
    const allow = (params?.options ?? []).find((o: any) => o.kind === 'allow_once');
    if (call?.kind !== 'edit' || !paths?.length || !allow) return undefined;
    for (const p of paths) this.review.set(norm(p), [...(this.review.get(norm(p)) ?? []), call.toolCallId]);
    return { outcome: { outcome: 'selected', optionId: allow.optionId } };
  }

  // ── hunk state (pull only: the tracker pushes no events) ────────────────

  scheduleRefresh(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.refresh().catch(() => undefined), this.debounceMs);
  }

  async refresh(): Promise<void> {
    clearTimeout(this.timer);
    const sessionId = this.client.sessionId;
    if (!sessionId) return;
    const r = unwrap(await this.client.request(HT + 'get-hunks', { sessionId, source: 'agent' }));
    this.hunks = r?.hunks ?? [];
    this.host.changed();
    const show = [...this.toShow];
    this.toShow.clear();
    for (const p of show) if (this.hunks.some(h => h.path === p)) await this.showDiff(p);
  }

  paths(): string[] {
    return [...new Set([...this.held.keys(), ...this.hunks.map(h => h.path)])];
  }

  async showDiff(path: string): Promise<void> {
    const held = this.held.get(norm(path));
    if (held) return this.host.openDiff(path, held.before, held.content);
    const sessionId = this.client.sessionId;
    const r = unwrap(await this.client.request(HT + 'get-hunks', { sessionId, path, source: 'agent' }));
    this.host.openDiff(path, r?.baseline?.content ?? r?.baselineContent ?? '');
  }

  async act(action: Action, target: Target): Promise<void> {
    if ('path' in target) {
      const held = this.held.get(norm(target.path));
      if (held) return held.resolve(action === 'accept');
    }
    const sessionId = this.client.sessionId;
    if (action === 'reject') {
      // The tracker's reject writes disk itself (tokio::fs::write), so save the buffer first; the tracker then patches what is on
      // disk, keeping the user's other edits, or leaves it alone when the hunk moved. Reverting in the buffer first instead
      // would make the tracker re-insert a pure-deletion hunk (newCount 0 still "matches" the reverted region).
      const paths = 'hunk' in target ? [target.hunk.path] : 'path' in target ? [target.path] : this.paths();
      for (const p of paths) await this.host.flush(p);
    }
    const [method, params] =
      'hunk' in target ? ['hunk-action', { sessionId, hunkId: target.hunk.id, action }]
      : 'path' in target ? ['file-action', { sessionId, path: target.path, action }]
      : ['all-action', { sessionId, action }];
    const r = unwrap(await this.client.request(HT + method, params));
    try {
      if (r && r.success === false) throw new Error(r.error ?? `${method} ${action} failed`);
    } finally {
      await this.refresh();
    }
  }

  dispose(): void {
    clearTimeout(this.timer);
    for (const h of this.held.values()) h.resolve(false);
  }
}
