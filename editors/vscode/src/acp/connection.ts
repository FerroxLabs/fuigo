import type * as vscode from 'vscode';
import type { FuigoClient } from './types';

// Newline-delimited JSON-RPC 2.0 (the ACP stdio framing). No vscode runtime import, so unit tests run in plain Node.
export interface Transport {
  send(line: string): void;
  onLine(cb: (line: string) => void): void;
  onClose(cb: (reason: string) => void): void;
  close(): void;
}

export class RpcError extends Error {
  constructor(readonly code: number, message: string, readonly data?: unknown) {
    super(message);
  }
}

type Handler = (params: any) => Promise<any>;
const disposable = (fn: () => void): vscode.Disposable => ({ dispose: fn }) as vscode.Disposable;

/** Fuigo extension methods carry a leading underscore on the wire, in both directions. */
export const wireName = (m: string) => (m.startsWith('fuigo/') ? '_' + m : m);
export const localName = (m: string) => m.replace(/^_/, '');

export class AcpConnection implements FuigoClient {
  private transport: Transport | undefined;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void; method: string }>();
  // A stack per method: the latest registration answers; disposing it restores the previous one.
  private handlers = new Map<string, Handler[]>();
  private sessionCbs = new Set<(sid: string, u: any) => void>();
  private notifCbs = new Map<string, Set<(p: any) => void>>();
  private closeCbs = new Set<(reason: string) => void>();
  private requestTaps = new Set<(method: string, params: any) => void>();
  private _sessionId: string | undefined;

  get sessionId() {
    return this._sessionId;
  }
  setSessionId(id: string | undefined) {
    this._sessionId = id;
  }
  get running() {
    return this.transport !== undefined;
  }

  attach(t: Transport) {
    this.transport = t;
    t.onLine((l) => this.onLine(l));
    t.onClose((reason) => {
      if (this.transport !== t) return;
      this.transport = undefined;
      this._sessionId = undefined;
      for (const [, p] of this.pending) p.reject(new Error(`fuigo agent exited (${reason}) during ${p.method}`));
      this.pending.clear();
      for (const cb of this.closeCbs) cb(reason);
    });
  }

  detach() {
    const t = this.transport;
    t?.close();
  }

  request<T = unknown>(method: string, params: unknown): Promise<T> {
    const t = this.transport;
    if (!t) return Promise.reject(new Error('fuigo agent is not running'));
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      t.send(JSON.stringify({ jsonrpc: '2.0', id, method: wireName(method), params }));
    });
  }

  notify(method: string, params: unknown): void {
    this.transport?.send(JSON.stringify({ jsonrpc: '2.0', method: wireName(method), params }));
  }

  onSessionUpdate(cb: (sessionId: string, update: any) => void): vscode.Disposable {
    this.sessionCbs.add(cb);
    return disposable(() => this.sessionCbs.delete(cb));
  }

  /** Agent notifications other than session/update, e.g. "fuigo/session/prompt_complete". */
  onNotification(method: string, cb: (params: any) => void): vscode.Disposable {
    const m = localName(method);
    if (!this.notifCbs.has(m)) this.notifCbs.set(m, new Set());
    this.notifCbs.get(m)!.add(cb);
    return disposable(() => this.notifCbs.get(m)?.delete(cb));
  }

  onClose(cb: (reason: string) => void): vscode.Disposable {
    this.closeCbs.add(cb);
    return disposable(() => this.closeCbs.delete(cb));
  }

  onRequest(method: string, handler: Handler): vscode.Disposable {
    const m = localName(method);
    const stack = this.handlers.get(m) ?? [];
    stack.push(handler);
    this.handlers.set(m, stack);
    return disposable(() => {
      const i = stack.lastIndexOf(handler);
      if (i >= 0) stack.splice(i, 1);
    });
  }

  /** Observe every agent->client request (local method name) before it is dispatched. Does not answer it. */
  onDidReceiveRequest(cb: (method: string, params: any) => void): vscode.Disposable {
    this.requestTaps.add(cb);
    return disposable(() => this.requestTaps.delete(cb));
  }

  hasHandler(method: string) {
    return (this.handlers.get(localName(method))?.length ?? 0) > 0;
  }

  private send(msg: object) {
    this.transport?.send(JSON.stringify(msg));
  }

  private onLine(line: string) {
    if (!line.trim()) return;
    let m: any;
    try {
      m = JSON.parse(line);
    } catch {
      return; // not JSON-RPC (stray log line); ignore
    }
    if (m.method !== undefined && m.id !== undefined) return void this.dispatchRequest(m);
    if (m.method !== undefined) return this.dispatchNotification(m);
    const p = this.pending.get(m.id);
    if (!p) return;
    this.pending.delete(m.id);
    if (m.error) p.reject(new RpcError(m.error.code, m.error.message, m.error.data));
    else p.resolve(m.result);
  }

  private dispatchNotification(m: any) {
    const name = localName(m.method);
    if (name === 'session/update') {
      for (const cb of this.sessionCbs) safe(() => cb(m.params?.sessionId, m.params?.update));
      return;
    }
    for (const cb of this.notifCbs.get(name) ?? []) safe(() => cb(m.params));
  }

  private async dispatchRequest(m: any) {
    for (const cb of this.requestTaps) safe(() => cb(localName(m.method), m.params));
    const stack = this.handlers.get(localName(m.method));
    const h = stack?.[stack.length - 1];
    if (!h) return this.send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: `client: method not found ${m.method}` } });
    try {
      const result = await h(m.params);
      this.send({ jsonrpc: '2.0', id: m.id, result: result === undefined ? null : result });
    } catch (e: any) {
      const code = typeof e?.code === 'number' ? e.code : -32603;
      this.send({ jsonrpc: '2.0', id: m.id, error: { code, message: String(e?.message ?? e) } });
    }
  }
}

function safe(fn: () => void) {
  try {
    fn();
  } catch (e) {
    console.error('[fuigo] listener failed', e);
  }
}
