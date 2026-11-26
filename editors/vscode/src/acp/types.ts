import type * as vscode from 'vscode';

// Shared contract for lanes L1/L2/L3 (coord-notes/1048-vscode-contract.md).
// Method names: pass Fuigo extension methods as "fuigo/..." or "_fuigo/..."; the wire always uses "_fuigo/...".
export interface FuigoClient {
  request<T = unknown>(method: string, params: unknown): Promise<T>;
  notify(method: string, params: unknown): void;
  onSessionUpdate(cb: (sessionId: string, update: any) => void): vscode.Disposable;
  onRequest(method: string, handler: (params: any) => Promise<any>): vscode.Disposable; // client-side handlers (fs/*, fuigo/mcp/sdk_call, ...)
  readonly sessionId: string | undefined;
}
