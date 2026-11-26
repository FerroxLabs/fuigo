// The single contract copy lives in src/acp/types.ts (L1).
export type { FuigoClient } from "../acp/types";
export interface Disposable { dispose(): unknown }

// The slice of the `vscode` API this lane uses, so tests can stub it. The real `vscode` module satisfies it.
export interface Pos { line: number; character: number }
export interface Rng { start: Pos; end: Pos }
export interface Uri { fsPath: string; scheme: string; toString(): string }
export interface Doc {
  uri: Uri; languageId: string; isDirty: boolean; isUntitled?: boolean;
  getText(range?: Rng): string;
}
export interface Editor { document: Doc; selection: Rng & { isEmpty: boolean } }
export interface Diag { range: Rng; message: string; severity: number; source?: string; code?: unknown }
export interface Tab { input: unknown; isActive: boolean; isDirty: boolean }
export interface VsLike {
  window: {
    activeTextEditor: Editor | undefined;
    tabGroups: { all: ReadonlyArray<{ tabs: ReadonlyArray<Tab> }> };
    showInformationMessage(msg: string): unknown;
  };
  workspace: {
    workspaceFolders: ReadonlyArray<{ name: string; uri: Uri }> | undefined;
    asRelativePath(p: string | Uri, includeFolder?: boolean): string;
  };
  languages: { getDiagnostics(): ReadonlyArray<[Uri, ReadonlyArray<Diag>]> };
  commands: { registerCommand(id: string, cb: (...a: any[]) => unknown): Disposable };
  Uri: { file(p: string): Uri };
}
