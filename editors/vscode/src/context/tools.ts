import type { VsLike, Doc, Uri } from './types';

// Size caps keep tool output small; every cut says so in `note`.
export const MAX_SELECTION_CHARS = 16 * 1024;
export const MAX_EDITORS = 50;
export const MAX_DIAGNOSTICS = 100;
export const MAX_MESSAGE_CHARS = 500;
const SEVERITY = ['error', 'warning', 'information', 'hint'];

const rng = (r: { start: { line: number; character: number }; end: { line: number; character: number } }) => ({
  start: { line: r.start.line + 1, character: r.start.character + 1 },
  end: { line: r.end.line + 1, character: r.end.character + 1 },
});
export const cut = (s: string, n: number) => (s.length > n ? { text: s.slice(0, n), cut: s.length - n } : { text: s, cut: 0 });

export interface Tool { name: string; description: string; inputSchema: object; run(vs: VsLike, args: any): unknown }

const nothing = { type: 'object', properties: {}, additionalProperties: false };

/** Input path (absolute or workspace-relative) to an absolute fsPath, or undefined if the arg is unset. */
function resolvePath(vs: VsLike, p: unknown): string | undefined {
  if (p === undefined) return undefined;
  if (typeof p !== 'string' || !p) throw new Error('path must be a non-empty string');
  if (p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p)) return p;
  const root = vs.workspace.workspaceFolders?.[0];
  return root ? root.uri.fsPath.replace(/[\\/]$/, '') + '/' + p : p;
}

export const TOOLS: Tool[] = [
  {
    name: 'ide_get_selection',
    description: 'Read-only. The active editor selection in VS Code: file, range (1-based) and selected text.',
    inputSchema: nothing,
    run(vs) {
      const ed = vs.window.activeTextEditor;
      if (!ed) return { selection: null, note: 'no active text editor' };
      const sel = ed.selection;
      const { text, cut: n } = cut(sel.isEmpty ? '' : ed.document.getText(sel), MAX_SELECTION_CHARS);
      return {
        file: ed.document.uri.fsPath, languageId: ed.document.languageId, range: rng(sel), isEmpty: sel.isEmpty, text,
        ...(n ? { truncated: true, note: `text cut by ${n} characters` } : {}),
      };
    },
  },
  {
    name: 'ide_get_open_editors',
    description: 'Read-only. Files open in VS Code tabs: path, whether it is the active tab, and whether it has unsaved changes.',
    inputSchema: nothing,
    run(vs) {
      const out: Array<{ path: string; active: boolean; dirty: boolean }> = [];
      for (const g of vs.window.tabGroups.all) for (const t of g.tabs) {
        const uri = (t.input as { uri?: Uri } | undefined)?.uri;
        if (uri?.scheme === 'file') out.push({ path: uri.fsPath, active: t.isActive, dirty: t.isDirty });
      }
      const editors = out.slice(0, MAX_EDITORS);
      return { editors, ...(out.length > MAX_EDITORS ? { truncated: true, note: `${out.length - MAX_EDITORS} more tabs not listed` } : {}) };
    },
  },
  {
    name: 'ide_get_diagnostics',
    description: 'Read-only. VS Code problems (errors, warnings, ...) for one file (`path`, absolute or workspace-relative) or, with no path, every file that has any. Ranges are 1-based.',
    inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'File to check; omit for all files' } }, additionalProperties: false },
    run(vs, args) {
      const want = resolvePath(vs, args?.path);
      const files: Array<{ file: string; diagnostics: unknown[] }> = [];
      let total = 0;
      let dropped = 0;
      for (const [uri, ds] of vs.languages.getDiagnostics()) {
        if (!ds.length || uri.scheme !== 'file' || (want !== undefined && uri.fsPath !== want)) continue;
        const keep: unknown[] = [];
        for (const d of ds) {
          if (total >= MAX_DIAGNOSTICS) { dropped++; continue; }
          total++;
          keep.push({
            severity: SEVERITY[d.severity] ?? 'unknown', range: rng(d.range), message: cut(d.message, MAX_MESSAGE_CHARS).text,
            ...(d.source ? { source: d.source } : {}), ...(d.code !== undefined ? { code: typeof d.code === 'object' ? (d.code as any)?.value : d.code } : {}),
          });
        }
        if (keep.length) files.push({ file: uri.fsPath, diagnostics: keep });
      }
      return { files, ...(dropped ? { truncated: true, note: `${dropped} more diagnostics not listed; pass path to narrow` } : {}) };
    },
  },
  {
    name: 'ide_get_workspace_folders',
    description: 'Read-only. The folders open in the VS Code workspace.',
    inputSchema: nothing,
    run(vs) { return { folders: (vs.workspace.workspaceFolders ?? []).map((f) => ({ name: f.name, path: f.uri.fsPath })) }; },
  },
];

export type { Doc };
