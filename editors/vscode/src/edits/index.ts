// Lane L2: FsBridge + native diff review of agent edits (Accept/Reject via CodeLens, editor title and the "Fuigo edits" view).
import * as path from 'path';
import * as vscode from 'vscode';
import type { FuigoClient } from '../acp/types';
import { EditController, EditHost, Hunk, Target } from './controller';

const SCHEME = 'fuigo-edit';
type Node = { path: string } | { hunk: Hunk };

function openDoc(p: string): vscode.TextDocument | undefined {
  // shortcut: exact fsPath match; case-insensitive filesystems (Windows/macOS) may need normalising if the agent's casing differs.
  return vscode.workspace.textDocuments.find(d => d.uri.scheme === 'file' && d.uri.fsPath === p);
}

async function exists(uri: vscode.Uri): Promise<boolean> {
  return vscode.workspace.fs.stat(uri).then(() => true, () => false);
}

export function registerEdits(context: vscode.ExtensionContext, client: FuigoClient): void {
  const virtual = new Map<string, string>();
  let seq = 0;
  const treeChanged = new vscode.EventEmitter<Node | undefined>();
  const lensChanged = new vscode.EventEmitter<void>();

  const host: EditHost = {
    async readText(p) {
      const doc = openDoc(p);
      if (doc) return doc.getText();
      try {
        return new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.file(p)));
      } catch {
        return undefined;
      }
    },
    async writeText(p, content) {
      const uri = vscode.Uri.file(p);
      if (!openDoc(p) && !(await exists(uri))) {
        await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(content));
        return;
      }
      const doc = await vscode.workspace.openTextDocument(uri);
      const edit = new vscode.WorkspaceEdit();
      edit.replace(uri, new vscode.Range(0, 0, doc.lineCount, 0), content);
      if (!(await vscode.workspace.applyEdit(edit)) || !(await doc.save())) throw new Error(`could not write ${p}`);
    },
    async flush(p) {
      const doc = openDoc(p);
      if (doc?.isDirty && !(await doc.save())) throw new Error(`could not save ${p} before reject`);
    },
    openDiff(p, left, right) {
      const mk = (text: string) => {
        // shortcut: virtual texts are never evicted; fine for a session's worth of edits, add an LRU if memory shows up.
        const uri = vscode.Uri.file(p).with({ scheme: SCHEME, query: String(++seq) });
        virtual.set(uri.toString(), text);
        return uri;
      };
      const rightUri = right === undefined ? vscode.Uri.file(p) : mk(right);
      const title = `${path.basename(p)} (Fuigo ${right === undefined ? 'edit' : 'proposed edit'})`;
      void vscode.commands.executeCommand('vscode.diff', mk(left), rightUri, title, { preview: true, preserveFocus: right === undefined });
    },
    changed() {
      treeChanged.fire(undefined);
      lensChanged.fire();
      void vscode.commands.executeCommand('setContext', 'fuigo.edits.pendingPaths', ctl.paths());
      void vscode.commands.executeCommand('setContext', 'fuigo.edits.pending', ctl.paths().length > 0);
    },
  };
  const ctl = new EditController(client, host);

  const tree: vscode.TreeDataProvider<Node> = {
    onDidChangeTreeData: treeChanged.event,
    getChildren(node) {
      if (!node) return ctl.paths().map(p => ({ path: p }));
      return 'path' in node ? ctl.hunks.filter(h => h.path === node.path).map(h => ({ hunk: h })) : [];
    },
    getTreeItem(node) {
      if ('hunk' in node) {
        const { newStart, newCount, oldCount } = node.hunk.lineInfo;
        const item = new vscode.TreeItem(newCount ? `Lines ${newStart}-${newStart + newCount - 1}` : `Deleted at line ${newStart}`);
        item.description = `+${newCount} -${oldCount}`;
        item.contextValue = 'fuigoEditHunk';
        item.command = { command: 'fuigo.edits.open', title: 'Open diff', arguments: [node.hunk.path] };
        return item;
      }
      const held = ctl.held.has(node.path);
      const item = new vscode.TreeItem(vscode.Uri.file(node.path), held ? vscode.TreeItemCollapsibleState.None : vscode.TreeItemCollapsibleState.Expanded);
      item.description = held ? 'waiting for review' : vscode.workspace.asRelativePath(node.path);
      item.contextValue = held ? 'fuigoEditHeld' : 'fuigoEditFile';
      item.command = { command: 'fuigo.edits.open', title: 'Open diff', arguments: [node.path] };
      return item;
    },
  };

  const lenses: vscode.CodeLensProvider = {
    onDidChangeCodeLenses: lensChanged.event,
    provideCodeLenses(doc) {
      const p = doc.uri.fsPath;
      const at = (line: number, target: Target) => {
        const r = new vscode.Range(Math.max(line, 0), 0, Math.max(line, 0), 0);
        return [
          new vscode.CodeLens(r, { title: 'Accept', command: 'fuigo.edits.accept', arguments: [target] }),
          new vscode.CodeLens(r, { title: 'Reject', command: 'fuigo.edits.reject', arguments: [target] }),
        ];
      };
      if (ctl.held.has(p)) return at(0, { path: p });
      if (doc.uri.scheme !== 'file') return [];
      return ctl.hunks.filter(h => h.path === p).flatMap(h => at(h.lineInfo.newStart - 1, { hunk: h }));
    },
  };

  // Tree nodes, CodeLens targets, editor-title Uris, or nothing (the active editor).
  const target = (arg: any): Target | undefined => {
    if (arg?.hunk || typeof arg?.path === 'string' && !(arg instanceof vscode.Uri)) return arg;
    const uri: vscode.Uri | undefined = arg instanceof vscode.Uri ? arg : vscode.window.activeTextEditor?.document.uri;
    return uri && { path: uri.fsPath };
  };
  const run = (action: 'accept' | 'reject', t: Target | undefined) =>
    t && ctl.act(action, t).catch(e => vscode.window.showWarningMessage(`Fuigo: ${action} failed: ${e?.message ?? e}`));

  context.subscriptions.push(
    treeChanged,
    lensChanged,
    { dispose: () => ctl.dispose() },
    client.onRequest('fs/read_text_file', p => ctl.readTextFile(p)),
    client.onRequest('fs/write_text_file', p => ctl.writeTextFile(p)),
    client.onSessionUpdate((_sid, update) => ctl.onUpdate(update)),
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, { provideTextDocumentContent: uri => virtual.get(uri.toString()) ?? '' }),
    vscode.window.registerTreeDataProvider('fuigo.edits', tree),
    vscode.languages.registerCodeLensProvider([{ scheme: 'file' }, { scheme: SCHEME }], lenses),
    vscode.commands.registerCommand('fuigo.edits.accept', arg => run('accept', target(arg))),
    vscode.commands.registerCommand('fuigo.edits.reject', arg => run('reject', target(arg))),
    vscode.commands.registerCommand('fuigo.edits.acceptAll', () => run('accept', { all: true })),
    vscode.commands.registerCommand('fuigo.edits.rejectAll', () => run('reject', { all: true })),
    vscode.commands.registerCommand('fuigo.edits.open', (p: string) => ctl.showDiff(p)),
    vscode.commands.registerCommand('fuigo.edits.refresh', () => ctl.refresh()),
    // For L1's PermissionUI on kind:"edit" requests: returns the permission response, or undefined to prompt as usual.
    vscode.commands.registerCommand('fuigo.edits.reviewPermission', params => ctl.reviewPermission(params)),
  );
}
