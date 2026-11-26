import type { FuigoClient, VsLike } from './types';
import { IDE_SERVER_ID, IDE_SERVER_NAME, IDE_TOOL_NAMES, sdkCallHandler } from './mcp';
import { addPending, MAX_CONTEXT_TEXT } from './pending';

export { getPendingContext, consumePendingContext, clearPendingContext, onDidChangePendingContext } from './pending';
export { IDE_SERVER_ID, IDE_SERVER_NAME, IDE_TOOL_NAMES };
/** L1: put this in `session/new` `_meta["fuigo/mcp/servers"]`. */
export const IDE_MCP_SERVERS = [{ name: IDE_SERVER_NAME, serverId: IDE_SERVER_ID }];
export const ADD_SELECTION_COMMAND = 'fuigo.addSelectionToContext';

/** The wire method is `_fuigo/mcp/sdk_call`; register both spellings so it works whichever way L1's client normalises. */
const SDK_CALL_METHODS = ['fuigo/mcp/sdk_call', '_fuigo/mcp/sdk_call'];

// eslint-disable-next-line @typescript-eslint/no-require-imports -- lazy, so unit tests can pass a fake `vs` without vscode
export function registerIdeTools(context: { subscriptions: { dispose(): unknown }[] }, client: FuigoClient, vs: VsLike = require('vscode')): void {
  const h = sdkCallHandler(vs);
  for (const m of SDK_CALL_METHODS) context.subscriptions.push(client.onRequest(m, h));
  context.subscriptions.push(vs.commands.registerCommand(ADD_SELECTION_COMMAND, () => {
    const ed = vs.window.activeTextEditor;
    if (!ed || ed.selection.isEmpty) { vs.window.showInformationMessage('Fuigo: select some text first.'); return; }
    const sel = ed.selection;
    // A selection ending at column 0 of a line does not include that line.
    const endLine = sel.end.character === 0 && sel.end.line > sel.start.line ? sel.end.line : sel.end.line + 1;
    addPending({
      path: ed.document.uri.fsPath, relPath: vs.workspace.asRelativePath(ed.document.uri, false),
      startLine: sel.start.line + 1, endLine, languageId: ed.document.languageId,
      text: ed.document.getText(sel).slice(0, MAX_CONTEXT_TEXT),
    });
  }));
}
