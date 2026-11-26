import * as vscode from 'vscode';
import { IDE_TOOL_NAMES } from '../context';
import type { AcpConnection } from './connection';
import {
  autoPermission, buildPermissionPrompt, DiffContent, permissionOutcome, PLAN_APPROVE, PLAN_OPEN, PLAN_REVISE, planOutcome,
  proposedText, SHOW_DIFF_LABEL, ToolCallCache,
} from './permission';

/** Fires right before a native prompt is shown (the integration test answers it). */
export const onDidShowPrompt = new vscode.EventEmitter<{ kind: 'permission' | 'plan' | 'install'; title: string }>();

const PLAN_RE = /[\\/]\.fuigo[\\/]sessions[\\/].*plan\.md$/i;

async function fileText(p: string): Promise<{ text: string; lang?: string }> {
  try {
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(p)); // open buffer if any, else disk
    return { text: doc.getText(), lang: doc.languageId };
  } catch {
    return { text: '' }; // new file
  }
}

async function showDiff(d: DiffContent) {
  const cur = await fileText(d.path);
  const left = await vscode.workspace.openTextDocument({ content: cur.text, language: cur.lang });
  const right = await vscode.workspace.openTextDocument({ content: proposedText(cur.text, d), language: cur.lang });
  await vscode.commands.executeCommand('vscode.diff', left.uri, right.uri, `${vscode.workspace.asRelativePath(d.path)} (proposed by Fuigo)`, { preview: true });
}

export function registerPromptUi(context: vscode.ExtensionContext, client: AcpConnection, cache: ToolCallCache) {
  // The plan file the agent last read (fs/* is served by src/edits), so plan approval can open it when planContent is null.
  let lastPlanPath: string | undefined;
  context.subscriptions.push(
    onDidShowPrompt,
    client.onDidReceiveRequest((method, params) => {
      if (method === 'fs/read_text_file' && typeof params?.path === 'string' && PLAN_RE.test(params.path)) lastPlanPath = params.path;
    }),
    client.onRequest('session/request_permission', async (params) => {
      const auto = autoPermission(params, IDE_TOOL_NAMES);
      if (auto) return auto;
      if (params?.toolCall?.kind === 'edit') {
        // L2 holds the write in a native diff (Accept/Reject there); undefined means it can't, so prompt here.
        const reviewed = await vscode.commands.executeCommand('fuigo.edits.reviewPermission', params);
        if (reviewed !== undefined) return reviewed;
      }
      const p = buildPermissionPrompt(params, cache);
      for (;;) {
        onDidShowPrompt.fire({ kind: 'permission', title: p.title });
        const picked = await vscode.window.showQuickPick(p.items, {
          title: `Fuigo: ${p.title}`,
          placeHolder: p.detail.split('\n')[0] || 'Allow this tool call?',
          ignoreFocusOut: true,
        });
        if (picked?.label === SHOW_DIFF_LABEL) {
          for (const d of p.diffs) await showDiff(d);
          continue;
        }
        return permissionOutcome(picked);
      }
    }),
    client.onRequest('fuigo/exit_plan_mode', async (params) => {
      for (;;) {
        const items = [PLAN_APPROVE, PLAN_REVISE];
        if (params?.planContent || lastPlanPath) items.push(PLAN_OPEN);
        onDidShowPrompt.fire({ kind: 'plan', title: 'Plan ready' });
        const picked = await vscode.window.showQuickPick(items, { title: 'Fuigo: plan ready. Start building?', ignoreFocusOut: true });
        if (picked === PLAN_OPEN) {
          const doc = params?.planContent
            ? await vscode.workspace.openTextDocument({ content: params.planContent, language: 'markdown' })
            : await vscode.workspace.openTextDocument(vscode.Uri.file(lastPlanPath!));
          await vscode.window.showTextDocument(doc, { preview: true, preserveFocus: true });
          continue;
        }
        const feedback = picked === PLAN_REVISE
          ? await vscode.window.showInputBox({ prompt: 'What should Fuigo change in the plan?', ignoreFocusOut: true })
          : undefined;
        return planOutcome(picked, feedback || undefined);
      }
    }),
  );
}
