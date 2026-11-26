// Pure permission mapping (no vscode import): ACP session/request_permission -> picker items -> ACP outcome.

export interface DiffContent {
  path: string;
  oldText: string | null;
  newText: string;
}

export interface CachedToolCall {
  toolCallId: string;
  title?: string;
  kind?: string;
  status?: string;
  rawInput?: any;
  content?: any[];
  locations?: { path: string; line?: number }[];
}

/**
 * Merges tool_call / tool_call_update by toolCallId. The edit permission request carries no diff; the diff arrives on
 * the preceding tool_call_update with the same toolCallId (L0 probe answer 1), so we look it up here, as Zed does.
 */
export class ToolCallCache {
  private calls = new Map<string, CachedToolCall>();

  apply(update: any) {
    const k = update?.sessionUpdate;
    if ((k !== 'tool_call' && k !== 'tool_call_update') || !update.toolCallId) return;
    const prev = this.calls.get(update.toolCallId) ?? { toolCallId: update.toolCallId };
    const next: CachedToolCall = { ...prev };
    for (const f of ['title', 'kind', 'status', 'rawInput', 'locations'] as const) if (update[f] != null) (next as any)[f] = update[f];
    // A completed update carries its own (richer) diff; keep the latest non-empty content.
    if (Array.isArray(update.content) && update.content.length) next.content = update.content;
    this.calls.set(update.toolCallId, next);
    // Finished calls are no longer needed for prompts; keep the map bounded.
    if (next.status === 'completed' || next.status === 'failed') this.calls.delete(update.toolCallId);
  }

  get(id: string) {
    return this.calls.get(id);
  }

  get size() {
    return this.calls.size;
  }
}

export function diffsOf(call: CachedToolCall | undefined): DiffContent[] {
  return (call?.content ?? []).filter((c) => c?.type === 'diff').map((c) => ({ path: c.path, oldText: c.oldText ?? null, newText: c.newText ?? '' }));
}

export interface PermissionItem {
  label: string;
  description?: string;
  optionId?: string; // undefined: a non-answer action (e.g. show diff)
}

export interface PermissionPrompt {
  title: string;
  detail: string;
  diffs: DiffContent[];
  items: PermissionItem[];
}

const KIND_LABEL: Record<string, string> = {
  allow_once: '$(check) Allow once',
  allow_always: '$(check-all) Always allow',
  reject_once: '$(close) Reject',
  reject_always: '$(circle-slash) Always reject',
};

export const SHOW_DIFF_LABEL = '$(diff) Show diff';

function shorten(s: string, n = 120) {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? one.slice(0, n - 1) + '…' : one;
}

export function buildPermissionPrompt(params: any, cache: ToolCallCache): PermissionPrompt {
  const tc = params?.toolCall ?? {};
  const cached = cache.get(tc.toolCallId);
  const merged: CachedToolCall = { toolCallId: tc.toolCallId, ...cached, ...stripNull(tc), content: tc.content?.length ? tc.content : cached?.content };
  const diffs = diffsOf(merged);
  const title = merged.title ?? 'Fuigo wants to run a tool';
  const detail = diffs.length
    ? diffs.map((d) => `${d.path}: −${shorten(d.oldText ?? '') || '∅'}  +${shorten(d.newText) || '∅'}`).join('\n')
    : merged.rawInput !== undefined
      ? shorten(typeof merged.rawInput === 'string' ? merged.rawInput : JSON.stringify(merged.rawInput), 300)
      : '';
  const items: PermissionItem[] = (params?.options ?? []).map((o: any) => ({
    label: KIND_LABEL[o.kind] ?? o.name ?? o.optionId,
    description: KIND_LABEL[o.kind] && o.name ? o.name : undefined,
    optionId: o.optionId,
  }));
  if (diffs.length) items.push({ label: SHOW_DIFF_LABEL });
  return { title, detail, diffs, items };
}

/** ACP RequestPermissionResponse for a picked item; undefined (Escape / dismissed) is "cancelled". */
export function permissionOutcome(picked: PermissionItem | undefined) {
  return picked?.optionId ? { outcome: { outcome: 'selected', optionId: picked.optionId } } : { outcome: { outcome: 'cancelled' } };
}

function stripNull(o: any) {
  return Object.fromEntries(Object.entries(o ?? {}).filter(([, v]) => v != null));
}

// _fuigo/exit_plan_mode: outcome is approved | cancelled | abandoned, plus optional feedback
// (fuigo-tools/src/implementations/fuigo_build/exit_plan_mode/types.rs).
export const PLAN_APPROVE = '$(check) Approve plan and start';
export const PLAN_REVISE = '$(edit) Keep planning (give feedback)';
export const PLAN_OPEN = '$(go-to-file) Open plan';

export function planOutcome(picked: string | undefined, feedback?: string) {
  if (picked === PLAN_APPROVE) return { outcome: 'approved' };
  if (picked === PLAN_REVISE) return feedback ? { outcome: 'cancelled', feedback } : { outcome: 'cancelled' };
  return { outcome: 'abandoned' };
}

/**
 * Requests answered without a prompt: a UseTool call of exactly one of the read-only IDE tools this extension serves
 * itself (`ownTools`, qualified with our per-activation server name; see context/mcp.ts). Fuigo has no read-only flag for
 * client MCP tools, so they would otherwise prompt on every call. Answered allow-once, never allow-always: an "always"
 * rule would be stored by tool name and outlive this extension's registration.
 */
export function autoPermission(params: any, ownTools: readonly string[]) {
  const raw = params?.toolCall?.rawInput;
  if (raw?.variant !== 'UseTool' || typeof raw.tool_name !== 'string' || !ownTools.includes(raw.tool_name)) return undefined;
  const o = (params.options ?? []).find((x: any) => x.kind === 'allow_once');
  return o ? { outcome: { outcome: 'selected', optionId: o.optionId } } : undefined;
}

/** Whole-file proposal for a snippet diff: the agent's diff is old_string/new_string, not the file (L0 answer 1). */
export function proposedText(current: string, d: DiffContent): string {
  if (!d.oldText) return d.newText; // write: oldText is always "" even when overwriting
  const i = current.indexOf(d.oldText);
  return i < 0 ? current : current.slice(0, i) + d.newText + current.slice(i + d.oldText.length);
}
