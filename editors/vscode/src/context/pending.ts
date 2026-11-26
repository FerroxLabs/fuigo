import { pathToFileURL } from 'node:url';
import type { Disposable } from './types';

/** One "Add selection to Fuigo" item. Lines are 1-based, inclusive. */
export interface ContextItem { path: string; relPath: string; startLine: number; endLine: number; languageId: string; text: string }

export const MAX_CONTEXT_TEXT = 16 * 1024;
export const MAX_PENDING_ITEMS = 10;

const items: ContextItem[] = [];
const listeners = new Set<() => void>();
const fire = () => listeners.forEach((l) => l());

export function addPending(it: ContextItem): void {
  items.push(it);
  if (items.length > MAX_PENDING_ITEMS) items.shift();
  fire();
}

/** For L1's panel chip: what will ride on the next prompt. Does not clear. */
export function getPendingContext(): readonly ContextItem[] { return items.slice(); }

export function clearPendingContext(): void { items.length = 0; fire(); }

export function onDidChangePendingContext(cb: () => void): Disposable {
  listeners.add(cb);
  return { dispose: () => { listeners.delete(cb); } };
}

/** Anchor for @-mentions: `path#L5-10` (or `#L5`). */
export const mention = (it: ContextItem) => `${it.relPath}#L${it.startLine}${it.endLine > it.startLine ? `-${it.endLine}` : ''}`;

/**
 * Take the pending items as ACP content blocks to put in front of the next prompt's text, and clear them.
 * One text block with the @-mentions, then one embedded `resource` block per item (agent advertises embeddedContext).
 */
export function consumePendingContext(): Array<Record<string, unknown>> {
  if (!items.length) return [];
  const taken = items.splice(0);
  fire();
  return [
    { type: 'text', text: taken.map((i) => `@${mention(i)}`).join(' ') },
    ...taken.map((i) => ({
      type: 'resource',
      resource: { uri: `${pathToFileURL(i.path).href}#L${i.startLine}-${i.endLine}`, mimeType: 'text/plain', text: i.text },
    })),
  ];
}
