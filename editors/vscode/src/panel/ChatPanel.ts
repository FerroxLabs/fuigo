import { randomBytes } from 'node:crypto';
import * as vscode from 'vscode';
import type { AgentController } from '../acp/agent';
import { clearPendingContext, consumePendingContext, getPendingContext, onDidChangePendingContext } from '../context';

const MAX_QUEUE = 2000;

export class ChatPanel implements vscode.WebviewViewProvider {
  static readonly viewId = 'fuigo.chat';
  private view: vscode.WebviewView | undefined;
  private ready = false;
  private queue: unknown[] = [];
  private busy = false;

  constructor(private extUri: vscode.Uri, private agent: AgentController, private onError: (e: unknown) => void) {
    agent.conn.onSessionUpdate((sid, update) => {
      if (agent.isCurrent(sid)) this.post({ type: 'update', update });
    });
    // session/load replays the whole history: start from an empty log so nothing shows twice.
    agent.onWillLoad = () => this.post({ type: 'clear' });
    agent.conn.onClose((reason) => {
      this.post({ type: 'notice', text: `Fuigo agent stopped (${reason}). Send a message to restart it.` });
      this.setBusy(false);
    });
    onDidChangePendingContext(() => this.postContext());
  }

  resolveWebviewView(view: vscode.WebviewView) {
    this.view = view;
    this.ready = false;
    const media = vscode.Uri.joinPath(this.extUri, 'media');
    const dist = vscode.Uri.joinPath(this.extUri, 'dist');
    view.webview.options = { enableScripts: true, localResourceRoots: [media, dist] };
    view.webview.html = this.html(view.webview, media, dist);
    view.webview.onDidReceiveMessage((m) => this.onMessage(m));
    view.onDidDispose(() => {
      this.view = undefined;
      this.ready = false;
    });
  }

  private post(msg: unknown) {
    if (this.view && this.ready) void this.view.webview.postMessage(msg);
    // shortcut: while the view is closed only the latest MAX_QUEUE messages are kept for it; replay from session/load if needed.
    else if (this.queue.push(msg) > MAX_QUEUE) this.queue.shift();
  }

  private postContext() {
    this.post({ type: 'context', items: getPendingContext().map((i) => ({ label: `${i.relPath}#L${i.startLine}${i.endLine > i.startLine ? '-' + i.endLine : ''}` })) });
  }

  private setBusy(b: boolean) {
    this.busy = b;
    this.post({ type: 'busy', busy: b });
  }

  private postModes() {
    const i = this.agent.info;
    if (i) this.post({ type: 'modes', modes: i.modes, current: i.currentModeId });
  }

  async startSession(fresh = false) {
    try {
      if (fresh) await this.agent.newSession();
      else await this.agent.ensureSession();
      if (fresh) this.post({ type: 'clear' });
      this.postModes();
      if (this.agent.info?.resumed && !fresh) this.post({ type: 'notice', text: 'Resumed the previous session. Use New to start over.' });
    } catch (e) {
      this.post({ type: 'error', text: String((e as Error)?.message ?? e) });
      this.onError(e);
    }
  }

  async send(text: string) {
    if (this.busy || !text.trim()) return;
    this.setBusy(true);
    try {
      await this.agent.ensureSession(); // may resume and replay history first, so the new message goes after it
      this.postModes();
      this.post({ type: 'user', text });
      const r = await this.agent.prompt([...consumePendingContext(), { type: 'text', text }]);
      this.post({ type: 'turnEnd', stopReason: r?.stopReason });
    } catch (e) {
      this.post({ type: 'error', text: String((e as Error)?.message ?? e) });
      this.onError(e);
    } finally {
      this.setBusy(false);
    }
  }

  private async onMessage(m: any) {
    switch (m?.type) {
      case 'ready':
        this.ready = true;
        for (const q of this.queue.splice(0)) void this.view?.webview.postMessage(q);
        this.post({ type: 'busy', busy: this.busy });
        this.postContext();
        void this.startSession();
        return;
      case 'send':
        return typeof m.text === 'string' ? this.send(m.text) : undefined;
      case 'stop':
        return this.agent.cancel();
      case 'mode':
        // Only a mode the agent offered; anything else is dropped and the picker is reset.
        if (!this.agent.info?.modes.some((x) => x.id === m.id)) return this.postModes();
        try {
          await this.agent.setMode(m.id);
        } catch (e) {
          this.post({ type: 'error', text: String((e as Error)?.message ?? e) });
        }
        return this.postModes();
      case 'newSession':
        return this.startSession(true);
      case 'clearContext':
        return clearPendingContext();
    }
  }

  private html(webview: vscode.Webview, media: vscode.Uri, dist: vscode.Uri) {
    const nonce = randomBytes(16).toString('base64url');
    const js = webview.asWebviewUri(vscode.Uri.joinPath(media, 'panel.js'));
    const css = webview.asWebviewUri(vscode.Uri.joinPath(media, 'panel.css'));
    const md = webview.asWebviewUri(vscode.Uri.joinPath(dist, 'markdown.js'));
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><link rel="stylesheet" href="${css}"><title>Fuigo</title></head>
<body>
<div id="toolbar"><label>Mode <select id="mode" aria-label="Mode"></select></label><button id="new" title="New session">New</button></div>
<div id="log" role="log" aria-live="polite"></div>
<div id="context" hidden><span id="context-label"></span><button id="context-clear" title="Remove context" aria-label="Remove context">×</button></div>
<form id="composer"><textarea id="input" rows="3" placeholder="Ask Fuigo… (Enter to send, Shift+Enter for a new line)" aria-label="Message"></textarea>
<div class="row"><button id="send" type="submit">Send</button><button id="stop" type="button" hidden>Stop</button></div></form>
<script nonce="${nonce}" src="${md}"></script><script nonce="${nonce}" src="${js}"></script></body></html>`;
  }
}
