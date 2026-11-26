// Fuigo chat webview. Agent replies are markdown rendered by fuigoMarkdown (dist/markdown.js: raw HTML escaped, no images,
// http(s)/mailto links only); everything else is set with textContent.
(function () {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  const log = $('log'), input = $('input'), mode = $('mode'), stop = $('stop'), send = $('send');
  const tools = new Map();
  let current = null; // the streaming bubble: { kind, el }
  let planEl = null;

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const scroll = () => { log.scrollTop = log.scrollHeight; };
  const add = (e) => { log.appendChild(e); scroll(); return e; };

  function stream(kind, text) {
    if (!current || current.kind !== kind) current = { kind, el: add(el('div', 'msg ' + kind + (kind === 'agent' ? ' md' : ''), '')), raw: '' };
    current.raw += text;
    if (kind === 'agent') current.el.innerHTML = fuigoMarkdown.render(current.raw);
    else current.el.textContent = current.raw;
    scroll();
  }

  const STATUS = { pending: '…', in_progress: '⟳', completed: '✓', failed: '✗' };

  function tool(u) {
    let t = tools.get(u.toolCallId);
    if (!t) {
      const card = add(el('div', 'tool'));
      const head = el('div', 'tool-head');
      const status = el('span', 'tool-status', '…');
      const title = el('span', 'tool-title', '');
      head.append(status, title);
      const body = el('pre', 'tool-body', '');
      body.hidden = true;
      card.append(head, body);
      head.addEventListener('click', () => { body.hidden = !body.hidden; });
      t = { card, status, title, body };
      tools.set(u.toolCallId, t);
      current = null;
    }
    if (u.title) t.title.textContent = u.title;
    if (u.status) { t.status.textContent = STATUS[u.status] || u.status; t.card.dataset.status = u.status; }
    const parts = [];
    for (const c of u.content || []) {
      if (c.type === 'diff') parts.push(`${c.path}\n- ${c.oldText || ''}\n+ ${c.newText || ''}`);
      else if (c.type === 'content' && c.content && c.content.type === 'text') parts.push(c.content.text);
    }
    if (parts.length) t.body.textContent = parts.join('\n\n');
  }

  function plan(entries) {
    if (!planEl) { planEl = add(el('div', 'plan')); current = null; }
    planEl.replaceChildren(el('div', 'plan-head', 'Plan'));
    const ul = el('ul');
    for (const e of entries || []) {
      const li = el('li', 'plan-' + (e.status || 'pending'), (e.status === 'completed' ? '✓ ' : e.status === 'in_progress' ? '▸ ' : '○ ') + e.content);
      ul.appendChild(li);
    }
    planEl.appendChild(ul);
    scroll();
  }

  function onUpdate(u) {
    switch (u.sessionUpdate) {
      case 'agent_message_chunk': if (u.content && u.content.type === 'text') stream('agent', u.content.text); break;
      case 'user_message_chunk': if (u.content && u.content.type === 'text') stream('user', u.content.text); break; // session/load replay
      case 'agent_thought_chunk': if (u.content && u.content.type === 'text') stream('thought', u.content.text); break;
      case 'tool_call': case 'tool_call_update': tool(u); break;
      case 'plan': plan(u.entries); break;
      case 'current_mode_update': mode.value = u.currentModeId; break;
    }
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    switch (m.type) {
      case 'update': onUpdate(m.update); break;
      case 'user': current = null; planEl = null; add(el('div', 'msg user', m.text)); break;
      case 'busy': stop.hidden = !m.busy; send.disabled = m.busy; break;
      case 'turnEnd':
        current = null;
        if (m.stopReason && m.stopReason !== 'end_turn') add(el('div', 'notice', m.stopReason === 'cancelled' ? 'Turn stopped.' : 'Turn ended: ' + m.stopReason));
        break;
      case 'error': current = null; add(el('div', 'notice error', m.text)); break;
      case 'notice': current = null; add(el('div', 'notice', m.text)); break;
      case 'clear': log.replaceChildren(); tools.clear(); current = null; planEl = null; break;
      case 'modes':
        mode.replaceChildren(...(m.modes || []).map((x) => { const o = el('option', null, x.name || x.id); o.value = x.id; if (x.description) o.title = x.description; return o; }));
        if (m.current) mode.value = m.current;
        break;
      case 'context': {
        const items = m.items || [];
        $('context').hidden = !items.length;
        $('context-label').textContent = items.map((i) => '@' + i.label).join('  ');
        break;
      }
    }
  });

  $('composer').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value;
    if (!text.trim() || send.disabled) return;
    input.value = '';
    vscode.postMessage({ type: 'send', text });
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); $('composer').requestSubmit(); }
  });
  stop.addEventListener('click', () => vscode.postMessage({ type: 'stop' }));
  mode.addEventListener('change', () => vscode.postMessage({ type: 'mode', id: mode.value }));
  $('new').addEventListener('click', () => vscode.postMessage({ type: 'newSession' }));
  $('context-clear').addEventListener('click', () => vscode.postMessage({ type: 'clearContext' }));
  vscode.postMessage({ type: 'ready' });
})();
