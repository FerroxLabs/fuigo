// Agent text -> HTML for the chat webview. Bundled into dist/markdown.js (global `fuigoMarkdown`) and unit-tested in Node.
// Safety: raw HTML in the text is escaped (html:false), images are not rendered (no remote fetches; the CSP also blocks
// them), and links keep only http(s)/mailto targets. Everything else markdown-it emits is its own fixed tag set.
import MarkdownIt from 'markdown-it';

const md = new MarkdownIt({ html: false, linkify: true, breaks: true });
md.disable(['image']);
md.validateLink = (url) => /^(https?:|mailto:)/i.test(url.trim());
const defaultLinkOpen = md.renderer.rules.link_open ?? ((t, i, o, _e, self) => self.renderToken(t, i, o));
md.renderer.rules.link_open = (tokens, idx, opts, env, self) => {
  tokens[idx].attrSet('rel', 'noreferrer noopener');
  return defaultLinkOpen(tokens, idx, opts, env, self);
};

export function render(text: string): string {
  return md.render(text);
}
