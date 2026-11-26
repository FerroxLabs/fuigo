import * as assert from 'assert';
import { render } from '../../src/panel/markdown';

describe('agent markdown rendering', () => {
  it('renders ordinary markdown', () => {
    const h = render('# T\n\n**b** `c`\n\n```ts\nlet x = 1 < 2;\n```\n\n- a\n- b');
    for (const want of ['<h1>T</h1>', '<strong>b</strong>', '<code>c</code>', '<pre><code class="language-ts">let x = 1 &lt; 2;', '<li>a</li>']) assert.ok(h.includes(want), want + ' in ' + h);
  });

  it('escapes raw HTML instead of emitting it', () => {
    const h = render('<script>alert(1)</script> <img src=x onerror=alert(1)> <iframe src="https://e.example"></iframe>');
    assert.ok(!/<(script|img|iframe)/i.test(h), h);
    assert.ok(h.includes('&lt;script&gt;'), h);
  });

  it('never renders images (no remote resource loads)', () => {
    const h = render('![x](https://evil.example/t.png) ![y](data:image/png;base64,AAAA)');
    assert.ok(!/<img/i.test(h), h);
  });

  it('keeps only http(s)/mailto links, with rel noreferrer', () => {
    const h = render('[a](https://ok.example) [m](mailto:a@b.example) [j](javascript:alert(1)) [c](command:workbench.action.quit) [f](file:///etc/passwd) [v](vbscript:x) [d](data:text/html,<b>x</b>)');
    assert.ok(h.includes('<a href="https://ok.example" rel="noreferrer noopener">a</a>'), h);
    assert.ok(h.includes('href="mailto:a@b.example"'), h);
    for (const bad of ['javascript:', 'command:', 'file:', 'vbscript:', 'data:']) assert.ok(!h.includes(`href="${bad}`), bad + ' in ' + h);
  });

  it('cannot break out of attributes', () => {
    const h = render('[x](https://a.example/"onmouseover="alert(1)) ```"><svg onload=alert(1)>\nx\n```');
    assert.ok(!/<svg/i.test(h) && !/\sonmouseover="/i.test(h), h);
  });
});
