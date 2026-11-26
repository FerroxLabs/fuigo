import * as esbuild from 'esbuild';

const common = { bundle: true, logLevel: 'info', minify: process.argv.includes('--minify') };
const builds = [
  // Extension host.
  { ...common, entryPoints: ['src/extension.ts'], outfile: 'dist/extension.js', external: ['vscode'], format: 'cjs', platform: 'node', target: 'node20', sourcemap: true },
  // Webview: the markdown renderer as the global `fuigoMarkdown` (media/panel.js calls fuigoMarkdown.render).
  { ...common, entryPoints: ['src/panel/markdown.ts'], outfile: 'dist/markdown.js', format: 'iife', globalName: 'fuigoMarkdown', platform: 'browser', target: 'es2022' },
];
if (process.argv.includes('--watch')) for (const b of builds) await (await esbuild.context(b)).watch();
else await Promise.all(builds.map((b) => esbuild.build(b)));
