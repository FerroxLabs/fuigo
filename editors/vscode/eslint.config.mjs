import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'out-test/**', 'node_modules/**', '.vscode-test/**', '*.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // JSON-RPC payloads are untyped on the wire; the code narrows them where it matters.
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }],
    },
  },
  {
    files: ['media/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: { acquireVsCodeApi: 'readonly', fuigoMarkdown: 'readonly', document: 'readonly', window: 'readonly' },
    },
  },
);
