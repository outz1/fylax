import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

// Invariante do projeto: toda rede passa pelo ScopedHttpClient (packages/http).
const MODULOS_DE_REDE = [
  'axios',
  'got',
  'undici',
  'node-fetch',
  'http',
  'https',
  'net',
  'tls',
  'dgram',
  'node:http',
  'node:https',
  'node:net',
  'node:tls',
  'node:dgram',
];

export default tseslint.config(
  {
    ignores: ['**/node_modules/**', '**/dist/**', 'evidencias/**', 'apps/api/prisma/migrations/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      'no-restricted-imports': [
        'error',
        {
          paths: MODULOS_DE_REDE.map((name) => ({
            name,
            message: 'Rede só via ScopedHttpClient (packages/http).',
          })),
        },
      ],
      'no-restricted-globals': [
        'error',
        { name: 'fetch', message: 'Rede só via ScopedHttpClient (packages/http).' },
      ],
    },
  },
  {
    files: ['scripts/**/*.mjs', '*.config.mjs'],
    languageOptions: { globals: { console: 'readonly', process: 'readonly' } },
  },
  {
    files: ['packages/http/**'],
    rules: { 'no-restricted-imports': 'off', 'no-restricted-globals': 'off' },
  },
);
