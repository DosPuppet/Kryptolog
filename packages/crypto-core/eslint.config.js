import js from '@eslint/js'
import globals from 'globals'
import { defineConfig } from 'eslint/config'

// This package had no lint gate for its whole life, while the other three had
// blocking ones — and it is the package that exists to be the single source of
// truth for every wire primitive. That gap shipped a real break: the module
// split left webauthn.js calling toHex/fromHex without importing them, so every
// biometric path threw ReferenceError before reaching the authenticator. It was
// invisible because that module needs `window` and so has no tests, and
// no-undef never ran over it. `no-undef` is the rule that matters most here.
export default defineConfig([
  {
    files: ['src/**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: {
      // Runs unchanged in Node, the browser SPA and an MV3 service worker, so
      // the globals are the intersection: Web Crypto, TextEncoder, btoa/atob.
      // `window` is deliberately NOT here — only webauthn.js may touch it, and
      // it is documented as SPA-only, so a stray reference elsewhere should
      // fail rather than pass.
      globals: { ...globals.browser },
      parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    },
    rules: {
      'no-unused-vars': ['error', { varsIgnorePattern: '^[A-Z_]' }],
    },
  },
  {
    files: ['test/**/*.js', 'vitest.config.js'],
    extends: [js.configs.recommended],
    languageOptions: {
      globals: { ...globals.node, ...globals.browser },
      parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    },
    rules: {
      'no-unused-vars': ['error', { varsIgnorePattern: '^[A-Z_]' }],
    },
  },
])
