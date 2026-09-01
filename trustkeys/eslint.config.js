import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      // MV3 extension code runs against the WebExtension APIs as well as the
      // DOM, so `chrome` (and friends) are real globals here — without this
      // every `chrome.*` call reported as no-undef, which is what kept lint
      // advisory-only rather than a real gate.
      globals: {
        ...globals.browser,
        ...globals.webextensions,
        // Build-time constant injected by vite.config.js `define`.
        __TRUSTKEYS_ALLOW_DEV_AUTOSIGN__: 'readonly',
      },
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    rules: {
      'no-unused-vars': ['error', { varsIgnorePattern: '^[A-Z_]' }],
    },
  },
])
