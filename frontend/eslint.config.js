import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import unusedImports from 'eslint-plugin-unused-imports'
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
    plugins: {
      react,
      'unused-imports': unusedImports,
    },
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    rules: {
      // Mark JSX-referenced identifiers (components, icons) as used so the
      // unused-imports autofix never strips an import that's only used in JSX.
      'react/jsx-uses-vars': 'error',
      'react/jsx-uses-react': 'off', // new JSX transform — React import not required
      // unused-imports owns dead imports (auto-removable via --fix) and vars.
      'no-unused-vars': 'off',
      'unused-imports/no-unused-imports': 'error',
      'unused-imports/no-unused-vars': [
        'error',
        { vars: 'all', varsIgnorePattern: '^[A-Z_]', args: 'none', caughtErrors: 'none' },
      ],
    },
  },
  // Vite / Node config files use Node globals (process, etc.)
  {
    files: ['**/*.config.js'],
    languageOptions: { globals: globals.node },
  },
  // Test files: vitest + Node globals (Buffer, vi, …)
  {
    files: ['**/*.test.{js,jsx}', 'src/test/**/*.{js,jsx}'],
    languageOptions: {
      globals: { ...globals.node, vi: 'readonly', vitest: 'readonly' },
    },
  },
])
