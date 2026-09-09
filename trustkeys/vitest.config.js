import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    // Match vite.config.js: crypto-core is a symlinked `file:` dep, and without
    // this its imports resolve against the real path instead of ours.
    preserveSymlinks: true,
  },
  define: {
    // Model a PRODUCTION build. This flag compiles out the localhost
    // silent-signing exemption, and production is the configuration whose
    // security properties are worth asserting — a dev build deliberately has
    // weaker ones. See vite.config.js.
    __TRUSTKEYS_ALLOW_DEV_AUTOSIGN__: 'false',
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    // The vault KDF is 600k PBKDF2 iterations BY DESIGN, and a test that boots
    // a vault pays it more than once — the .kvault round-trip derives on
    // export, on import and on the re-save. That blows vitest's 5s default on
    // an unremarkable machine, so the suite failed locally while CI called it
    // green (audit N-3). The slowness is the product working; the budget was
    // just never raised to match.
    testTimeout: 30000,
  },
});
