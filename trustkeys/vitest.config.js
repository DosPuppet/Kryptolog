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
  },
});
