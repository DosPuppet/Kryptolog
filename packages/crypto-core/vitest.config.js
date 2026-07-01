import { defineConfig } from 'vitest/config';

// Node's global webcrypto (crypto.subtle / getRandomValues) covers everything
// the byte-compat suite exercises, so no jsdom is needed. The WebAuthn-PRF
// helpers reference `window`, but the suite never calls them.
export default defineConfig({
  test: {
    environment: 'node',
  },
});
