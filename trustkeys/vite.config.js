import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { crx } from '@crxjs/vite-plugin'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import manifest from './manifest.json'

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  define: {
    // Popup-free ("silent") chat-message signing for http://localhost origins
    // is a DEVELOPMENT convenience only: without this gate, any page served
    // from localhost or 127.0.0.1 — on any port, by any locally-running app —
    // can sign messages as the user with no prompt and no per-site grant.
    //
    // A compile-time constant rather than a runtime check, so `vite build`
    // (mode "production") dead-code-eliminates the bypass: it is not present in
    // the shipped extension at all. Use `npm run build:dev` to keep it.
    __TRUSTKEYS_ALLOW_DEV_AUTOSIGN__: JSON.stringify(mode !== 'production'),
  },
  resolve: {
    preserveSymlinks: true,
  },
  plugins: [
    react(),
    crx({ manifest }),
    nodePolyfills({
      include: ['buffer', 'util', 'stream', 'fs', 'crypto'],
      globals: {
        Buffer: true,
        process: true,
      },
    }),
  ],
}))
