import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { crx } from '@crxjs/vite-plugin'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import manifest from './manifest.json'
import { viteStaticCopy } from 'vite-plugin-static-copy'

// https://vite.dev/config/
export default defineConfig({
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
    viteStaticCopy({
      targets: [
        {
          src: 'node_modules/dilithium-crystals-js/dilithium.wasm',
          dest: ''
        }
      ]
    }),
  ],
})
