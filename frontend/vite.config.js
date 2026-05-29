import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'


// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const allowedHosts = env.ALLOWED_HOSTS ? env.ALLOWED_HOSTS.split(',') : []

  return {
    plugins: [
      react(),
      nodePolyfills(),
    ],
    server: {
      allowedHosts: allowedHosts,
      // SPA fallback: serve index.html for all routes (React Router handles client-side routing)
      historyApiFallback: true,
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: './src/test/setup.js',
      // ethers -> node-stdlib-browser does a bare `import 'punycode'` directory
      // import that Node's native ESM loader rejects when the dep is externalized.
      // Inline it so Vite transforms it, and alias punycode to its concrete file.
      alias: {
        punycode: 'punycode/punycode.js',
      },
      server: {
        deps: {
          inline: ['node-stdlib-browser'],
        },
      },
    }
  }
})
