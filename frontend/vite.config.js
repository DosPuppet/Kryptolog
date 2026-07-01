import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'


// https://vite.dev/config/
// Build the CSP connect-src from the configured API base so the frontend can
// reach its API/WebSocket whatever origin they live on (same-origin proxy or a
// separate api.* subdomain). Covers both the http(s) and ws(s) origins.
function cspConnectSrc(apiBase) {
  try {
    const u = new URL(apiBase)
    const wsOrigin = (u.protocol === 'https:' ? 'wss://' : 'ws://') + u.host
    return `'self' ${u.origin} ${wsOrigin}`
  } catch {
    return `'self'`
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const allowedHosts = env.ALLOWED_HOSTS ? env.ALLOWED_HOSTS.split(',') : []
  const connectSrc = cspConnectSrc(env.VITE_API_BASE_URL || 'http://localhost:8000')

  return {
    resolve: {
      preserveSymlinks: true,
    },
    plugins: [
      react(),
      {
        // Inject the computed connect-src into the index.html CSP meta tag.
        name: 'html-csp-connect-src',
        transformIndexHtml(html) {
          return html.replace('__CSP_CONNECT_SRC__', connectSrc)
        },
      },
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
    }
  }
})
