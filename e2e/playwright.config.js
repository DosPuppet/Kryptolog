// End-to-end: the real SPA, the real backend, and the real TrustKeys extension
// loaded unpacked into Chromium (audit 2026-10-12: "no test in a real browser,
// nor of the extension loaded in Chrome"). What E2E-RECIPE.md walks by hand,
// for the critical path, on every run.
//
// Needs the dev stack's Postgres and Redis running (docker compose) and the
// extension built with `npm run build:dev` in trustkeys/ — `npm test` here
// does that first. See README.md in this directory.
import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    // One stack, shared state (the directory): the specs run in order.
    workers: 1,
    fullyParallel: false,
    timeout: 180_000,
    expect: { timeout: 20_000 },
    reporter: [['list']],
    use: {
        baseURL: 'http://localhost:5174',
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
    },
    webServer: [
        {
            command: './serve-backend.sh',
            url: 'http://127.0.0.1:8002/healthz',
            timeout: 120_000,
            reuseExistingServer: false,
        },
        {
            // 127.0.0.1 explicitly: by default Vite answers on ::1 only, and
            // the readiness check waited out its whole timeout on that.
            command: 'npx vite --host 127.0.0.1 --port 5174 --strictPort',
            cwd: '../frontend',
            url: 'http://127.0.0.1:5174',
            timeout: 120_000,
            reuseExistingServer: false,
            env: { VITE_API_BASE_URL: 'http://localhost:8002' },
        },
    ],
});
