# End-to-end tests

The real SPA, the real backend and the real TrustKeys extension, loaded unpacked
into Chromium. Two people: Alice keeps her keys in TrustKeys, Bob in a local
vault. They sign in, find each other in the directory, exchange messages both
ways, and Alice shares a secret Bob opens. Every TrustKeys approval window is
clicked through, and what it said is asserted on.

```bash
docker compose --env-file ../backend/.env up -d postgres redis   # the dev stack's services
npm ci && npx playwright install chromium                         # once
npm test        # builds the extension (build:dev), starts both servers, runs
```

`serve-backend.sh` starts the backend on port 8002 against its own database,
`kryptolog_e2e`, dropped and recreated on every run, and Redis database 7,
flushed on every run — never the dev data. The SPA runs on Vite at
`http://localhost:5174`.

Screenshots of each step land in `test-results/shots/`; a failure keeps a trace
(`npx playwright show-trace test-results/…/trace.zip`). CI runs the same suite
(`.github/workflows/ci.yml`, job `e2e`).

Two things the first runs found, worth knowing before editing this:

- **Approval windows failed to open** whenever Chrome refused their computed
  position — fixed in the extension (`openTrackedWindow` retries unpositioned).
- **Back-to-back runs tripped the login rate limit** through Redis counters
  left from the previous run, which is why database 7 is flushed at start.
- **On this WSL2 dev box, a run sometimes waits ~2 min 13 s before starting
  each server** — before Playwright's first readiness probe returns, which is
  the Linux TCP SYN-retry timeout, not anything Kryptolog does. Intermittent
  (most runs start in seconds); cause not established — WSL2's localhost relay
  is the suspect. The suite itself takes about 10 s.

