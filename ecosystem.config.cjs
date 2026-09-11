// PM2 process definitions.
//
// The backend runs through `backend/serve.sh`, which loads the env, applies
// `alembic upgrade head` and refuses to start if that fails, then execs
// uvicorn. Going through a wrapper is the point: PM2 restarts the backend for
// reasons that never touch start_all.sh (a bare `pm2 restart` after a pull, a
// crash, max_memory_restart, `pm2 resurrect` at boot), and each of those used
// to serve new code against whatever schema it found (audit §8 item 4; commit
// 98c5f87 documented the hole instead of closing it). Migrations stay a
// deliberate deployment step, never an import-time side effect (audit M-3);
// see README "Database Migrations (Alembic)".
module.exports = {
  apps: [
    {
      name: 'kryptolog-backend',
      script: './serve.sh',
      cwd: './backend',
      // The script has its own shebang and execs uvicorn itself.
      interpreter: 'none',
      // Keep 1 unless REDIS_URL is set. Without Redis the rate limiter, WebSocket
      // registry, and presence are in-process: multiple instances multiply
      // effective rate limits and drop real-time messages held by another
      // instance (audit F-3). With REDIS_URL set, limits and WS fan-out/presence
      // are shared through Redis and scaling instances is safe.
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      // A migration that cannot apply is a permanent failure, not a transient
      // one — f6a7b8c9d0e5 aborts on a username collision and waits for an
      // operator. Without these, `autorestart` turns that into an endless
      // restart loop that buries the reason in scrollback.
      exp_backoff_restart_delay: 1000,
      max_restarts: 5
    },
    {
      name: 'kryptolog-frontend',
      script: 'npm',
      args: 'run preview -- --host 0.0.0.0 --port 5173',
      cwd: './frontend',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M'
    }
  ]
};
