module.exports = {
  apps: [
    {
      name: 'kryptolog-backend',
      script: 'uvicorn',
      args: 'main:app --host 0.0.0.0 --port 8000 --h11-max-incomplete-event-size 65536',
      cwd: './backend',
      interpreter: 'python3',
      // MUST stay 1 (and uvicorn must run without --workers). The rate limiter,
      // WebSocket connection registry, and presence state are in-process; running
      // multiple instances multiplies effective rate limits and drops real-time
      // messages delivered by another instance. See audit F-3 — adding instances
      // requires Redis-backed limits + a shared WebSocket fan-out first.
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M'
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
