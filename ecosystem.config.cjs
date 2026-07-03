module.exports = {
  apps: [
    {
      name: 'kryptolog-backend',
      script: 'uvicorn',
      args: 'main:app --host 0.0.0.0 --port 8000 --h11-max-incomplete-event-size 65536',
      cwd: './backend',
      interpreter: 'python3',
      // Keep 1 unless REDIS_URL is set. Without Redis the rate limiter, WebSocket
      // registry, and presence are in-process: multiple instances multiply
      // effective rate limits and drop real-time messages held by another
      // instance (audit F-3). With REDIS_URL set, limits and WS fan-out/presence
      // are shared through Redis and scaling instances is safe.
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
