module.exports = {
  apps: [
    {
      name: 'safelog-backend',
      script: 'uvicorn',
      args: 'main:app --host 0.0.0.0 --port 8000 --h11-max-incomplete-event-size 65536',
      cwd: './backend',
      interpreter: 'python3',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M'
    },
    {
      name: 'safelog-frontend',
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
