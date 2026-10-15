// PM2 for a deployment: the backend alone.
//
// ecosystem.config.cjs is the local stack, and also starts `vite preview` —
// which production must not run (DEPLOYMENT.md): it sends no security headers,
// so at best it is unused, at worst a second, header-less copy of the SPA
// exposed by mistake. The SPA is served from the reverse proxy instead
// (scripts/deploy_frontend.sh). The backend's definition is taken from the
// dev file rather than copied, so the two cannot drift.
const { apps } = require('./ecosystem.config.cjs');

module.exports = {
  apps: apps.filter((app) => app.name === 'kryptolog-backend'),
};
