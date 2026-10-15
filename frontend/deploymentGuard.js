// What a production bundle must not ship with, checked when it is built.
//
// Vite bakes VITE_* values in at build time and treats a missing one as an
// empty string, so a bundle without VITE_API_BASE_URL builds cleanly and calls
// http://localhost:8000 — from every user's browser, to their own machine —
// and one without VITE_VAPID_PUBLIC_KEY fails only when a user turns push on.
// A real install shipped both (2026-10-15) with nothing said at build time.
//
// Strict mode (KRYPTOLOG_STRICT_BUILD=1, which scripts/deploy_frontend.sh sets)
// refuses the build, in the spirit of KRYPTOLOG_ENV=production on the backend.
// Every other build only warns: CI, start_all.sh's local preview and the
// tests build for localhost on purpose.

const LOOPBACK_HOSTS = /^(localhost|127(\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)$/i

// An uncompressed P-256 point is 65 bytes, 0x04 first: 87 base64url
// characters, the first of which is then always 'B'.
const VAPID_PUBLIC_KEY = /^B[A-Za-z0-9_-]{86}$/

export function deploymentProblems(env) {
  const problems = []
  const api = env.VITE_API_BASE_URL
  if (!api) {
    problems.push({
      fatal: true,
      message: 'VITE_API_BASE_URL is unset: the bundle would call http://localhost:8000, which only answers on the machine running the browser.',
    })
  } else {
    let url = null
    try {
      url = new URL(api)
    } catch {
      problems.push({ fatal: true, message: `VITE_API_BASE_URL is not a URL: ${api}` })
    }
    if (url && (LOOPBACK_HOSTS.test(url.hostname) || url.hostname.endsWith('.localhost'))) {
      problems.push({
        fatal: true,
        message: `VITE_API_BASE_URL is ${api}: a loopback address only answers on the machine running the browser.`,
      })
    } else if (url && url.protocol !== 'https:') {
      problems.push({
        fatal: true,
        message: `VITE_API_BASE_URL is ${api}: the SPA holds keys, and plain http lets anyone on the path rewrite what it loads.`,
      })
    }
  }

  const vapid = env.VITE_VAPID_PUBLIC_KEY
  if (!vapid) {
    // Push is optional, so this one never fails a build on its own.
    problems.push({ fatal: false, message: 'VITE_VAPID_PUBLIC_KEY is empty: push notifications are off in this bundle.' })
  } else if (!VAPID_PUBLIC_KEY.test(vapid)) {
    problems.push({
      fatal: true,
      message: 'VITE_VAPID_PUBLIC_KEY is not a base64url uncompressed P-256 key (87 characters, starting with B); browsers would refuse to subscribe.',
    })
  }
  return problems
}

export function deploymentGuard(env) {
  return {
    name: 'kryptolog-deployment-guard',
    apply: 'build',
    buildStart() {
      const problems = deploymentProblems(env)
      if (problems.length === 0) return
      const strict = env.KRYPTOLOG_STRICT_BUILD === '1'
      const lines = problems.map((p) => `  - ${p.message}`).join('\n')
      if (strict && problems.some((p) => p.fatal)) {
        this.error(`This bundle is not deployable:\n${lines}`)
      }
      const banner = '='.repeat(72)
      console.warn(`\n${banner}\nNOT A DEPLOYABLE BUNDLE as configured:\n${lines}\n` +
        `Deploy with scripts/deploy_frontend.sh, which refuses these.\n${banner}\n`)
    },
  }
}
