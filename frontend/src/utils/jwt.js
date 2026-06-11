// Client-side JWT helpers. These DECODE only (no signature verification) — used
// to read claims like `exp` so the UI can proactively log out an expired session
// instead of leaving the user in a broken, half-authenticated state (every API
// call 401s) after the app has been backgrounded past the token's lifetime.

export const decodeJwtPayload = (token) => {
    try {
        const part = token.split('.')[1];
        const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
        return JSON.parse(atob(padded));
    } catch {
        return null;
    }
};

// True if the token's `exp` (seconds since epoch) is in the past. `skewMs` logs
// out slightly early to avoid a window where requests fail before we react.
// If `exp` can't be read we return false (don't force a logout on a token we
// simply can't parse — a real 401 would still surface the problem).
export const isTokenExpired = (token, skewMs = 5000) => {
    const payload = decodeJwtPayload(token);
    if (!payload || typeof payload.exp !== 'number') return false;
    return Date.now() >= payload.exp * 1000 - skewMs;
};
