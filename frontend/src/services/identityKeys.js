import API_ENDPOINTS from '../config';
import { apiFetch } from './api';
import { isAddressOf } from '../utils/crypto';

// The identity public key an address names — what every signature by that
// identity is verified against (crypto-core 3.3.0, audit 2026-10-12 K-10).
//
// Until 4.0.0 the key IS the address, and verifiers were handed the address.
// 4.0.0 makes the address a hash of the key, so a reader needs the key itself,
// and it comes from the server: embedded in the user records responses already
// carry, or from GET /users/{address} when a frame carried only the address.
//
// The server's word is never enough. A key is used — and cached — only if it
// hashes to the address it is served for (`isAddressOf`), so a server that
// served another key under someone's address gets every signature checked
// against it refused, not accepted.
//
// Cached for the whole page, across logins: an address names one key forever,
// which is what makes caching a checked key safe. Lookups in flight are
// shared, because a page of history from one sender would otherwise be one
// request per message against a route limited to 30 a minute. A failure is
// not cached, so the next verification asks again.
const cache = new Map();
const inFlight = new Map();

const bound = (address, key) => (isAddressOf(address, key) ? key : null);

/**
 * The checked identity key of `address`, or null when it cannot be had.
 * `hint` is any user record in hand (a message's `sender`, a member's `user`):
 * its embedded `identity_public_key` is taken first, if it checks out.
 */
export const identityKeyFor = async (address, { hint = null, token = null } = {}) => {
    const addr = String(address || '').toLowerCase();
    if (!addr) return null;
    if (cache.has(addr)) return cache.get(addr);

    const embedded = bound(addr, hint?.identity_public_key);
    if (embedded) {
        cache.set(addr, embedded);
        return embedded;
    }

    if (!inFlight.has(addr)) {
        const pending = apiFetch(API_ENDPOINTS.USERS.GET(addr), token)
            .then((user) => {
                const key = bound(addr, user?.identity_public_key);
                if (key) cache.set(addr, key);
                return key;
            })
            .catch(() => null)
            .finally(() => inFlight.delete(addr));
        inFlight.set(addr, pending);
    }
    return inFlight.get(addr);
};

/** Tests only: forget everything. */
export const _resetIdentityKeys = () => {
    cache.clear();
    inFlight.clear();
};
