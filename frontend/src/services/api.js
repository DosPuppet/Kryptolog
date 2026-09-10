// Authenticated fetch, in one place.
//
// The Authorization header was written out by hand at thirty-five call sites
// across eighteen files, alongside three different conventions for what a
// failed request does: throw the server's `detail`, throw the status code, or
// return false. A caller could not tell which one it was getting without
// reading the callee.
//
// `apiFetch` picks the first of those: it throws an Error carrying the server's
// `detail` when there is one. Callers that genuinely need the Response — to
// branch on a status, or to read a non-JSON body — pass `raw: true` and get it
// untouched.

// FastAPI answers a validation failure with `detail` as a LIST of
// {type, loc, msg, input} objects rather than a string, and handing that to
// Error() renders the useless "[object Object]" — which is exactly how two
// separate 422s on this branch looked from the browser: a status code and no
// reason. Name the offending field and quote the server's own message.
//
// `input` is deliberately dropped: it echoes the whole rejected value, which
// for an encrypted group name is a quarter of a megabyte of ciphertext.
const describeDetail = (detail) => {
    if (typeof detail === 'string') return detail;
    if (!Array.isArray(detail)) return null;
    return detail
        .map((d) => {
            const msg = d?.msg || 'invalid value';
            const field = Array.isArray(d?.loc)
                ? d.loc.filter((part) => part !== 'body').join('.')
                : '';
            return field ? `${field}: ${msg}` : msg;
        })
        .filter(Boolean)
        .join('; ');
};

/** Authorization header for `token`, merged with any extras. */
export const authHeaders = (token, extra) => ({
    Authorization: `Bearer ${token}`,
    ...extra,
});

/**
 * Fetch `url` with the caller's bearer token.
 *
 * Sends and parses JSON by default. `body` is stringified for you, so pass the
 * OBJECT — a string body is refused rather than encoded twice. On a non-2xx the
 * thrown Error's message is the server's `detail`, because that is the text
 * worth showing a user.
 *
 * opts: { method?, body?, headers?, raw?, signal? }
 */
export async function apiFetch(url, token, opts = {}) {
    const { method = 'GET', body, headers, raw = false, signal } = opts;

    // A pre-stringified body would be encoded twice and reach the server as a
    // JSON string rather than an object, which every endpoint rejects as a 422.
    // That is silent at the call site and obvious only in the network tab, so
    // it fails here instead, naming the fix.
    if (typeof body === 'string') {
        throw new TypeError(
            'apiFetch encodes the body for you — pass the object, not JSON.stringify(...)'
        );
    }

    const res = await fetch(url, {
        method,
        signal,
        headers: authHeaders(token, {
            ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
            ...headers,
        }),
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

    if (raw) return res;

    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(describeDetail(err.detail) || `Request failed: ${res.status}`);
    }

    // 204 and other empty bodies are a success, not a parse error.
    if (res.status === 204) return null;
    return res.json().catch(() => null);
}

export default apiFetch;
