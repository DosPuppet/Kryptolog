/**
 * Walking a paged list endpoint to the end (audit O-3).
 *
 * `GET /secrets`, `/secrets/shared-with-me`, `/secrets/{id}/access`,
 * `/multisig/workflows` and `GET /groups` now return at most one page instead
 * of everything the account holds. A caller that reads only the first response
 * would silently hide a user's own secrets past row 50 — worse than the
 * unbounded response the cap replaced, because nothing looks wrong. So every
 * view that needs the whole set asks for the next page until one comes back
 * short.
 *
 * Short page = last page: the server never returns fewer rows than asked for
 * while more remain, so `rows.length < limit` is the end of the list.
 */

/** Must not exceed the smallest server-side ceiling (100 on the secret lists). */
export const PAGE_SIZE = 100;

/** Runaway guard, far past any plausible account. Only reachable if the server
 *  stops shortening its last page, i.e. if the contract above broke. */
const MAX_PAGES = 500;

/** Append `limit`/`offset` to a URL that may already carry a query string. */
export function pageUrl(url, { limit, offset }) {
    return `${url}${url.includes('?') ? '&' : '?'}limit=${limit}&offset=${offset}`;
}

/**
 * @param {(page: {limit: number, offset: number}) => Promise<Array>} fetchPage
 * @returns {Promise<Array>} every row, in server order
 */
export async function fetchAllPages(fetchPage, { pageSize = PAGE_SIZE } = {}) {
    const all = [];
    for (let page = 0; page < MAX_PAGES; page++) {
        const rows = await fetchPage({ limit: pageSize, offset: page * pageSize });
        if (!Array.isArray(rows)) break;
        all.push(...rows);
        if (rows.length < pageSize) return all;
    }
    console.warn(`Stopped paging at ${all.length} rows: the list never ended.`);
    return all;
}
