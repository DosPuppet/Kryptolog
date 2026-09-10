/**
 * Walking paged list endpoints (audit O-3).
 *
 * The server now caps its list endpoints. The failure mode this guards against
 * is not an error but a silence: a client that reads one response and stops
 * shows the user 50 of their 130 secrets, with nothing on screen to say so.
 */
import { describe, it, expect, vi } from 'vitest';
import { fetchAllPages, pageUrl, PAGE_SIZE } from '../utils/paging';

/** A server holding `total` rows that never returns more than one page. */
function pagedServer(total, pageSize = PAGE_SIZE) {
    const rows = Array.from({ length: total }, (_, i) => ({ id: i }));
    return vi.fn(async ({ limit, offset }) => {
        expect(limit).toBe(pageSize);
        return rows.slice(offset, offset + limit);
    });
}

describe('fetchAllPages', () => {
    it('returns every row when the list spans several pages', async () => {
        const server = pagedServer(PAGE_SIZE * 2 + 7);
        const all = await fetchAllPages(server);

        expect(all).toHaveLength(PAGE_SIZE * 2 + 7);
        expect(all.map(r => r.id)).toEqual([...Array(PAGE_SIZE * 2 + 7).keys()]);
        // Three requests: two full pages, then a short one that ends the walk.
        expect(server).toHaveBeenCalledTimes(3);
    });

    it('stops on the first short page instead of asking for one more', async () => {
        const server = pagedServer(3);
        expect(await fetchAllPages(server)).toHaveLength(3);
        expect(server).toHaveBeenCalledTimes(1);
    });

    it('asks once for an empty list', async () => {
        const server = pagedServer(0);
        expect(await fetchAllPages(server)).toEqual([]);
        expect(server).toHaveBeenCalledTimes(1);
    });

    it('reads exactly the page boundary without an extra request per page', async () => {
        // A total that is an exact multiple needs one extra (empty) request to
        // learn it has ended — but only one.
        const server = pagedServer(PAGE_SIZE * 2);
        expect(await fetchAllPages(server)).toHaveLength(PAGE_SIZE * 2);
        expect(server).toHaveBeenCalledTimes(3);
    });

    it('lets a failing page reject rather than silently truncating', async () => {
        const server = vi.fn(async ({ offset }) => {
            if (offset > 0) throw new Error('Request failed: 500');
            return Array.from({ length: PAGE_SIZE }, (_, i) => ({ id: i }));
        });
        // A half-read list must not look like a complete one: the caller's
        // catch block decides what to show, and it can only do that if the
        // error reaches it.
        await expect(fetchAllPages(server)).rejects.toThrow('Request failed: 500');
    });

    it('gives up rather than looping if the list never ends', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const endless = vi.fn(async ({ limit }) =>
            Array.from({ length: limit }, (_, i) => ({ id: i })));

        const all = await fetchAllPages(endless);

        expect(all.length).toBeGreaterThan(0);
        expect(warn).toHaveBeenCalled();
        warn.mockRestore();
    });
});

describe('pageUrl', () => {
    it('starts a query string', () => {
        expect(pageUrl('http://api/secrets', { limit: 100, offset: 0 }))
            .toBe('http://api/secrets?limit=100&offset=0');
    });

    it('appends to one that already exists', () => {
        expect(pageUrl('http://api/users?search=al', { limit: 50, offset: 50 }))
            .toBe('http://api/users?search=al&limit=50&offset=50');
    });
});
