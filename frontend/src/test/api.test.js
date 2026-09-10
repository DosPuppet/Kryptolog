/**
 * The authenticated fetch helper.
 *
 * This had no tests, which is how a double-encoded body reached the running
 * app: every messenger write posted a JSON string instead of an object and the
 * server answered 422. The body contract is pinned here first.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { apiFetch, authHeaders } from '../services/api';

const jsonResponse = (data, { ok = true, status = 200 } = {}) => ({
    ok,
    status,
    json: async () => data,
});

beforeEach(() => { global.fetch = vi.fn(); });
afterEach(() => { vi.restoreAllMocks(); });

const lastCall = () => global.fetch.mock.calls.at(-1);

describe('the body contract', () => {
    it('encodes an object exactly once', async () => {
        global.fetch.mockResolvedValue(jsonResponse({ ok: 1 }));
        await apiFetch('/x', 'tok', { method: 'POST', body: { a: 1, b: 'two' } });

        const [, init] = lastCall();
        // Not '"{\\"a\\":1}"' — the server must receive an object.
        expect(init.body).toBe('{"a":1,"b":"two"}');
        expect(JSON.parse(init.body)).toEqual({ a: 1, b: 'two' });
    });

    it('refuses a pre-stringified body instead of encoding it twice', async () => {
        await expect(
            apiFetch('/x', 'tok', { method: 'POST', body: JSON.stringify({ a: 1 }) })
        ).rejects.toThrow(/pass the object/i);
        expect(global.fetch).not.toHaveBeenCalled();
    });

    it('keeps a nested string field as a string', async () => {
        // Message content is an encrypted envelope serialized on the wire, so
        // the inner stringify is correct and must survive.
        global.fetch.mockResolvedValue(jsonResponse({}));
        await apiFetch('/x', 'tok', {
            method: 'POST',
            body: { content: JSON.stringify({ v: 2 }) },
        });
        expect(JSON.parse(lastCall()[1].body)).toEqual({ content: '{"v":2}' });
    });

    it('sends no body and no content type on a plain GET', async () => {
        global.fetch.mockResolvedValue(jsonResponse([]));
        await apiFetch('/x', 'tok');
        const [, init] = lastCall();
        expect(init.body).toBeUndefined();
        expect(init.headers['Content-Type']).toBeUndefined();
        expect(init.method).toBe('GET');
    });
});

describe('headers', () => {
    it('carries the bearer token', () => {
        expect(authHeaders('tok')).toEqual({ Authorization: 'Bearer tok' });
    });

    it('lets a caller add headers without losing the token', async () => {
        global.fetch.mockResolvedValue(jsonResponse({}));
        await apiFetch('/x', 'tok', { headers: { 'X-Trace': 'abc' } });
        const [, init] = lastCall();
        expect(init.headers.Authorization).toBe('Bearer tok');
        expect(init.headers['X-Trace']).toBe('abc');
    });
});

describe('responses', () => {
    it('throws the server detail, which is the text worth showing a user', async () => {
        global.fetch.mockResolvedValue(
            jsonResponse({ detail: 'Recipient not found' }, { ok: false, status: 404 })
        );
        await expect(apiFetch('/x', 'tok')).rejects.toThrow('Recipient not found');
    });

    it('renders a 422 validation detail instead of "[object Object]"', async () => {
        // The real shape FastAPI returns, and the one that left two bugs on
        // this branch showing a status code with no reason.
        global.fetch.mockResolvedValue(
            jsonResponse(
                {
                    detail: [
                        {
                            type: 'string_too_long',
                            loc: ['body', 'name'],
                            msg: 'String should have at most 2000 characters',
                            input: 'encg1:' + 'x'.repeat(100000),
                        },
                    ],
                },
                { ok: false, status: 422 }
            )
        );
        const err = await apiFetch('/groups', 'tok', { method: 'POST', body: {} }).catch((e) => e);
        expect(err.message).toBe('name: String should have at most 2000 characters');
        // The rejected value is not dragged into the message.
        expect(err.message).not.toContain('encg1:');
    });

    it('joins several validation failures rather than showing only one', async () => {
        global.fetch.mockResolvedValue(
            jsonResponse(
                {
                    detail: [
                        { loc: ['body', 'name'], msg: 'Field required' },
                        { loc: ['body', 'member_addresses'], msg: 'Field required' },
                    ],
                },
                { ok: false, status: 422 }
            )
        );
        await expect(apiFetch('/groups', 'tok', { method: 'POST', body: {} })).rejects.toThrow(
            'name: Field required; member_addresses: Field required'
        );
    });

    it('falls back to the status when there is no detail', async () => {
        global.fetch.mockResolvedValue({
            ok: false, status: 500, json: async () => { throw new Error('not json'); },
        });
        await expect(apiFetch('/x', 'tok')).rejects.toThrow(/500/);
    });

    it('treats an empty 204 as success, not a parse failure', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 204, json: async () => {
            throw new Error('no body');
        } });
        await expect(apiFetch('/x', 'tok', { method: 'DELETE' })).resolves.toBeNull();
    });

    it('hands back the Response untouched when raw is set', async () => {
        // The delete, share and revoke paths branch on res.ok themselves.
        const res = jsonResponse({}, { ok: false, status: 409 });
        global.fetch.mockResolvedValue(res);
        await expect(apiFetch('/x', 'tok', { raw: true })).resolves.toBe(res);
    });
});
