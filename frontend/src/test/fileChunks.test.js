// Chunked upload/download, end to end against real AES-GCM.
//
// This module had no tests at all, and the part that most needed one is the
// GLOBAL chunk index: uploadMultipleChunkedFiles binds (secret, globalIndex)
// into the AAD, and downloadFileByRange must rebuild that same index from
// `chunk_offset + i`. secretPayload.test.js checks that the metadata carries
// the right offsets, but stops there — "getting this wrong downloads another
// file's bytes, and the AAD binding then fails to decrypt them" was a comment,
// not an assertion.
//
// The store below behaves like the server: it keys chunks by (secret, index)
// and hands back whatever is stored at the index asked for, so a wrong index is
// a wrong answer rather than a missing one.
import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../services/api', () => ({ apiFetch: vi.fn() }));

import { apiFetch } from '../services/api';
import {
    CHUNK_SIZE,
    uploadChunkedFile,
    downloadChunkedFile,
    uploadMultipleChunkedFiles,
    downloadFileByRange,
} from '../utils/fileChunks';

const KEY = 'ab'.repeat(32); // 32-byte AES key, hex (a handle, still hex after L-12)
const SECRET_ID = 7;

// Deterministic bytes, distinct per file, so a mixed-up chunk is detectable
// even if it somehow decrypted.
const bytesFor = (seed, length) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = (i * 31 + seed * 101) & 0xff;
    return out;
};

const fileOf = (name, seed, length) =>
    new File([bytesFor(seed, length)], name, { type: 'application/octet-stream' });

/** A stand-in server: stores chunks by (secret, index), serves by index. */
const makeStore = () => {
    const chunks = new Map();
    const key = (secretId, index) => `${secretId}/${index}`;
    apiFetch.mockImplementation(async (url, _token, opts = {}) => {
        if (opts.method === 'POST') {
            const { secret_id, chunk_index, iv, encrypted_data } = opts.body;
            chunks.set(key(secret_id, chunk_index), { iv, encrypted_data });
            return { ok: true, json: async () => ({ status: 'ok' }) };
        }
        const m = url.match(/\/secrets\/(\d+)\/chunks\/(\d+)$/);
        const stored = chunks.get(key(Number(m[1]), Number(m[2])));
        if (!stored) return { ok: false, status: 404, text: async () => 'not found' };
        return { ok: true, json: async () => stored };
    });
    return chunks;
};

// jsdom's Blob has no arrayBuffer(), so read it the way the module itself
// reads files.
const blobBytes = (blob) =>
    new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result));
        reader.onerror = reject;
        reader.readAsArrayBuffer(blob);
    });

describe('chunked file round-trip', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('round-trips a single multi-chunk file', async () => {
        makeStore();
        const size = CHUNK_SIZE * 2 + 1234; // three chunks, last one short
        const file = fileOf('one.bin', 1, size);

        const meta = await uploadChunkedFile(file, SECRET_ID, KEY, 't', '');
        expect(meta.totalChunks).toBe(3);

        const blob = await downloadChunkedFile(SECRET_ID, KEY, 't', '', 3);
        expect(await blobBytes(blob)).toEqual(bytesFor(1, size));
    });

    it('round-trips several files through the global chunk index', async () => {
        makeStore();
        const sizes = [CHUNK_SIZE * 2, CHUNK_SIZE + 10, CHUNK_SIZE * 2 - 1];
        const files = sizes.map((size, i) => fileOf(`f${i}.bin`, i + 1, size));

        const meta = await uploadMultipleChunkedFiles(files, SECRET_ID, KEY, 't', '');
        expect(meta.total_chunks).toBe(6);
        // Offsets must be cumulative: 0, 2, 4.
        expect(meta.files.map((f) => f.chunk_offset)).toEqual([0, 2, 4]);

        for (const [i, fileMeta] of meta.files.entries()) {
            const blob = await downloadFileByRange(
                SECRET_ID, KEY, 't', '',
                fileMeta.chunk_offset, fileMeta.total_chunks, fileMeta.mime_type
            );
            expect(await blobBytes(blob)).toEqual(bytesFor(i + 1, sizes[i]));
        }
    });

    it('refuses a chunk served under the wrong index (audit M-2)', async () => {
        // The AAD binds (secret, index), so a server that swaps two chunks
        // fails the GCM tag instead of silently corrupting the reassembled
        // file. Nothing else catches this: the message signature layer covers
        // metadata, not file bytes.
        const chunks = makeStore();
        const file = fileOf('two.bin', 4, CHUNK_SIZE * 2);
        await uploadChunkedFile(file, SECRET_ID, KEY, 't', '');

        const first = chunks.get(`${SECRET_ID}/0`);
        chunks.set(`${SECRET_ID}/1`, first); // serve chunk 0 as chunk 1

        await expect(downloadChunkedFile(SECRET_ID, KEY, 't', '', 2)).rejects.toThrow();
    });

    it('refuses one file\'s chunk served in another file\'s range', async () => {
        // The case the global index exists for: with a per-file index, file B's
        // chunk 0 and file A's chunk 0 would carry the same AAD and swap
        // cleanly. This asserts they do not.
        const chunks = makeStore();
        const files = [fileOf('a.bin', 5, CHUNK_SIZE * 2), fileOf('b.bin', 6, CHUNK_SIZE * 2)];
        const meta = await uploadMultipleChunkedFiles(files, SECRET_ID, KEY, 't', '');

        const [a, b] = meta.files;
        expect(b.chunk_offset).toBe(2);
        chunks.set(`${SECRET_ID}/${a.chunk_offset}`, chunks.get(`${SECRET_ID}/${b.chunk_offset}`));

        await expect(
            downloadFileByRange(SECRET_ID, KEY, 't', '', a.chunk_offset, a.total_chunks, a.mime_type)
        ).rejects.toThrow();
    });

    it('fails the download rather than returning a short file when a chunk is missing', async () => {
        const chunks = makeStore();
        await uploadChunkedFile(fileOf('three.bin', 7, CHUNK_SIZE * 2), SECRET_ID, KEY, 't', '');
        chunks.delete(`${SECRET_ID}/1`);

        await expect(downloadChunkedFile(SECRET_ID, KEY, 't', '', 2)).rejects.toThrow(/failed/i);
    });
});
