import { describe, it, expect } from 'vitest';
import { buildFileMetadata } from '../utils/secretPayload';
import { CHUNK_SIZE } from '../utils/fileChunks';

// A File stand-in: only name, type, size and arrayBuffer() are read.
const fakeFile = (name, size, type = 'text/plain', byte = 0x41) => ({
    name,
    size,
    type,
    arrayBuffer: async () => new Uint8Array(size).fill(byte).buffer,
});

describe('buildFileMetadata', () => {
    it('keeps the flat legacy shape for a single file', async () => {
        const meta = JSON.parse(await buildFileMetadata(fakeFile('a.txt', CHUNK_SIZE * 2)));
        expect(meta.files).toBeUndefined();
        expect(meta).toMatchObject({
            file_name: 'a.txt',
            mime_type: 'text/plain',
            total_chunks: 2,
            total_size: CHUNK_SIZE * 2,
            chunk_size: CHUNK_SIZE,
            file_hash: null,
        });
    });

    it('accepts a bare file or a one-element array identically', async () => {
        const file = fakeFile('a.txt', 10);
        expect(await buildFileMetadata(file)).toBe(await buildFileMetadata([file]));
    });

    it('lays multi-file chunks out in one index space', async () => {
        // Every file's chunks share the secret's index space, so each offset
        // must be the running total. Getting this wrong downloads another
        // file's bytes, and the AAD binding then fails to decrypt them.
        const meta = JSON.parse(await buildFileMetadata([
            fakeFile('a.txt', CHUNK_SIZE * 2),
            fakeFile('b.txt', CHUNK_SIZE),
            fakeFile('c.txt', CHUNK_SIZE * 3),
        ]));
        expect(meta.files.map(f => f.chunk_offset)).toEqual([0, 2, 3]);
        expect(meta.files.map(f => f.total_chunks)).toEqual([2, 1, 3]);
        expect(meta.total_chunks).toBe(6);
    });

    it('rounds a partial chunk up', async () => {
        const meta = JSON.parse(await buildFileMetadata(fakeFile('a.txt', CHUNK_SIZE + 1)));
        expect(meta.total_chunks).toBe(2);
    });

    it('hashes only when asked, and hashes contents not names', async () => {
        const plain = JSON.parse(await buildFileMetadata(fakeFile('a.txt', 8)));
        expect(plain.file_hash).toBeNull();

        const hashed = JSON.parse(await buildFileMetadata(fakeFile('a.txt', 8), { hash: true }));
        expect(hashed.file_hash).toMatch(/^[0-9a-f]{64}$/);

        // Same bytes under a different name must hash the same.
        const renamed = JSON.parse(await buildFileMetadata(fakeFile('b.txt', 8), { hash: true }));
        expect(renamed.file_hash).toBe(hashed.file_hash);

        // Different bytes must not.
        const other = JSON.parse(
            await buildFileMetadata(fakeFile('a.txt', 8, 'text/plain', 0x42), { hash: true })
        );
        expect(other.file_hash).not.toBe(hashed.file_hash);
    });

    it('defaults a missing mime type rather than emitting an empty one', async () => {
        const meta = JSON.parse(await buildFileMetadata(fakeFile('a.bin', 4, '')));
        expect(meta.mime_type).toBe('application/octet-stream');
    });

    it('announces hashing once, and not at all when it is skipped', async () => {
        const seen = [];
        await buildFileMetadata([fakeFile('a', 4), fakeFile('b', 4)],
            { hash: true, onProgress: (m) => seen.push(m) });
        expect(seen).toEqual(['Hashing Files...']);

        const quiet = [];
        await buildFileMetadata(fakeFile('a', 4), { onProgress: (m) => quiet.push(m) });
        expect(quiet).toEqual([]);
    });
});
