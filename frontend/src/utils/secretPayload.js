// The file-metadata envelope stored in place of a chunked file's content.
//
// A chunked upload does not put the file in `encrypted_data`; it puts this
// descriptor there and ships the bytes separately as chunks. Both the secret
// creator and the multisig workflow creator built it, in two copies that
// differed only in whether hashing was conditional — and the hash is what a
// signed document's integrity check later compares against, so the two copies
// drifting apart would be found by a verification failure and nothing earlier.

import { sha256HexBytes } from './crypto';
import { CHUNK_SIZE } from './fileChunks';

const chunkCount = (file) => Math.ceil(file.size / CHUNK_SIZE);

const hashOf = async (file) => sha256HexBytes(await file.arrayBuffer());

/**
 * Build the metadata envelope for one or more files.
 *
 * Single files keep the flat legacy shape rather than a one-element `files`
 * array: it is what already exists in stored secrets, and reading it is not
 * this function's job.
 *
 * `hash` is opt-in because it costs a full read of every file, which only
 * signed documents need. `onProgress` is called once before the hashing starts,
 * since that is the part with a visible delay.
 */
export async function buildFileMetadata(files, { hash = false, onProgress } = {}) {
    const list = Array.isArray(files) ? files : [files];
    if (hash) onProgress?.(list.length === 1 ? 'Hashing File...' : 'Hashing Files...');

    if (list.length === 1) {
        const file = list[0];
        return JSON.stringify({
            file_name: file.name,
            mime_type: file.type || 'application/octet-stream',
            total_chunks: chunkCount(file),
            total_size: file.size,
            chunk_size: CHUNK_SIZE,
            file_hash: hash ? await hashOf(file) : null,
        });
    }

    // Multi-file: every file's chunks live in one index space on the secret, so
    // each descriptor carries the offset its own chunks start at.
    let chunkOffset = 0;
    const filesMeta = [];
    for (const file of list) {
        const totalChunks = chunkCount(file);
        filesMeta.push({
            file_name: file.name,
            mime_type: file.type || 'application/octet-stream',
            total_chunks: totalChunks,
            total_size: file.size,
            chunk_offset: chunkOffset,
            file_hash: hash ? await hashOf(file) : null,
        });
        chunkOffset += totalChunks;
    }

    return JSON.stringify({
        files: filesMeta,
        total_chunks: chunkOffset,
        chunk_size: CHUNK_SIZE,
    });
}
