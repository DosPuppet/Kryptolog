import { describe, it, expect } from 'vitest';
import { unwrapSignedDocument, readFileDescriptor } from '../utils/secretContent';

describe('unwrapSignedDocument', () => {
    it('passes plain text through untouched', () => {
        // A secret that is simply not JSON is the common case, not an error.
        expect(unwrapSignedDocument('hello world')).toEqual({
            content: 'hello world', isSignedDoc: false, signedPayload: null,
        });
    });

    it('passes JSON that is not a signed document through untouched', () => {
        const json = JSON.stringify({ some: 'object' });
        expect(unwrapSignedDocument(json).isSignedDoc).toBe(false);
        expect(unwrapSignedDocument(json).content).toBe(json);
    });

    it('handles an empty or missing secret', () => {
        expect(unwrapSignedDocument('').content).toBe('');
        expect(unwrapSignedDocument(undefined).isSignedDoc).toBe(false);
    });

    it('unwraps a text document to its inner content', () => {
        const doc = { signature: 'sig', signerPublicKey: 'pk', content: 'the text' };
        const out = unwrapSignedDocument(JSON.stringify(doc));
        expect(out.isSignedDoc).toBe(true);
        expect(out.content).toBe('the text');
        expect(out.signedPayload).toMatchObject(doc);
    });

    it('re-encodes a signed single file as a plain file descriptor', () => {
        // So the renderer sees one shape whether or not the file was signed.
        const out = unwrapSignedDocument(JSON.stringify({
            signature: 'sig', signerPublicKey: 'pk', content: 'ignored',
            fileUrl: 'blob:x',
            fileMeta: { file_name: 'a.pdf', mime_type: 'application/pdf', total_size: 99 },
        }));
        expect(JSON.parse(out.content)).toEqual({
            type: 'file', name: 'a.pdf', mime: 'application/pdf', content: 'blob:x', size: 99,
        });
    });

    it('re-encodes signed multi-file documents as a file list', () => {
        const items = [{ name: 'a', mime: 'text/plain', content: 'blob:a', size: 1 }];
        const out = unwrapSignedDocument(JSON.stringify({
            signature: 'sig', signerPublicKey: 'pk', content: 'ignored', fileUrls: items,
        }));
        expect(JSON.parse(out.content)).toEqual({ type: 'files', items });
    });

    it('keeps the inner content when the blob URLs are not there yet', () => {
        // Before the chunks come down there is nothing to point an <img> at.
        const out = unwrapSignedDocument(JSON.stringify({
            signature: 'sig', signerPublicKey: 'pk', content: 'still encrypted',
        }));
        expect(out.content).toBe('still encrypted');
    });
});

// A blob URL minted by THIS page, the only kind a descriptor may carry.
const BLOB = `blob:${window.location.origin}/0f8c2d1e-0000-4000-8000-000000000000`;

describe('readFileDescriptor', () => {
    it('returns null for text, empty input and unrelated JSON', () => {
        expect(readFileDescriptor('just text')).toBeNull();
        expect(readFileDescriptor('')).toBeNull();
        expect(readFileDescriptor(JSON.stringify({ type: 'other' }))).toBeNull();
    });

    it('normalises a single file into a one-element list', () => {
        // The caller then renders `files` without branching on which shape came in.
        const out = readFileDescriptor(JSON.stringify({
            type: 'file', name: 'a.pdf', mime: 'application/pdf', content: BLOB, size: 9,
        }));
        expect(out.multiple).toBe(false);
        expect(out.files).toEqual([
            { name: 'a.pdf', mime: 'application/pdf', content: BLOB, size: 9 },
        ]);
    });

    it('reads a multi-file list and flags it as such', () => {
        const items = [{ name: 'a', content: BLOB }, { name: 'b', content: BLOB }];
        const out = readFileDescriptor(JSON.stringify({ type: 'files', items }));
        expect(out).toEqual({ multiple: true, files: items });
    });

    it('rejects a file entry with no content to point at', () => {
        expect(readFileDescriptor(JSON.stringify({ type: 'file', name: 'a' }))).toBeNull();
    });

    // Audit 2026-10-12 K-15. A descriptor is recognised by its shape, and a
    // shared secret is plaintext its sender chose, so text that LOOKS like one
    // used to draw a Download button to wherever it pointed.
    it.each([
        ['an external https link', 'https://evil.example/invoice.exe'],
        ['a javascript: URL', 'javascript:alert(1)'],
        ['a data: URL', 'data:text/html,<script>alert(1)</script>'],
        ['a blob URL of another origin', 'blob:https://evil.example/0f8c2d1e'],
        ['a lookalike prefix', `blob:${window.location.origin}.evil.example/x`],
        ['an external link that merely contains a local blob URL', `https://evil.example/?u=${BLOB}`],
    ])('renders as text, not a file, when it points at %s', (_label, url) => {
        expect(readFileDescriptor(JSON.stringify({ type: 'file', name: 'a.pdf', content: url }))).toBeNull();
        expect(readFileDescriptor(JSON.stringify({
            type: 'files', items: [{ name: 'ok', content: BLOB }, { name: 'bad', content: url }],
        }))).toBeNull();
    });
});
