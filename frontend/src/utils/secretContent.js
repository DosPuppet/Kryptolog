// Reading a decrypted secret back out.
//
// What comes out of decryption is a string, but it may be one of several
// shapes: plain text, a signed-document wrapper, or a file descriptor whose
// blob URLs were injected after the chunks were downloaded. Working out which
// is a data question, kept here so the component that renders it does not have
// to nest two JSON.parse attempts inside its render.

/**
 * Unwrap a signed document, if that is what this is.
 *
 * Returns { content, isSignedDoc, signedPayload }. `content` is what to display:
 * for a signed document that is the inner content, and for a signed document
 * carrying files it is re-encoded into the same file descriptor a plain file
 * secret uses, so the renderer has one shape to handle rather than two.
 *
 * Anything unparseable is passed through untouched. A secret that is simply not
 * JSON is the common case, not an error.
 */
export function unwrapSignedDocument(decryptedContent) {
    const plain = { content: decryptedContent, isSignedDoc: false, signedPayload: null };
    if (!decryptedContent) return plain;

    let parsed;
    try {
        parsed = JSON.parse(decryptedContent);
    } catch {
        return plain;
    }
    if (!parsed || !parsed.signature || !parsed.signerPublicKey || !parsed.content) {
        return plain;
    }

    // Blob URLs injected by useSecrets once the chunks came down. Multi-file
    // documents carry `fileUrls` already shaped as descriptors; single files
    // carry `fileUrl` plus the metadata to build one.
    let content = parsed.content;
    if (Array.isArray(parsed.fileUrls)) {
        content = JSON.stringify({ type: 'files', items: parsed.fileUrls });
    } else if (parsed.fileUrl && parsed.fileMeta) {
        content = JSON.stringify({
            type: 'file',
            name: parsed.fileMeta.file_name,
            mime: parsed.fileMeta.mime_type,
            content: parsed.fileUrl,
            size: parsed.fileMeta.total_size,
        });
    }

    return { content, isSignedDoc: true, signedPayload: parsed };
}

/**
 * Is this a blob: URL this page created (URL.createObjectURL)?
 *
 * The only URL a file descriptor may carry (audit 2026-10-12 K-15). Descriptors
 * are built by useSecrets AFTER the chunks are downloaded and decrypted, and
 * every URL in them is a blob of this origin. But the descriptor is recognised
 * by its SHAPE, and a secret is plaintext someone else chose: share a text
 * secret reading {"type":"file","content":"https://evil.example/invoice.exe"}
 * and the trusted interface drew a Download button to it. A blob URL names the
 * origin that minted it, so this page's prefix is something nobody else's
 * plaintext can produce a working link with.
 */
export function isLocalBlobUrl(url) {
    return typeof url === 'string' && url.startsWith(`blob:${window.location.origin}/`);
}

/**
 * The file descriptor inside `content`, or null if it is not one.
 *
 * Normalises the single-file and multi-file shapes to one list, so a caller
 * renders `files` and never branches on which of the two it received.
 *
 * A descriptor whose files are not all local blob URLs is NOT one: it renders
 * as the text it is (see isLocalBlobUrl).
 */
export function readFileDescriptor(content) {
    if (!content) return null;

    let parsed;
    try {
        parsed = JSON.parse(content);
    } catch {
        return null;
    }
    if (!parsed) return null;

    if (parsed.type === 'files' && Array.isArray(parsed.items)) {
        if (!parsed.items.every((f) => isLocalBlobUrl(f?.content))) return null;
        return { multiple: true, files: parsed.items };
    }
    if (parsed.type === 'file' && isLocalBlobUrl(parsed.content)) {
        return {
            multiple: false,
            files: [{
                name: parsed.name,
                mime: parsed.mime,
                content: parsed.content,
                size: parsed.size,
            }],
        };
    }
    return null;
}
