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
 * The file descriptor inside `content`, or null if it is not one.
 *
 * Normalises the single-file and multi-file shapes to one list, so a caller
 * renders `files` and never branches on which of the two it received.
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
        return { multiple: true, files: parsed.items };
    }
    if (parsed.type === 'file' && parsed.content) {
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
