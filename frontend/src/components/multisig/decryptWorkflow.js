import API_ENDPOINTS from '../../config';
import { verifySignaturePQC, domainSeparate, SIGNING_CONTEXT, decryptSymmetric } from '../../utils/crypto';
import { downloadChunkedFile, downloadFileByRange } from '../../utils/fileChunks';

// Envelope model: the workflow's secret is AES-encrypted under a fileKey, and
// the fileKey is ML-KEM-wrapped separately for the owner, each signer, and
// (once completed) each recipient. Viewing = unwrap MY copy of the fileKey,
// then decrypt the content with it.

// Locate MY wrapped fileKey on the workflow based on role.
const resolveMyEncryptedKey = ({ workflow, user, isOwner, isSigner, isRecipient }) => {
    if (isOwner) {
        // Check top-level owner key first (robust fix)
        if (workflow.owner_encrypted_key) {
            return workflow.owner_encrypted_key;
        }
        // Fallback to nested if top-level missing (legacy support)
        if (workflow.secret && workflow.secret.encrypted_key) {
            return workflow.secret.encrypted_key;
        }
    } else if (isSigner) {
        const s = workflow.signers.find(s => s.user_address === user.address);
        if (s) return s.encrypted_key;
    } else if (isRecipient && workflow.status === 'completed') {
        const r = workflow.recipients.find(r => r.user_address === user.address);
        if (r) return r.encrypted_key;
    }
    return null;
};

// Unwrap my fileKey and decrypt the secret's content blob.
// Returns { contentString, fileKey }; throws with a user-facing message.
export const decryptWorkflowSecret = async ({ workflow, user, isOwner, isSigner, isRecipient, decryptPQC, onProgress }) => {
    if (workflow.secret_id === undefined) {
        console.error("Workflow object missing secret_id", workflow);
        throw new Error("Invalid workflow data: missing secret ID");
    }

    const myEncryptedKey = resolveMyEncryptedKey({ workflow, user, isOwner, isSigner, isRecipient });
    if (!myEncryptedKey) throw new Error("Acccess Denied: No key found for your user.");

    const encryptedContentBlob = workflow.secret?.encrypted_data;
    if (!encryptedContentBlob) throw new Error("Secret content not found in workflow.");

    onProgress(40, "Decrypting Key...");

    // Decrypt the wrapped AES file key (ML-KEM envelope).
    const fileKey = await decryptPQC(JSON.parse(myEncryptedKey));

    onProgress(60, "Decrypting Content...");

    const encDataObj = JSON.parse(encryptedContentBlob);
    const contentString = await decryptSymmetric(encDataObj, fileKey);

    return { contentString, fileKey };
};

// Interpret a decrypted content string: verify the creator's embedded signature
// (H1 — signed over the `content`-domain-separated bytes), and resolve chunked
// single-/multi-file payloads by downloading + decrypting their chunks.
// Returns the state the modal should display:
// { verificationStatus, creatorSignature, creatorSignedContent, rawDecryptedContent, decryptedContent }
export const interpretDecryptedContent = async ({ contentString, fileKey, workflow, token, onProgress }) => {
    let parsed;
    try { parsed = JSON.parse(contentString); } catch { /* best-effort: failure is non-fatal */ }

    if (!(parsed && parsed.signature && parsed.signerPublicKey)) {
        return {
            verificationStatus: 'unsigned',
            creatorSignature: null,
            creatorSignedContent: null,
            rawDecryptedContent: contentString,
            decryptedContent: parsed || contentString,
        };
    }

    // Signed Document Wrapper. The creator signed the `content`-domain-
    // separated bytes, not the raw content (H1) — verify against those.
    const signedBody = domainSeparate(SIGNING_CONTEXT.CONTENT, parsed.content);
    const isValid = await verifySignaturePQC(signedBody, parsed.signature, parsed.signerPublicKey);

    const result = {
        verificationStatus: isValid ? 'verified' : 'failed',
        creatorSignature: parsed.signature,
        creatorSignedContent: parsed.content,
        rawDecryptedContent: contentString,
        decryptedContent: null,
    };

    try {
        const inner = JSON.parse(parsed.content);

        // Check if the inner content is actually a chunked file payload
        if (inner.files && Array.isArray(inner.files)) {
            // Multi-file metadata
            try {
                onProgress(70, "Downloading files...");
                const fileResults = [];
                for (let fi = 0; fi < inner.files.length; fi++) {
                    const fileMeta = inner.files[fi];
                    const blob = await downloadFileByRange(
                        workflow.secret_id,
                        fileKey,
                        token,
                        API_ENDPOINTS.BASE,
                        fileMeta.chunk_offset,
                        fileMeta.total_chunks,
                        fileMeta.mime_type,
                        (pct) => {
                            const overallPct = Math.round(((fi + pct / 100) / inner.files.length) * 100);
                            onProgress(70 + Math.round(overallPct * 0.25));
                        }
                    );
                    fileResults.push({
                        name: fileMeta.file_name,
                        mime: fileMeta.mime_type,
                        content: URL.createObjectURL(blob),
                        size: fileMeta.total_size
                    });
                }
                result.decryptedContent = { type: 'files', items: fileResults };
            } catch (chunkErr) {
                console.error("Failed to download multi-file chunks", chunkErr);
                result.decryptedContent = inner;
            }
        } else if (inner.total_chunks && inner.file_name) {
            try {
                onProgress(70, "Downloading file chunks...");
                const blob = await downloadChunkedFile(
                    workflow.secret_id,
                    fileKey,
                    token,
                    API_ENDPOINTS.BASE,
                    inner.total_chunks,
                    inner.mime_type,
                    (pct) => onProgress(70 + Math.round(pct * 0.25))
                );
                result.decryptedContent = {
                    type: 'file',
                    name: inner.file_name,
                    mime: inner.mime_type,
                    content: URL.createObjectURL(blob),
                    size: inner.total_size,
                    chunked: true
                };
            } catch (chunkErr) {
                console.error("Failed to download chunks", chunkErr);
                result.decryptedContent = inner;
            }
        } else {
            result.decryptedContent = inner;
        }
    } catch {
        result.decryptedContent = parsed.content;
    }

    return result;
};
