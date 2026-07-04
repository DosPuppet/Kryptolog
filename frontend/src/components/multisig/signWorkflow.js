import API_ENDPOINTS from '../../config';
import { sha256Hex, multisigApprovalMessage, decryptSymmetric } from '../../utils/crypto';
import { assertSafeRecipient } from '../../services/trustedKeys';

// The signer-side approval pipeline (M1): decrypt the secret so the signer can
// review what they're approving, then sign sha256(stored ciphertext) bound to
// this workflow — a server-verifiable approval. The creator's own signature
// over the plaintext lives inside the secret (created in MultisigCreateModal)
// and is verified separately. Returns the updated workflow from the server.
export const signMultisigWorkflow = async ({ workflow, user, token, decryptPQC, signPQC, encryptPQC, onProgress }) => {
    let encryptedKey = null;

    // 1. Try to get key from my Signer Entry
    const mySignerEntry = workflow.signers.find(s => s.user_address === user.address);
    if (mySignerEntry && mySignerEntry.encrypted_key) {
        encryptedKey = mySignerEntry.encrypted_key;
    }

    // 2. Fallback: Check SHARED/Access Grants (Legacy)
    if (!encryptedKey) {
        try {
            const res = await fetch(API_ENDPOINTS.SECRETS.SHARED_WITH, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const shared = await res.json();
            const myShare = shared.find(s => s.secret_id === workflow.secret_id);
            if (myShare) {
                encryptedKey = myShare.encrypted_key;
            }
        } catch (e) {
            console.warn("Legacy shared secret fetch failed", e);
        }
    }

    if (!encryptedKey) throw new Error("Access denied: No key found for signing");

    onProgress(30, "Decrypting content for signing...");

    // 1. Decrypt the AES file key (ML-KEM envelope).
    let fileKey;
    try {
        const decryptedKeyJson = await decryptPQC(JSON.parse(encryptedKey));
        // Tolerate a double-encoded (JSON-string) key from older payloads.
        try {
            const obj = JSON.parse(decryptedKeyJson);
            fileKey = typeof obj === 'string' ? obj : decryptedKeyJson;
        } catch {
            fileKey = decryptedKeyJson;
        }
    } catch (e) {
        console.error("Failed to decrypt AES key", e);
        throw new Error("Failed to decrypt your access key");
    }

    // 2. Fetch and Decrypt the Content
    const encryptedContentBlob = workflow.secret?.encrypted_data;
    if (!encryptedContentBlob) throw new Error("Secret content not found to sign.");

    // Decrypt as a readability guard: confirm we can actually read the
    // content we're about to approve (we don't blind-sign a ciphertext).
    const encDataObj = JSON.parse(encryptedContentBlob);
    await decryptSymmetric(encDataObj, fileKey);

    onProgress(50, "Signing...");

    // Server-verifiable approval (M1): we decrypted and reviewed the content
    // above, but we SIGN the SHA-256 of the stored ciphertext, bound to this
    // workflow + secret, under the `multisig-approval` domain (H1). The server
    // is zero-knowledge — it can't see the plaintext — but it can hash the
    // ciphertext it holds and verify this signature, so it can gate completion
    // on the actual signing key (not merely a session token). One signature,
    // no extra prompt.
    const ctHash = await sha256Hex(workflow.secret.encrypted_data);
    const approvalMessage = multisigApprovalMessage(workflow.id, workflow.secret_id, ctHash);
    const signature = await signPQC(approvalMessage);

    // Completing Signer Logic: Release Recipient Keys.
    // N-of-M: the signature that reaches the threshold completes the
    // workflow and releases the secret. That signer (whoever they are,
    // not necessarily the last in the list) re-wraps the recipient keys.
    const alreadySignedCount = workflow.signers.filter(s => s.has_signed).length;
    const quorum = workflow.threshold || workflow.signers.length;
    const isCompletingSigner = (alreadySignedCount + 1) >= quorum;

    let recipientKeys = null;
    if (isCompletingSigner && workflow.recipients && workflow.recipients.length > 0) {
        onProgress(70, "Encrypting for recipients...");
        recipientKeys = {};
        for (const r of workflow.recipients) {
            const pubKey = r.user?.encryption_public_key;
            if (!pubKey) continue;

            try {
                // Attestation gate (audit M-1): the final release is exactly
                // where a substituted recipient key would leak the secret.
                await assertSafeRecipient({ ...r.user, address: r.user_address });
                // ML-KEM wrap of the file key for this recipient.
                recipientKeys[r.user_address] = JSON.stringify(await encryptPQC(fileKey, pubKey));
            } catch (encErr) {
                console.error(`Failed to encrypt for recipient ${r.user_address}`, encErr);
                // Failsafe: fail hard rather than complete the workflow with a
                // recipient silently unable to decrypt.
                throw new Error(`Failed to encrypt for recipient ${r.user?.username || r.user_address}: ${encErr.message}`);
            }
        }
    }

    onProgress(85, "Submitting...");

    const signRes = await fetch(`${API_ENDPOINTS.SECRETS.LIST}/../multisig/workflow/${workflow.id}/sign`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            signature,
            recipient_keys: recipientKeys
        })
    });

    if (!signRes.ok) {
        const err = await signRes.json();
        throw new Error(err.detail || "Failed to submit signature");
    }
    return signRes.json();
};
