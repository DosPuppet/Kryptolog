import { sha256Hex } from '../../utils/crypto';

// Build and download the offline verification proof for a workflow: the
// document content plus every signature an auditor needs to re-verify it
// without the server. Explicit signers signed sha256(ciphertext) bound to the
// workflow (M1), so the proof carries secret_id + the ciphertext hash for the
// auditor to rebuild and verify their approval messages. The creator's
// signature is over the plaintext content (verified separately).
export const downloadMultisigProof = async ({ workflow, creatorSignature, creatorSignedContent, rawDecryptedContent }) => {
    // Build signer list: virtual creator + explicit signers
    const signatures = [];

    // Creator (implicit signer)
    if (creatorSignature) {
        const isPQC = workflow.owner_address.length > 200;
        signatures.push({
            address: workflow.owner_address,
            username: workflow.owner?.username || null,
            signature: creatorSignature,
            signed_at: workflow.created_at,
            algorithm: isPQC ? 'DILITHIUM2' : 'ECDSA',
            role: 'creator',
        });
    }

    // Explicit signers
    for (const s of workflow.signers) {
        if (s.has_signed && s.signature) {
            const isPQC = s.user_address.length > 200;
            signatures.push({
                address: s.user_address,
                username: s.user?.username || null,
                signature: s.signature,
                signed_at: s.signed_at,
                algorithm: isPQC ? 'DILITHIUM2' : 'ECDSA',
                role: 'signer',
            });
        }
    }

    const ciphertextSha256 = workflow.secret?.encrypted_data
        ? await sha256Hex(workflow.secret.encrypted_data)
        : null;

    const proof = {
        type: 'kryptolog_multisig_proof',
        version: '1.1',
        exported_at: new Date().toISOString(),
        workflow: {
            id: workflow.id,
            name: workflow.name,
            status: workflow.status,
            created_at: workflow.created_at,
            secret_id: workflow.secret_id,
        },
        document: {
            content: creatorSignedContent || rawDecryptedContent,
            ciphertext_sha256: ciphertextSha256,
        },
        signatures,
    };

    const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${workflow.name.replace(/[^a-zA-Z0-9_-]/g, '_')}.kryptolog-proof.json`;
    a.click();
    URL.revokeObjectURL(url);
};
