import {
    sha256Hex, verifyIdentitySignature, domainSeparate, SIGNING_CONTEXT, multisigApprovalMessage,
} from '../../utils/crypto';

// Build and download the offline verification proof for a workflow: the
// document content plus every signature an auditor needs to re-verify it
// without the server. Explicit signers signed sha256(ciphertext) bound to the
// workflow (M1), so the proof carries secret_id + the ciphertext hash for the
// auditor to rebuild and verify their approval messages. The creator's
// signature is over the plaintext content (verified separately).
export const downloadMultisigProof = async ({
    workflow, creatorSignature, creatorSignedContent, rawDecryptedContent, verificationStatus,
}) => {
    // The proof labels the creator's signature with workflow.owner_address, but
    // that attribution was never checked against the key the signature actually
    // verifies under (audit L-3) — so the exported artifact asserted authorship
    // it had no basis for, to an auditor who by definition cannot see the
    // workflow. Refuse to export rather than emit a claim we cannot stand
    // behind; interpretDecryptedContent reports 'mismatch' for exactly this.
    if (creatorSignature && verificationStatus !== 'verified') {
        throw new Error(
            "Refusing to export a proof: the creator's signature does not verify " +
            "against this workflow's owner. Exporting it would attribute the " +
            "document to someone the signature does not name."
        );
    }

    // Build signer list: virtual creator + explicit signers
    const signatures = [];

    // Creator (implicit signer)
    if (creatorSignature) {
        signatures.push({
            address: workflow.owner_address,
            // The key the address names (crypto-core 3.3.0): what an auditor
            // verifies against, offline, after checking it is that address's.
            identity_public_key: workflow.owner?.identity_public_key || null,
            username: workflow.owner?.username || null,
            signature: creatorSignature,
            signed_at: workflow.created_at,
            algorithm: 'ML-DSA-44',
            role: 'creator',
        });
    }

    // Explicit signers
    for (const s of workflow.signers) {
        if (s.has_signed && s.signature) {
            signatures.push({
                address: s.user_address,
                identity_public_key: s.user?.identity_public_key || null,
                username: s.user?.username || null,
                signature: s.signature,
                signed_at: s.signed_at,
                algorithm: 'ML-DSA-44',
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

// The algorithm labels a proof may carry for an ML-DSA signature. Proofs made
// before the FIPS name was used say DILITHIUM2.
export const isMlDsaLabel = (label) => label === 'ML-DSA-44' || label === 'DILITHIUM2';

/**
 * Re-verify every signature a multisig proof carries, offline — Proof Audit's
 * job, kept next to the code that writes the proof so the two cannot drift.
 *
 * Each role signed different bytes (H1/M1): the creator the plaintext document
 * under the `content` domain, a signer sha256(ciphertext) bound to the
 * workflow under the `multisig-approval` domain (server-verifiable).
 *
 * Each entry is verified with the identity key it carries, which must be the
 * one its address names (crypto-core 3.3.0). An entry without one is NOT
 * verified against its address instead: that shortcut is exactly what stops
 * working when the address becomes a hash of the key.
 */
export const verifyMultisigProofSignatures = async (proofData) => {
    const creatorBody = domainSeparate(SIGNING_CONTEXT.CONTENT, proofData.document?.content);
    const approvalBody = (proofData.document?.ciphertext_sha256 != null)
        ? multisigApprovalMessage(
            proofData.workflow?.id,
            proofData.workflow?.secret_id,
            proofData.document.ciphertext_sha256,
        )
        : null;

    const results = [];
    for (const entry of proofData.signatures || []) {
        // 'signer' approvals need the ciphertext hash; 'creator' uses content.
        const message = entry.role === 'signer' ? approvalBody : creatorBody;
        let valid = false;
        // PQC (ML-DSA-44) only; legacy ECDSA entries are unsupported.
        if (message && isMlDsaLabel(entry.algorithm)) {
            valid = await verifyIdentitySignature({
                address: (entry.address || '').toLowerCase(),
                identityPublicKey: entry.identity_public_key,
                message,
                signature: entry.signature,
            });
        }
        results.push({
            publicKey: entry.address,
            algorithm: entry.algorithm,
            valid,
            username: entry.username || null,
            role: entry.role,
            signedAt: entry.signed_at,
        });
    }
    return results;
};
