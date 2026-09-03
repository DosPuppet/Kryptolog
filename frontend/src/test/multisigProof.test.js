// Creator-signature attribution on a multisig workflow (audit L-3).
//
// The signature was verified against `signerPublicKey` taken FROM THE
// DECRYPTED BLOB. That proves whoever wrote the blob held a key — not that it
// was the workflow's creator. Anyone able to write the payload could sign it
// with a key they generated and the UI rendered "verified", while the exported
// proof labelled it with workflow.owner_address, an attribution nothing had
// checked. The proof is the artifact an auditor sees INSTEAD of the workflow,
// so an unfounded claim there is the one that travels.

import { describe, it, expect, beforeAll, vi } from 'vitest';
import {
    generateMlDsaKeyPair, signMessagePQC, domainSeparate, SIGNING_CONTEXT,
} from '../utils/crypto';
import { interpretDecryptedContent } from '../components/multisig/decryptWorkflow';
import { downloadMultisigProof } from '../components/multisig/proof';

let owner, impostor;

beforeAll(async () => {
    [owner, impostor] = await Promise.all([generateMlDsaKeyPair(), generateMlDsaKeyPair()]);
}, 60000);

const signedBlob = async (signer, content = 'the document') => {
    const body = domainSeparate(SIGNING_CONTEXT.CONTENT, content);
    return JSON.stringify({
        content,
        signature: await signMessagePQC(body, signer.privateKey),
        signerPublicKey: signer.publicKey,
    });
};

const interpret = (contentString, workflow) => interpretDecryptedContent({
    contentString, fileKey: null, workflow, token: 't', onProgress: () => { },
});

describe('creator signature attribution', () => {
    it('verifies when the signer IS the workflow owner', async () => {
        const workflow = { owner_address: owner.publicKey.toLowerCase() };
        const result = await interpret(await signedBlob(owner), workflow);
        expect(result.verificationStatus).toBe('verified');
        expect(result.signerMatchesOwner).toBe(true);
    });

    it('is case-insensitive about the address, as the directory is', async () => {
        const workflow = { owner_address: owner.publicKey.toUpperCase() };
        const result = await interpret(await signedBlob(owner), workflow);
        expect(result.verificationStatus).toBe('verified');
    });

    it('reports mismatch — not verified — when another key signed it', async () => {
        // The blob is internally consistent: the signature DOES verify against
        // the key it carries. That is exactly why the old check passed it.
        const workflow = { owner_address: owner.publicKey.toLowerCase() };
        const result = await interpret(await signedBlob(impostor), workflow);
        expect(result.verificationStatus).toBe('mismatch');
        expect(result.signerMatchesOwner).toBe(false);
    });

    it('reports mismatch rather than verified when the workflow has no owner', async () => {
        const result = await interpret(await signedBlob(owner), {});
        expect(result.verificationStatus).toBe('mismatch');
    });

    it('still reports failed for a genuinely broken signature', async () => {
        // 'failed' and 'mismatch' are different statements and must stay distinct.
        const blob = JSON.parse(await signedBlob(owner));
        blob.content = 'tampered after signing';
        const workflow = { owner_address: owner.publicKey.toLowerCase() };
        const result = await interpret(JSON.stringify(blob), workflow);
        expect(result.verificationStatus).toBe('failed');
    });

    it('leaves an unsigned payload alone', async () => {
        const result = await interpret(JSON.stringify({ hello: 'world' }), {
            owner_address: owner.publicKey.toLowerCase(),
        });
        expect(result.verificationStatus).toBe('unsigned');
    });
});

describe('proof export', () => {
    const workflow = {
        id: 1, name: 'wf', status: 'completed', created_at: null, secret_id: 2,
        owner_address: 'abc', signers: [], secret: {},
    };

    it('refuses to export a proof whose attribution does not hold', async () => {
        await expect(downloadMultisigProof({
            workflow,
            creatorSignature: 'sig',
            creatorSignedContent: 'doc',
            rawDecryptedContent: 'doc',
            verificationStatus: 'mismatch',
        })).rejects.toThrow(/does not verify against this workflow's owner/);
    });

    it('refuses on a failed signature too', async () => {
        await expect(downloadMultisigProof({
            workflow,
            creatorSignature: 'sig',
            creatorSignedContent: 'doc',
            rawDecryptedContent: 'doc',
            verificationStatus: 'failed',
        })).rejects.toThrow(/Refusing to export/);
    });

    it('exports when the attribution holds', async () => {
        // jsdom has no real download; assert it gets as far as building the blob.
        const click = vi.fn();
        vi.spyOn(document, 'createElement').mockReturnValue({ href: '', download: '', click });
        globalThis.URL.createObjectURL = vi.fn(() => 'blob:x');
        globalThis.URL.revokeObjectURL = vi.fn();

        await downloadMultisigProof({
            workflow,
            creatorSignature: 'sig',
            creatorSignedContent: 'doc',
            rawDecryptedContent: 'doc',
            verificationStatus: 'verified',
        });
        expect(click).toHaveBeenCalled();
        vi.restoreAllMocks();
    });

    it('exports an unsigned document without a creator claim', async () => {
        // Nothing is being attributed, so there is nothing to refuse.
        const click = vi.fn();
        vi.spyOn(document, 'createElement').mockReturnValue({ href: '', download: '', click });
        globalThis.URL.createObjectURL = vi.fn(() => 'blob:x');
        globalThis.URL.revokeObjectURL = vi.fn();

        await downloadMultisigProof({
            workflow,
            creatorSignature: null,
            creatorSignedContent: null,
            rawDecryptedContent: 'doc',
            verificationStatus: 'unsigned',
        });
        expect(click).toHaveBeenCalled();
        vi.restoreAllMocks();
    });
});
