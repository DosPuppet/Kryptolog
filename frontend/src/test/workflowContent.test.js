/**
 * A summary workflow can't be signed or viewed (audit O-3).
 *
 * `GET /multisig/workflows` stopped carrying its secret's ciphertext, so the
 * modal fetches the full workflow from `GET /multisig/workflow/{id}` when it
 * opens. These pin the other half of that contract: handed a list row anyway,
 * the two crypto entry points refuse it by name instead of proceeding.
 *
 * Signing is the one that matters. The approval message is the SHA-256 of the
 * STORED ciphertext, which the server recomputes from its own row before it
 * will accept the signature — so a workflow with no ciphertext must stop here,
 * where the error says what is wrong, rather than at the server, where it comes
 * back as "Invalid approval signature".
 */
import { describe, it, expect, vi } from 'vitest';
import { decryptWorkflowSecret } from '../components/multisig/decryptWorkflow';
import { signMultisigWorkflow } from '../components/multisig/signWorkflow';

const USER = { address: 'aa'.repeat(1312) };

/** What `GET /multisig/workflows` returns: no `secret.encrypted_data`. */
const summaryWorkflow = () => ({
    id: 7,
    secret_id: 42,
    status: 'pending',
    owner_address: USER.address,
    owner_encrypted_key: '{"kem":"x","iv":"y","content":"z"}',
    secret: { id: 42, name: 'title', type: 'note', owner_address: USER.address },
    signers: [{ user_address: USER.address, has_signed: false, encrypted_key: '{"kem":"x"}' }],
    recipients: [],
});

describe('a workflow without its ciphertext', () => {
    it('cannot be viewed', async () => {
        await expect(decryptWorkflowSecret({
            workflow: summaryWorkflow(),
            user: USER,
            isOwner: true,
            isSigner: false,
            isRecipient: false,
            decryptPQC: vi.fn(),
            onProgress: vi.fn(),
        })).rejects.toThrow(/content not found/i);
    });

    it('cannot be signed', async () => {
        const decryptPQC = vi.fn().mockResolvedValue('00'.repeat(32));
        const signPQC = vi.fn();

        await expect(signMultisigWorkflow({
            workflow: summaryWorkflow(),
            user: USER,
            token: 't',
            decryptPQC,
            signPQC,
            encryptPQC: vi.fn(),
            onProgress: vi.fn(),
        })).rejects.toThrow(/content not found to sign/i);

        // And it stopped BEFORE producing a signature — a signature over a
        // hash of nothing is the failure this guards against.
        expect(signPQC).not.toHaveBeenCalled();
    });

    it('still carries everything the list itself renders', () => {
        const wf = summaryWorkflow();
        expect(wf.secret.name).toBe('title');
        expect(wf.status).toBe('pending');
        expect(wf.signers[0].has_signed).toBe(false);
    });
});
