import { useState } from 'react';
import { Shield, AlertTriangle } from 'lucide-react';
import { verifySignaturePQC, domainSeparate, SIGNING_CONTEXT, sha256Hex, multisigApprovalMessage } from '../../utils/crypto';

// verifyTarget describes exactly what the signer signed:
//   { kind: 'content', content }  — the CREATOR's signature over the plaintext
//      document (CONTENT domain, embedded in the secret; server can't see it).
//   { kind: 'approval', workflowId, secretId, encryptedData } — an explicit
//      SIGNER's server-verifiable approval over sha256(ciphertext) (M1).
const SignerVerificationBadge = ({ signer, verifyTarget }) => {
    const [status, setStatus] = useState('idle'); // idle, verifying, valid, invalid

    const verify = async () => {
        if (!signer.signature || !verifyTarget) {
            console.warn("Missing signature or verify target", { sig: !!signer.signature, target: !!verifyTarget });
            return;
        }
        setStatus('verifying');
        try {
            // Rebuild the exact domain-separated bytes the signer signed.
            let message;
            if (verifyTarget.kind === 'approval') {
                const ctHash = await sha256Hex(verifyTarget.encryptedData);
                message = multisigApprovalMessage(verifyTarget.workflowId, verifyTarget.secretId, ctHash);
            } else {
                message = domainSeparate(SIGNING_CONTEXT.CONTENT, verifyTarget.content);
            }

            // The signer's user_address is their ML-DSA-44 public key.
            const isValid = await verifySignaturePQC(message, signer.signature, signer.user_address);
            setStatus(isValid ? 'valid' : 'invalid');
        } catch (e) {
            console.error(e);
            setStatus('invalid');
        }
    };

    if (!signer.signature) return null;

    if (status === 'idle') {
        return (
            <button
                onClick={(e) => { e.stopPropagation(); verify(); }}
                className="text-xs text-indigo-500 hover:text-indigo-400 font-medium px-2 py-1 rounded bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-100 dark:border-indigo-800 transition-colors"
                title="Verify Signature"
            >
                Verify
            </button>
        );
    }

    if (status === 'verifying') {
        return <span className="text-xs text-slate-400 animate-pulse">Verifying...</span>;
    }

    if (status === 'valid') {
        return (
            <span className="flex items-center gap-1 text-xs text-emerald-600 bg-emerald-50 dark:bg-emerald-900/20 px-2 py-1 rounded border border-emerald-100 dark:border-emerald-800">
                <Shield className="w-3 h-3" /> Verified
            </span>
        );
    }

    return (
        <span className="flex items-center gap-1 text-xs text-red-600 bg-red-50 dark:bg-red-900/20 px-2 py-1 rounded border border-red-100 dark:border-red-800">
            <AlertTriangle className="w-3 h-3" /> Invalid
        </span>
    );
};

export default SignerVerificationBadge;
