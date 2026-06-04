import React, { useState } from 'react';
import { X, Check, Clock, User, Shield, ShieldCheck, AlertTriangle, Eye, FileText, Download } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { usePQC } from '../context/PQCContext';
import { useWeb3 } from '../context/Web3Context';
import API_ENDPOINTS from '../config';
import { decryptData, verifySignaturePQC, encryptData, verifyMessageEth } from '../utils/crypto';
import { downloadChunkedFile, downloadFileByRange } from '../utils/fileChunks';

const SignerVerificationBadge = ({ signer, contentToVerify }) => {
    const [status, setStatus] = useState('idle'); // idle, verifying, valid, invalid

    const verify = async () => {
        console.log("Verify Clicked for", signer.user_address);
        if (!signer.signature || !contentToVerify) {
            console.warn("Missing signature or content", { sig: !!signer.signature, content: !!contentToVerify });
            return;
        }
        setStatus('verifying');
        console.log("SignerVerificationBadge: Verifying content length", contentToVerify.length);
        try {
            // Reconstruct Signed Message (Sig + Content) or detached? 
            // In handleSign, we sent detached prefix/suffix.
            // verifySignaturePQC handles detached.
            // verifySignaturePQC handles detached.
            let isValid = false;
            if (signer.user_address && signer.user_address.length > 200) { // PQC address is public key
                isValid = await verifySignaturePQC(contentToVerify, signer.signature, signer.user_address);
            } else {
                // Eth address is short. User Address is the Public Key (Address).
                const recovered = verifyMessageEth(contentToVerify, signer.signature);
                isValid = recovered && recovered.toLowerCase() === signer.user_address.toLowerCase();
            }
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

export default function MultisigWorkflow({ workflow, onClose, onUpdate, setUploadProgress, setStatusMessage }) {
    const { user, token, authType } = useAuth();
    const { encrypt: encryptPQC, decrypt: decryptPQC, sign: signPQC, pqcAccount, kyberKey } = usePQC();
    const { currentAccount } = useWeb3();

    const [isSigning, setIsSigning] = useState(false);
    const [isViewing, setIsViewing] = useState(false);
    const [decryptedContent, setDecryptedContent] = useState(null);
    const [rawDecryptedContent, setRawDecryptedContent] = useState(null); // The actual string signers signed
    const [verificationStatus, setVerificationStatus] = useState(null); // 'verified', 'failed', 'unsigned'
    const [creatorSignature, setCreatorSignature] = useState(null);
    const [creatorSignedContent, setCreatorSignedContent] = useState(null);
    const [error, setError] = useState('');

    const isOwner = workflow.owner_address.toLowerCase() === user.address.toLowerCase();
    const mySignerEntry = workflow.signers.find(s => s.user_address.toLowerCase() === user.address.toLowerCase());
    const isSigner = !!mySignerEntry;
    const hasSigned = mySignerEntry?.has_signed;

    // Check if user is a recipient
    const isRecipient = workflow.recipients.find(r => r.user_address.toLowerCase() === user.address.toLowerCase());
    const canView = isOwner || isSigner || (isRecipient && workflow.status === 'completed');

    // console.log("MultisigWorkflow Debug:", { ... });

    const completedSignatures = workflow.signers.filter(s => s.has_signed).length;
    const totalSignatures = workflow.signers.length;
    const progress = (completedSignatures / totalSignatures) * 100;

    const handleDownloadProof = () => {
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

        const proof = {
            type: 'kryptolog_multisig_proof',
            version: '1.0',
            exported_at: new Date().toISOString(),
            workflow: {
                id: workflow.id,
                name: workflow.name,
                status: workflow.status,
                created_at: workflow.created_at,
            },
            document: {
                content: creatorSignedContent || rawDecryptedContent,
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

    const fetchAndDecrypt = async () => {
        setIsViewing(true);
        setError('');
        if (setUploadProgress) {
            setUploadProgress(10);
            setStatusMessage && setStatusMessage("Fetching...");
        }

        try {
            if (workflow.secret_id === undefined) {
                console.error("Workflow object missing secret_id", workflow);
                throw new Error("Invalid workflow data: missing secret ID");
            }

            let encryptedKeyToDecrypt = null;

            // 1. Check if I am a Recipient with direct key access (Completed Workflow)
            if (isRecipient && workflow.status === 'completed') {
                const myRecipientEntry = workflow.recipients.find(r => r.user_address === user.address);
                if (myRecipientEntry && myRecipientEntry.encrypted_key) {
                    encryptedKeyToDecrypt = myRecipientEntry.encrypted_key;
                }
            }

            // 2. Check if I am a Signer with direct key access
            if (!encryptedKeyToDecrypt && isSigner) {
                const mySignerEntry = workflow.signers.find(s => s.user_address === user.address);
                console.log("Found signer key in workflow object");
            }

            // 3. Fallback: Check if Secret Data is embedded in Workflow (New Backend Schema)
            if (!encryptedKeyToDecrypt && workflow.secret && workflow.secret.encrypted_data) {
                // If I am a signer, I have the key (step 2), but I need the CONTENT.
                // Wait, 'encryptedKeyToDecrypt' variable name in this function is confusing.
                // It seems to be used as 'dataBlobToDecrypt'.
                // LET'S RENAME/CLARIFY LOGIC:
                // We need TWO things:
                // A. The KEY (AES Key) -> derived from my Signer Entry (encrypted_key)
                // B. The CONTENT (AES Encrypted Blob) -> derived from workflow.secret.encrypted_data

                // The current function seems to expect ONE blob?
                // `decryptContentValues` splits it? No.
                // old `decryptContentValues` did `decryptData(encryptedDataString)`.

                // NEW ENVELOPE LOGIC:
                // 1. Decrypt KEY (from my signer entry)
                // 2. Decrypt CONTENT (from workflow.secret) using KEY.

                // logic below is legacy "Decrypt ONE thing". We must refactor `fetchAndDecrypt` significantly.
            }

            // NEW ENVELOPE LOGIC
            // 1. Get MY Encrypted Key
            let myEncryptedKey = null;
            if (isOwner) {
                // Check top-level owner key first (robust fix)
                if (workflow.owner_encrypted_key) {
                    myEncryptedKey = workflow.owner_encrypted_key;
                }
                // Fallback to nested if top-level missing (legacy support)
                else if (workflow.secret && workflow.secret.encrypted_key) {
                    myEncryptedKey = workflow.secret.encrypted_key;
                }
            } else if (isSigner) {
                const s = workflow.signers.find(s => s.user_address === user.address);
                if (s) myEncryptedKey = s.encrypted_key;
            } else if (isRecipient && workflow.status === 'completed') {
                const r = workflow.recipients.find(r => r.user_address === user.address);
                if (r) myEncryptedKey = r.encrypted_key;
            }

            if (!myEncryptedKey) throw new Error("Acccess Denied: No key found for your user.");

            // 2. Get Encrypted Content
            const encryptedContentBlob = workflow.secret?.encrypted_data;
            if (!encryptedContentBlob) throw new Error("Secret content not found in workflow.");

            if (setUploadProgress) {
                setUploadProgress(40);
                setStatusMessage && setStatusMessage("Decrypting Key...");
            }

            // 3. Decrypt Key
            // We need secureDecrypt from useSecrets or import utils.
            // Since we are in a component, we can import `secureDecrypt` logic or helpers.
            // Let's use the raw utils for simplicity:
            const { decryptData, decryptSymmetric } = await import('../utils/crypto');

            let fileKey;
            // PQC or Eth?
            try {
                // Try parsing JSON (PQC envelope)
                const parsedKey = JSON.parse(myEncryptedKey);
                if (authType === 'trustkeys') {
                    fileKey = await decryptPQC(parsedKey);
                } else {
                    // Maybe it was just stringified PQC struct but we are metamask? (Shouldn't happen if created correctly)
                    // Fallback to eth decrypt if simple string
                    fileKey = await decryptData(myEncryptedKey, currentAccount);
                }
            } catch (e) {
                // Not JSON, assume Eth String
                fileKey = await decryptData(myEncryptedKey, currentAccount);
            }

            if (setUploadProgress) {
                setUploadProgress(60);
                setStatusMessage && setStatusMessage("Decrypting Content...");
            }

            // 4. Decrypt Content
            const encDataObj = JSON.parse(encryptedContentBlob);
            const contentString = await decryptSymmetric(encDataObj, fileKey);

            // 5. Process Content (Parse JSON / Verify Signature)
            await processDecryptedContent(contentString, fileKey);

            if (setUploadProgress) {
                setUploadProgress(100);
                setTimeout(() => {
                    setUploadProgress(0);
                    setStatusMessage && setStatusMessage('');
                }, 500);
            }

        } catch (e) {
            console.error("View failed", e);
            setError(e.message);
            setIsViewing(false);
            if (setUploadProgress) {
                setUploadProgress(0);
                setStatusMessage && setStatusMessage('');
            }
        }
    };

    const processDecryptedContent = async (contentString, fileKey) => {
        try {
            let parsed;
            try { parsed = JSON.parse(contentString); } catch (e) { }

            if (parsed && parsed.signature && parsed.signerPublicKey) {
                // Signed Document Wrapper
                let isValid = false;
                if (parsed.signerPublicKey.length > 200) {
                    // we need verifySignaturePQC
                    const { verifySignaturePQC } = await import('../utils/crypto');
                    isValid = await verifySignaturePQC(parsed.content, parsed.signature, parsed.signerPublicKey);
                } else {
                    const { verifyMessageEth } = await import('../utils/crypto');
                    const recovered = verifyMessageEth(parsed.content, parsed.signature);
                    isValid = recovered && recovered.toLowerCase() === parsed.signerPublicKey.toLowerCase();
                }
                setVerificationStatus(isValid ? 'verified' : 'failed');
                setCreatorSignature(parsed.signature);
                setCreatorSignedContent(parsed.content);
                setRawDecryptedContent(contentString);

                try {
                    const inner = JSON.parse(parsed.content);

                    // Check if the inner content is actually a chunked file payload
                    if (inner.files && Array.isArray(inner.files)) {
                        // Multi-file metadata
                        try {
                            if (setUploadProgress) {
                                setUploadProgress(70);
                                setStatusMessage && setStatusMessage("Downloading files...");
                            }
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
                                    (pct, msg) => {
                                        if (setUploadProgress) {
                                            const overallPct = Math.round(((fi + pct / 100) / inner.files.length) * 100);
                                            setUploadProgress(70 + Math.round(overallPct * 0.25));
                                        }
                                    }
                                );
                                fileResults.push({
                                    name: fileMeta.file_name,
                                    mime: fileMeta.mime_type,
                                    content: URL.createObjectURL(blob),
                                    size: fileMeta.total_size
                                });
                            }
                            setDecryptedContent({
                                type: 'files',
                                items: fileResults
                            });
                        } catch (chunkErr) {
                            console.error("Failed to download multi-file chunks", chunkErr);
                            setDecryptedContent(inner);
                        }
                    } else if (inner.total_chunks && inner.file_name) {
                        try {
                            if (setUploadProgress) {
                                setUploadProgress(70);
                                setStatusMessage && setStatusMessage("Downloading file chunks...");
                            }
                            const blob = await downloadChunkedFile(
                                workflow.secret_id,
                                fileKey,
                                token,
                                API_ENDPOINTS.BASE,
                                inner.total_chunks,
                                inner.mime_type,
                                (pct, msg) => {
                                    if (setUploadProgress) setUploadProgress(70 + Math.round(pct * 0.25));
                                }
                            );
                            const blobUrl = URL.createObjectURL(blob);
                            setDecryptedContent({
                                type: 'file',
                                name: inner.file_name,
                                mime: inner.mime_type,
                                content: blobUrl,
                                size: inner.total_size,
                                chunked: true
                            });
                        } catch (chunkErr) {
                            console.error("Failed to download chunks", chunkErr);
                            setDecryptedContent(inner);
                        }
                    } else {
                        setDecryptedContent(inner);
                    }
                } catch {
                    setDecryptedContent(parsed.content);
                }
            } else {
                setVerificationStatus('unsigned');
                setDecryptedContent(parsed || contentString);
                setRawDecryptedContent(contentString);
            }
            setIsViewing(false);
        } catch (e) {
            console.error("Processing failed", e);
            setError("Content malformed");
        }
    };

    const handleSign = async () => {
        setIsSigning(true);
        setError('');
        if (setUploadProgress) {
            setUploadProgress(10);
            setStatusMessage && setStatusMessage("Preparing...");
        }

        try {
            // We need the raw content string that was signed? 
            // Actually, `signPQC` signs the `rawContent`.
            // If we already verified, we have `parsed.content`.
            // But to be safe, let's re-fetch or use state if available.
            // Simplest: Re-run verify logic or just sign the *inner content*?
            // WAIT. `MultisigCreateModal` logic:
            // Signer signs `payloadToEncrypt`? OR `rawContent`?
            // Line 146 in Modal: `signerKeys... = secureEncrypt(payloadToEncrypt...)`
            // `payloadToEncrypt` IS the struct `{ content, signature, publicKey }`.
            //
            // So the Signer receives the Signed Struct.
            // When the Signer signs, they should sign:
            // A) The Original Content? (Proves they agree to content)
            // B) The Creator's Signed Struct? (Proves they verify creator + content)
            // 
            // Logic in `MultisigWorkflow.jsx` (previous version): `signature = await signPQC(content)`.
            // If `content` is the huge struct, fine.
            // 
            // Let's stick to signing what we See.
            // If we decrypted the struct, we sign the struct.

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

            if (setUploadProgress) {
                setUploadProgress(30);
                setStatusMessage && setStatusMessage("Decrypting content for signing...");
            }

            // 1. Decrypt the AES Key (fileKey)
            let fileKey;
            try {
                if (authType === 'trustkeys') {
                    const decryptedKeyJson = await decryptPQC(JSON.parse(encryptedKey));
                    // Check if it's a JSON string or raw
                    try {
                        // Sometimes double encoded?
                        const obj = JSON.parse(decryptedKeyJson);
                        // If it's the raw key hex string
                        fileKey = typeof obj === 'string' ? obj : decryptedKeyJson;
                    } catch {
                        fileKey = decryptedKeyJson;
                    }
                } else {
                    fileKey = await decryptData(encryptedKey, currentAccount);
                }
            } catch (e) {
                console.error("Failed to decrypt AES key", e);
                throw new Error("Failed to decrypt your access key");
            }

            // 2. Fetch and Decrypt the Content
            const encryptedContentBlob = workflow.secret?.encrypted_data;
            if (!encryptedContentBlob) throw new Error("Secret content not found to sign.");

            const { decryptSymmetric, signMessageEth } = await import('../utils/crypto');

            const encDataObj = JSON.parse(encryptedContentBlob);
            const contentToSign = await decryptSymmetric(encDataObj, fileKey);

            if (setUploadProgress) {
                setUploadProgress(50);
                setStatusMessage && setStatusMessage(authType === 'trustkeys' ? "Signing..." : "Signing with Wallet...");
            }

            // Always sign the exact string the creator signed (the inner .content).
            // If the creator signed a JSON metadata structure representing the chunked file,
            // we sign that EXACT metadata structure (which includes the file_hash).
            // `creatorSignedContent` holds the exact inner JSON string originally generated by the creator.
            const dataToSign = creatorSignedContent || contentToSign;

            let signature;
            if (authType === 'trustkeys') {
                signature = await signPQC(dataToSign);
            } else {
                signature = await signMessageEth(dataToSign);
            }

            // Handle "Signed Message" (Attached Code) vs "Detached Signature"
            // We now support Attached Signatures (Full Blob) in backend (Text column).

            // Last Signer Logic: Release Recipient Keys
            // Check if I am the LAST signer (Assuming I am about to sign and succeed)
            const alreadySignedCount = workflow.signers.filter(s => s.has_signed).length;
            const totalSigners = workflow.signers.length;
            const isLastSigner = (alreadySignedCount + 1) === totalSigners;

            let recipientKeys = null;
            if (isLastSigner && workflow.recipients && workflow.recipients.length > 0) {
                console.log("Last Signer identified. Generating keys for recipients...");
                if (setUploadProgress) {
                    setUploadProgress(70);
                    setStatusMessage && setStatusMessage("Encrypting for recipients...");
                }
                recipientKeys = {};
                for (const r of workflow.recipients) {
                    const pubKey = r.user?.encryption_public_key;
                    if (!pubKey) continue;

                    try {
                        let encrypted;
                        // Heuristic: PQC keys are long (>200 chars)
                        if (pubKey.length > 200) {
                            const res = await encryptPQC(fileKey, pubKey);
                            encrypted = JSON.stringify(res);
                        } else {
                            encrypted = await encryptData(fileKey, pubKey);
                        }
                        recipientKeys[r.user_address] = encrypted;
                    } catch (encErr) {
                        console.error(`Failed to encrypt for recipient ${r.user_address}`, encErr);
                        // Continue? Or fail? If we fail, workflow can't complete.
                        // Better to warn but continue, or fail to ensure integrity.
                        // Failsafe: Let's fail hard so we know something is wrong.
                        throw new Error(`Failed to encrypt for recipient ${r.user?.username || r.user_address}: ${encErr.message}`);
                    }
                }
            }

            if (setUploadProgress) {
                setUploadProgress(85);
                setStatusMessage && setStatusMessage("Submitting...");
            }

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

            if (signRes.ok) {
                const updatedWf = await signRes.json();
                onUpdate(updatedWf);
                if (setUploadProgress) {
                    setUploadProgress(100);
                    setTimeout(() => {
                        setUploadProgress(0);
                        setStatusMessage && setStatusMessage('');
                    }, 500);
                }
                // Don't close, let them see success
            } else {
                const err = await signRes.json();
                throw new Error(err.detail || "Failed to submit signature");
            }

        } catch (e) {
            console.error("Signing failed", e);
            setError(e.message);
            if (setUploadProgress) {
                setUploadProgress(0);
                setStatusMessage && setStatusMessage('');
            }
        } finally {
            setIsSigning(false);
        }
    };

    const renderContent = () => {
        if (!decryptedContent) return null;

        const isFile = decryptedContent?.type === 'file' && decryptedContent?.content;
        const isMultiFile = decryptedContent?.type === 'files' && decryptedContent?.items;

        return (
            <div className="mt-4 p-4 bg-slate-50 dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-700">
                <div className="flex justify-between items-start mb-2">
                    <h5 className="text-sm font-medium text-slate-500">Decrypted Content</h5>
                    <div className="flex items-center gap-2">
                        {(creatorSignature || workflow.signers.some(s => s.has_signed && s.signature)) && (
                            <button
                                onClick={handleDownloadProof}
                                className="flex items-center gap-1 text-xs px-3 py-1 bg-purple-600 text-white rounded hover:bg-purple-500 transition-colors"
                                title="Download cryptographic proof (all signatures + metadata)"
                            >
                                <ShieldCheck className="w-3 h-3" /> Download Proof
                            </button>
                        )}
                    </div>
                    {verificationStatus === 'failed' && (
                        <div className="flex items-center gap-1 text-red-600 text-xs px-2 py-1 bg-red-100 rounded-full">
                            <AlertTriangle className="w-3 h-3" /> Signature Invalid
                        </div>
                    )}
                </div>

                {isMultiFile ? (
                    <div className="space-y-2">
                        <div className="text-xs text-slate-500 mb-1">{decryptedContent.items.length} files</div>
                        {decryptedContent.items.map((item, idx) => (
                            <div key={idx} className="flex items-center gap-3 p-3 bg-white dark:bg-slate-850 rounded border border-slate-200 dark:border-slate-700">
                                <FileText className="w-6 h-6 text-indigo-500" />
                                <div className="flex-1 overflow-hidden">
                                    <div className="font-medium truncate">{item.name}</div>
                                    <div className="text-xs text-slate-500">{item.mime}</div>
                                </div>
                                <a
                                    href={item.content}
                                    download={item.name}
                                    className="p-2 text-indigo-600 hover:bg-indigo-50 rounded"
                                    title="Download"
                                >
                                    <Download className="w-5 h-5" />
                                </a>
                            </div>
                        ))}
                    </div>
                ) : isFile ? (
                    <div className="flex items-center gap-3 p-3 bg-white dark:bg-slate-850 rounded border border-slate-200 dark:border-slate-700">
                        <FileText className="w-8 h-8 text-indigo-500" />
                        <div className="flex-1 overflow-hidden">
                            <div className="font-medium truncate">{decryptedContent.name}</div>
                            <div className="text-xs text-slate-500">{decryptedContent.mime}</div>
                        </div>
                        <a
                            href={decryptedContent.content}
                            download={decryptedContent.name}
                            className="p-2 text-indigo-600 hover:bg-indigo-50 rounded"
                            title="Download"
                        >
                            <Download className="w-5 h-5" />
                        </a>
                    </div>
                ) : (
                    <div className="whitespace-pre-wrap font-mono text-sm">
                        {typeof decryptedContent === 'string' ? decryptedContent : JSON.stringify(decryptedContent, null, 2)}
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
                <div className="flex justify-between items-center mb-6">
                    <div>
                        <h3 className="text-xl font-semibold text-slate-900 dark:text-white">Workflow: {workflow.name}</h3>
                        <div className="text-xs text-slate-500">ID: {workflow.id} • Created {new Date(workflow.created_at).toLocaleDateString()}</div>
                    </div>
                    <button onClick={onClose}><X className="w-5 h-5 text-slate-400" /></button>
                </div>

                <div className="space-y-6">
                    {/* Status Card */}
                    <div className={`p-4 rounded-lg border ${workflow.status === 'completed' ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800' : 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800'}`}>
                        <div className="flex justify-between items-center mb-2">
                            <span className={`font-semibold ${workflow.status === 'completed' ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'}`}>
                                {workflow.status.toUpperCase()}
                            </span>
                            <span className="text-sm text-slate-600 dark:text-slate-400">{completedSignatures}/{totalSignatures} Signatures</span>
                        </div>
                        <div className="h-2 bg-white/50 rounded-full overflow-hidden">
                            <div className={`h-full transition-all duration-500 ${workflow.status === 'completed' ? 'bg-emerald-500' : 'bg-amber-500'}`} style={{ width: `${progress}%` }} />
                        </div>
                    </div>

                    {/* Signers List */}
                    <div>
                        <h4 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Signers</h4>
                        <div className="space-y-2">
                            {(() => {
                                // Prepare Signers List with Virtual Creator
                                let displayedSigners = [...workflow.signers];
                                // Always show Creator if not in list (Implicitly signed)
                                if (!displayedSigners.find(s => s.user_address === workflow.owner_address)) {
                                    displayedSigners.unshift({
                                        user_address: workflow.owner_address,
                                        user: workflow.owner,
                                        has_signed: true,
                                        signature: creatorSignature, // Will be null until decrypted
                                        signed_at: workflow.created_at,
                                        isCreator: true
                                    });
                                }
                                return displayedSigners.map(s => (
                                    <div key={s.user_address} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-750/50 rounded-lg border border-slate-100 dark:border-slate-700">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-2 h-2 rounded-full ${s.has_signed ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                                            <div>
                                                <div className="font-medium text-slate-900 dark:text-slate-200 flex items-center gap-2">
                                                    {s.user?.username || s.user_address.substring(0, 12)}
                                                    {s.user_address === user.address && <span className="text-xs bg-slate-200 dark:bg-slate-700 px-1.5 py-0.5 rounded text-slate-500">You</span>}
                                                </div>
                                                {s.has_signed && (
                                                    <div className="text-xs text-slate-500 flex items-center gap-2 mt-0.5">
                                                        <span className="flex items-center gap-1">
                                                            <Check className="w-3 h-3" /> Signed
                                                        </span>
                                                        <span className="text-slate-400">•</span>
                                                        <span>{new Date(s.signed_at).toLocaleDateString()}</span>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                        {/* Verification Badge */}
                                        {s.has_signed && decryptedContent && (
                                            <SignerVerificationBadge
                                                signer={s}
                                                contentToVerify={s.isCreator ? creatorSignedContent : (creatorSignedContent || rawDecryptedContent)}
                                            />
                                        )}
                                    </div>
                                ));
                            })()}
                        </div>
                    </div>

                    {/* Recipients List */}
                    < div >
                        <h4 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Recipients</h4>
                        <div className="space-y-2">
                            {workflow.recipients.map(r => (
                                <div key={r.user_address} className="flex items-center justify-between p-2 rounded hover:bg-slate-50 dark:hover:bg-slate-700">
                                    <div className="flex items-center gap-3">
                                        <User className="w-4 h-4 text-slate-400" />
                                        <div className="text-sm text-slate-900 dark:text-slate-200">
                                            {r.user?.username || r.user_address.substring(0, 8)}
                                        </div>
                                    </div>
                                    {workflow.status === 'completed' ? (
                                        <span className="text-xs px-2 py-1 bg-emerald-100 text-emerald-700 rounded-full">Access Granted</span>
                                    ) : (
                                        <span className="text-xs px-2 py-1 bg-slate-100 text-slate-500 rounded-full">Pending</span>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div >

                    {/* View/Decrypt Section */}
                    {
                        canView && !decryptedContent && (
                            <button
                                onClick={fetchAndDecrypt}
                                className="w-full border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 py-2 rounded-lg flex items-center justify-center gap-2"
                            >
                                <Eye className="w-4 h-4" /> View Secret Content
                            </button>
                        )
                    }

                    {decryptedContent && renderContent()}

                    {/* Actions */}
                    {
                        error && (
                            <div className="p-3 bg-red-50 text-red-600 rounded-lg text-sm flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4" /> {error}
                            </div>
                        )
                    }

                    {
                        isSigner && !hasSigned && workflow.status !== 'completed' && (
                            <button
                                onClick={handleSign}
                                disabled={isSigning}
                                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-lg font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                            >
                                {isSigning ? 'Signing...' : (
                                    <>
                                        <Shield className="w-4 h-4" /> Sign Workflow
                                    </>
                                )}
                            </button>
                        )
                    }

                    {
                        (!isSigner || hasSigned || workflow.status === 'completed') && (
                            <button
                                onClick={onClose}
                                className="w-full border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 py-3 rounded-lg font-medium transition-colors"
                            >
                                Close
                            </button>
                        )
                    }
                </div >
            </div >
        </div >
    );
}
