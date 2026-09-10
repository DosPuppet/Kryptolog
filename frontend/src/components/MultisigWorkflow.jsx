import { useEffect, useState } from 'react';
import { X, Shield, AlertTriangle, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { usePQC } from '../context/PQCContext';
import API_ENDPOINTS from '../config';
import { decryptWorkflowSecret, interpretDecryptedContent } from './multisig/decryptWorkflow';
import { signMultisigWorkflow } from './multisig/signWorkflow';
import { downloadMultisigProof } from './multisig/proof';
import { SignersList, RecipientsList } from './multisig/WorkflowLists';
import DecryptedContentPanel from './multisig/DecryptedContentPanel';
import { confirmDialog } from '../utils/confirm';
import { apiFetch } from '../services/api';

export default function MultisigWorkflow({ workflow: listWorkflow, onClose, onUpdate, onDelete, setUploadProgress, setStatusMessage }) {
    const { user, token } = useAuth();
    const { encrypt: encryptPQC, decrypt: decryptPQC, sign: signPQC } = usePQC();

    // The workflow list no longer carries its secret's ciphertext (audit O-3),
    // so this modal — the only place that needs it — fetches the full workflow
    // when it opens. The list row still draws the header while that lands.
    //
    // Signing benefits beyond the byte count: the approval message is the hash
    // of the STORED ciphertext, which the server recomputes from the row. A
    // list copy that had gone stale could only ever produce "Invalid approval
    // signature"; a freshly fetched one signs what is actually there.
    const [detail, setDetail] = useState(null);
    const [detailError, setDetailError] = useState('');
    const workflow = detail || listWorkflow;
    const contentReady = !!detail;

    const [isSigning, setIsSigning] = useState(false);
    const [isRejecting, setIsRejecting] = useState(false);
    const [isDeleting, setIsDeleting] = useState(false);
    const [decryptedContent, setDecryptedContent] = useState(null);
    const [rawDecryptedContent, setRawDecryptedContent] = useState(null); // The actual string signers signed
    const [verificationStatus, setVerificationStatus] = useState(null); // 'verified' | 'failed' | 'mismatch' | 'unsigned'
    const [creatorSignature, setCreatorSignature] = useState(null);
    const [creatorSignedContent, setCreatorSignedContent] = useState(null);
    const [error, setError] = useState('');

    useEffect(() => {
        let cancelled = false;
        setDetail(null);
        setDetailError('');
        (async () => {
            try {
                const full = await apiFetch(
                    API_ENDPOINTS.MULTISIG.WORKFLOW(listWorkflow.id), token
                );
                if (!cancelled) setDetail(full);
            } catch (e) {
                console.error("Workflow detail fetch failed", e);
                if (!cancelled) setDetailError(e.message);
            }
        })();
        // Ignore a response that arrives after the modal moved on to another
        // workflow — it would hand the wrong ciphertext to the sign button.
        return () => { cancelled = true; };
    }, [listWorkflow.id, token]);

    const isOwner = workflow.owner_address.toLowerCase() === user.address.toLowerCase();
    const mySignerEntry = workflow.signers.find(s => s.user_address.toLowerCase() === user.address.toLowerCase());
    const isSigner = !!mySignerEntry;
    const hasSigned = mySignerEntry?.has_signed;

    // Check if user is a recipient
    const isRecipient = workflow.recipients.find(r => r.user_address.toLowerCase() === user.address.toLowerCase());
    const canView = isOwner || isSigner || (isRecipient && workflow.status === 'completed');

    const completedSignatures = workflow.signers.filter(s => s.has_signed).length;
    const totalSigners = workflow.signers.length;
    // N-of-M: progress is measured against the threshold (N), not the full
    // signer set (M). NULL threshold ⇒ legacy N-of-N (= totalSigners).
    const requiredSignatures = workflow.threshold || totalSigners;
    const progress = Math.min(100, (completedSignatures / requiredSignatures) * 100);
    const isRejected = workflow.status === 'rejected';

    // Progress plumbing for the crypto pipelines (optional props from parent).
    const onProgress = (pct, msg) => {
        if (!setUploadProgress) return;
        setUploadProgress(pct);
        if (msg !== undefined && setStatusMessage) setStatusMessage(msg);
    };
    const resetProgress = () => {
        if (!setUploadProgress) return;
        setUploadProgress(0);
        setStatusMessage && setStatusMessage('');
    };
    const finishProgress = () => {
        if (!setUploadProgress) return;
        setUploadProgress(100);
        setTimeout(resetProgress, 500);
    };

    const handleDownloadProof = async () => {
        try {
            await downloadMultisigProof({
                workflow, creatorSignature, creatorSignedContent, rawDecryptedContent,
                verificationStatus,
            });
        } catch (e) {
            setError(e.message);
        }
    };

    const fetchAndDecrypt = async () => {
        setError('');
        onProgress(10, "Fetching...");

        try {
            const { contentString, fileKey } = await decryptWorkflowSecret({
                workflow, user, isOwner, isSigner, isRecipient, decryptPQC, onProgress
            });

            try {
                const result = await interpretDecryptedContent({ contentString, fileKey, workflow, token, onProgress });
                setVerificationStatus(result.verificationStatus);
                setCreatorSignature(result.creatorSignature);
                setCreatorSignedContent(result.creatorSignedContent);
                setRawDecryptedContent(result.rawDecryptedContent);
                setDecryptedContent(result.decryptedContent);
            } catch (e) {
                console.error("Processing failed", e);
                setError("Content malformed");
            }

            finishProgress();
        } catch (e) {
            console.error("View failed", e);
            setError(e.message);
            resetProgress();
        }
    };

    const handleSign = async () => {
        setIsSigning(true);
        setError('');
        onProgress(10, "Preparing...");

        try {
            const updatedWf = await signMultisigWorkflow({
                workflow, user, token, decryptPQC, signPQC, encryptPQC, onProgress
            });
            onUpdate(updatedWf);
            // /sign returns the full workflow, so this keeps the open modal on
            // the same footing as a fresh detail fetch.
            setDetail(updatedWf);
            finishProgress();
            // Don't close, let them see success
        } catch (e) {
            console.error("Signing failed", e);
            setError(e.message);
            resetProgress();
        } finally {
            setIsSigning(false);
        }
    };

    const handleReject = async () => {
        const ok = await confirmDialog({
            title: 'Reject workflow',
            message: 'Reject this workflow? This blocks it permanently — the secret will not be released.',
            confirmText: 'Reject',
            danger: true,
        });
        if (!ok) return;
        setError('');
        setIsRejecting(true);
        try {
            const updatedWf = await apiFetch(
                API_ENDPOINTS.MULTISIG.REJECT(workflow.id), token, { method: 'POST', body: {} }
            );
            onUpdate(updatedWf);
            setDetail(updatedWf);
        } catch (e) {
            console.error("Reject failed", e);
            setError(e.message);
        } finally {
            setIsRejecting(false);
        }
    };

    const handleDelete = async () => {
        const ok = await confirmDialog({
            title: 'Delete workflow',
            message: 'Delete this workflow and its secret? This cannot be undone.',
            confirmText: 'Delete',
            danger: true,
        });
        if (!ok) return;
        setError('');
        setIsDeleting(true);
        try {
            await apiFetch(API_ENDPOINTS.MULTISIG.WORKFLOW(workflow.id), token, {
                method: 'DELETE',
            });
            onDelete ? onDelete(workflow.id) : onClose();
        } catch (e) {
            console.error("Delete failed", e);
            setError(e.message);
        } finally {
            setIsDeleting(false);
        }
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
                    <div className={`p-4 rounded-lg border ${workflow.status === 'completed' ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800' : isRejected ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800' : 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800'}`}>
                        <div className="flex justify-between items-center mb-2">
                            <span className={`font-semibold ${workflow.status === 'completed' ? 'text-emerald-700 dark:text-emerald-400' : isRejected ? 'text-red-700 dark:text-red-400' : 'text-amber-700 dark:text-amber-400'}`}>
                                {workflow.status.toUpperCase()}
                            </span>
                            <span className="text-sm text-slate-600 dark:text-slate-400">
                                {completedSignatures}/{requiredSignatures} required
                                {requiredSignatures !== totalSigners && ` (${totalSigners} signers)`}
                            </span>
                        </div>
                        {isRejected ? (
                            <div className="text-sm text-red-700 dark:text-red-400">
                                Rejected{workflow.rejected_by ? ` by ${workflow.rejected_by.slice(0, 10)}…` : ''}. The secret was not released.
                            </div>
                        ) : (
                            <div className="h-2 bg-white/50 rounded-full overflow-hidden">
                                <div className={`h-full transition-all duration-500 ${workflow.status === 'completed' ? 'bg-emerald-500' : 'bg-amber-500'}`} style={{ width: `${progress}%` }} />
                            </div>
                        )}
                    </div>

                    <SignersList
                        workflow={workflow}
                        user={user}
                        decryptedContent={decryptedContent}
                        creatorSignature={creatorSignature}
                        creatorSignedContent={creatorSignedContent}
                    />

                    <RecipientsList workflow={workflow} />

                    {/* View/Decrypt Section */}
                    {canView && !decryptedContent && (
                        <button
                            onClick={fetchAndDecrypt}
                            disabled={!contentReady}
                            className="w-full border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 py-2 rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                            <Eye className="w-4 h-4" /> {contentReady ? 'View Secret Content' : 'Loading…'}
                        </button>
                    )}

                    {detailError && (
                        <div className="p-3 bg-red-50 text-red-600 rounded-lg text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" /> {detailError}
                        </div>
                    )}

                    {decryptedContent && (
                        <div className="space-y-2">
                            <div className="flex justify-end">
                                <button
                                    onClick={() => { setDecryptedContent(null); setRawDecryptedContent(null); }}
                                    className="text-xs text-slate-500 hover:text-amber-500 transition-colors flex items-center gap-1"
                                    title="Hide decrypted content"
                                >
                                    <EyeOff className="w-3.5 h-3.5" /> Hide content
                                </button>
                            </div>
                            <DecryptedContentPanel
                                workflow={workflow}
                                decryptedContent={decryptedContent}
                                verificationStatus={verificationStatus}
                                creatorSignature={creatorSignature}
                                onDownloadProof={handleDownloadProof}
                            />
                        </div>
                    )}

                    {/* Actions */}
                    {error && (
                        <div className="p-3 bg-red-50 text-red-600 rounded-lg text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" /> {error}
                        </div>
                    )}

                    {isSigner && !hasSigned && workflow.status === 'pending' && (
                        <div className="flex gap-3">
                            <button
                                onClick={handleSign}
                                // Signing hashes the ciphertext, so it waits
                                // for the detail fetch (audit O-3).
                                disabled={isSigning || isRejecting || !contentReady}
                                className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-lg font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                            >
                                {isSigning ? 'Signing...' : (
                                    <>
                                        <Shield className="w-4 h-4" /> Sign Workflow
                                    </>
                                )}
                            </button>
                            <button
                                onClick={handleReject}
                                disabled={isSigning || isRejecting}
                                className="px-4 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 py-3 rounded-lg font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                            >
                                {isRejecting ? 'Rejecting...' : 'Reject'}
                            </button>
                        </div>
                    )}

                    {isOwner && isRejected && (
                        <button
                            onClick={handleDelete}
                            disabled={isDeleting}
                            className="w-full bg-red-600 hover:bg-red-500 text-white py-3 rounded-lg font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                            {isDeleting ? 'Deleting...' : 'Delete Workflow'}
                        </button>
                    )}

                    {(!isSigner || hasSigned || workflow.status !== 'pending') && (
                        <button
                            onClick={onClose}
                            className="w-full border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 py-3 rounded-lg font-medium transition-colors"
                        >
                            Close
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
