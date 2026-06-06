import { useState } from 'react';
import { Lock, Copy, FileText, Share2, Trash2, FileSignature, BadgeCheck, AlertTriangle, Download, Users, ShieldCheck, ChevronDown } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
import { verifySignaturePQC } from '../../utils/crypto';
import API_ENDPOINTS from '../../config';

const SecretItem = ({ secret, decryptedContent, onDecrypt, onLock, onDelete, onShare, onViewDetails, authType, viewMode = 'grid', isSharedView }) => {
    const { theme } = useTheme();
    const { token } = useAuth();
    const [verificationResult, setVerificationResult] = useState(null);
    const [verifying, setVerifying] = useState(false);
    const [expanded, setExpanded] = useState(false);

    const handleCopy = (text) => {
        navigator.clipboard.writeText(text);
        // Toast logic handled by parent or simplified here (could add local 'copied' state)
        alert("Copied to clipboard!");
    };

    const handleVerify = async (docData) => {
        setVerifying(true);
        try {
            if (!docData.signature || !docData.signerPublicKey) {
                alert("Invalid document format for verification.");
                setVerifying(false);
                return;
            }

            const isValid = await verifySignaturePQC(docData.content, docData.signature, docData.signerPublicKey);

            // Resolve User (Optional)
            let signerInfo = null;
            try {
                const res = await fetch(API_ENDPOINTS.USERS.RESOLVE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ address: docData.signerPublicKey })
                });
                if (res.ok) signerInfo = await res.json();
            } catch (e) { }

            setVerificationResult({
                valid: isValid,
                signer: signerInfo,
                publicKey: docData.signerPublicKey
            });
        } catch (e) {
            alert("Verification failed: " + e.message);
        } finally {
            setVerifying(false);
        }
    };

    const handleDownloadProof = (secretName, docData) => {
        const isPQC = docData.signerPublicKey.length > 200;
        const proof = {
            type: 'kryptolog_signed_document_proof',
            version: '1.0',
            exported_at: new Date().toISOString(),
            document: {
                name: secretName,
                content: docData.content,
            },
            signer: {
                publicKey: docData.signerPublicKey,
                algorithm: isPQC ? 'DILITHIUM2' : 'ECDSA',
            },
            signature: docData.signature,
        };
        const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${secretName.replace(/[^a-zA-Z0-9_-]/g, '_')}.kryptolog-proof.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleDownload = (jsonContent) => {
        try {
            const fileData = JSON.parse(jsonContent);
            if (fileData.type !== 'file') return;

            const link = document.createElement('a');
            link.download = fileData.name;

            if (fileData.content) {
                // Content is always a blob: URL now (handled by useSecrets)
                link.href = fileData.content;
            }

            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (e) {
            console.error("Download failed", e);
        }
    };

    const formatFileSize = (bytes) => {
        if (!bytes) return '';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    // Render Logic
    let content = decryptedContent;
    let isSignedDoc = false;
    let signedPayload = null;

    if (content) {
        try {
            const parsed = JSON.parse(content);
            if (parsed.signature && parsed.signerPublicKey && parsed.content) {
                isSignedDoc = true;
                signedPayload = parsed;
                content = parsed.content;

                // If useSecrets dynamically injected a local Blob URL for a chunked file:
                if (parsed.fileUrl && parsed.fileMeta) {
                    content = JSON.stringify({
                        type: 'file',
                        name: parsed.fileMeta.file_name,
                        mime: parsed.fileMeta.mime_type,
                        content: parsed.fileUrl,
                        size: parsed.fileMeta.total_size
                    });
                }
            }
        } catch (e) { }
    }

    // Inner Content (File/Text)
    let innerDisplay = content;
    let isFile = false;

    if (content) {
        try {
            const parsed = JSON.parse(content);
            if (parsed && parsed.type === 'files' && parsed.items) {
                // Multi-file secret
                isFile = true;
                innerDisplay = (
                    <div className="flex flex-col gap-2">
                        <div className="text-xs text-slate-500 mb-1">{parsed.items.length} files</div>
                        {parsed.items.map((item, idx) => {
                            const isImage = item.mime && item.mime.startsWith('image/');
                            return (
                                <div key={idx} className="flex flex-col gap-1">
                                    <div className="flex items-center gap-2">
                                        <FileText className="w-4 h-4 text-indigo-300" />
                                        <span className="font-medium text-indigo-300">{item.name}</span>
                                        <span className="text-xs text-slate-500">
                                            ({item.mime}{item.size ? ` · ${formatFileSize(item.size)}` : ''})
                                        </span>
                                        <a
                                            href={item.content}
                                            download={item.name}
                                            className="flex items-center gap-1 px-2 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs transition-colors ml-auto"
                                        >
                                            <Download className="w-3 h-3" /> Download
                                        </a>
                                    </div>
                                    {isImage && (
                                        <img
                                            src={item.content}
                                            alt={item.name}
                                            className="max-w-xs max-h-32 rounded-lg border border-slate-700 object-contain ml-6"
                                        />
                                    )}
                                </div>
                            );
                        })}
                    </div>
                );
            } else if (parsed && parsed.type === 'file' && parsed.content) {
                isFile = true;

                const isImage = parsed.mime && parsed.mime.startsWith('image/');

                innerDisplay = (
                    <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-2 text-indigo-300">
                            <FileText className="w-4 h-4" />
                            <span className="font-medium">{parsed.name}</span>
                            <span className="text-xs text-slate-500">
                                ({parsed.mime}{parsed.size ? ` · ${formatFileSize(parsed.size)}` : ''})
                            </span>
                        </div>
                        {isImage && (
                            <img
                                src={parsed.content}
                                alt={parsed.name}
                                className="max-w-xs max-h-48 rounded-lg border border-slate-700 object-contain"
                            />
                        )}
                        <button
                            onClick={() => handleDownload(content)}
                            className="flex items-center gap-2 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm w-fit transition-colors"
                        >
                            <Download className="w-4 h-4" /> Download File
                        </button>
                    </div>
                );
            }
        } catch (e) { }
    }

    // === LIST VIEW ===
    if (viewMode === 'list') {
        const typeIcon = secret.type === 'file' ? <FileText className="w-4 h-4" /> :
            secret.type === 'signed_document' ? <FileSignature className="w-4 h-4" /> :
                <Lock className="w-4 h-4" />;

        const typeColor = secret.type === 'file'
            ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'
            : secret.type === 'signed_document'
                ? 'bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400'
                : 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400';

        return (
            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-lg hover:shadow-md transition-shadow">
                <div
                    className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                    onClick={() => setExpanded(!expanded)}
                >
                    <div className={`p-1.5 rounded-md ${typeColor}`}>
                        {typeIcon}
                    </div>
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-900 dark:text-white truncate">{secret.name}</span>
                            <span className={`text-xs px-1.5 py-0.5 rounded ${typeColor} font-medium`}>
                                {secret.type.replace('_', ' ')}
                            </span>
                            {isSharedView && (
                                <span className="text-xs px-1.5 py-0.5 rounded bg-amber-50 dark:bg-amber-900/20 text-amber-600 dark:text-amber-400 font-medium">shared</span>
                            )}
                        </div>
                    </div>
                    <span className="text-xs text-slate-400 whitespace-nowrap hidden sm:block">
                        {secret.created_at ? new Date(secret.created_at).toLocaleDateString() : ''}
                    </span>
                    <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                        {decryptedContent && (
                            <button onClick={() => onLock(secret)} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-md text-slate-400 hover:text-amber-500 transition-colors" title="Lock (hide content)">
                                <Lock className="w-4 h-4" />
                            </button>
                        )}
                        {!secret.isShared && (
                            <button onClick={() => onShare(secret)} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-md text-slate-400 hover:text-indigo-500 transition-colors" title="Share">
                                <Share2 className="w-4 h-4" />
                            </button>
                        )}
                        <button onClick={() => onDelete(secret.id)} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-md text-slate-400 hover:text-red-500 transition-colors" title="Delete">
                            <Trash2 className="w-4 h-4" />
                        </button>
                        {onViewDetails && !secret.isShared && (
                            <button onClick={() => onViewDetails(secret)} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-md text-slate-400 hover:text-indigo-500 transition-colors" title="Details">
                                <Users className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                    <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform ${expanded ? 'rotate-180' : ''}`} />
                </div>

                {expanded && !decryptedContent && (
                    <div className="px-4 pb-3 border-t border-slate-100 dark:border-slate-700 pt-3 animate-in fade-in slide-in-from-top-1">
                        <button
                            onClick={() => onDecrypt(secret)}
                            className="w-full py-3 border-2 border-dashed border-slate-200 dark:border-slate-700 rounded-lg text-slate-400 hover:text-indigo-500 hover:border-indigo-300 dark:hover:border-indigo-800 hover:bg-indigo-50 dark:hover:bg-indigo-900/10 transition-all flex items-center justify-center gap-2 group"
                        >
                            <Lock className="w-5 h-5 group-hover:scale-110 transition-transform" />
                            <span className="text-sm font-medium">Click to Decrypt</span>
                        </button>
                    </div>
                )}

                {expanded && decryptedContent && (
                    <div className="px-4 pb-3 border-t border-slate-100 dark:border-slate-700 pt-3 animate-in fade-in slide-in-from-top-1">
                        {isSignedDoc && (
                            <div className="p-3 mb-3 bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-lg flex items-center justify-between">
                                <div className="flex items-center gap-2 text-indigo-700 dark:text-indigo-300">
                                    <FileSignature className="w-4 h-4" />
                                    <span className="font-medium text-sm">Digitally Signed</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <button
                                        onClick={() => handleDownloadProof(secret.name, signedPayload)}
                                        className="text-xs px-2 py-1 bg-purple-600 text-white rounded hover:bg-purple-500 transition-colors flex items-center gap-1"
                                    >
                                        <ShieldCheck className="w-3 h-3" /> Proof
                                    </button>
                                    <button
                                        onClick={() => handleVerify(signedPayload)}
                                        disabled={verifying}
                                        className="text-xs px-2 py-1 bg-indigo-600 text-white rounded hover:bg-indigo-500 transition-colors disabled:opacity-50"
                                    >
                                        {verifying ? "Verifying..." : "Verify"}
                                    </button>
                                </div>
                            </div>
                        )}

                        {verificationResult && isSignedDoc && verificationResult.publicKey === signedPayload.signerPublicKey && (
                            <div className={`p-3 mb-3 rounded-lg border ${verificationResult.valid ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800' : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'}`}>
                                <div className="flex items-center gap-2">
                                    {verificationResult.valid ? <BadgeCheck className="w-4 h-4 text-emerald-500" /> : <AlertTriangle className="w-4 h-4 text-red-500" />}
                                    <span className={`text-sm font-semibold ${verificationResult.valid ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                                        {verificationResult.valid ? "Signature Valid" : "Signature Invalid"}
                                    </span>
                                    {verificationResult.valid && verificationResult.signer && (
                                        <span className="text-xs text-emerald-600 dark:text-emerald-500 ml-1">— {verificationResult.signer.username}</span>
                                    )}
                                </div>
                            </div>
                        )}

                        <div
                            style={{ backgroundColor: theme === 'dark' ? '#152033' : '#f8fafc', borderColor: theme === 'dark' ? '#1e3048' : '#e2e8f0', color: theme === 'dark' ? '#cbd5e1' : '#1e293b' }}
                            className="p-3 rounded-lg border font-mono text-sm whitespace-pre-wrap break-all relative group"
                        >
                            {innerDisplay}
                            {!isFile && (
                                <button
                                    onClick={() => handleCopy(content)}
                                    className="absolute top-2 right-2 p-1.5 bg-slate-200 dark:bg-slate-750 rounded hover:bg-slate-300 dark:hover:bg-slate-700 opacity-0 group-hover:opacity-100 transition-opacity"
                                    title="Copy content"
                                >
                                    <Copy className="w-3 h-3 text-slate-500" />
                                </button>
                            )}
                        </div>
                    </div>
                )}
            </div>
        );
    }

    // === GRID VIEW (existing card) ===
    return (
        <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow">
            <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${secret.type === 'file'
                        ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'
                        : secret.type === 'signed_document'
                            ? 'bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400'
                            : 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400'
                        }`}>
                        {secret.type === 'file' ? <FileText className="w-5 h-5" /> :
                            secret.type === 'signed_document' ? <FileSignature className="w-5 h-5" /> :
                                <Lock className="w-5 h-5" />}
                    </div>
                    <div>
                        <h3 className="font-bold text-slate-900 dark:text-white">{secret.name}</h3>
                        <p className="text-xs text-slate-500 capitalize">{secret.type.replace('_', ' ')}</p>
                    </div>
                </div>
                <div className="flex gap-1">
                    {decryptedContent && (
                        <button onClick={() => onLock(secret)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg text-slate-400 hover:text-amber-500 transition-colors" title="Lock (hide content)">
                            <Lock className="w-4 h-4" />
                        </button>
                    )}
                    {!secret.isShared && (
                        <button onClick={() => onShare(secret)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg text-slate-400 hover:text-indigo-500 transition-colors" title="Share">
                            <Share2 className="w-4 h-4" />
                        </button>
                    )}

                    <button onClick={() => onDelete(secret.id)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg text-slate-400 hover:text-red-500 transition-colors" title="Delete">
                        <Trash2 className="w-4 h-4" />
                    </button>
                    {onViewDetails && !secret.isShared && (
                        <button onClick={() => onViewDetails(secret)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg text-slate-400 hover:text-indigo-500 transition-colors" title="Details & Access">
                            <Users className="w-4 h-4" />
                        </button>
                    )}
                </div>
            </div>

            {decryptedContent ? (
                <div className="space-y-4 animate-in fade-in slide-in-from-top-2">
                    {isSignedDoc && (
                        <div className="p-3 bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-lg flex items-center justify-between">
                            <div className="flex items-center gap-2 text-indigo-700 dark:text-indigo-300">
                                <FileSignature className="w-5 h-5" />
                                <span className="font-medium text-sm">Digitally Signed Document</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={() => handleDownloadProof(secret.name, signedPayload)}
                                    className="text-xs px-3 py-1 bg-purple-600 text-white rounded hover:bg-purple-500 transition-colors flex items-center gap-1"
                                    title="Download cryptographic proof (signature + metadata)"
                                >
                                    <ShieldCheck className="w-3 h-3" /> Download Proof
                                </button>
                                <button
                                    onClick={() => handleVerify(signedPayload)}
                                    disabled={verifying}
                                    className="text-xs px-3 py-1 bg-indigo-600 text-white rounded hover:bg-indigo-500 transition-colors disabled:opacity-50"
                                >
                                    {verifying ? "Verifying..." : "Verify Signature"}
                                </button>
                            </div>
                        </div>
                    )}

                    {verificationResult && isSignedDoc && verificationResult.publicKey === signedPayload.signerPublicKey && (
                        <div className={`p-3 rounded-lg border ${verificationResult.valid ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800' : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'}`}>
                            <div className="flex items-start gap-3">
                                {verificationResult.valid ? (
                                    <BadgeCheck className="w-5 h-5 text-emerald-500 mt-0.5" />
                                ) : (
                                    <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5" />
                                )}
                                <div>
                                    <h4 className={`text-sm font-semibold ${verificationResult.valid ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                                        {verificationResult.valid ? "Signature Valid" : "Signature Invalid"}
                                    </h4>
                                    {verificationResult.valid && (
                                        <div className="text-xs text-emerald-600 dark:text-emerald-500 mt-1 space-y-1">
                                            <p>Signed by: <span className="font-semibold">{verificationResult.signer ? verificationResult.signer.username : "Unknown User"}</span></p>
                                            <p className="font-mono opacity-80 break-all">{verificationResult.publicKey}</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    <div
                        style={{ backgroundColor: theme === 'dark' ? '#152033' : '#f8fafc', borderColor: theme === 'dark' ? '#1e3048' : '#e2e8f0', color: theme === 'dark' ? '#cbd5e1' : '#1e293b' }}
                        className="p-4 rounded-lg border font-mono text-sm whitespace-pre-wrap break-all relative group"
                    >
                        {innerDisplay}
                        {!isFile && (
                            <button
                                onClick={() => handleCopy(content)}
                                className="absolute top-2 right-2 p-1.5 bg-slate-200 dark:bg-slate-750 rounded hover:bg-slate-300 dark:hover:bg-slate-700 opacity-0 group-hover:opacity-100 transition-opacity"
                                title="Copy content"
                            >
                                <Copy className="w-3 h-3 text-slate-500" />
                            </button>
                        )}
                    </div>
                </div>
            ) : (
                <div className="mt-4">
                    <button
                        onClick={() => onDecrypt(secret)}
                        className="w-full py-3 border-2 border-dashed border-slate-200 dark:border-slate-700 rounded-lg text-slate-400 hover:text-indigo-500 hover:border-indigo-300 dark:hover:border-indigo-800 hover:bg-indigo-50 dark:hover:bg-indigo-900/10 transition-all flex flex-col items-center justify-center gap-2 group"
                    >
                        <Lock className="w-6 h-6 group-hover:scale-110 transition-transform" />
                        <span className="text-sm font-medium">Click to Decrypt</span>
                    </button>
                </div>
            )}
        </div>
    );
};

export default SecretItem;
