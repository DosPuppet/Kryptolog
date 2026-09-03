import { ShieldCheck, AlertTriangle, FileText, Download } from 'lucide-react';

// Renders the decrypted secret: multi-file list, single file, or raw text —
// plus the proof-download button and the creator-signature verdict.
const DecryptedContentPanel = ({ workflow, decryptedContent, verificationStatus, creatorSignature, onDownloadProof }) => {
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
                            onClick={onDownloadProof}
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
                {/* Audit L-3: the signature is sound but was made by a key that
                    is not this workflow's owner, so the document is authentic
                    to SOMEONE — just not to who this panel would otherwise
                    name. Distinct wording from "invalid" on purpose. */}
                {verificationStatus === 'mismatch' && (
                    <div className="flex items-center gap-1 text-amber-700 text-xs px-2 py-1 bg-amber-100 rounded-full">
                        <AlertTriangle className="w-3 h-3" /> Signed by a different key than the owner
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

export default DecryptedContentPanel;
