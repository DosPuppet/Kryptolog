import { useState, useRef } from 'react';
import { Upload, ShieldCheck, ShieldAlert, FileJson, User, Key, Clock, FileText, X, Loader2, FileCheck, FileWarning, Type } from 'lucide-react';
import { verifySignaturePQC, domainSeparate, SIGNING_CONTEXT, multisigApprovalMessage } from '../utils/crypto';
import { verifyMessageEth } from '../utils/web3';

// Parse proof content to detect type: text, single file, or multi-file
function parseProofContent(proofData) {
    const raw = proofData?.document?.content;
    if (!raw) return null;
    try {
        const parsed = JSON.parse(raw);
        if (parsed.files && Array.isArray(parsed.files)) {
            return { kind: 'files', files: parsed.files };
        }
        if (parsed.file_hash && parsed.file_name) {
            return { kind: 'file', file: parsed };
        }
    } catch (e) { /* not JSON = text */ }
    return { kind: 'text', text: raw };
}

async function hashFile(file) {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function ProofAudit() {
    const fileInputRef = useRef(null);
    const contentFileRef = useRef(null);
    const [proof, setProof] = useState(null);
    const [results, setResults] = useState(null);
    const [verifying, setVerifying] = useState(false);
    const [error, setError] = useState('');
    const [dragOver, setDragOver] = useState(false);

    // Content integrity verification
    const [contentCheck, setContentCheck] = useState(null); // { matches: bool, details: [] }
    const [checkingContent, setCheckingContent] = useState(false);
    const [textInput, setTextInput] = useState('');

    const reset = () => {
        setProof(null);
        setResults(null);
        setContentCheck(null);
        setTextInput('');
        setError('');
        if (fileInputRef.current) fileInputRef.current.value = '';
    };

    const verifyProof = async (proofData) => {
        setVerifying(true);
        setError('');
        setResults(null);

        try {
            if (proofData.type === 'kryptolog_signed_document_proof') {
                await verifySingleSignature(proofData);
            } else if (proofData.type === 'kryptolog_multisig_proof') {
                await verifyMultisigProof(proofData);
            } else {
                setError('Unknown proof type: ' + (proofData.type || 'missing'));
            }
        } catch (e) {
            setError('Verification failed: ' + e.message);
        } finally {
            setVerifying(false);
        }
    };

    const verifySingleSignature = async (proofData) => {
        const { document: doc, signer, signature } = proofData;
        const isPQC = signer.algorithm === 'DILITHIUM2';

        let isValid = false;
        let recoveredAddress = null;

        // Verify against the `content`-domain-separated bytes the signer actually signed (H1).
        const signedBody = domainSeparate(SIGNING_CONTEXT.CONTENT, doc.content);
        if (isPQC) {
            isValid = await verifySignaturePQC(signedBody, signature, signer.publicKey);
        } else {
            recoveredAddress = verifyMessageEth(signedBody, signature);
            isValid = !!recoveredAddress;
        }

        setResults({
            type: 'single',
            documentName: doc.name,
            exportedAt: proofData.exported_at,
            signers: [{
                publicKey: signer.publicKey,
                algorithm: signer.algorithm,
                valid: isValid,
                username: signer.username || null,
                recoveredAddress,
            }]
        });
    };

    const verifyMultisigProof = async (proofData) => {
        const content = proofData.document.content;
        // Each role signed different bytes (H1/M1):
        //   creator → the plaintext document under the `content` domain.
        //   signer  → sha256(ciphertext) bound to the workflow, under the
        //             `multisig-approval` domain (server-verifiable).
        const creatorBody = domainSeparate(SIGNING_CONTEXT.CONTENT, content);
        const approvalBody = (proofData.document?.ciphertext_sha256 != null)
            ? multisigApprovalMessage(
                proofData.workflow?.id,
                proofData.workflow?.secret_id,
                proofData.document.ciphertext_sha256,
            )
            : null;
        const signerResults = [];

        for (const entry of proofData.signatures) {
            const isPQC = entry.algorithm === 'DILITHIUM2';
            let isValid = false;
            let recoveredAddress = null;

            // 'signer' approvals need the ciphertext hash; 'creator' uses content.
            const message = entry.role === 'signer' ? approvalBody : creatorBody;

            try {
                if (!message) {
                    isValid = false; // proof lacks the data to verify this entry
                } else if (isPQC) {
                    isValid = await verifySignaturePQC(message, entry.signature, entry.address);
                } else {
                    recoveredAddress = verifyMessageEth(message, entry.signature);
                    isValid = recoveredAddress && recoveredAddress.toLowerCase() === entry.address.toLowerCase();
                }
            } catch (e) {
                isValid = false;
            }

            signerResults.push({
                publicKey: entry.address,
                algorithm: entry.algorithm,
                valid: isValid,
                username: entry.username || null,
                role: entry.role,
                signedAt: entry.signed_at,
                recoveredAddress,
            });
        }

        setResults({
            type: 'multisig',
            workflowName: proofData.workflow?.name,
            workflowStatus: proofData.workflow?.status,
            exportedAt: proofData.exported_at,
            documentName: proofData.document?.name,
            signers: signerResults,
        });
    };

    const verifyText = () => {
        const parsed = parseProofContent(proof?.data);
        if (!parsed || parsed.kind !== 'text') return;
        const matches = textInput === parsed.text;
        setContentCheck({
            matches,
            details: [{
                name: 'Text content',
                matches,
                expected: parsed.text.length + ' chars',
                got: textInput.length + ' chars',
            }]
        });
    };

    const verifyFiles = async (fileList) => {
        setCheckingContent(true);
        setContentCheck(null);
        try {
            const parsed = parseProofContent(proof?.data);
            if (!parsed) return;

            const expectedFiles = parsed.kind === 'files' ? parsed.files : [parsed.file];
            const details = [];

            for (const expected of expectedFiles) {
                const match = Array.from(fileList).find(f => f.name === expected.file_name);
                if (!match) {
                    details.push({
                        name: expected.file_name,
                        matches: false,
                        expected: expected.file_hash,
                        got: 'File not provided',
                    });
                    continue;
                }
                const hash = await hashFile(match);
                details.push({
                    name: expected.file_name,
                    matches: hash === expected.file_hash,
                    expected: expected.file_hash,
                    got: hash,
                    size: match.size,
                });
            }

            setContentCheck({
                matches: details.every(d => d.matches),
                details,
            });
        } catch (e) {
            setError('File hashing failed: ' + e.message);
        } finally {
            setCheckingContent(false);
        }
    };

    const handleFile = async (file) => {
        reset();
        if (!file) return;

        if (!file.name.endsWith('.json') && !file.type.includes('json')) {
            setError('Please upload a .kryptolog-proof.json file');
            return;
        }

        try {
            const text = await file.text();
            const data = JSON.parse(text);

            if (!data.type || !data.type.startsWith('kryptolog_')) {
                setError('Not a valid Kryptolog proof file. Expected "type" field starting with "kryptolog_".');
                return;
            }

            setProof({ data, fileName: file.name });
            await verifyProof(data);
        } catch (e) {
            setError('Failed to parse proof file: ' + e.message);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setDragOver(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
    };

    const allValid = results?.signers?.every(s => s.valid);
    const someValid = results?.signers?.some(s => s.valid);

    return (
        <div className="space-y-6">
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Proof Audit</h2>
            <p className="text-sm text-slate-500">
                Upload a <code className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-750 rounded text-xs">.kryptolog-proof.json</code> file
                to verify its cryptographic signatures offline.
            </p>

            {/* Upload area */}
            {!proof && (
                <div
                    onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all
                        ${dragOver
                            ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20'
                            : 'border-slate-300 dark:border-slate-600 hover:border-indigo-400 hover:bg-slate-50 dark:hover:bg-slate-900'
                        }`}
                >
                    <Upload className="w-10 h-10 mx-auto mb-4 text-slate-400" />
                    <p className="font-medium text-slate-700 dark:text-slate-300">
                        Drop a proof file here or click to browse
                    </p>
                    <p className="text-xs text-slate-400 mt-2">Supports signed document and multisig proofs</p>
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".json"
                        className="hidden"
                        onChange={(e) => handleFile(e.target.files[0])}
                    />
                </div>
            )}

            {/* Error */}
            {error && (
                <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-center gap-3 text-red-700 dark:text-red-400">
                    <ShieldAlert className="w-5 h-5 shrink-0" />
                    <span className="text-sm">{error}</span>
                </div>
            )}

            {/* Verifying spinner */}
            {verifying && (
                <div className="flex items-center justify-center gap-3 py-8 text-indigo-500">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span className="font-medium">Verifying signatures...</span>
                </div>
            )}

            {/* Results */}
            {results && !verifying && (
                <div className="space-y-4">
                    {/* Summary banner */}
                    <div className={`p-4 rounded-lg border flex items-center gap-3 ${
                        allValid
                            ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800'
                            : someValid
                                ? 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800'
                                : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                    }`}>
                        {allValid
                            ? <ShieldCheck className="w-6 h-6 text-emerald-600" />
                            : <ShieldAlert className="w-6 h-6 text-red-600" />
                        }
                        <div>
                            <div className={`font-semibold ${allValid ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                                {allValid
                                    ? `All ${results.signers.length} signature${results.signers.length > 1 ? 's' : ''} valid`
                                    : `${results.signers.filter(s => !s.valid).length} of ${results.signers.length} signature${results.signers.length > 1 ? 's' : ''} invalid`
                                }
                            </div>
                            <div className="text-xs text-slate-500 mt-0.5">
                                {results.type === 'multisig' ? `Workflow: ${results.workflowName}` : `Document: ${results.documentName}`}
                                {results.exportedAt && ` · Exported ${new Date(results.exportedAt).toLocaleString()}`}
                            </div>
                        </div>
                        <button onClick={reset} className="ml-auto p-1 hover:bg-white/50 rounded" title="Clear">
                            <X className="w-4 h-4 text-slate-400" />
                        </button>
                    </div>

                    {/* Proof file info */}
                    <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-5">
                        <div className="flex items-center gap-2 mb-4">
                            <FileJson className="w-4 h-4 text-indigo-500" />
                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{proof?.fileName}</span>
                            <span className="text-xs px-2 py-0.5 bg-slate-100 dark:bg-slate-750 rounded text-slate-500">
                                {results.type === 'multisig' ? 'Multisig Proof' : 'Signed Document Proof'}
                            </span>
                        </div>

                        {/* Signer(s) details */}
                        <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                            {results.signers.length > 1 ? 'Signatures' : 'Signature'}
                        </h4>
                        <div className="space-y-3">
                            {results.signers.map((signer, i) => (
                                <div key={i} className={`p-4 rounded-lg border ${
                                    signer.valid
                                        ? 'bg-emerald-50/50 dark:bg-emerald-900/10 border-emerald-200 dark:border-emerald-800'
                                        : 'bg-red-50/50 dark:bg-red-900/10 border-red-200 dark:border-red-800'
                                }`}>
                                    <div className="flex items-center justify-between mb-3">
                                        <div className="flex items-center gap-2">
                                            {signer.valid
                                                ? <ShieldCheck className="w-4 h-4 text-emerald-600" />
                                                : <ShieldAlert className="w-4 h-4 text-red-600" />
                                            }
                                            <span className={`text-sm font-semibold ${signer.valid ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                                                {signer.valid ? 'Valid' : 'Invalid'}
                                            </span>
                                            {signer.role && (
                                                <span className="text-xs px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-slate-600 dark:text-slate-400 capitalize">
                                                    {signer.role}
                                                </span>
                                            )}
                                        </div>
                                        <span className="text-xs px-2 py-0.5 bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 rounded font-mono">
                                            {signer.algorithm}
                                        </span>
                                    </div>

                                    <div className="space-y-2 text-sm">
                                        {signer.username && (
                                            <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                                                <User className="w-3.5 h-3.5 text-slate-400" />
                                                <span className="font-medium">{signer.username}</span>
                                            </div>
                                        )}
                                        <div className="flex items-start gap-2 text-slate-600 dark:text-slate-400">
                                            <Key className="w-3.5 h-3.5 text-slate-400 mt-0.5 shrink-0" />
                                            <span className="font-mono text-xs break-all leading-relaxed">
                                                {signer.publicKey}
                                            </span>
                                        </div>
                                        {signer.signedAt && (
                                            <div className="flex items-center gap-2 text-slate-500">
                                                <Clock className="w-3.5 h-3.5 text-slate-400" />
                                                <span className="text-xs">{new Date(signer.signedAt).toLocaleString()}</span>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Content Integrity Verification */}
                    {proof?.data?.document?.content && (() => {
                        const parsed = parseProofContent(proof.data);
                        if (!parsed) return null;

                        return (
                            <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-5 space-y-4">
                                <div className="flex items-center gap-2">
                                    <FileText className="w-4 h-4 text-slate-400" />
                                    <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Content Integrity</span>
                                    <span className="text-xs px-2 py-0.5 bg-slate-100 dark:bg-slate-750 rounded text-slate-500 capitalize">
                                        {parsed.kind === 'files' ? `${parsed.files.length} files` : parsed.kind}
                                    </span>
                                </div>

                                {parsed.kind === 'text' ? (
                                    <>
                                        <p className="text-xs text-slate-500">
                                            Paste the original text below to verify it matches the signed content.
                                        </p>
                                        <textarea
                                            value={textInput}
                                            onChange={(e) => { setTextInput(e.target.value); setContentCheck(null); }}
                                            placeholder="Paste original text here..."
                                            rows={5}
                                            className="w-full p-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg text-sm font-mono text-slate-700 dark:text-slate-300 resize-y"
                                        />
                                        <button
                                            onClick={verifyText}
                                            disabled={!textInput}
                                            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium disabled:opacity-40 transition-colors"
                                        >
                                            <Type className="w-4 h-4" /> Verify Text
                                        </button>
                                    </>
                                ) : (
                                    <>
                                        <p className="text-xs text-slate-500">
                                            Upload the original file{parsed.kind === 'files' ? 's' : ''} to verify
                                            {parsed.kind === 'files' ? ' their' : ' its'} SHA-256 hash matches the proof.
                                        </p>
                                        <div className="flex flex-wrap gap-2 text-xs text-slate-500">
                                            {(parsed.kind === 'files' ? parsed.files : [parsed.file]).map((f, i) => (
                                                <span key={i} className="px-2 py-1 bg-slate-100 dark:bg-slate-750 rounded font-mono">
                                                    {f.file_name}
                                                </span>
                                            ))}
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <button
                                                onClick={() => contentFileRef.current?.click()}
                                                disabled={checkingContent}
                                                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium disabled:opacity-40 transition-colors"
                                            >
                                                {checkingContent
                                                    ? <><Loader2 className="w-4 h-4 animate-spin" /> Hashing...</>
                                                    : <><Upload className="w-4 h-4" /> Upload File{parsed.kind === 'files' ? 's' : ''}</>
                                                }
                                            </button>
                                            <input
                                                ref={contentFileRef}
                                                type="file"
                                                multiple={parsed.kind === 'files'}
                                                className="hidden"
                                                onChange={(e) => verifyFiles(e.target.files)}
                                            />
                                        </div>
                                    </>
                                )}

                                {/* Content check results */}
                                {contentCheck && (
                                    <div className="space-y-2">
                                        <div className={`p-3 rounded-lg border flex items-center gap-2 ${
                                            contentCheck.matches
                                                ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800'
                                                : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                                        }`}>
                                            {contentCheck.matches
                                                ? <FileCheck className="w-5 h-5 text-emerald-600" />
                                                : <FileWarning className="w-5 h-5 text-red-600" />
                                            }
                                            <span className={`text-sm font-semibold ${contentCheck.matches ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                                                {contentCheck.matches ? 'Content matches the proof' : 'Content does NOT match the proof'}
                                            </span>
                                        </div>

                                        {contentCheck.details.map((d, i) => (
                                            <div key={i} className="p-3 bg-slate-50 dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-mono space-y-1">
                                                <div className="flex items-center gap-2">
                                                    {d.matches
                                                        ? <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                                                        : <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
                                                    }
                                                    <span className="font-semibold text-slate-700 dark:text-slate-300">{d.name}</span>
                                                </div>
                                                {d.expected && d.expected !== d.got && (
                                                    <>
                                                        <div className="text-slate-500 break-all">Expected: {d.expected}</div>
                                                        <div className="text-slate-500 break-all">Got: {d.got}</div>
                                                    </>
                                                )}
                                                {d.matches && d.expected && d.expected === d.got && (
                                                    <div className="text-emerald-600 break-all">SHA-256: {d.got}</div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* Raw signed content preview (collapsed) */}
                                <details className="text-xs">
                                    <summary className="cursor-pointer text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 font-medium">
                                        View raw signed content
                                    </summary>
                                    <pre className="mt-2 p-3 bg-slate-50 dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-700 font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                                        {proof.data.document.content}
                                    </pre>
                                </details>
                            </div>
                        );
                    })()}
                </div>
            )}
        </div>
    );
}
