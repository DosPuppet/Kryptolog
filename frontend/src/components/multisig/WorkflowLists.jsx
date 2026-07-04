import { Check, User } from 'lucide-react';
import SignerVerificationBadge from './SignerVerificationBadge';

// Presentational lists for the workflow modal: signers (with the implicit
// creator and per-signature verification badges) and recipients.

export const SignersList = ({ workflow, user, decryptedContent, creatorSignature, creatorSignedContent }) => {
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

    return (
        <div>
            <h4 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Signers</h4>
            <div className="space-y-2">
                {displayedSigners.map(s => (
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
                                verifyTarget={s.isCreator
                                    ? { kind: 'content', content: creatorSignedContent }
                                    : {
                                        kind: 'approval',
                                        workflowId: workflow.id,
                                        secretId: workflow.secret_id,
                                        encryptedData: workflow.secret?.encrypted_data,
                                    }}
                            />
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
};

export const RecipientsList = ({ workflow }) => (
    <div>
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
    </div>
);
