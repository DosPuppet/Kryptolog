import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { usePQC } from '../context/PQCContext';
import API_ENDPOINTS from '../config';
import { generateSymmetricKey, encryptSymmetric, decryptSymmetric, domainSeparate, SIGNING_CONTEXT } from '../utils/crypto';
import { encryptData, decryptData } from '../utils/web3';
import { uploadChunkedFile, downloadChunkedFile, uploadMultipleChunkedFiles, downloadFileByRange, CHUNK_SIZE } from '../utils/fileChunks';

export function useSecrets(authType, encryptionPublicKey, pqcAccount, options = {}) {
    const { token, user } = useAuth();
    const { encrypt: encryptPQC, decrypt: decryptPQC, sign: signPQC } = usePQC();
    const { onProgress } = options;

    const [secrets, setSecrets] = useState([]);
    const [sharedSecrets, setSharedSecrets] = useState([]);
    const [loading, setLoading] = useState(true);
    const [decryptedSecrets, setDecryptedSecrets] = useState({});

    // Load secrets once authenticated. The fetchers close only over the
    // current token, so token is the only meaningful trigger.
    useEffect(() => {
        if (token) {
            fetchSecrets();
            fetchSharedSecrets();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    const reportProgress = (percent, msg) => {
        if (onProgress) onProgress(percent, msg);
    };

    const fetchSecrets = async () => {
        try {
            const res = await fetch(API_ENDPOINTS.SECRETS.LIST, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setSecrets(data);
            }
        } catch (error) {
            console.error("Failed to fetch secrets", error);
        } finally {
            setLoading(false);
        }
    };

    const fetchSharedSecrets = async () => {
        try {
            const res = await fetch(API_ENDPOINTS.SECRETS.SHARED_WITH, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setSharedSecrets(data);
            }
        } catch (error) {
            console.error("Failed to fetch shared secrets", error);
        }
    };

    const secureDecrypt = async (encryptedString) => {
        try {
            const parsed = JSON.parse(encryptedString);
            // Check for TrustKeys (PQC) format: {kem, iv, content}
            if (parsed.kem && parsed.iv && parsed.content && authType === 'trustkeys') {
                return await decryptPQC(parsed);
            }

            // Fallback to MetaMask decryption
            return decryptData(encryptedString, user.address);
        } catch (e) {
            return decryptData(encryptedString, user.address);
        }
    };

    const secureEncrypt = async (content, pubKey) => {
        if (authType === 'trustkeys') {
            const res = await encryptPQC(content, pubKey);
            return JSON.stringify(res);
        } else {
            return encryptData(content, pubKey);
        }
    };

    const handleDecrypt = async (item, isShared = false) => {
        reportProgress(10, 'Decrypting Key...');
        try {
            // Envelope Encryption Flow
            const encKeyBlob = item.encrypted_key;
            if (!encKeyBlob) {
                throw new Error("Missing encryption key. Legacy secrets are not supported.");
            }

            // 1. Decrypt AES Key
            const fileKey = await secureDecrypt(encKeyBlob);

            // 2. Decrypt Content
            reportProgress(50, 'Decrypting Content...');
            const encryptedDataHex = isShared ? item.secret.encrypted_data : item.encrypted_data;

            const encDataObj = JSON.parse(encryptedDataHex);
            const decrypted = await decryptSymmetric(encDataObj, fileKey);

            // Check if this is a chunked file (metadata-only in encrypted_data)
            try {
                // Determine if we need to parse wrapped signed content or direct content
                let meta = JSON.parse(decrypted);
                let isSignedOuter = false;
                let outerPayload = null;

                // If it's a signed_document, the meta is wrapped inside .content
                if (meta.signature && meta.signerPublicKey && meta.content) {
                    isSignedOuter = true;
                    outerPayload = meta;
                    meta = JSON.parse(meta.content);
                }

                if (meta.files && Array.isArray(meta.files)) {
                    // Multi-file metadata — download each file by range
                    reportProgress(60, 'Downloading files...');
                    const secretId = isShared ? item.secret.id : item.id;
                    const fileResults = [];

                    for (let fi = 0; fi < meta.files.length; fi++) {
                        const fileMeta = meta.files[fi];
                        const blob = await downloadFileByRange(
                            secretId, fileKey, token, API_ENDPOINTS.BASE,
                            fileMeta.chunk_offset, fileMeta.total_chunks, fileMeta.mime_type,
                            (pct, msg) => {
                                const overallPct = Math.round(((fi + pct / 100) / meta.files.length) * 100);
                                reportProgress(60 + Math.round(overallPct * 0.35), msg);
                            }
                        );
                        fileResults.push({
                            name: fileMeta.file_name,
                            mime: fileMeta.mime_type,
                            content: URL.createObjectURL(blob),
                            size: fileMeta.total_size
                        });
                    }

                    let result;
                    if (isSignedOuter) {
                        result = JSON.stringify({
                            ...outerPayload,
                            fileUrls: fileResults,
                            fileMeta: meta
                        });
                    } else {
                        result = JSON.stringify({
                            type: 'files',
                            items: fileResults,
                            chunked: true
                        });
                    }

                    const key = isShared ? `shared_${item.id}` : item.id;
                    setDecryptedSecrets(prev => ({ ...prev, [key]: result }));
                    reportProgress(100, 'Decrypted');
                    setTimeout(() => reportProgress(0, ''), 500);
                    return result;
                } else if (meta.total_chunks && meta.total_chunks > 0 && meta.file_name) {
                    // Single-file chunked metadata (legacy format)
                    reportProgress(60, 'Downloading file chunks...');
                    const blob = await downloadChunkedFile(
                        isShared ? item.secret.id : item.id,
                        fileKey,
                        token,
                        API_ENDPOINTS.BASE,
                        meta.total_chunks,
                        meta.mime_type,
                        (pct, msg) => reportProgress(60 + Math.round(pct * 0.35), msg)
                    );
                    const blobUrl = URL.createObjectURL(blob);

                    let result;
                    if (isSignedOuter) {
                        result = JSON.stringify({
                            ...outerPayload,
                            fileUrl: blobUrl,
                            fileMeta: meta
                        });
                    } else {
                        result = JSON.stringify({
                            type: 'file',
                            name: meta.file_name,
                            mime: meta.mime_type,
                            content: blobUrl,
                            chunked: true,
                            size: meta.total_size
                        });
                    }

                    const key = isShared ? `shared_${item.id}` : item.id;
                    setDecryptedSecrets(prev => ({ ...prev, [key]: result }));
                    reportProgress(100, 'Decrypted');
                    setTimeout(() => reportProgress(0, ''), 500);
                    return result;
                }
            } catch (_) {
                // Not JSON or not chunked — proceed with normal flow
            }

            // Check for legacy file format (base64 in JSON) -> Convert to Blob URL for consistency
            try {
                const parsed = JSON.parse(decrypted);
                if (parsed && parsed.type === 'file' && parsed.content && parsed.content.startsWith('data:')) {
                    // Convert data URI to Blob
                    const byteString = atob(parsed.content.split(',')[1]);
                    const mimeString = parsed.content.split(',')[0].split(':')[1].split(';')[0];
                    const ab = new ArrayBuffer(byteString.length);
                    const ia = new Uint8Array(ab);
                    for (let i = 0; i < byteString.length; i++) ia[i] = byteString.charCodeAt(i);
                    const blob = new Blob([ab], { type: mimeString });
                    const blobUrl = URL.createObjectURL(blob);

                    const result = JSON.stringify({
                        ...parsed,
                        content: blobUrl, // Replace base64 with blob URL
                        chunked: false // Explicitly mark as not chunked (legacy)
                    });

                    const key = isShared ? `shared_${item.id}` : item.id;
                    setDecryptedSecrets(prev => ({ ...prev, [key]: result }));
                    reportProgress(100, 'Decrypted');
                    setTimeout(() => reportProgress(0, ''), 500);
                    return result;
                }
            } catch { /* best-effort: failure is non-fatal */ }

            const key = isShared ? `shared_${item.id}` : item.id;
            setDecryptedSecrets(prev => ({ ...prev, [key]: decrypted }));
            reportProgress(100, 'Decrypted');
            setTimeout(() => reportProgress(0, ''), 500);
            return decrypted;
        } catch (e) {
            console.error(e);
            reportProgress(0, '');
            throw new Error("Decryption failed: " + e.message);
        }
    };

    const createSecret = async (name, type, rawContent, isSigned = false, files = null) => {
        reportProgress(10, 'Preparing Envelope...');
        try {
            // 1. Generate AES-256 Key
            const fileKey = await generateSymmetricKey();

            // 3. Prepare Payload (Signed or Raw)
            let payloadToEncrypt = rawContent;
            let secretType = type;
            let isChunkedFile = false;
            let fileMetadataStr = null;

            // Normalize: accept single File or File[] array
            const fileList = files ? (Array.isArray(files) ? files : [files]) : null;

            if (fileList && fileList.length > 0) {
                isChunkedFile = true;

                if (fileList.length === 1) {
                    // Single file: use legacy format for backward compat
                    const file = fileList[0];
                    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

                    let fileHash = null;
                    if (isSigned) {
                        reportProgress(15, 'Hashing File...');
                        const arrayBuffer = await file.arrayBuffer();
                        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
                        const hashArray = Array.from(new Uint8Array(hashBuffer));
                        fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    }

                    fileMetadataStr = JSON.stringify({
                        file_name: file.name,
                        mime_type: file.type || 'application/octet-stream',
                        total_chunks: totalChunks,
                        total_size: file.size,
                        chunk_size: CHUNK_SIZE,
                        file_hash: fileHash
                    });
                } else {
                    // Multiple files: new multi-file metadata format
                    let chunkOffset = 0;
                    const filesMetaArray = [];

                    if (isSigned) {
                        reportProgress(15, 'Hashing Files...');
                    }

                    for (const file of fileList) {
                        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
                        let fileHash = null;

                        if (isSigned) {
                            const arrayBuffer = await file.arrayBuffer();
                            const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
                            const hashArray = Array.from(new Uint8Array(hashBuffer));
                            fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                        }

                        filesMetaArray.push({
                            file_name: file.name,
                            mime_type: file.type || 'application/octet-stream',
                            total_chunks: totalChunks,
                            total_size: file.size,
                            chunk_offset: chunkOffset,
                            file_hash: fileHash
                        });
                        chunkOffset += totalChunks;
                    }

                    fileMetadataStr = JSON.stringify({
                        files: filesMetaArray,
                        total_chunks: chunkOffset,
                        chunk_size: CHUNK_SIZE
                    });
                }

                payloadToEncrypt = fileMetadataStr;
            }

            if (isSigned) {
                reportProgress(20, 'Signing...');
                // Domain-separate under the `content` context (H1) so this document
                // signature can never be replayed as a login challenge.
                const signature = await signPQC(domainSeparate(SIGNING_CONTEXT.CONTENT, payloadToEncrypt));
                const signedPayload = {
                    content: payloadToEncrypt,
                    signature: signature,
                    signerPublicKey: pqcAccount
                };
                payloadToEncrypt = JSON.stringify(signedPayload);
                secretType = 'signed_document';
            }

            // 4. Encrypt Content with AES Key
            reportProgress(40, 'Encrypting Content (AES)...');
            const encryptedContentIdx = await encryptSymmetric(payloadToEncrypt, fileKey);
            const encryptedDataStr = JSON.stringify(encryptedContentIdx);

            // 4. Encrypt AES Key for Owner (Me)
            reportProgress(50, 'Encrypting Key...');
            let encryptedKeyForMe;
            if (authType === 'trustkeys') {
                const res = await encryptPQC(fileKey, encryptionPublicKey);
                encryptedKeyForMe = JSON.stringify(res);
            } else {
                encryptedKeyForMe = encryptData(fileKey, encryptionPublicKey);
            }

            // 5. Send to API (creates the secret record)
            reportProgress(60, 'Creating secret...');
            const res = await fetch(API_ENDPOINTS.SECRETS.CREATE, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    name,
                    type: secretType,
                    encrypted_data: encryptedDataStr,
                    encrypted_key: encryptedKeyForMe
                })
            });

            if (!res.ok) throw new Error(await res.text());
            const createdSecret = await res.json();

            // 6. Upload chunks
            if (isChunkedFile) {
                reportProgress(65, 'Uploading encrypted chunks...');
                if (fileList.length === 1) {
                    await uploadChunkedFile(
                        fileList[0],
                        createdSecret.id,
                        fileKey,
                        token,
                        API_ENDPOINTS.BASE,
                        (pct, msg) => reportProgress(65 + Math.round(pct * 0.30), msg)
                    );
                } else {
                    await uploadMultipleChunkedFiles(
                        fileList,
                        createdSecret.id,
                        fileKey,
                        token,
                        API_ENDPOINTS.BASE,
                        (pct, msg) => reportProgress(65 + Math.round(pct * 0.30), msg)
                    );
                }
            }

            await fetchSecrets();
            reportProgress(100, 'Saved');
            setTimeout(() => reportProgress(0, ''), 500);
            return true;
        } catch (e) {
            reportProgress(0, '');
            throw e;
        }
    };

    const updateSecret = async (id, name, content) => {
        reportProgress(30, 'Encrypting...');
        try {
            const encrypted = await secureEncrypt(content, encryptionPublicKey);
            reportProgress(60, 'Updating...');
            const res = await fetch(API_ENDPOINTS.SECRETS.UPDATE(id), {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    name,
                    encrypted_data: encrypted
                })
            });

            if (!res.ok) throw new Error("Update failed");

            setDecryptedSecrets(prev => ({ ...prev, [id]: content }));
            await fetchSecrets();
            reportProgress(100, 'Updated');
            setTimeout(() => reportProgress(0, ''), 500);
            return true;
        } catch (e) {
            reportProgress(0, '');
            throw e;
        }
    };

    const deleteSecret = async (id) => {
        const res = await fetch(API_ENDPOINTS.SECRETS.DELETE(id), {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
            setSecrets(prev => prev.filter(s => s.id !== id));
        }
        return res.ok;
    };

    const shareSecret = async (secretId, originalEncryptedKey, recipientAddress, recipientPublicKey, expiry = 0) => {
        // 1. Decrypt the File Key (AES)
        // We need the key, not the content.
        // The UI might pass 'originalEncryptedKey' (which is the key for ME).
        // Wait, the function signature passed 'originalEncryptedData' in old version.
        // We likely need to pass the encrypted_key now.
        // Assuming the UI calls this with the Owner's 'encrypted_key'.

        const fileKey = await secureDecrypt(originalEncryptedKey);

        // 2. Re-encrypt the File Key for Recipient
        let reEncryptedKey;
        if (recipientPublicKey && recipientPublicKey.length > 60) {
            try {
                const res = await encryptPQC(fileKey, recipientPublicKey);
                reEncryptedKey = JSON.stringify(res);
            } catch (e) {
                throw new Error("TrustKeys required to share with this user.");
            }
        } else {
            reEncryptedKey = encryptData(fileKey, recipientPublicKey);
        }

        // 3. API Call
        const res = await fetch(API_ENDPOINTS.SECRETS.SHARE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                secret_id: secretId,
                grantee_address: recipientAddress,
                encrypted_key: reEncryptedKey,
                expires_in: expiry > 0 ? expiry : null
            })
        });

        return res.ok;
    };

    const revokeGrant = async (grantId, isSharedView = false) => {
        const res = await fetch(API_ENDPOINTS.SECRETS.REVOKE(grantId), {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (res.ok) {
            if (isSharedView) {
                setSharedSecrets(prev => prev.filter(g => g.id !== grantId));
            }
            // If viewing access list, caller handles update
        }
        return res.ok;
    };

    // Re-lock a decrypted secret: drop its plaintext from memory so it's hidden again.
    const handleLock = (item, isShared = false) => {
        const key = isShared ? `shared_${item.id}` : item.id;
        setDecryptedSecrets(prev => {
            if (!(key in prev)) return prev;
            const next = { ...prev };
            delete next[key];
            return next;
        });
    };

    return {
        secrets,
        sharedSecrets,
        loading,
        decryptedSecrets,
        secureDecrypt, // Exporting for manual usage if needed
        handleDecrypt,
        handleLock,
        createSecret,
        updateSecret,
        deleteSecret,
        shareSecret,
        revokeGrant,
        fetchSecrets, // For manual refresh
        fetchSharedSecrets
    };
}
