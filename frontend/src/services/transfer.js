// Device-to-device key transfer relay client.
//
// The vault is encrypted client-side under a one-time passphrase BEFORE it
// reaches here; this module only moves the resulting ciphertext blob through the
// server. The passphrase is carried out of band (QR / typed code) and never
// touches the network, so the relay stays zero-knowledge.
import API_ENDPOINTS from '../config';

// Upload an encrypted vault blob; returns { id, expires_at }. Requires a session.
export const uploadTransfer = async (ciphertext, token) => {
    const res = await fetch(API_ENDPOINTS.TRANSFERS.CREATE, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ ciphertext }),
    });
    if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.detail || `Upload failed (${res.status})`);
    }
    return res.json();
};

// Claim (single-use) an encrypted vault blob by id. No auth — the target device
// has no identity yet; the unguessable id + short TTL are the protection.
export const claimTransfer = async (id) => {
    const res = await fetch(API_ENDPOINTS.TRANSFERS.CLAIM(id));
    if (res.status === 404) {
        throw new Error("Transfer not found or expired — it may have already been used. Generate a new code on the sending device.");
    }
    if (!res.ok) throw new Error(`Fetch failed (${res.status})`);
    const data = await res.json();
    return data.ciphertext;
};

// Pack/unpack the out-of-band hand-off string "<id>.<passphrase>". The QR
// encodes a deep link to /receive carrying this in the URL FRAGMENT (after #),
// which browsers never send to the server.
export const packHandoff = (id, passphrase) => `${id}.${passphrase}`;
export const unpackHandoff = (str) => {
    const trimmed = (str || '').trim();
    const dot = trimmed.indexOf('.');
    if (dot < 1) return null;
    const id = trimmed.slice(0, dot);
    const passphrase = trimmed.slice(dot + 1);
    if (!id || !passphrase) return null;
    return { id, passphrase };
};
