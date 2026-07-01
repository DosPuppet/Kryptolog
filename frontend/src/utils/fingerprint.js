// Verifiable identity fingerprint ("safety number") — audit S1.
//
// The server is the key directory: clients fetch a contact's public keys from
// the API, and a malicious/compromised server could serve substituted keys.
// There is no in-band way to detect that, so we give users an out-of-band one:
// a short, deterministic digest over a contact's public identity (their
// address / ML-DSA key + their ML-KEM encryption key). Two people compare these
// (read aloud, scan, etc.); a mismatch means the directory served different
// keys to each side. Display-only — never sent to the server.

export const safetyNumber = async (address, encryptionPublicKey) => {
    if (!address && !encryptionPublicKey) return null;
    const data = new TextEncoder().encode(`${address || ''}|${encryptionPublicKey || ''}`);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    // First 10 bytes (80 bits) -> 5 space-separated groups of 4 hex chars.
    const hex = [...digest.slice(0, 10)]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
    return hex.match(/.{4}/g).join(' ');
};
