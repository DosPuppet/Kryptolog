// Verifiable identity fingerprint ("safety number") — audit S1/M-1.
//
// The server is the key directory: clients fetch a contact's public keys from
// the API, and a malicious/compromised server could serve substituted keys.
// The attestation (trustedKeys.attestationStatus) detects a substituted KEM
// key cryptographically; this fingerprint covers the remaining out-of-band
// step — confirming you have the right IDENTITY (address) in the first place.
// Two people compare these (read aloud, scan, etc.); a mismatch means the
// directory served different keys to each side. Display-only — never sent to
// the server.
//
// The digest/format lives in crypto-core (keyFingerprint) so the SPA and the
// extension render the identical number for the same contact.

import { keyFingerprint } from './crypto';

export const safetyNumber = async (address, encryptionPublicKey) => {
    if (!address && !encryptionPublicKey) return null;
    return keyFingerprint((address || '').toLowerCase(), encryptionPublicKey || '');
};
