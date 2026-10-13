// Test identities in the crypto-core 4 shape: an address (the SHA-384 of the
// identity key), the composite identity key and its seed, and an X-Wing
// encryption key. In 3.x a test could use one ML-DSA key for both the address
// and the key; these keep the two apart, which is what the code under test
// has to do too.
import { generateAccount, attestEncryptionKey } from '../utils/crypto';

/** A fresh identity. */
export const makeSigner = (name = 'U') => {
    const account = generateAccount(name);
    return {
        account,
        address: account.id,
        identityPublicKey: account.identity.publicKey,
        seed: account.identity.seed,
        encryptionPublicKey: account.encryption.publicKey,
        encryptionSeed: account.encryption.seed,
    };
};

/** The user record the server's directory serves for `signer`, attested. */
export const directoryRecord = async (signer, username = 'U') => ({
    address: signer.address,
    identity_public_key: signer.identityPublicKey,
    username,
    encryption_public_key: signer.encryptionPublicKey,
    encryption_key_attestation: await attestEncryptionKey(
        { address: signer.address, encryptionPublicKey: signer.encryptionPublicKey }, signer.seed
    ),
});
