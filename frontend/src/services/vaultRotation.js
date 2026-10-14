// Replacing the active identity's encryption key in the local vault
// (crypto-core 5.1.0). Mixed into VaultService like the backup and biometric
// methods.
//
// The order is the point: the rotated account is SAVED before anything is
// published, so the server never serves a key this device could lose — and
// if the server then refuses it, `revertEncryptionKeyRotation` puts the old
// key back, since a key nobody was told about must not become the one the
// next rotation is signed from. The seeds never leave this file's methods.

import {
    rotateAccountEncryptionKey, revertAccountEncryptionKeyRotation, destroyRetiredEncryptionKey,
    attestEncryptionKey, signKeyRotation,
} from '../utils/crypto';

async function withActiveAccount(service, password, change) {
    if (service.isLocked) throw new Error("Vault locked");
    const fullVault = await service._getFullVault(password);
    const index = fullVault.accounts.findIndex(a => a.id === fullVault.activeAccountId);
    if (index < 0) throw new Error("Active account not found in vault");
    const result = await change(fullVault.accounts[index]);
    fullVault.accounts[index] = result.account;
    await service._save(fullVault, password);
    service.vault.accounts = service.vault.accounts.map(
        a => (a.id === result.account.id ? service._sanitize(result.account) : a)
    );
    return result;
}

export const rotationMethods = {
    /**
     * Rotate, persist, and sign what the server needs: the new key, its
     * attestation, and the rotation from the key it holds now.
     */
    async rotateEncryptionKey(password, { ts }) {
        const { published } = await withActiveAccount(this, password, async (account) => {
            const rotated = rotateAccountEncryptionKey(account, ts);
            const seed = account.identity.seed;
            return {
                account: rotated,
                published: {
                    encryptionPublicKey: rotated.encryption.publicKey,
                    oldKid: account.encryption.kid,
                    newKid: rotated.encryption.kid,
                    attestation: await attestEncryptionKey(
                        { address: account.id, encryptionPublicKey: rotated.encryption.publicKey }, seed
                    ),
                    signature: await signKeyRotation(
                        { address: account.id, oldKid: account.encryption.kid, newKid: rotated.encryption.kid, ts },
                        seed
                    ),
                },
            };
        });
        return published;
    },

    async revertEncryptionKeyRotation(password, newKid) {
        await withActiveAccount(this, password, async (account) => ({
            account: revertAccountEncryptionKeyRotation(account, newKid),
        }));
    },

    async destroyRetiredEncryptionKey(password, kid) {
        await withActiveAccount(this, password, async (account) => ({
            account: destroyRetiredEncryptionKey(account, kid),
        }));
    },
};
