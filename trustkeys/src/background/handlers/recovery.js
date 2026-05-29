import { deriveShareA, createShareB, recoverSecret, toHex, fromHex } from '../../utils/mpc.js';
import { state } from '../state.js';
import { saveVault } from '../utils.js';

export const backupToGoogle = async (request) => {
    if (state.isLocked) throw new Error("Vault is locked");
    const { password, token } = request;
    const { devMode } = await chrome.storage.local.get('devMode');
    const apiBase = devMode ? 'http://localhost:8000' : 'https://safeapi.hashpar.com';

    const account = state.vault.accounts.find(a => a.id === state.vault.activeAccountId) || state.vault.accounts[0];
    if (!account) throw new Error("No account to backup");

    const privKeyBytes = fromHex(account.dilithium.privateKey);
    const salt = "safelog_mpc_v1";
    const shareA = await deriveShareA(password, salt, privKeyBytes.length);
    const shareB = createShareB(privKeyBytes, shareA);
    const shareBHex = toHex(shareB);

    const kybSalt = salt + "_kyber";
    const kybPrivBytes = fromHex(account.kyber.privateKey);
    const kybShareA = await deriveShareA(password, kybSalt, kybPrivBytes.length);
    const kybShareB = createShareB(kybPrivBytes, kybShareA);

    const res = await fetch(`${apiBase}/recovery/store`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            token,
            share_data: JSON.stringify({
                type: 'dilithium_mpc',
                shareB: shareBHex,
                name: account.name,
                dilithiumPublicKey: account.dilithium.publicKey,
                kyberPublicKey: account.kyber.publicKey,
                kyberShareB: toHex(kybShareB)
            })
        })
    });

    if (!res.ok) throw new Error("Upload failed: " + res.status);
    return { success: true };
};

export const restoreFromGoogle = async (request) => {
    const { password, token } = request;
    const { devMode } = await chrome.storage.local.get('devMode');
    const apiBase = devMode ? 'http://localhost:8000' : 'https://safeapi.hashpar.com';

    const apiRes = await fetch(`${apiBase}/recovery/fetch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });

    if (!apiRes.ok) throw new Error("Fetch failed (Check Token or No Backup)");
    const { share_data } = await apiRes.json();
    const backupData = JSON.parse(share_data);

    const salt = "safelog_mpc_v1";
    const dimShareB = fromHex(backupData.shareB);
    const dimShareA = await deriveShareA(password, salt, dimShareB.length);
    const dimPrivKey = recoverSecret(dimShareA, dimShareB);

    const kybShareB = fromHex(backupData.kyberShareB);
    const kybShareA = await deriveShareA(password, salt + "_kyber", kybShareB.length);
    const kybPrivKey = recoverSecret(kybShareA, kybShareB);

    const newAccount = {
        id: Date.now(),
        name: backupData.name + " (Recovered)",
        dilithium: {
            publicKey: backupData.dilithiumPublicKey,
            privateKey: toHex(dimPrivKey)
        },
        kyber: {
            publicKey: backupData.kyberPublicKey,
            privateKey: toHex(kybPrivKey)
        },
        createdAt: new Date().toISOString()
    };

    if (!state.vault) {
        if (!state.hasPassword) throw new Error("Please set up a password first");
        throw new Error("Vault locked");
    }

    state.vault.accounts.push(newAccount);
    await saveVault(password);

    return { success: true, count: 1 };
};
