// Web3 / MetaMask (Ethereum) helpers.
//
// Split out of crypto.js so the heavy `ethers` / `@metamask/eth-sig-util`
// dependency (and its Node polyfills) stops leaking into every post-quantum
// consumer and the crypto test infra. Only MetaMask-auth code paths import this.
import { Buffer } from 'buffer';
import { encrypt } from '@metamask/eth-sig-util';
import { verifyMessage, BrowserProvider } from 'ethers';

export const connectWallet = async () => {
    if (!window.ethereum) {
        throw new Error("MetaMask not found. Please install it.");
    }
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    return accounts[0];
};

export const getEncryptionPublicKey = async (address) => {
    if (!window.ethereum) {
        throw new Error("MetaMask not found.");
    }
    try {
        const key = await window.ethereum.request({
            method: 'eth_getEncryptionPublicKey',
            params: [address],
        });
        return key;
    } catch (error) {
        if (error.code === 4001) {
            throw new Error("User rejected public key request");
        }
        throw error;
    }
};

export const encryptData = (data, publicKey) => {
    const encrypted = encrypt({
        publicKey: publicKey,
        data: data,
        version: 'x25519-xsalsa20-poly1305',
    });
    return JSON.stringify(encrypted);
};

export const decryptData = async (encryptedDataStr, address) => {
    if (!window.ethereum) {
        throw new Error("MetaMask not found.");
    }
    try {
        const hexEncoded = '0x' + Buffer.from(encryptedDataStr).toString('hex');

        const decrypted = await window.ethereum.request({
            method: 'eth_decrypt',
            params: [hexEncoded, address],
        });
        return decrypted;
    } catch (error) {
        console.error("Decryption failed:", error);
        throw error;
    }
};

// --- Web3 Signature (Legacy Name) ---
export const signMessage = async (message, address) => {
    const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [message, address],
    });
    return signature;
};

// Safe Ethers-based signing (matches verifyMessage)
export const signMessageEth = async (message) => {
    try {
        const provider = new BrowserProvider(window.ethereum);
        const signer = await provider.getSigner();
        // Ethers handles hex/string conversion automatically matching verifyMessage
        return await signer.signMessage(message);
    } catch (e) {
        console.error("signMessageEth failed", e);
        throw e;
    }
};

export const verifyMessageEth = (message, signature) => {
    try {
        return verifyMessage(message, signature);
    } catch (e) {
        console.error("Eth signature verification failed", e);
        return null;
    }
};
