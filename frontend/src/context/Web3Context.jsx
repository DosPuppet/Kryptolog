import React, { createContext, useState, useEffect, useContext } from 'react';
import API_ENDPOINTS from '../config';
import { connectWallet, getEncryptionPublicKey, signMessage } from '../utils/crypto';
import { useAuth } from './AuthContext';

const Web3Context = createContext();

export const useWeb3 = () => useContext(Web3Context);

export const Web3Provider = ({ children }) => {
    const { login: authLogin } = useAuth();
    const [currentAccount, setCurrentAccount] = useState(null);
    const [encryptionPublicKey, setEncryptionPublicKey] = useState(null);

    const checkWalletConnection = async () => {
        if (window.ethereum) {
            const accounts = await window.ethereum.request({ method: 'eth_accounts' });
            if (accounts.length > 0) {
                setCurrentAccount(accounts[0]);
            }
        }
    };

    useEffect(() => {
        checkWalletConnection();

        if (window.ethereum) {
            window.ethereum.on('accountsChanged', (accounts) => {
                if (accounts.length > 0) {
                    setCurrentAccount(accounts[0]);
                    // Note: We might want to logout on account change, but AuthContext handles user state.
                    // For now, let's just update the local account.
                    // Ideally, we should trigger a logout in AuthContext if the user changes wallet.
                } else {
                    setCurrentAccount(null);
                }
            });
        }
    }, []);

    const login = async () => {
        // Ensure we have an account
        let account = currentAccount;
        if (!account) {
            account = await connectWallet();
            setCurrentAccount(account);
        }

        // 1. Get Nonce
        const nonceRes = await fetch(API_ENDPOINTS.AUTH.NONCE(account));
        const { nonce } = await nonceRes.json();

        // 2. Sign Nonce
        const message = `Sign in to Secure Log App with nonce: ${nonce}`;
        const signature = await signMessage(message, account);

        // 3. Get Encryption Public Key
        let pubKey = encryptionPublicKey;
        if (!pubKey) {
            try {
                pubKey = await getEncryptionPublicKey(account);
                setEncryptionPublicKey(pubKey);
            } catch (e) {
                console.warn("User rejected public key request", e);
            }
        }

        // 4. Verify on Backend
        const loginRes = await fetch(API_ENDPOINTS.AUTH.LOGIN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: account,
                signature,
                nonce,
                encryption_public_key: pubKey,
                username: account // Use ETH Address as default username for MetaMask users
            })
        });

        if (loginRes.ok) {
            const data = await loginRes.json();
            authLogin(data.user, 'metamask', data.access_token); // Update Global Auth State
            return data.user;
        } else {
            throw new Error("Login failed");
        }
    };

    return (
        <Web3Context.Provider value={{
            currentAccount,
            encryptionPublicKey,
            connect: connectWallet,
            login,
        }}>
            {children}
        </Web3Context.Provider>
    );
};

