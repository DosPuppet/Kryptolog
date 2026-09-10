// WebAuthn PRF, for unlocking a vault with a hardware-bound biometric key.
//
// The only module here that needs `window`. It is used by the SPA alone; the
// extension's service worker imports the package root and never reaches these.

// --- WebAuthn PRF (Biometric Vault) ---

export const checkPrfSupport = async () => {
    try {
        if (!window.PublicKeyCredential) return false;
        // We can't reliably detect PRF support before attempting credential creation.
        // The actual check happens during registration by inspecting extension results.
        return true;
    } catch (e) {
        return false;
    }
};

/**
 * Creates a new WebAuthn credential for biometric vault unlock.
 *
 * Requires a HARDWARE-BOUND key via the WebAuthn PRF extension (iOS, modern
 * desktop Chrome/Firefox). There is intentionally no software fallback: a
 * non-hardware-bound key would have to live in JS-readable storage, which
 * defeats the vault's at-rest encryption. On devices without PRF this throws
 * and biometric unlock is simply not offered.
 *
 * Returns: { mode: 'prf', credentialId, prfKey (hex), prfSalt (hex) }
 */
export const registerBiometricCredential = async (username) => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const prfSalt = crypto.getRandomValues(new Uint8Array(32));

    const creationOptions = {
        publicKey: {
            challenge,
            rp: {
                name: "Kryptolog Vault",
                id: window.location.hostname
            },
            user: {
                id: userId,
                name: username,
                displayName: username
            },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 },   // ES256
                { type: "public-key", alg: -257 }  // RS256
            ],
            authenticatorSelection: {
                // 'platform' forces the device's own biometrics (fingerprint/face)
                // instead of the cross-device picker (Bluetooth/QR/another phone)
                authenticatorAttachment: "platform",
                residentKey: "preferred",
                userVerification: "required"
            },
            extensions: {
                prf: {
                    eval: { first: prfSalt }
                }
            }
        }
    };

    const credential = await navigator.credentials.create(creationOptions);
    const extResults = credential.getClientExtensionResults();

    // Hardware-bound PRF path (iOS, desktop Chrome, Firefox).
    if (extResults.prf && extResults.prf.results && extResults.prf.results.first) {
        const prfBytes = new Uint8Array(extResults.prf.results.first);
        return {
            mode: 'prf',
            credentialId: credential.id,
            prfKey: toHex(prfBytes),
            prfSalt: toHex(prfSalt)
        };
    }

    // No PRF => no hardware-bound key. We deliberately do NOT fall back to a
    // localStorage-stored key (that would expose a vault-unlocking secret to any
    // XSS / local read). Biometric unlock is unavailable; the user uses their password.
    throw new Error(
        "This device doesn't support hardware-bound biometric keys (WebAuthn PRF), " +
        "so biometric unlock isn't available here. You can still unlock with your password."
    );
};

/**
 * Authenticates with an existing credential and derives the hardware-bound key
 * from the WebAuthn PRF extension result. Returns the key as hex.
 *
 * `mode` exists only to reject legacy 'fallback' credentials (the insecure
 * localStorage path has been removed) — those users must re-enable biometrics.
 */
export const getBiometricKey = async (credentialId, prfSaltHex, mode = 'prf') => {
    if (mode !== 'prf') {
        throw new Error(
            "This biometric credential uses an unsupported legacy mode. Please disable " +
            "and re-enable biometric unlock to use a hardware-bound key."
        );
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const extensions = {
        prf: {
            eval: {
                first: prfSaltHex ? fromHex(prfSaltHex) : new Uint8Array(32).fill(1)
            }
        }
    };

    const requestOptions = {
        publicKey: {
            challenge,
            rpId: window.location.hostname,
            allowCredentials: [{
                id: fromBase64Url(credentialId),
                type: "public-key",
                // 'internal' hints to Chrome that this is a platform credential
                // preventing the cross-device (Bluetooth/QR) picker from appearing
                transports: ["internal"]
            }],
            userVerification: "required",
            extensions
        }
    };

    // This triggers the biometric prompt on the device
    const assertion = await navigator.credentials.get(requestOptions);

    const extResults = assertion.getClientExtensionResults();
    if (!extResults.prf || !extResults.prf.results || !extResults.prf.results.first) {
        throw new Error("Biometric auth succeeded but PRF key was not returned. Your device may not support hardware-bound biometrics.");
    }
    return toHex(new Uint8Array(extResults.prf.results.first));
};

// Helper for Base64URL -> Uint8Array
const fromBase64Url = (str) => {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd((base64.length + 3) & ~3, '=');
    const bin = atob(padded);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        arr[i] = bin.charCodeAt(i);
    }
    return arr;
};
