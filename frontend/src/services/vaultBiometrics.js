// Biometric (FaceID/TouchID) unlock methods for VaultService. Defined here and
// merged onto VaultService.prototype in vault.js — `this` is the singleton.
// WebAuthn PRF only (hardware-bound); there is deliberately NO software fallback.
export const biometricMethods = {

    hasBiometrics() {
        const prefs = localStorage.getItem('kryptolog_biometrics');
        return !!prefs;
    },

    async enableBiometrics(password) {
        if (!window.PublicKeyCredential) throw new Error("Biometrics not supported on this device/browser.");

        // 1. Verify Password First
        const fullVault = await this._getFullVault(password); // will throw if wrong

        // 2. Register Credential (PRF or Fallback)
        const activeAcct = fullVault.accounts.find(a => a.id === fullVault.activeAccountId);
        const name = activeAcct ? activeAcct.name : "Kryptolog User";

        const { registerBiometricCredential, encryptSymmetric, checkPrfSupport } = await import('../utils/crypto');

        if (!await checkPrfSupport()) {
            throw new Error("Your browser does not support WebAuthn. Biometrics unavailable.");
        }

        // Throws on devices without hardware-bound PRF — there is no software fallback.
        const result = await registerBiometricCredential(name);

        // 3. Encrypt the vault password with the hardware-bound PRF key
        const encryptedPass = await encryptSymmetric(password, result.prfKey);

        // Clear any key left by the removed legacy fallback path.
        localStorage.removeItem('kryptolog_bio_fallback_key');

        // 4. Save Preferences
        const prefs = {
            mode: 'prf',
            credentialId: result.credentialId,
            encryptedPass,
            prfSalt: result.prfSalt
        };
        localStorage.setItem('kryptolog_biometrics', JSON.stringify(prefs));

        return 'prf';
    },

    // Concurrent callers share ONE ceremony.
    //
    // WebAuthn allows a single outstanding navigator.credentials.get() per
    // browser; an overlapping second call is rejected with NotAllowedError
    // ("a request is already pending"). PQCContext.requestPassword treats any
    // biometric failure as "fall back to the password box", so two custody
    // operations that start together turned a working authenticator into a
    // password prompt — and the app starts several together by design
    // (hooks/useSecrets.js fetches own and shared secrets in parallel and each
    // batch-decrypts its titles; useGroupNames resolves channel names the same
    // way). That is the "biometrics works, then it asks for my password anyway"
    // report.
    //
    // In flight only, NEVER cached: the reference is dropped as soon as the
    // ceremony settles, so the recovered password is not retained between
    // operations and the next one re-authenticates. Sharing a pending ceremony
    // grants nothing a caller could not already have had by waiting for it.
    async recoverPasswordWithBiometrics() {
        if (this._bioInFlight) return this._bioInFlight;

        const pending = this._recoverPasswordWithBiometrics().finally(() => {
            if (this._bioInFlight === pending) this._bioInFlight = null;
        });
        this._bioInFlight = pending;
        return pending;
    },

    async _recoverPasswordWithBiometrics() {
        if (!this.hasBiometrics()) throw new Error("Biometrics not set up.");

        const prefsString = localStorage.getItem('kryptolog_biometrics');
        if (!prefsString) throw new Error("No biometric preferences found.");
        const prefs = JSON.parse(prefsString);

        // mode selects the PRF or legacy-fallback path.
        const { getBiometricKey, decryptSymmetric } = await import('../utils/crypto');

        const mode = prefs.mode || 'prf'; // backward compat: old prefs without mode default to prf
        const key = await getBiometricKey(prefs.credentialId, prefs.prfSalt, mode);

        const password = await decryptSymmetric(prefs.encryptedPass, key);
        if (!password) throw new Error("Biometric decryption failed.");

        return password;
    },

    disableBiometrics() {
        localStorage.removeItem('kryptolog_biometrics');
        localStorage.removeItem('kryptolog_bio_fallback_key'); // Clean up fallback key if present
    },

    // Returns 'prf', 'fallback', or null if biometrics not enabled
    biometricMode() {
        const prefsString = localStorage.getItem('kryptolog_biometrics');
        if (!prefsString) return null;
        try {
            const prefs = JSON.parse(prefsString);
            return prefs.mode || 'prf'; // backward compat
        } catch {
            return null;
        }
    },
};
