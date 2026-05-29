import { encryptVault } from '../utils/crypto.js';
import { state, setSessionPassword } from './state.js';

export const saveVault = async (password) => {
    if (!state.vault) return;
    const encryptionResult = await encryptVault(state.vault, password);
    await chrome.storage.local.set({ vaultData: encryptionResult });
    state.hasPassword = true;
};

export const launchPopup = async (route, params = {}) => {
    const queryString = new URLSearchParams({ route, ...params }).toString();
    const width = 360;
    const height = 600;

    let left, top;

    try {
        // Attempt to position in top-right of current window
        const lastWin = await chrome.windows.getLastFocused();
        if (lastWin && lastWin.left !== undefined && lastWin.width !== undefined) {
            // Position: Right side with 20px padding, Top with 80px padding (account for toolbar)
            left = lastWin.left + lastWin.width - width - 20;
            top = lastWin.top + 80;
        }
    } catch (e) {
        // Fallback to OS default if we can't get window info
        console.warn("Failed to calculate popup position", e);
    }

    await chrome.windows.create({
        url: `index.html?${queryString}`,
        type: 'popup',
        width,
        height,
        left,
        top,
        focused: true
    });
};

export const updateActivity = () => {
    if (!state.isLocked) {
        chrome.storage.session.set({ lastActive: Date.now() }).catch(() => { });
    }
}
