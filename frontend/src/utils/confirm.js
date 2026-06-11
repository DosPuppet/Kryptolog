// Promise-based confirm dialog — a PWA-safe replacement for window.confirm().
//
// window.confirm() is blocking and unreliable in installed PWAs (it can return
// false or hang in iOS standalone), which silently drops destructive actions.
// This store lets any code do `if (await confirmDialog({ message })) { ... }`
// while <ConfirmDialogHost/> (mounted once at the app root) renders the UI.

let _state = null;          // { message, title, confirmText, cancelText, danger, resolve } | null
const _listeners = new Set();

const _emit = () => {
    for (const fn of _listeners) fn(_state);
};

export const subscribeConfirm = (fn) => {
    _listeners.add(fn);
    return () => _listeners.delete(fn);
};

export const getConfirmState = () => _state;

// Resolve the open dialog (true = confirmed, false = cancelled/dismissed).
export const resolveConfirm = (result) => {
    if (_state) {
        const { resolve } = _state;
        _state = null;
        _emit();
        resolve(result);
    }
};

/**
 * Show a confirmation dialog. Returns a Promise<boolean>.
 * opts: { message, title?, confirmText?, cancelText?, danger? }
 */
export const confirmDialog = (opts) =>
    new Promise((resolve) => {
        // If one is somehow already open, cancel it first.
        if (_state) _state.resolve(false);
        _state = {
            title: 'Please confirm',
            confirmText: 'Confirm',
            cancelText: 'Cancel',
            danger: false,
            ...(typeof opts === 'string' ? { message: opts } : opts),
            resolve,
        };
        _emit();
    });

export default confirmDialog;
