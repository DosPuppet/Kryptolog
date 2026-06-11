// Tiny store-based toast system.
//
// Why not window.alert(): blocking native dialogs are unreliable in installed
// PWAs (notably iOS standalone) — they can be suppressed or hang, leaving flows
// "stuck" after an action that actually succeeded. Toasts are plain in-app UI.
//
// Store-based (not React context) so it can be called from anywhere — function
// components, hooks (useSecrets), and context providers (PQC/Messenger) alike —
// without prop drilling or nesting another provider. <ToastContainer/> (mounted
// once at the app root) subscribes and renders.

let _toasts = [];
const _listeners = new Set();
let _id = 0;

const _emit = () => {
    for (const fn of _listeners) fn(_toasts);
};

export const subscribeToasts = (fn) => {
    _listeners.add(fn);
    return () => _listeners.delete(fn);
};

export const getToasts = () => _toasts;

export const dismissToast = (id) => {
    _toasts = _toasts.filter((t) => t.id !== id);
    _emit();
};

// duration: ms before auto-dismiss (0 = sticky). Returns the toast id.
const push = (type, message, duration) => {
    const id = ++_id;
    _toasts = [..._toasts, { id, type, message }];
    _emit();
    if (duration !== 0) {
        setTimeout(() => dismissToast(id), duration ?? (type === 'error' ? 6000 : 3500));
    }
    return id;
};

export const toast = {
    success: (message, duration) => push('success', message, duration),
    error: (message, duration) => push('error', message, duration),
    info: (message, duration) => push('info', message, duration),
};

export default toast;
