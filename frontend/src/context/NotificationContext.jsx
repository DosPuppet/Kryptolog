import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { useAuth } from './AuthContext';
import { API_ENDPOINTS } from '../config';

const NotificationContext = createContext();

export const useNotifications = () => useContext(NotificationContext);

// Public half of the server's VAPID keypair. MUST match the backend's
// VAPID_PRIVATE_KEY, so it's configured per-deployment via env rather than
// hardcoded. Generate a pair with the `vapid` CLI (pywebpush); see README.
const VAPID_PUBLIC_KEY = import.meta.env.VITE_VAPID_PUBLIC_KEY || '';

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

// iOS Safari in a normal tab (not an installed PWA) has NO Notification API.
// Touching `Notification.permission` unguarded throws at render and blanks the
// whole app, so gate every access behind this.
const NOTIFICATIONS_SUPPORTED = typeof window !== 'undefined' && 'Notification' in window;
const currentPermission = () => (NOTIFICATIONS_SUPPORTED ? Notification.permission : 'default');

export const NotificationProvider = ({ children }) => {
    const { user, isAuthenticated, token } = useAuth();
    const [permission, setPermission] = useState(currentPermission);
    const [subscription, setSubscription] = useState(null);
    const [error, setError] = useState(null);
    // Guard against concurrent subscribe() calls (requestPermission + the
    // permission-change effect could otherwise both subscribe, leaving two
    // backend rows → notifications delivered twice).
    const subscribingRef = useRef(false);

    const subscribe = useCallback(async () => {
        if (subscribingRef.current) return; // a subscribe is already in flight
        if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
            const msg = 'Push messaging is not supported in this browser.';
            console.warn(msg);
            setError(msg);
            return;
        }
        if (!window.isSecureContext) {
            const msg = 'Push notifications require a secure context (HTTPS) or localhost.';
            console.warn(msg);
            setError(msg);
            return;
        }
        if (!VAPID_PUBLIC_KEY) {
            const msg = 'Push notifications are not configured (VITE_VAPID_PUBLIC_KEY is unset).';
            console.warn(msg);
            setError(msg);
            return;
        }

        subscribingRef.current = true;
        setError(null);
        // Clear opt-out flag since user is explicitly subscribing
        localStorage.removeItem('kryptolog_push_disabled');
        const authToken = token || localStorage.getItem('token');

        try {
            const registration = await navigator.serviceWorker.ready;
            const existingSub = await registration.pushManager.getSubscription();
            const oldEndpoint = existingSub?.endpoint || null;

            if (existingSub) {
                await existingSub.unsubscribe();
            }

            const newSub = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
            });

            // Send to backend
            const subData = newSub.toJSON();
            const res = await fetch(API_ENDPOINTS.NOTIFICATIONS.SUBSCRIBE, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${authToken}`
                },
                body: JSON.stringify({
                    endpoint: subData.endpoint,
                    p256dh: subData.keys.p256dh,
                    auth: subData.keys.auth
                })
            });

            if (!res.ok) {
                throw new Error(`Server returned ${res.status} when saving subscription.`);
            }

            // Drop the previous endpoint server-side so we never accumulate stale
            // subscriptions for this device (which would deliver duplicate pushes).
            if (oldEndpoint && oldEndpoint !== subData.endpoint) {
                fetch(`${API_ENDPOINTS.NOTIFICATIONS.UNSUBSCRIBE}?endpoint=${encodeURIComponent(oldEndpoint)}`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                }).catch(() => { /* best effort */ });
            }

            setSubscription(newSub);
            setPermission(currentPermission());
        } catch (error) {
            console.error('Failed to subscribe to push notifications:', error);
            setError(error.message || 'Failed to subscribe.');
        } finally {
            subscribingRef.current = false;
        }
    }, [token]);

    useEffect(() => {
        if (isAuthenticated && permission === 'granted' && !localStorage.getItem('kryptolog_push_disabled')) {
            // Check if we already have a subscription on mount
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.ready.then(reg => {
                    reg.pushManager.getSubscription().then(sub => {
                        if (sub) {
                            setSubscription(sub);
                        } else {
                            // Permission granted but no subscription — auto-subscribe
                            subscribe();
                        }
                    });
                });
            }
        }
    }, [isAuthenticated, permission, subscribe]);

    const requestPermission = async () => {
        if (!NOTIFICATIONS_SUPPORTED) {
            setError('Notifications are not supported here. On iOS, add Kryptolog to your Home Screen first.');
            return;
        }
        const result = await Notification.requestPermission();
        setPermission(result);
        if (result === 'granted' && isAuthenticated) {
            await subscribe();
        }
    };

    const unsubscribe = useCallback(async () => {
        if (!subscription) return;
        setError(null);

        try {
            // Unsubscribe from backend first
            const authToken = token || localStorage.getItem('token');
            await fetch(`${API_ENDPOINTS.NOTIFICATIONS.UNSUBSCRIBE}?endpoint=${encodeURIComponent(subscription.endpoint)}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });

            // Unsubscribe from browser
            await subscription.unsubscribe();

            setSubscription(null);
            // Persist user's opt-out so auto-subscribe doesn't re-enable on reload
            localStorage.setItem('kryptolog_push_disabled', 'true');
        } catch (error) {
            console.error('Failed to unsubscribe:', error);
            setError('Failed to unsubscribe.');
        }
    }, [subscription, token]);

    return (
        <NotificationContext.Provider value={{ permission, subscription, error, requestPermission, subscribe, unsubscribe }}>
            {children}
        </NotificationContext.Provider>
    );
};
