import { useEffect, useRef } from 'react';
import API_ENDPOINTS from '../../config';

// Owns the messenger WebSocket LIFECYCLE: connect + AUTH, presence signalling
// (focus/blur/visibility), 30s heartbeat, exponential-backoff reconnect, and
// teardown. Message SEMANTICS stay with the caller: `handlers` maps a server
// event type to a callback. Handlers are read through a ref so the long-lived
// socket always dispatches to the latest render's callbacks — including them as
// effect deps would tear down and rebuild the socket on every render.
export const useMessengerSocket = ({ user, token, handlers }) => {
    const wsRef = useRef(null);
    const handlersRef = useRef(handlers);
    handlersRef.current = handlers;

    useEffect(() => {
        if (!user) return;

        let ws = null;
        let heartbeatInterval = null;
        let reconnectTimeout = null;
        let retryCount = 0;
        const maxRetries = 10;
        let isUnmounting = false;

        // Visibility / focus handlers — added ONCE, cleaned up on unmount
        const sendFocusState = () => {
            const currentWs = wsRef.current;
            if (currentWs && currentWs.readyState === WebSocket.OPEN) {
                const focused = document.visibilityState === 'visible';
                currentWs.send(JSON.stringify({ type: focused ? 'APP_FOCUSED' : 'APP_BLURRED' }));
            }
        };
        const onFocus = () => {
            const currentWs = wsRef.current;
            if (currentWs && currentWs.readyState === WebSocket.OPEN) {
                currentWs.send(JSON.stringify({ type: 'APP_FOCUSED' }));
            }
        };
        const onBlur = () => {
            const currentWs = wsRef.current;
            if (currentWs && currentWs.readyState === WebSocket.OPEN) {
                currentWs.send(JSON.stringify({ type: 'APP_BLURRED' }));
            }
        };

        document.addEventListener('visibilitychange', sendFocusState);
        window.addEventListener('focus', onFocus);
        window.addEventListener('blur', onBlur);

        const connect = () => {
            if (isUnmounting) return;

            const url = API_ENDPOINTS.BASE.replace('http', 'ws');
            const wsUrl = `${url}/ws`;
            ws = new WebSocket(wsUrl);
            wsRef.current = ws;

            ws.onopen = () => {
                retryCount = 0;
                ws.send(JSON.stringify({ type: 'AUTH', token }));

                if (document.visibilityState === 'visible') {
                    ws.send(JSON.stringify({ type: 'APP_FOCUSED' }));
                }

                // Start Heartbeat
                if (heartbeatInterval) clearInterval(heartbeatInterval);
                heartbeatInterval = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        console.debug("WS Sending PING");
                        ws.send(JSON.stringify({ type: 'PING' }));
                    }
                }, 30000);
            };

            ws.onmessage = async (event) => {
                try {
                    const data = JSON.parse(event.data);
                    const handle = handlersRef.current[data.type];
                    if (handle) await handle(data);
                } catch (e) {
                    console.error("WS Parse Error", e);
                }
            };

            ws.onclose = () => {
                if (heartbeatInterval) clearInterval(heartbeatInterval);

                if (!isUnmounting && retryCount < maxRetries) {
                    const timeout = Math.min(1000 * (2 ** retryCount), 30000);
                    reconnectTimeout = setTimeout(() => {
                        retryCount++;
                        connect();
                    }, timeout);
                }
            };

            ws.onerror = (err) => {
                console.error("WS Error:", err);
                ws.close();
            };
        };

        connect();

        return () => {
            isUnmounting = true;
            document.removeEventListener('visibilitychange', sendFocusState);
            window.removeEventListener('focus', onFocus);
            window.removeEventListener('blur', onBlur);
            if (heartbeatInterval) clearInterval(heartbeatInterval);
            if (reconnectTimeout) clearTimeout(reconnectTimeout);
            if (wsRef.current) {
                wsRef.current.close();
                wsRef.current = null;
            }
        };
        // Reconnect only on identity/token change (handlers go through the ref).
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user?.address, token]);
};
