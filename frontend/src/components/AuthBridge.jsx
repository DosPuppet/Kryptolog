import React, { useEffect, useState } from 'react';

const AuthBridge = () => {
    const [status, setStatus] = useState('initializing');
    const [extId, setExtId] = useState(null);
    const [errorMessage, setErrorMessage] = useState('');

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const id = params.get('ext_id');
        setExtId(id);

        // Optional: If ID is present, we can use it. If not, we rely on postMessage bridge.
        if (!id) {
            // console.log("No Extension ID provided. Will use postMessage bridge.");
        }

        const initGsi = () => {
            if (!window.google) return;
            try {
                // Use env var or fallback (which will likely fail on custom domains)
                const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || "277636686001-av155j3451d80d26bdl764k1kdd2862d.apps.googleusercontent.com";

                window.google.accounts.id.initialize({
                    client_id: clientId,
                    callback: handleCredentialResponse
                });

                // Check for client_id param override
                const clientIdParam = params.get('client_id');
                if (clientIdParam) {
                    window.google.accounts.id.initialize({
                        client_id: clientIdParam,
                        callback: handleCredentialResponse
                    });
                }

                window.google.accounts.id.renderButton(
                    document.getElementById("buttonDiv"),
                    { theme: "outline", size: "large" }
                );
                setStatus('ready');
                clearInterval(interval);
            } catch (e) {
                console.error("GSI Error:", e);
                setStatus('error_gsi');
                clearInterval(interval);
            }
        };

        // Poll for GSI
        const interval = setInterval(initGsi, 100);
        // Also try immediately
        initGsi();

        // Timeout after 5s
        const timeout = setTimeout(() => {
            clearInterval(interval);
            setStatus(prev => prev === 'initializing' ? 'timeout_gsi' : prev);
        }, 5000);

        return () => {
            clearInterval(interval);
            clearTimeout(timeout);
        };
    }, []);

    const handleCredentialResponse = (response) => {

        // Fix: Read ID directly from URL to avoid stale closure (useEffect captures initial null state)
        const params = new URLSearchParams(window.location.search);
        const currentExtId = params.get('ext_id');

        // Send to Extension
        // Send to Extension
        let sent = false;

        // Method 1: Direct Runtime Message (Best if ID is known and externally_connectable is set)
        if (currentExtId && window.chrome && window.chrome.runtime) {
            setStatus('sending');
            sent = true;
            window.chrome.runtime.sendMessage(currentExtId, {
                type: "OAUTH_SUCCESS",
                token: response.credential
            }, (res) => {
                if (window.chrome.runtime.lastError) {
                    console.warn("Runtime Message Failed (trying fallback):", window.chrome.runtime.lastError);
                    // Fallback to postMessage if runtime failed?
                    sendViaPostMessage(response.credential);
                } else if (res && !res.success) {
                    setErrorMessage(res.error || "Extension returned failure");
                    setStatus('send_error');
                } else {
                    setStatus('success');
                }
            });
        }

        // Method 2: Post Message (Works if content script is injected - e.g. Localhost or SafeLog domain)
        // If we didn't send via runtime (no ID), or as a parallel/fallback mechanism.
        if (!sent) {
            sendViaPostMessage(response.credential);
        }
    };

    const sendViaPostMessage = (token) => {
        setStatus('sending_bridge');
        // We use the same channel as the API
        // TRUSTKEYS_OAUTH_SUCCESS

        // We need a unique ID for the request to track response (though we might not strictly need it for fire-and-forget)
        const reqId = Math.random().toString(36).substr(2, 9);

        // Listen for response
        const listener = (event) => {
            if (event.source !== window) return;
            if (event.data.source === 'TRUSTKEYS_CONTENT' && event.data.id === reqId) {
                window.removeEventListener('message', listener);
                if (event.data.success) {
                    setStatus('success');
                } else {
                    setErrorMessage(event.data.error || "Bridge failed");
                    setStatus('send_error');
                }
            }
        };
        window.addEventListener('message', listener);

        window.postMessage({
            type: 'TRUSTKEYS_OAUTH_SUCCESS',
            id: reqId,
            source: 'TRUSTKEYS_PAGE',
            token: token
        }, '*');

        // Fallback success UI if we assume it worked (Bridge might not reply fast?)
        // But better to wait for response.
        setTimeout(() => {
            // If status still sending after 2s, show success_sent (optimistic)
            setStatus(prev => prev === 'sending_bridge' ? 'success_sent' : prev);
        }, 2000);
    };

    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100vh',
            fontFamily: 'sans-serif',
            background: '#152033',
            color: '#fff'
        }}>
            <h2>SafeLog Auth Bridge</h2>

            {status === 'initializing' && (
                <div style={{ color: '#aaa' }}>
                    <p>Loading Google Sign-In...</p>
                    <p style={{ fontSize: '0.8em' }}>Status: {status}</p>
                </div>
            )}

            {/* Visual Debug for User */}
            {status !== 'initializing' && status !== 'ready' && (
                <div style={{ marginTop: '20px', color: 'yellow', fontSize: '10px' }}>
                    Debug Status: {status}
                </div>
            )}

            {status === 'timeout_gsi' && (
                <div style={{ color: 'orange' }}>
                    <p>Google Script failed to load (Timeout).</p>
                    <button onClick={() => window.location.reload()} style={{ padding: '10px', marginTop: '10px' }}>Retry</button>
                </div>
            )}

            {status === 'ready' && (
                <p>Please sign in to connect.</p>
            )}

            <div id="buttonDiv" style={{ display: status === 'ready' ? 'block' : 'none' }}></div>

            {status === 'success' && (
                <div style={{ textAlign: 'center', color: '#4caf50' }}>
                    <h3>✓ Connection Successful</h3>
                    <p>You have signed in to TrustKeys.</p>
                    <p style={{ fontSize: '0.8em', marginTop: '10px', color: '#aaa' }}>You can now close this tab.</p>
                </div>
            )}

            {status === 'success_sent' && (
                <div style={{ textAlign: 'center', color: '#4caf50' }}>
                    <h3>✓ Connected (Fallback)</h3>
                    <p>Token ready.</p>
                </div>
            )}

            {status === 'send_error' && (
                <div style={{ color: 'orange', textAlign: 'center' }}>
                    <p>Token received, but failed to send to extension.</p>
                    <p style={{ fontSize: '0.8em', marginTop: '10px' }}>Error Details:</p>
                    <pre style={{ background: '#333', padding: '10px', borderRadius: '4px' }}>
                        {errorMessage}
                    </pre>
                </div>
            )}

            {status === 'error_bridge' && (
                <div style={{ color: 'red', textAlign: 'center' }}>
                    <p>Bridge Error: Extension not detected.</p>
                    <p style={{ fontSize: '0.8em' }}>
                        Missing:
                        {!window.chrome ? ' window.chrome' : ''}
                        {window.chrome && !window.chrome.runtime ? ' chrome.runtime' : ''}
                    </p>
                    <p style={{ fontSize: '0.8em', marginTop: '10px' }}>
                        Did you <strong>Reload the Extension</strong> in chrome://extensions?
                    </p>
                </div>
            )}

            {status === 'error_gsi' && (
                <p style={{ color: 'red' }}>Google Initialization Error. Check Console.</p>
            )}

            {extId && <p style={{ marginTop: '20px', fontSize: '0.8em', color: '#666' }}>Extension ID: {extId}</p>}
        </div>
    );
};

export default AuthBridge;
