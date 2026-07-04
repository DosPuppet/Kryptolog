import { useState, useEffect } from 'react'
import './App.css'
import { SetupScreen, LoginScreen } from './components/AuthScreens'
import { ConnectScreen, SignScreen, DecryptScreen } from './components/RequestScreens'
import Dashboard from './components/Dashboard'

// Popup shell: vault status + auth guard, and routing between the dashboard
// and the request-approval screens (opened via ?route=...&requestId=...).
function App() {
  const [status, setStatus] = useState({ loading: true, isLocked: true, hasPassword: false });
  const [pendingRequest, setPendingRequest] = useState(null);

  // Check URL params
  const params = new URLSearchParams(window.location.search);
  const route = params.get('route');
  const requestId = params.get('requestId');

  const checkStatus = () => {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
      if (response && response.success) {
        setStatus({ loading: false, isLocked: response.isLocked, hasPassword: response.hasPassword });
      } else {
        setStatus(prev => ({ ...prev, loading: false }));
      }
    });
  };

  useEffect(() => {
    checkStatus();
    if (requestId) {
      // Fetch request data
      chrome.runtime.sendMessage({ type: 'GET_PENDING_REQUEST', requestId }, (response) => {
        if (response && response.success) {
          setPendingRequest({ id: requestId, ...response.request });
        }
      });
    }
  }, [requestId]);

  const handleSetup = (password) => {
    chrome.runtime.sendMessage({ type: 'SETUP_PASSWORD', password }, (response) => {
      if (response && response.success) {
        checkStatus();
      }
    });
  };

  const handleUnlock = (password, cb) => {
    chrome.runtime.sendMessage({ type: 'UNLOCK', password }, (response) => {
      if (response && response.success) {
        checkStatus();
        cb(true);
      } else {
        cb(false);
      }
    });
  };

  const handleResolve = (approved) => {
    chrome.runtime.sendMessage({ type: 'RESOLVE_REQUEST', requestId, approved }, (response) => {
      if (response && response.success) {
        window.close(); // Close popup context
      }
    });
  };

  if (status.loading) return <div className="loading">Loading...</div>;

  // Global Auth Guard
  if (!status.hasPassword) return <SetupScreen onSetup={handleSetup} />;
  if (status.isLocked) return <LoginScreen onUnlock={handleUnlock} />;

  // Routing
  if (route === 'connect' && pendingRequest?.type === 'CONNECT') {
    return <ConnectScreen requestData={pendingRequest.data} onResolve={handleResolve} />;
  }
  if (route === 'sign' && pendingRequest?.type === 'SIGN') {
    return <SignScreen requestData={pendingRequest.data} onResolve={handleResolve} />;
  }
  if (route === 'decrypt' && pendingRequest?.type === 'DECRYPT') {
    return <DecryptScreen requestData={pendingRequest.data} onResolve={handleResolve} />;
  }

  return <Dashboard />;
}

export default App;
