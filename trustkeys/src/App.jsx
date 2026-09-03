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

  // Load one approval request. With no id the background hands back the next
  // queued one, which is how the popup walks the queue (audit M-6): a second
  // request that arrived while this window was busy used to sit until it timed
  // out, because only the id in the original URL was ever fetched.
  const loadPendingRequest = (id) => {
    chrome.runtime.sendMessage(
      id ? { type: 'GET_PENDING_REQUEST', requestId: id } : { type: 'GET_PENDING_REQUEST' },
      (response) => {
        if (response && response.success) setPendingRequest(response.request);
        else setPendingRequest(null);
      }
    );
  };

  useEffect(() => {
    checkStatus();
    // `route` marks a window the background opened to ask for approval. Without
    // it this is the toolbar popup, which should show the dashboard rather than
    // ambush the user with whatever a site happens to be asking for.
    if (requestId || route) loadPendingRequest(requestId);
  }, [requestId, route]);

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
    const id = pendingRequest?.id;
    if (!id) return;
    chrome.runtime.sendMessage({ type: 'RESOLVE_REQUEST', requestId: id, approved }, (response) => {
      // Advance to the next queued approval rather than closing on the first
      // one; closing here would dismiss the window, and dismissal rejects
      // everything still queued (audit M-6).
      if (response?.next) loadPendingRequest(response.next);
      else window.close();
    });
  };

  if (status.loading) return <div className="loading">Loading...</div>;

  // Global Auth Guard
  if (!status.hasPassword) return <SetupScreen onSetup={handleSetup} />;
  if (status.isLocked) return <LoginScreen onUnlock={handleUnlock} />;

  // Routing is driven by the REQUEST's type, not the URL's route: when the popup
  // advances to the next queued approval that one may be a different type, and
  // the original ?route= would no longer match it.
  if (pendingRequest?.type === 'CONNECT') {
    return <ConnectScreen requestData={pendingRequest.data} onResolve={handleResolve} />;
  }
  if (pendingRequest?.type === 'SIGN') {
    return <SignScreen requestData={pendingRequest.data} onResolve={handleResolve} />;
  }
  if (pendingRequest?.type === 'DECRYPT') {
    return <DecryptScreen requestData={pendingRequest.data} onResolve={handleResolve} />;
  }

  return <Dashboard />;
}

export default App;
