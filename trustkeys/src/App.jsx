import { useState, useEffect } from 'react'
import './App.css'

// --- Components ---

const SetupScreen = ({ onSetup }) => {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (password.length < 4) return setError("Password too short");
    if (password !== confirm) return setError("Passwords do not match");
    onSetup(password);
  };

  return (
    <div className="auth-screen">
      <h2>Welcome to TrustKeys</h2>
      <p>Create a password to secure your quantum vault.</p>
      <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
      <input type="password" placeholder="Confirm Password" value={confirm} onChange={e => setConfirm(e.target.value)} />
      {error && <div className="error">{error}</div>}
      <button className="primary" onClick={handleSubmit}>Create Vault</button>
    </div>
  );
};

const LoginScreen = ({ onUnlock }) => {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    onUnlock(password, (success) => {
      if (!success) setError("Incorrect password");
    });
  };

  return (
    <div className="auth-screen">
      <h2>Unlock Vault</h2>
      <p>Enter your password to access your keys.</p>
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={e => { setPassword(e.target.value); setError(''); }}
        onKeyDown={e => e.key === 'Enter' && handleSubmit()}
      />
      {error && <div className="error">{error}</div>}
      <button className="primary" onClick={handleSubmit}>Unlock</button>
    </div>
  );
};

const ConnectScreen = ({ requestId, requestData, onResolve }) => {
  return (
    <div className="auth-screen">
      <h2>Connection Request</h2>
      <p><strong>{requestData.origin}</strong> wants to connect to your TrustKeys wallet.</p>
      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
        <button className="secondary" onClick={() => onResolve(false)} style={{ flex: 1, padding: '12px', background: '#333', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Reject</button>
        <button className="primary" onClick={() => onResolve(true)} style={{ flex: 1 }}>Connect</button>
      </div>
    </div>
  );
};

const SignScreen = ({ requestId, requestData, onResolve }) => {
  return (
    <div className="auth-screen">
      <h2>Signature Request</h2>
      <p><strong>{requestData.origin}</strong> is requesting a signature.</p>
      <div style={{ background: '#111', padding: '10px', borderRadius: '6px', width: '100%', marginBottom: '20px', textAlign: 'left', maxHeight: '100px', overflowY: 'auto' }}>
        <div style={{ fontSize: '0.7em', color: '#888', marginBottom: '4px' }}>MESSAGE</div>
        <code style={{ fontSize: '0.85em', wordBreak: 'break-all' }}>{requestData.message}</code>
      </div>
      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
        <button onClick={() => onResolve(false)} style={{ flex: 1, padding: '12px', background: '#333', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Reject</button>
        <button className="primary" onClick={() => onResolve(true)} style={{ flex: 1 }}>Sign</button>
      </div>
    </div>
  );
};

const DecryptScreen = ({ requestId, requestData, onResolve }) => {
  return (
    <div className="auth-screen">
      <h2>Decryption Request</h2>
      <p><strong>{requestData.origin}</strong> is requesting to decrypt data.</p>
      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
        <button onClick={() => onResolve(false)} style={{ flex: 1, padding: '12px', background: '#333', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Reject</button>
        <button className="primary" onClick={() => onResolve(true)} style={{ flex: 1 }}>Decrypt</button>
      </div>
    </div>
  );
};

// Default Configuration
const DEFAULT_API_URL = 'http://localhost:8000';
const DEFAULT_BRIDGE_URL = 'http://localhost:5173';

const SettingsModal = ({ onClose, onExport, onImport, onGoogleBackup, onGoogleRestore, loading }) => {
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('menu'); // menu, export, backup, restore, config, trusted-sites
  const [error, setError] = useState('');
  const [token, setToken] = useState(''); // Google ID Token (Simulated Input)

  // Config State
  const [apiUrl, setApiUrl] = useState(DEFAULT_API_URL);
  const [bridgeUrl, setBridgeUrl] = useState(DEFAULT_BRIDGE_URL);
  const [showConfig, setShowConfig] = useState(false);

  // Trusted Sites State
  const [trustedSites, setTrustedSites] = useState([]);
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [sitesLoading, setSitesLoading] = useState(false);

  useEffect(() => {
    // Check for stored token and config
    chrome.storage.local.get(['googleToken', 'apiUrl', 'bridgeUrl'], (res) => {
      if (res.googleToken) setToken(res.googleToken);
      if (res.apiUrl) setApiUrl(res.apiUrl);
      if (res.bridgeUrl) setBridgeUrl(res.bridgeUrl);
    });

    // Listen for changes
    const listener = (changes) => {
      if (changes.googleToken) setToken(changes.googleToken.newValue);
    };
    chrome.storage.onChanged.addListener(listener);
    return () => chrome.storage.onChanged.removeListener(listener);
  }, []);

  const saveConfig = () => {
    chrome.storage.local.set({ apiUrl, bridgeUrl }, () => {
      setShowConfig(false);
    });
  };

  const fetchTrustedSites = () => {
    setSitesLoading(true);
    chrome.runtime.sendMessage({ type: 'GET_TRUSTED_SITES' }, (res) => {
      setSitesLoading(false);
      if (res && res.success) setTrustedSites(res.sites);
    });
  };

  const addTrustedSite = () => {
    let origin = newSiteUrl.trim();
    if (!origin) return setError('Enter a URL');
    try {
      if (!origin.startsWith('http://') && !origin.startsWith('https://')) {
        origin = 'https://' + origin;
      }
      origin = new URL(origin).origin;
    } catch {
      return setError('Invalid URL format');
    }
    setSitesLoading(true);
    chrome.runtime.sendMessage({ type: 'ADD_TRUSTED_SITE', origin }, (res) => {
      setSitesLoading(false);
      if (res && res.success) {
        setNewSiteUrl('');
        setError('');
        fetchTrustedSites();
      } else {
        setError(res?.error || 'Failed to add site');
      }
    });
  };

  const removeTrustedSite = (origin) => {
    if (!window.confirm(`Remove "${origin}" from trusted sites?`)) return;
    chrome.runtime.sendMessage({ type: 'REMOVE_TRUSTED_SITE', origin }, (res) => {
      if (res && res.success) {
        fetchTrustedSites();
      } else {
        setError(res?.error || 'Failed to remove site');
      }
    });
  };

  const handleExport = () => {
    if (!password) return setError("Password required");
    onExport(password, (success, err) => {
      if (!success) setError(err || "Export failed");
      else onClose();
    });
  };

  const handleImport = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        if (!data.accounts) throw new Error("Invalid format");
        onImport(data.accounts);
      } catch (err) {
        setError("Invalid file format");
      }
    };
    reader.readAsText(file);
  };

  const handleBackup = () => {
    if (!password || !token) return setError("Password and Token required");
    onGoogleBackup(password, token, (success, err) => {
      if (success) {
        alert("Backup successful!");
        onClose();
      } else {
        setError(err || "Backup failed");
      }
    });
  };

  const handleRestore = () => {
    if (!password || !token) return setError("Password and Token required");
    onGoogleRestore(password, token, (success, err) => {
      if (success) {
        alert("Restore successful!");
        onClose();
      } else {
        setError(err || "Restore failed");
      }
    });
  };

  const handleGoogleLogin = () => {
    const extId = chrome.runtime.id;
    // Use configured bridge URL or default
    const base = bridgeUrl || DEFAULT_BRIDGE_URL;
    // Ensure no trailing slash for clean concat? Or just use template literal carefully.
    const url = `${base}/auth-bridge?ext_id=${extId}`;
    chrome.tabs.create({ url });
  };

  return (
    <div className="modal-overlay">
      <div className="modal">
        <button className="close-btn" onClick={onClose}>×</button>
        <h3>Settings</h3>

        {mode === 'menu' && !showConfig && (
          <div className="settings-menu">
            <button onClick={() => setMode('export')} className="danger-btn">Export Keys (JSON)</button>
            <label className="primary-btn" style={{ display: 'block', textAlign: 'center', marginTop: '10px', cursor: 'pointer' }}>
              Import Keys (JSON)
              <input type="file" style={{ display: 'none' }} onChange={handleImport} accept=".json" />
            </label>
            <hr style={{ margin: '15px 0', borderColor: '#333' }} />
            <button onClick={() => setMode('backup')} className="secondary-btn" style={{ background: '#4285F4', color: 'white' }}> Backup with Google ID (MPC)</button>
            <button onClick={() => setMode('restore')} className="text-btn" style={{ marginTop: '10px' }}>Restore with Google ID</button>
            <hr style={{ margin: '15px 0', borderColor: '#333' }} />
            <button onClick={() => { setMode('trusted-sites'); fetchTrustedSites(); }} className="secondary-btn">
              Manage Trusted Sites
            </button>
            <hr style={{ margin: '15px 0', borderColor: '#333' }} />
            <button onClick={() => setShowConfig(true)} className="text-btn" style={{ fontSize: '0.8em', color: '#888' }}>
              Config (API & Bridge)
            </button>
          </div>
        )}

        {showConfig && (
          <div className="config-form" style={{ textAlign: 'left' }}>
            <h4>Configuration</h4>
            <div style={{ marginBottom: '10px' }}>
              <label style={{ fontSize: '0.8em', color: '#aaa' }}>API URL (Backend)</label>
              <input type="text" value={apiUrl} onChange={e => setApiUrl(e.target.value)} style={{ width: '100%', padding: '6px' }} />
            </div>
            <div style={{ marginBottom: '15px' }}>
              <label style={{ fontSize: '0.8em', color: '#aaa' }}>Bridge URL (Frontend)</label>
              <input type="text" value={bridgeUrl} onChange={e => setBridgeUrl(e.target.value)} style={{ width: '100%', padding: '6px' }} />
            </div>
            <button onClick={saveConfig} className="primary-btn">Save</button>
            <button onClick={() => setShowConfig(false)} className="text-btn">Cancel</button>
          </div>
        )}

        {mode === 'export' && (
          <div className="export-flow">
            <div className="warning-box">
              <strong>⚠️ SECURITY WARNING</strong>
              <p>You are about to export your private keys in plain text.</p>
            </div>
            <p>Enter password to confirm:</p>
            <input type="password" value={password} onChange={e => { setPassword(e.target.value); setError('') }} placeholder="Password" />
            {error && <div className="error">{error}</div>}
            <button onClick={handleExport} className="danger-btn">Confirm Export</button>
            <button onClick={() => setMode('menu')} className="text-btn">Back</button>
          </div>
        )}

        {(mode === 'backup' || mode === 'restore') && (
          <div className="export-flow">
            <h3>{mode === 'backup' ? 'Backup with Google ID' : 'Restore with Google ID'}</h3>
            <p>1. Enter your TrustKeys Password.</p>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="TrustKeys Password" />

            <p>2. Connect Google Account:</p>
            {token ? (
              <div style={{ color: '#4caf50', marginBottom: '10px' }}>✓ Google Connected</div>
            ) : (
              <button onClick={handleGoogleLogin} style={{ background: '#4285F4', color: 'white', padding: '10px', width: '100%', marginBottom: '10px', border: 'none', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                <span style={{ background: 'white', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#4285F4', fontWeight: 'bold' }}>G</span>
                Sign in with Google
              </button>
            )}

            {error && <div className="error">{error}</div>}

            <button onClick={mode === 'backup' ? handleBackup : handleRestore} className="primary-btn" disabled={loading || !token}>
              {loading ? 'Processing...' : (mode === 'backup' ? 'Encrypt & Upload' : 'Download & Decrypt')}
            </button>
            <button onClick={() => setMode('menu')} className="text-btn">Back</button>
          </div>
        )}

        {mode === 'trusted-sites' && (
          <div className="export-flow">
            <h3>Trusted Sites</h3>
            <p style={{ fontSize: '0.85em', color: '#aaa', marginBottom: '10px' }}>
              Sites authorized to use TrustKeys. Dev sites cannot be removed.
            </p>

            {sitesLoading ? (
              <div style={{ textAlign: 'center', padding: '20px', color: '#888' }}>Loading...</div>
            ) : (
              <div style={{ maxHeight: '220px', overflowY: 'auto', marginBottom: '10px' }}>
                {trustedSites.length === 0 ? (
                  <div style={{ color: '#888', textAlign: 'center', padding: '10px' }}>No trusted sites yet.</div>
                ) : (
                  trustedSites.map(site => (
                    <div key={site.origin} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 8px', background: '#111', borderRadius: '4px', marginBottom: '4px', fontSize: '0.85em' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                        <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{site.origin}</span>
                        {site.isDefault && <span style={{ fontSize: '0.7em', background: '#333', color: '#aaa', padding: '1px 5px', borderRadius: '3px', whiteSpace: 'nowrap' }}>DEV</span>}
                      </div>
                      {!site.isDefault && (
                        <button onClick={() => removeTrustedSite(site.origin)} style={{ background: '#c0392b', color: 'white', border: 'none', borderRadius: '3px', padding: '2px 8px', cursor: 'pointer', fontSize: '0.8em', flexShrink: 0 }}>
                          Remove
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
              <input
                type="text"
                value={newSiteUrl}
                onChange={e => { setNewSiteUrl(e.target.value); setError(''); }}
                onKeyDown={e => e.key === 'Enter' && addTrustedSite()}
                placeholder="https://example.com"
                style={{ flex: 1 }}
              />
              <button onClick={addTrustedSite} className="primary-btn" disabled={sitesLoading} style={{ whiteSpace: 'nowrap' }}>Add</button>
            </div>

            {error && <div className="error">{error}</div>}
            <button onClick={() => { setMode('menu'); setError(''); }} className="text-btn">Back</button>
          </div>
        )}

      </div>
    </div>
  );
};

const Dashboard = () => {
  const [accounts, setAccounts] = useState([]);
  const [activeAccount, setActiveAccount] = useState(null);
  const [newAccountName, setNewAccountName] = useState('');
  const [loading, setLoading] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [currentTabOrigin, setCurrentTabOrigin] = useState(null);
  const [authStatus, setAuthStatus] = useState(null); // null, 'authorized', 'unauthorized'

  useEffect(() => {
    fetchAccounts();
    fetchActiveAccount();
    // Check current tab authorization status
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs?.[0];
      if (tab?.url) {
        try {
          const origin = new URL(tab.url).origin;
          if (origin.startsWith('chrome') || origin === 'null') {
            setCurrentTabOrigin(null);
            return;
          }
          setCurrentTabOrigin(origin);
          chrome.runtime.sendMessage({ type: 'CHECK_CONNECTION', origin }, (res) => {
            setAuthStatus(res?.connected ? 'authorized' : 'unauthorized');
          });
        } catch { setCurrentTabOrigin(null); }
      }
    });
  }, []);

  const fetchAccounts = () => {
    chrome.runtime.sendMessage({ type: 'GET_ACCOUNTS' }, (response) => {
      if (response && response.success) setAccounts(response.accounts);
    });
  };

  const fetchActiveAccount = () => {
    chrome.runtime.sendMessage({ type: 'GET_ACTIVE_ACCOUNT' }, (response) => {
      if (response && response.success) setActiveAccount(response.account);
    });
  };

  const createAccount = () => {
    if (!newAccountName) return;
    setLoading(true);
    chrome.runtime.sendMessage({ type: 'CREATE_ACCOUNT', name: newAccountName }, (response) => {
      setLoading(false);
      if (response && response.success) {
        setNewAccountName('');
        fetchAccounts();
        if (!activeAccount) fetchActiveAccount();
      }
    });
  };

  const selectAccount = (id) => {
    chrome.runtime.sendMessage({ type: 'SET_ACTIVE_ACCOUNT', id }, (res) => {
      if (res && res.success) {
        fetchActiveAccount();
        fetchAccounts(); // Refresh list to update highlight
      }
    });
  };

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopyFeedback(label);
    setTimeout(() => setCopyFeedback(null), 2000);
  };

  const deleteAccount = (id, name, e) => {
    e.stopPropagation(); // Don't select the account when clicking delete
    if (window.confirm(`Are you sure you want to delete the account "${name}"? This action cannot be undone.`)) {
      chrome.runtime.sendMessage({ type: 'DELETE_ACCOUNT', id }, (res) => {
        if (res && res.success) {
          fetchAccounts();
          fetchActiveAccount();
        } else {
          alert(`Delete failed: ${res.error}`);
        }
      });
    }
  };

  const lockVault = () => {
    chrome.runtime.sendMessage({ type: 'LOCK' }, () => {
      window.location.reload();
    });
  };

  const authorizeCurrentTab = () => {
    setLoading(true);
    chrome.runtime.sendMessage({ type: 'AUTHORIZE_CURRENT_TAB' }, (res) => {
      setLoading(false);
      if (res && res.success) {
        setAuthStatus('authorized');
      } else {
        alert('Failed to authorize: ' + (res?.error || 'Unknown error'));
      }
    });
  };

  const handleExportKeys = (password, cb) => {
    chrome.runtime.sendMessage({ type: 'EXPORT_KEYS', password }, (res) => {
      if (res && res.success) {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ accounts: res.accounts }));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "trustkeys_backup.json");
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
        cb(true);
      } else {
        cb(false, res.error);
      }
    });
  };

  const handleImportKeys = (newAccounts) => {
    chrome.runtime.sendMessage({ type: 'IMPORT_KEYS', accounts: newAccounts }, (res) => {
      if (res && res.success) {
        alert(`Successfully imported ${res.count} accounts.`);
        fetchAccounts();
        setShowSettings(false);
      } else {
        alert(`Import failed: ${res.error}`);
      }
    });
  };

  return (

    <div className="dashboard">
      <div className="header">
        <h2>TrustKeys <span className="highlight">PQC</span></h2>
        <div className="header-actions">
          <button className="small-btn" onClick={() => setShowSettings(true)} title="Settings">⚙️</button>
          <button className="small-btn" onClick={lockVault} title="Lock Vault">🔒</button>
          <div className={`status-indicator ${activeAccount ? 'active' : ''}`}></div>
        </div>
      </div>

      {showSettings && (
        <SettingsModal
          onClose={() => setShowSettings(false)}
          onExport={handleExportKeys}
          onImport={handleImportKeys}
          onGoogleBackup={(password, token, cb) => {
            setLoading(true);
            chrome.runtime.sendMessage({ type: 'BACKUP_TO_GOOGLE', password, token }, (res) => {
              setLoading(false);
              cb(res && res.success, res?.error);
            });
          }}
          onGoogleRestore={(password, token, cb) => {
            setLoading(true);
            chrome.runtime.sendMessage({ type: 'RESTORE_FROM_GOOGLE', password, token }, (res) => {
              setLoading(false);
              cb(res && res.success, res?.error);
            });
          }}
          loading={loading}
        />
      )}

      {currentTabOrigin && authStatus === 'unauthorized' && (
        <div style={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: '6px', padding: '10px 12px', marginBottom: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
          <div style={{ fontSize: '0.8em', color: '#ccc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {currentTabOrigin}
          </div>
          <button
            onClick={authorizeCurrentTab}
            disabled={loading}
            style={{ background: '#16a34a', color: 'white', border: 'none', borderRadius: '4px', padding: '6px 12px', cursor: 'pointer', fontSize: '0.8em', whiteSpace: 'nowrap', flexShrink: 0 }}
          >
            {loading ? '...' : 'Authorize'}
          </button>
        </div>
      )}

      {currentTabOrigin && authStatus === 'authorized' && (
        <div style={{ fontSize: '0.75em', color: '#4ade80', marginBottom: '8px', textAlign: 'center' }}>
          {currentTabOrigin} is authorized
        </div>
      )}

      {activeAccount ? (
        <div className="card active-card">
          <div className="card-header">
            <strong>{activeAccount.name}</strong>
            <span className="badge">ACTIVE</span>
          </div>

          <div className="key-section">
            <div className="key-header">
              <span>ML-KEM (Kyber)</span>
              <button onClick={() => copyToClipboard(activeAccount.kyberPublicKey, 'kyber')} className={copyFeedback === 'kyber' ? 'copied' : ''}>
                {copyFeedback === 'kyber' ? 'COPIED' : 'COPY'}
              </button>
            </div>
            <div className="key-box">{activeAccount.kyberPublicKey}</div>
          </div>

          <div className="key-section">
            <div className="key-header">
              <span>ML-DSA (Dilithium)</span>
              <button onClick={() => copyToClipboard(activeAccount.dilithiumPublicKey, 'dilithium')} className={copyFeedback === 'dilithium' ? 'copied' : ''}>
                {copyFeedback === 'dilithium' ? 'COPIED' : 'COPY'}
              </button>
            </div>
            <div className="key-box">{activeAccount.dilithiumPublicKey}</div>
          </div>
        </div>
      ) : (
        <div className="empty-state">No Active Account</div>
      )}

      <div className="accounts-list">
        <h3>Accounts</h3>
        {accounts.map(acc => (
          <div key={acc.id} className={`account-item ${acc.active ? 'current' : ''}`} onClick={() => selectAccount(acc.id)}>
            <div className="account-info">
              <span>{acc.name}</span>
              {acc.active && <span className="check">✓</span>}
            </div>
            <button
              className="delete-btn"
              onClick={(e) => deleteAccount(acc.id, acc.name, e)}
              title="Delete Account"
            >
              🗑️
            </button>
          </div>
        ))}

        <div className="create-account">
          <input
            type="text"
            placeholder="New Account Name"
            value={newAccountName}
            onChange={e => setNewAccountName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && createAccount()}
          />
          <button onClick={createAccount} disabled={loading}>{loading ? '...' : '+'}</button>
        </div>
      </div>
    </div>
  );
};

// --- Main App ---

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
  if (route === 'connect' && pendingRequest) {
    if (pendingRequest.type === 'CONNECT') {
      return <ConnectScreen requestId={requestId} requestData={pendingRequest.data} onResolve={handleResolve} />;
    }
  }
  if (route === 'sign' && pendingRequest) {
    if (pendingRequest.type === 'SIGN') {
      return <SignScreen requestId={requestId} requestData={pendingRequest.data} onResolve={handleResolve} />;
    }
  }
  if (route === 'decrypt' && pendingRequest) {
    if (pendingRequest.type === 'DECRYPT') {
      return <DecryptScreen requestId={requestId} requestData={pendingRequest.data} onResolve={handleResolve} />;
    }
  }

  return <Dashboard />;
}

export default App;
