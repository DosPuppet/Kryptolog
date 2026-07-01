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
  const [loading, setLoading] = useState(false);

  const handleSubmit = () => {
    if (loading) return;
    setError('');
    setLoading(true);
    onUnlock(password, (success) => {
      // On success the app re-renders to the Dashboard; only need to recover
      // the form (re-enable input + button) on failure.
      if (!success) {
        setError("Incorrect password");
        setLoading(false);
      }
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
        disabled={loading}
        onChange={e => { setPassword(e.target.value); setError(''); }}
        onKeyDown={e => e.key === 'Enter' && handleSubmit()}
      />
      {error && <div className="error">{error}</div>}
      <button className="primary" onClick={handleSubmit} disabled={loading}>
        {loading ? <><span className="spinner" />Unlocking…</> : 'Unlock'}
      </button>
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

const SettingsModal = ({ onClose, onExport, onImport }) => {
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('menu'); // menu, export, config, trusted-sites
  const [error, setError] = useState('');

  // Export format: 'encrypted' (.kvault, recommended) or 'plain' (JSON).
  const [exportFormat, setExportFormat] = useState('encrypted');
  const [passphrase, setPassphrase] = useState('');
  const [passphrase2, setPassphrase2] = useState('');

  // Import state: parsed file contents, plus the backup passphrase needed when
  // the chosen file is an encrypted .kvault backup.
  const [importData, setImportData] = useState(null);
  const [importFileName, setImportFileName] = useState('');
  const [importIsEncrypted, setImportIsEncrypted] = useState(false);
  const [importPassphrase, setImportPassphrase] = useState('');

  // Config State
  const [apiUrl, setApiUrl] = useState(DEFAULT_API_URL);
  const [showConfig, setShowConfig] = useState(false);

  // Trusted Sites State
  const [trustedSites, setTrustedSites] = useState([]);
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [sitesLoading, setSitesLoading] = useState(false);

  useEffect(() => {
    // Load stored config
    chrome.storage.local.get(['apiUrl'], (res) => {
      if (res.apiUrl) setApiUrl(res.apiUrl);
    });
  }, []);

  const saveConfig = () => {
    chrome.storage.local.set({ apiUrl }, () => {
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

  const isDevOrigin = (o) => o.startsWith('http://localhost') || o.startsWith('http://127.0.0.1');

  const addTrustedSite = async () => {
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
    // HTTPS-only for real sites (a plain-http origin can be tampered in transit).
    if (!isDevOrigin(origin) && !origin.startsWith('https://')) {
      return setError('Only HTTPS sites can be trusted.');
    }
    setSitesLoading(true);
    try {
      // Request the host permission under THIS user gesture (popup). The
      // extension then holds access to exactly the sites the user approved.
      if (!isDevOrigin(origin)) {
        const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
        if (!granted) {
          setSitesLoading(false);
          return setError('Permission denied — site not added.');
        }
      }
    } catch (e) {
      setSitesLoading(false);
      return setError('Permission request failed: ' + e.message);
    }
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
    if (!window.confirm(`Remove "${origin}" from trusted sites? This revokes the extension's access to it.`)) return;
    // Background also calls chrome.permissions.remove (no gesture needed).
    chrome.runtime.sendMessage({ type: 'REMOVE_TRUSTED_SITE', origin }, (res) => {
      if (res && res.success) {
        fetchTrustedSites();
      } else {
        setError(res?.error || 'Failed to remove site');
      }
    });
  };

  const setSiteAutoSign = (origin, enabled) => {
    chrome.runtime.sendMessage({ type: 'SET_SITE_AUTOSIGN', origin, enabled }, (res) => {
      if (res && res.success) fetchTrustedSites();
      else setError(res?.error || 'Failed to update setting');
    });
  };

  const handleExport = () => {
    if (!password) return setError("Vault password required");
    if (exportFormat === 'encrypted') {
      if (passphrase.length < 8) return setError("Backup passphrase must be at least 8 characters");
      if (passphrase !== passphrase2) return setError("Passphrases don't match");
    }
    onExport(password, { format: exportFormat, passphrase }, (success, err) => {
      if (!success) setError(err || "Export failed");
      else onClose();
    });
  };

  // Read a chosen backup file. Accepts plaintext JSON ({accounts:[...]}) or an
  // encrypted .kvault backup ({salt, iv, data}); the latter needs a passphrase,
  // collected in the import view before the actual import runs.
  const handleImportFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setError('');
    setImportFileName(file.name);
    setImportPassphrase('');
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        const encrypted = !!(data && data.salt && data.iv && data.data);
        if (!encrypted && !Array.isArray(data.accounts)) throw new Error("Invalid format");
        setImportData(data);
        setImportIsEncrypted(encrypted);
      } catch (err) {
        setImportData(null);
        setImportIsEncrypted(false);
        setError("Invalid file format");
      }
    };
    reader.readAsText(file);
  };

  const handleImportConfirm = () => {
    if (!importData) return setError("Choose a backup file first");
    if (importIsEncrypted && !importPassphrase) return setError("Backup passphrase required");
    onImport(importData, importIsEncrypted ? importPassphrase : undefined);
  };

  return (
    <div className="modal-overlay">
      <div className="modal">
        <button className="close-btn" onClick={onClose}>×</button>
        <h3>Settings</h3>

        {mode === 'menu' && !showConfig && (
          <div className="settings-menu">
            <button onClick={() => setMode('export')} className="primary-btn">Export / Back up Keys</button>
            <button
              onClick={() => { setMode('import'); setError(''); setImportData(null); setImportFileName(''); setImportIsEncrypted(false); setImportPassphrase(''); }}
              className="primary-btn"
              style={{ marginTop: '10px' }}
            >
              Import Keys
            </button>
            <hr style={{ margin: '15px 0', borderColor: '#333' }} />
            <button onClick={() => { setMode('trusted-sites'); fetchTrustedSites(); }} className="secondary-btn">
              Manage Trusted Sites
            </button>
            <hr style={{ margin: '15px 0', borderColor: '#333' }} />
            <button onClick={() => setShowConfig(true)} className="text-btn" style={{ fontSize: '0.8em', color: '#888' }}>
              Config (API)
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
            <button onClick={saveConfig} className="primary-btn">Save</button>
            <button onClick={() => setShowConfig(false)} className="text-btn">Cancel</button>
          </div>
        )}

        {mode === 'export' && (
          <div className="export-flow">
            {/* Format choice */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <button
                onClick={() => { setExportFormat('encrypted'); setError(''); }}
                className={exportFormat === 'encrypted' ? 'primary-btn' : 'secondary-btn'}
                style={{ flex: 1 }}
              >
                🔒 Encrypted (.kvault)
              </button>
              <button
                onClick={() => { setExportFormat('plain'); setError(''); }}
                className={exportFormat === 'plain' ? 'danger-btn' : 'secondary-btn'}
                style={{ flex: 1 }}
              >
                Plain JSON
              </button>
            </div>

            {exportFormat === 'encrypted' ? (
              <p style={{ fontSize: '0.85em', color: '#aaa' }}>
                Password-protected backup, importable on another device or the web app
                (Receive → Backup file). Keep the file and passphrase separate.
              </p>
            ) : (
              <div className="warning-box">
                <strong>⚠️ SECURITY WARNING</strong>
                <p>This exports your private keys in <strong>plain text</strong>. Anyone with the file gets full control.</p>
              </div>
            )}

            <p style={{ marginTop: '10px' }}>Vault password (to confirm):</p>
            <input type="password" value={password} onChange={e => { setPassword(e.target.value); setError('') }} placeholder="Vault password" />

            {exportFormat === 'encrypted' && (
              <>
                <p style={{ marginTop: '10px' }}>Backup passphrase (min 8 chars):</p>
                <input type="password" value={passphrase} onChange={e => { setPassphrase(e.target.value); setError('') }} placeholder="Backup passphrase" />
                <input type="password" value={passphrase2} onChange={e => { setPassphrase2(e.target.value); setError('') }} placeholder="Confirm passphrase" style={{ marginTop: '8px' }} />
              </>
            )}

            {error && <div className="error">{error}</div>}
            <button onClick={handleExport} className={exportFormat === 'plain' ? 'danger-btn' : 'primary-btn'} style={{ marginTop: '10px' }}>
              {exportFormat === 'plain' ? 'Confirm Plain Export' : 'Download Encrypted Backup'}
            </button>
            <button onClick={() => setMode('menu')} className="text-btn">Back</button>
          </div>
        )}

        {mode === 'import' && (
          <div className="export-flow">
            <h3>Import Keys</h3>
            <p style={{ fontSize: '0.85em', color: '#aaa' }}>
              Import a plain JSON export or an encrypted <strong>.kvault</strong> backup
              made with TrustKeys or the web app. Accounts are merged into your vault.
            </p>

            <label className="primary-btn" style={{ display: 'block', textAlign: 'center', marginTop: '12px', cursor: 'pointer' }}>
              {importFileName || 'Choose a .kvault or .json file'}
              <input type="file" style={{ display: 'none' }} onChange={handleImportFile} accept=".kvault,.json,application/json" />
            </label>

            {importIsEncrypted && (
              <>
                <p style={{ marginTop: '10px' }}>Backup passphrase:</p>
                <input
                  type="password"
                  value={importPassphrase}
                  onChange={e => { setImportPassphrase(e.target.value); setError(''); }}
                  placeholder="Backup passphrase"
                />
              </>
            )}

            {error && <div className="error">{error}</div>}
            <button onClick={handleImportConfirm} className="primary-btn" disabled={!importData} style={{ marginTop: '10px' }}>
              Import
            </button>
            <button onClick={() => { setMode('menu'); setError(''); }} className="text-btn">Back</button>
          </div>
        )}

        {mode === 'trusted-sites' && (
          <div className="export-flow">
            <h3>Trusted Sites</h3>
            <p style={{ fontSize: '0.85em', color: '#aaa', marginBottom: '10px' }}>
              Sites you authorize can request signatures and decryptions with your keys.
              Only add sites you trust — at your own risk. Dev sites cannot be removed.
            </p>

            {sitesLoading ? (
              <div style={{ textAlign: 'center', padding: '20px', color: '#888' }}>Loading...</div>
            ) : (
              <div style={{ maxHeight: '220px', overflowY: 'auto', marginBottom: '10px' }}>
                {trustedSites.length === 0 ? (
                  <div style={{ color: '#888', textAlign: 'center', padding: '10px' }}>No trusted sites yet.</div>
                ) : (
                  trustedSites.map(site => (
                    <div key={site.origin} style={{ padding: '6px 8px', background: '#111', borderRadius: '4px', marginBottom: '4px', fontSize: '0.85em' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px' }}>
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
                      {!site.isDefault && (
                        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '5px', fontSize: '0.8em', color: '#aaa', cursor: 'pointer' }} title="Let this site sign chat messages without a prompt each time. Leave off to approve every message.">
                          <input
                            type="checkbox"
                            checked={!!site.autoSign}
                            onChange={e => setSiteAutoSign(site.origin, e.target.checked)}
                          />
                          Allow silent message signing
                        </label>
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

  const authorizeCurrentTab = async () => {
    const origin = currentTabOrigin;
    const isDev = !!origin && (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1'));
    if (!isDev && !(origin && origin.startsWith('https://'))) {
      alert('Only HTTPS sites can be authorized (this site uses an insecure connection).');
      return;
    }
    if (!window.confirm(
      `Authorize ${origin}?\n\nThis site will be able to request signatures and decryptions ` +
      `with your keys. Only continue if you trust it.`
    )) return;

    setLoading(true);
    try {
      // Request the per-site host permission under this user gesture.
      if (!isDev) {
        const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
        if (!granted) { setLoading(false); alert('Permission denied — site not authorized.'); return; }
      }
    } catch (e) {
      setLoading(false);
      alert('Permission request failed: ' + e.message);
      return;
    }
    chrome.runtime.sendMessage({ type: 'AUTHORIZE_CURRENT_TAB' }, (res) => {
      setLoading(false);
      if (res && res.success) {
        setAuthStatus('authorized');
      } else {
        alert('Failed to authorize: ' + (res?.error || 'Unknown error'));
      }
    });
  };

  const triggerDownload = (content, filename, mime) => {
    const dataStr = `data:${mime};charset=utf-8,` + encodeURIComponent(content);
    const a = document.createElement('a');
    a.setAttribute("href", dataStr);
    a.setAttribute("download", filename);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const handleExportKeys = (password, options, cb) => {
    const { format = 'encrypted', passphrase } = options || {};
    if (format === 'plain') {
      chrome.runtime.sendMessage({ type: 'EXPORT_KEYS', password }, (res) => {
        if (res && res.success) {
          triggerDownload(JSON.stringify({ accounts: res.accounts }), "trustkeys_backup.json", "text/json");
          cb(true);
        } else {
          cb(false, res?.error);
        }
      });
    } else {
      // Encrypted .kvault — same format the web app reads (Receive → Backup file).
      chrome.runtime.sendMessage({ type: 'EXPORT_KEYS_ENCRYPTED', password, passphrase }, (res) => {
        if (res && res.success) {
          triggerDownload(res.blob, `trustkeys-keys-${Date.now()}.kvault`, "application/json");
          cb(true);
        } else {
          cb(false, res?.error);
        }
      });
    }
  };

  const handleImportKeys = (vaultData, passphrase) => {
    chrome.runtime.sendMessage({ type: 'IMPORT_KEYS', data: vaultData, passphrase }, (res) => {
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
