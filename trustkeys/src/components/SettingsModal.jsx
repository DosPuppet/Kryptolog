import { useState, useEffect } from 'react'

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
      } catch {
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

export default SettingsModal;
