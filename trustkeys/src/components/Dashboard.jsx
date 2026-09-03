import { useState, useEffect } from 'react'
import SettingsModal from './SettingsModal'

// Main unlocked popup view: active account, per-tab authorization, account
// list/create/delete, and the settings modal (export/import/trusted sites).
const Dashboard = () => {
  const [accounts, setAccounts] = useState([]);
  const [activeAccount, setActiveAccount] = useState(null);
  const [newAccountName, setNewAccountName] = useState('');
  const [loading, setLoading] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [currentTabOrigin, setCurrentTabOrigin] = useState(null);
  const [authStatus, setAuthStatus] = useState(null); // null, 'authorized', 'unauthorized'

  // Declared above the mount effect that calls them: a `const` arrow function is
  // in its temporal dead zone until its own line, so declaring these below the
  // effect leaves the effect reading a binding that is not initialized yet
  // (react-hooks/immutability).
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
              <button onClick={() => copyToClipboard(activeAccount.mlkemPublicKey, 'mlkem')} className={copyFeedback === 'mlkem' ? 'copied' : ''}>
                {copyFeedback === 'mlkem' ? 'COPIED' : 'COPY'}
              </button>
            </div>
            <div className="key-box">{activeAccount.mlkemPublicKey}</div>
          </div>

          <div className="key-section">
            <div className="key-header">
              <span>ML-DSA (Dilithium)</span>
              <button onClick={() => copyToClipboard(activeAccount.mldsaPublicKey, 'mldsa')} className={copyFeedback === 'mldsa' ? 'copied' : ''}>
                {copyFeedback === 'mldsa' ? 'COPIED' : 'COPY'}
              </button>
            </div>
            <div className="key-box">{activeAccount.mldsaPublicKey}</div>
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

export default Dashboard;
