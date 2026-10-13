// Per-request approval screens, opened by the background service worker when a
// connected site asks to connect / sign / decrypt and user consent is required.

export const ConnectScreen = ({ requestData, onResolve }) => {
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

// What a signature request DOES, in words (audit 2026-10-12 K-03). The window
// used to show the raw signed body, which no person reads; a login challenge
// for another site looked like any other string. The background now sends a
// `kind` and typed `details`, and the exact bytes stay one click away.
const describeSignature = ({ kind, details = {}, origin }) => {
  switch (kind) {
    case 'login':
      return { title: 'Sign in', lines: [`Sign in to Kryptolog at ${origin}.`, `Server: ${details.deployment}`] };
    case 'account-deletion':
      return {
        title: 'Delete account',
        danger: true,
        lines: (details.mode === 'erase'
          ? [`Permanently ERASE this account on ${origin}.`, 'Your content is removed and this key can never be used there again.',
            `${details.redactions} message(s) will be redacted.`]
          : [`Remove this account from ${origin}.`, 'Logging in again with this key brings it back.'])
          .concat(details.address ? [`Account: ${details.address}`] : []),
      };
    case 'conversation-erase':
      return {
        title: 'Erase your messages',
        danger: true,
        lines: [
          details.conversationKind === 'dm'
            ? `Permanently erase YOUR messages in the conversation with ${details.conversation} on ${origin}.`
            : `Permanently erase YOUR messages in group ${details.conversation} on ${origin}.`,
          'Their messages stay. This cannot be undone.',
          `${details.redactions} message(s) will be redacted.`,
        ],
      };
    case 'multisig-approval':
      return {
        title: 'Approve workflow',
        lines: [`Approve multisig workflow #${details.workflowId} (secret #${details.secretId}) on ${origin}.`,
          `Content fingerprint: ${String(details.ciphertextSha384).slice(0, 16)}…`],
      };
    case 'content':
      return { title: 'Sign document', lines: [`${origin} asks you to sign this document:`], text: details.text };
    case 'message':
      return { title: 'Sign message', lines: [`Sign a chat message on ${origin}.`] };
    default:
      return {
        title: 'Signature request',
        danger: true,
        lines: [`${origin} asks you to sign text that is not a Kryptolog document.`, 'Sign it only if you know why.'],
      };
  }
};

const boxStyle = { background: '#111', padding: '10px', borderRadius: '6px', width: '100%', marginBottom: '12px', textAlign: 'left', maxHeight: '120px', overflowY: 'auto' };

export const SignScreen = ({ requestData, onResolve }) => {
  const d = describeSignature(requestData);
  return (
    <div className="auth-screen">
      <h2>{d.title}</h2>
      {d.lines.map((line) => (
        <p key={line} style={d.danger ? { color: '#f87171' } : undefined}>{line}</p>
      ))}
      {requestData.account && <p style={{ fontSize: '0.8em', color: '#888' }}>As: {requestData.account}</p>}
      {d.text != null && (
        <div style={boxStyle}><code style={{ fontSize: '0.85em', wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>{d.text}</code></div>
      )}
      <details style={{ width: '100%', marginBottom: '16px', textAlign: 'left' }}>
        <summary style={{ fontSize: '0.75em', color: '#888', cursor: 'pointer' }}>Exact bytes to be signed</summary>
        <div style={boxStyle}><code style={{ fontSize: '0.75em', wordBreak: 'break-all' }}>{requestData.message}</code></div>
      </details>
      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
        <button onClick={() => onResolve(false)} style={{ flex: 1, padding: '12px', background: '#333', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Reject</button>
        <button className="primary" onClick={() => onResolve(true)} style={{ flex: 1 }}>Sign</button>
      </div>
    </div>
  );
};

export const DecryptScreen = ({ requestData, onResolve }) => {
  return (
    <div className="auth-screen">
      <h2>Decryption Request</h2>
      <p><strong>{requestData.origin}</strong> is requesting to decrypt{' '}
        {requestData.kind === 'session-keys'
          ? `${requestData.count ?? 1} conversation key(s) — this lets it read those messages`
          : `${requestData.count ?? 1} encrypted item(s) addressed to you`}.</p>
      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
        <button onClick={() => onResolve(false)} style={{ flex: 1, padding: '12px', background: '#333', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Reject</button>
        <button className="primary" onClick={() => onResolve(true)} style={{ flex: 1 }}>Decrypt</button>
      </div>
    </div>
  );
};
