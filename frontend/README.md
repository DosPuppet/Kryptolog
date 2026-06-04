# Kryptolog Frontend

The React-based frontend for Kryptolog, featuring dual authentication (MetaMask + TrustKeys) and a context-driven secure architecture.

## Architecture

### Context Providers (`/src/context`)

The application state is managed through three distinct contexts to separate concerns:

1. **`AuthContext.jsx`**
   - **Role**: Global User Session Management.
   - **State**: `user` object, `isAuthenticated`, `authType` ('metamask' | 'trustkeys').
   - **Functions**: `login`, `logout`, `updateUser`.
   - **Dependents**: Consumed by UI components to check login status.

2. **`Web3Context.jsx`**
   - **Role**: Ethereum / MetaMask Integration.
   - **State**: `currentAccount` (Eth Address), `encryptionPublicKey` (Eth Key).
   - **Functions**: `connect`, `login` (Sign-in with Ethereum).
   - **Dependents**: Used for standard wallet operations.

3. **`PQCContext.jsx`**
   - **Role**: TrustKeys / Post-Quantum Integration.
   - **State**: `pqcAccount` (Dilithium PK), `kyberKey` (Encryption Key).
   - **Functions**: 
     - `loginTrustKeys`: Authenticates via PQC signature.
     - `encrypt`: Client-side hybrid encryption (Kyber+AES).
     - `decrypt`: Client-side decryption.

### Component Structure

- **`Login.jsx`**: Handles the initial routing to either MetaMask or TrustKeys login flows.
- **`Dashboard.jsx`**: Main secure area. 
  - Dynamically switches encryption/decryption logic based on `authType`.
  - Adapts UI labels (e.g., "Wallet Address" vs "ML-DSA ID").
- **`utils/crypto.js`**: Helper functions for standard Ethereum cryptography.

## Development

### Setup

```bash
# Install dependencies
npm install

# Setup environment
cp .env.example .env
```

### Environment Variables

Edit `.env`:
```ini
VITE_API_BASE_URL=http://localhost:8000
ALLOWED_HOSTS=localhost,kryptolog.hashpar.com
```

### Run

```bash
# Run dev server
npm run dev
```

## Key Features

- **Profile Management**: Users can update their username.
- **Secret Sharing**: Secrets are re-encrypted client-side for the recipient.
- **File Vault**: Upload, Encrypt, and Timebomb files.
- **Truncated Display**: Long keys (Ethereum and PQC) are visually truncated (e.g., `0x123...456`) but full keys are available via copy-to-clipboard.

## TrustKeys Integration

The frontend detects the `window.trustkeys` API injected by the browser extension.

- **Check Availability**: `usePQC().checkAvailability()`
- **Login Flow**:
  1. Frontend requests Connection (`window.trustkeys.connect()`).
  2. Frontend requests Account Info.
  3. Frontend signs a Nonce with ML-DSA-44 (`sign()`).
  4. Backend verifies the signature in-process via liboqs.
