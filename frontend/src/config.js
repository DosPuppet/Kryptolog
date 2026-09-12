const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export const API_ENDPOINTS = {
    BASE: API_BASE_URL,
    AUTH: {
        NONCE: (address) => `${API_BASE_URL}/auth/nonce/${address}`,
        LOGIN: `${API_BASE_URL}/auth/login`,
        LOGOUT: `${API_BASE_URL}/auth/logout`,
    },
    // The caller's own account, as opposed to USERS which is the directory.
    ACCOUNT: {
        // Messages an erase must redact rather than delete, because they carry
        // a session key other people's messages depend on. Paged (audit O-3).
        REDACTABLE: `${API_BASE_URL}/account/redactable-messages`,
        DELETE: `${API_BASE_URL}/account/delete`,
    },
    USERS: {
        GET: (address) => `${API_BASE_URL}/users/${address}`,
        LIST: `${API_BASE_URL}/users`,
        UPDATE: (address) => `${API_BASE_URL}/users/${address}`,
        RESOLVE: `${API_BASE_URL}/users/resolve`,
    },
    SECRETS: {
        LIST: `${API_BASE_URL}/secrets`,
        // The lists return metadata only (audit O-3) — a secret's ciphertext
        // comes from here, one secret at a time, when the user opens it.
        GET: (secretId) => `${API_BASE_URL}/secrets/${secretId}`,
        CREATE: `${API_BASE_URL}/secrets`,
        SHARE: `${API_BASE_URL}/secrets/share`,
        SHARED_WITH: `${API_BASE_URL}/secrets/shared-with-me`,
        ACCESS: (secretId) => `${API_BASE_URL}/secrets/${secretId}/access`,
        UPDATE: (secretId) => `${API_BASE_URL}/secrets/${secretId}`,
        DELETE: (secretId) => `${API_BASE_URL}/secrets/${secretId}`,
        REVOKE: (grantId) => `${API_BASE_URL}/secrets/share/${grantId}`,
        CHUNKS_UPLOAD: `${API_BASE_URL}/secrets/chunks`,
        // No bulk chunk listing: the server endpoint was removed (audit H-2) —
        // it returned every chunk's full payload in one response. Fetch chunks
        // one at a time by index instead (see utils/fileChunks.js).
        CHUNK: (secretId, index) => `${API_BASE_URL}/secrets/${secretId}/chunks/${index}`,
    },
    GROUPS: {
        LIST: `${API_BASE_URL}/groups`,
        CREATE: `${API_BASE_URL}/groups`,
        GET: (channelId) => `${API_BASE_URL}/groups/${channelId}`,
        MESSAGES: (channelId) => `${API_BASE_URL}/groups/${channelId}/messages`,
        HISTORY: (channelId) => `${API_BASE_URL}/groups/${channelId}/history`,
        MEMBERS: (channelId) => `${API_BASE_URL}/groups/${channelId}/members`,
        REMOVE_MEMBER: (channelId, addr) => `${API_BASE_URL}/groups/${channelId}/members/${addr}`,
        UPDATE_ROLE: (channelId, addr) => `${API_BASE_URL}/groups/${channelId}/members/${addr}/role`,
        DETAILS: (channelId) => `${API_BASE_URL}/groups/${channelId}`,
    },
    MULTISIG: {
        // Note the singular/plural split, which mirrors the server: the
        // collection is /workflows, every single-workflow route is /workflow.
        CREATE: `${API_BASE_URL}/multisig/workflow`,
        WORKFLOWS: `${API_BASE_URL}/multisig/workflows`,
        WORKFLOW: (id) => `${API_BASE_URL}/multisig/workflow/${id}`,
        SIGN: (id) => `${API_BASE_URL}/multisig/workflow/${id}/sign`,
        REJECT: (id) => `${API_BASE_URL}/multisig/workflow/${id}/reject`,
    },
    NOTIFICATIONS: {
        SUBSCRIBE: `${API_BASE_URL}/notifications/subscribe`,
        UNSUBSCRIBE: `${API_BASE_URL}/notifications/unsubscribe`,
        TEST: `${API_BASE_URL}/notifications/test`,
    },
    TRANSFERS: {
        CREATE: `${API_BASE_URL}/transfers`,
        CLAIM: (id) => `${API_BASE_URL}/transfers/${id}`,
    }
};

export default API_ENDPOINTS;
