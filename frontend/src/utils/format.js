// Display formatting shared across the UI.
//
// Each of these was written inline in a dozen places, and the address ones had
// drifted into three different lengths (8, 10 and 12 characters) for the same
// idea, so the same person could be labelled differently in two panels of the
// same screen.

/** Human-readable byte size. Empty string for 0 or undefined. */
export const formatSize = (bytes) => {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

/**
 * A leading fragment of an address, for when a name is unavailable.
 *
 * Truncated from the front only. These are ML-DSA public keys, so no prefix of
 * a reasonable length is remotely unique — this is a label, never an identity
 * check. Compare full keys, or the safety number from keyFingerprint.
 */
export const shortAddress = (address, chars = 8) =>
    address ? `${address.slice(0, chars)}...` : '';

/**
 * Both ends of a value with the middle elided.
 *
 * Used where the reader is checking their OWN key against something they can
 * see elsewhere, which is the one case where showing the tail earns its space.
 */
export const middleEllipsis = (value, lead = 8, tail = 8) =>
    value && value.length > lead + tail
        ? `${value.slice(0, lead)}...${value.slice(-tail)}`
        : value || '';

/** What a deleted identity is called everywhere it still appears. */
export const DELETED_USER_LABEL = 'User removed';

/**
 * How to label a user: their name if they have one, else a short address.
 *
 * A deleted account is NOT the same thing as a lookup that failed, and this is
 * the one place that distinction is rendered. Deletion strips the row but keeps
 * it, precisely so the server can still answer "this address belonged to
 * someone who left" — without the flag a deleted sender would fall through to
 * the short-address branch and read as a stranger who never registered.
 */
export const displayName = (user) => {
    if (!user) return '';
    if (user.deleted) return DELETED_USER_LABEL;
    return user.username || shortAddress(user.address || user.user_address);
};

/** The single letter shown in an avatar bubble. */
export const avatarInitial = (nameOrAddress) =>
    (nameOrAddress || '?').substring(0, 1).toUpperCase();
