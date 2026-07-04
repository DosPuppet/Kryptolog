import { useRef } from 'react';
import { encryptGroupName, decryptGroupName, groupNameWrapFor, isEncryptedTitle, LOCKED_TITLE } from '../../utils/titles';
import { assertSafeRecipient } from '../../services/trustedKeys';

// Encrypted group-channel names (audit M-3): decrypt `encg1:` blobs with my
// per-member-wrapped name key, and build fresh blobs for create/rename/re-wrap.
export const useGroupNames = ({ user, mlkemKey, unwrapManySessionKeys }) => {
    // Group-name keys, keyed by my wrap's JSON so re-fetches never re-prompt;
    // unresolved wraps decrypt in ONE batch.
    const groupNameKeyCache = useRef({});

    // Decrypt an encrypted channel name with my wrapped name-key, resolving
    // uncached wraps in ONE batch unwrap. Legacy plaintext passes through;
    // undecryptable names render a locked placeholder.
    const resolveChannelName = async (channel, batchCache = null) => {
        const name = channel?.name;
        if (!isEncryptedTitle(name)) return name ?? '';
        const wrap = groupNameWrapFor(name, user.address);
        if (!wrap) return LOCKED_TITLE;
        const cacheKey = JSON.stringify(wrap);
        let key = (batchCache ?? groupNameKeyCache.current)[cacheKey];
        if (key === undefined) {
            try {
                key = (await unwrapManySessionKeys([wrap]))[0] || null;
            } catch { key = null; }
            groupNameKeyCache.current[cacheKey] = key;
        }
        const plain = await decryptGroupName(name, key);
        return plain ?? LOCKED_TITLE;
    };

    const resolveGroupNames = async (groups) => {
        // Batch-unwrap every uncached name-key first (one extension approval).
        const pending = [];
        for (const g of groups) {
            const wrap = isEncryptedTitle(g.channel?.name) ? groupNameWrapFor(g.channel.name, user.address) : null;
            if (wrap && !(JSON.stringify(wrap) in groupNameKeyCache.current)) pending.push(wrap);
        }
        if (pending.length > 0) {
            try {
                const keys = await unwrapManySessionKeys(pending);
                pending.forEach((w, i) => { groupNameKeyCache.current[JSON.stringify(w)] = keys[i] || null; });
            } catch (e) {
                console.error("Group name key batch unwrap failed", e);
                pending.forEach((w) => { groupNameKeyCache.current[JSON.stringify(w)] = null; });
            }
        }
        return Promise.all(groups.map(async (g) => ({
            ...g,
            channel: { ...g.channel, display_name: await resolveChannelName(g.channel) },
        })));
    };

    // Build the encrypted name blob for the given member set (audit M-3).
    // Always mints a FRESH name key, so members removed before a rename can
    // never read the new name. Attestation-gated like message-key wraps.
    const buildGroupNameBlob = async (plainName, memberUsers) => {
        const me = { address: user.address, encryption_public_key: user?.encryption_public_key || mlkemKey };
        const targets = [me];
        for (const m of memberUsers) {
            if (m.address.toLowerCase() === me.address.toLowerCase()) continue;
            await assertSafeRecipient(m); // throws on an invalid attestation
            targets.push(m);
        }
        return encryptGroupName(plainName, targets);
    };

    return { resolveChannelName, resolveGroupNames, buildGroupNameBlob };
};
