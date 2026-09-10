import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import API_ENDPOINTS from '../config';
import { fetchAllPages, pageUrl } from '../utils/paging';
import { apiFetch } from '../services/api';

export function useMultisig() {
    const { token, user } = useAuth();
    const [workflows, setWorkflows] = useState([]);
    const [loading, setLoading] = useState(true);

    const [actionRequiredCount, setActionRequiredCount] = useState(0);

    // Fetch + poll while authenticated. fetchWorkflows closes only over the
    // current token, so re-running solely on token change is correct; keeping
    // it out of deps avoids tearing down the interval every render.
    useEffect(() => {
        if (token) {
            fetchWorkflows();
            // Poll for updates every 10 seconds
            const interval = setInterval(fetchWorkflows, 10000);
            return () => clearInterval(interval);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    const fetchWorkflows = async () => {
        try {
            // Paged (audit O-3): a workflow awaiting my signature must not be
            // invisible because it sits past the first page.
            const data = await fetchAllPages((page) =>
                apiFetch(pageUrl(API_ENDPOINTS.MULTISIG.WORKFLOWS, page), token)
            );
            setWorkflows(data);

            // Calculate Action Required
            if (user && user.address) {
                const count = data.filter(wf => {
                    const myAddr = user.address.toLowerCase();
                    // 1. I am a signer and haven't signed
                    const isSigner = wf.signers.some(s => {
                        const sAddr = s.user_address || (s.user && s.user.address);
                        return sAddr && sAddr.toLowerCase() === myAddr && !s.has_signed;
                    });
                    // Only blocking actions raise the dot: a signature this user
                    // still owes. Being a recipient of a finished workflow does not.
                    return isSigner && wf.status === 'pending';
                }).length;
                setActionRequiredCount(count);
            }
        } catch (error) {
            console.error("Failed to fetch workflows", error);
        } finally {
            setLoading(false);
        }
    };

    return {
        workflows,
        loading,
        fetchWorkflows,
        setWorkflows, // Exposed for optimistic updates
        actionRequiredCount
    };
}
