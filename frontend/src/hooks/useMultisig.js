import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import API_ENDPOINTS from '../config';

export function useMultisig() {
    const { token, user } = useAuth();
    const [workflows, setWorkflows] = useState([]);
    const [loading, setLoading] = useState(true);

    const [actionRequiredCount, setActionRequiredCount] = useState(0);

    useEffect(() => {
        if (token) {
            fetchWorkflows();
            // Poll for updates every 10 seconds
            const interval = setInterval(fetchWorkflows, 10000);
            return () => clearInterval(interval);
        }
    }, [token]);

    const fetchWorkflows = async () => {
        try {
            const res = await fetch(API_ENDPOINTS.SECRETS.LIST + '/../multisig/workflows', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
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
                        // 2. Workflow is complete and I am a recipient (maybe notification needed? let's stick to signer actions for now for red dot)
                        // Actually, if I created it and it's done?
                        // Let's stick to "Blocking Actions": Need to sign.
                        return isSigner && wf.status === 'pending';
                    }).length;
                    setActionRequiredCount(count);
                }
            }
        } catch (error) {
            console.error("Failed to fetch workflows", error);
        } finally {
            setLoading(false);
        }
    };

    const createWorkflow = async (name, signers, recipients, secretId) => {
        // This usually requires a separate modal logic or API call helper
        // For now just exposing state and fetch
        // API call would be here if extended
    };

    return {
        workflows,
        loading,
        fetchWorkflows,
        setWorkflows, // Exposed for optimistic updates
        actionRequiredCount
    };
}
