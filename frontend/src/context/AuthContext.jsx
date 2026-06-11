import { createContext, useState, useContext, useEffect, useRef, useCallback } from 'react';
import { isTokenExpired } from '../utils/jwt';
import { toast } from '../utils/toast';

const AuthContext = createContext();

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [authType, setAuthType] = useState(null); // 'metamask' | 'trustkeys'

    // No useEffect to load from localStorage - Session is transient.

    const login = (userData, type, accessToken) => {
        setUser(userData);
        setAuthType(type);
        setToken(accessToken);
        setIsAuthenticated(true);
    };

    const logout = useCallback(() => {
        setUser(null);
        setAuthType(null);
        setToken(null);
        setIsAuthenticated(false);
    }, []);

    const updateUser = (userData) => {
        setUser(userData);
    };

    // Session guard: when the app is backgrounded (PWA/tab) past the JWT's
    // lifetime, the in-memory session is still flagged authenticated but the
    // token is dead — every API call 401s and the app looks "stuck". Detect the
    // expired token (on resume from background, on focus, and on a periodic
    // tick) and log out cleanly so the user lands on the sign-in screen instead.
    const expiredRef = useRef(false);
    useEffect(() => {
        if (!isAuthenticated || !token) return;
        expiredRef.current = false;

        const checkSession = () => {
            if (expiredRef.current) return;          // already handled
            if (isTokenExpired(token)) {
                expiredRef.current = true;
                toast.info('Your session expired. Please sign in again.');
                logout();
            }
        };

        const onVisible = () => { if (!document.hidden) checkSession(); };
        document.addEventListener('visibilitychange', onVisible);
        window.addEventListener('focus', checkSession);
        // Also tick while in the foreground so an idle session logs out promptly.
        const interval = setInterval(checkSession, 30000);
        checkSession(); // in case we mounted with an already-stale token

        return () => {
            document.removeEventListener('visibilitychange', onVisible);
            window.removeEventListener('focus', checkSession);
            clearInterval(interval);
        };
    }, [isAuthenticated, token, logout]);

    return (
        <AuthContext.Provider value={{
            user,
            token,
            isAuthenticated,
            authType,
            login,
            logout,
            updateUser,
            setUser
        }}>
            {children}
        </AuthContext.Provider>
    );
};
