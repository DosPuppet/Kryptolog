import React, { createContext, useState, useContext } from 'react';

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

    const logout = () => {
        setUser(null);
        setAuthType(null);
        setToken(null);
        setIsAuthenticated(false);
    };

    const updateUser = (userData) => {
        setUser(userData);
    };

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
