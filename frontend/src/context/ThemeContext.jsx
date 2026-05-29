import React, { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext();

export const useTheme = () => {
    const context = useContext(ThemeContext);
    if (!context) throw new Error('useTheme must be used within a ThemeProvider');
    return context;
};

export const ThemeProvider = ({ children }) => {
    // Default to dark if no match found (safelog default)
    const [theme, setTheme] = useState(() => {
        if (localStorage.getItem('theme')) {
            return localStorage.getItem('theme');
        }
        return 'dark';
    });

    const [isRetro, setIsRetro] = useState(() => localStorage.getItem('retro') === 'true');
    const [isCrashing, setIsCrashing] = useState(false);
    const [clickCount, setClickCount] = useState(0);
    const [lastClickTime, setLastClickTime] = useState(0);

    useEffect(() => {
        const root = window.document.documentElement;
        root.classList.remove('light', 'dark');
        root.classList.add(theme);
        localStorage.setItem('theme', theme);
    }, [theme]);

    useEffect(() => {
        if (isRetro) {
            document.documentElement.classList.add('retro');
        } else {
            document.documentElement.classList.remove('retro');
        }
        localStorage.setItem('retro', isRetro);
    }, [isRetro]);

    const toggleTheme = () => {
        const now = Date.now();
        // Reset if too slow (> 1s between clicks is generous, but total sequence matters)
        // Plan said: 10 times in 3 seconds.
        // Let's just track rapid clicks.
        if (now - lastClickTime > 800) {
            setClickCount(1);
        } else {
            setClickCount(prev => prev + 1);
        }
        setLastClickTime(now);

        setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));

        // Trigger Easter Egg
        if (clickCount >= 9) { // 9 + current click = 10
            triggerRetroMode();
            setClickCount(0);
        }
    };

    const triggerRetroMode = () => {
        if (isRetro) {
            // Disable if already on? Or maybe re-crash? Let's toggle off for sanity if they spam again.
            setIsRetro(false);
            return;
        }
        setIsCrashing(true);
        setTimeout(() => {
            setIsCrashing(false);
            setIsRetro(true);
        }, 3000); // 3s crash animation
    };

    return (
        <ThemeContext.Provider value={{ theme, toggleTheme, isRetro, isCrashing }}>
            {children}
        </ThemeContext.Provider>
    );
};
