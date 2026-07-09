import { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext();

export const useTheme = () => {
    const context = useContext(ThemeContext);
    if (!context) throw new Error('useTheme must be used within a ThemeProvider');
    return context;
};

export const ThemeProvider = ({ children }) => {
    // Default to dark if no match found (kryptolog default)
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

    const toggleTheme = (event) => {
        // Use the click event's timestamp (a page-relative monotonic clock)
        // rather than the impure Date.now(), which the purity rule flags.
        const now = event?.timeStamp ?? 0;
        // A pause > 800ms between clicks restarts the streak. Compute the new
        // count locally: checking the clickCount state here would read the
        // pre-reset value and fire the egg on a single click after a pause.
        const streak = now - lastClickTime > 800 ? 1 : clickCount + 1;
        setClickCount(streak >= 10 ? 0 : streak);
        setLastClickTime(now);

        setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));

        // Easter Egg: 10 rapid toggles in a row
        if (streak >= 10) {
            triggerRetroMode();
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
