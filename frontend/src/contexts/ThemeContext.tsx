import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

export type ThemeName = 'obsidian' | 'carbon';

interface ThemeContextValue {
  theme: ThemeName;
  setTheme: (t: ThemeName) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function getStoredTheme(): ThemeName {
  const stored = localStorage.getItem('auditgraph-theme');
  return stored === 'carbon' ? 'carbon' : 'obsidian';
}

function applyTheme(t: ThemeName) {
  document.documentElement.setAttribute('data-theme', t);
  // Remove legacy dark class if present
  document.documentElement.classList.remove('dark');
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(getStoredTheme);

  const setTheme = useCallback((t: ThemeName) => {
    setThemeState(t);
    localStorage.setItem('auditgraph-theme', t);
    applyTheme(t);
    window.dispatchEvent(new Event('theme-sync'));
  }, []);

  // Apply on mount
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Cross-tab sync via storage event
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === 'auditgraph-theme') {
        const next = e.newValue === 'carbon' ? 'carbon' : 'obsidian';
        setThemeState(next);
        applyTheme(next);
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  // Same-tab sync via custom event (for multiple hook instances)
  useEffect(() => {
    const onSync = () => {
      const next = getStoredTheme();
      setThemeState(next);
    };
    window.addEventListener('theme-sync', onSync);
    return () => window.removeEventListener('theme-sync', onSync);
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useThemeContext(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useThemeContext must be used within ThemeProvider');
  return ctx;
}
