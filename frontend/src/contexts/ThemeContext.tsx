import React, { createContext, useContext, useEffect } from 'react';

export type ThemeName = 'obsidian' | 'sentinel' | 'arctic';

interface ThemeContextValue {
  theme: ThemeName;
  setTheme: (t: ThemeName) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function applyTheme() {
  document.documentElement.setAttribute('data-theme', 'obsidian');
  document.documentElement.classList.remove('dark');
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    applyTheme();
    localStorage.setItem('auditgraph-theme', 'obsidian');
  }, []);

  const value: ThemeContextValue = {
    theme: 'obsidian',
    setTheme: () => {
      // Dark-only — no-op, always obsidian
      applyTheme();
    },
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useThemeContext(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useThemeContext must be used within ThemeProvider');
  return ctx;
}
