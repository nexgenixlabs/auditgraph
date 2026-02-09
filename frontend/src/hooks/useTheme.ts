import { useState, useEffect, useCallback } from 'react';

export function useTheme() {
  const [dark, setDark] = useState(() => {
    const stored = localStorage.getItem('theme');
    if (stored) return stored === 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  }, [dark]);

  // Sync across multiple hook instances (storage event only fires cross-tab)
  useEffect(() => {
    const handler = () => {
      const stored = localStorage.getItem('theme');
      if (stored) setDark(stored === 'dark');
    };
    window.addEventListener('theme-sync', handler);
    return () => window.removeEventListener('theme-sync', handler);
  }, []);

  const toggle = useCallback(() => {
    setDark(prev => {
      const next = !prev;
      localStorage.setItem('theme', next ? 'dark' : 'light');
      document.documentElement.classList.toggle('dark', next);
      window.dispatchEvent(new Event('theme-sync'));
      return next;
    });
  }, []);

  return { dark, toggle };
}
