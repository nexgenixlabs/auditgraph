import React from 'react';
import { useTheme } from '../../hooks/useTheme';

export default function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div
      className="flex items-center rounded-lg border p-0.5 gap-0.5"
      style={{
        borderColor: 'var(--border-default)',
        backgroundColor: 'var(--bg-primary)',
      }}
    >
      <button
        onClick={() => setTheme('dark')}
        className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium transition-colors"
        style={{
          backgroundColor: theme === 'dark' ? 'var(--accent-primary-bg)' : 'transparent',
          color: theme === 'dark' ? 'var(--accent-primary)' : 'var(--text-tertiary)',
        }}
        title="Dark theme"
      >
        {/* Moon icon */}
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
        <span className="hidden sm:inline">Dark</span>
      </button>
      <button
        onClick={() => setTheme('natural')}
        className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium transition-colors"
        style={{
          backgroundColor: theme === 'natural' ? 'var(--accent-primary-bg)' : 'transparent',
          color: theme === 'natural' ? 'var(--accent-primary)' : 'var(--text-tertiary)',
        }}
        title="Natural theme"
      >
        {/* Sun icon */}
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        </svg>
        <span className="hidden sm:inline">Natural</span>
      </button>
    </div>
  );
}
