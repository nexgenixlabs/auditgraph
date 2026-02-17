import { useThemeContext, ThemeName } from '../contexts/ThemeContext';

/**
 * Thin wrapper around ThemeContext for backward compatibility.
 * `dark` is always true (we only have dark themes).
 * `toggle` cycles between obsidian and carbon.
 */
export function useTheme() {
  const { theme, setTheme } = useThemeContext();

  const toggle = () => {
    setTheme(theme === 'obsidian' ? 'carbon' : 'obsidian');
  };

  return {
    theme,
    dark: true as const,
    setTheme,
    toggle,
  };
}
