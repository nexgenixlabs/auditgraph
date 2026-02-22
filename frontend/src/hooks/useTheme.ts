import { useThemeContext } from '../contexts/ThemeContext';

/**
 * Thin wrapper around ThemeContext.
 * `dark` is true when theme is 'obsidian', false for 'arctic'.
 * `toggle` cycles between obsidian and arctic.
 */
export function useTheme() {
  const { theme, setTheme } = useThemeContext();

  const toggle = () => {
    setTheme(theme === 'obsidian' ? 'arctic' : 'obsidian');
  };

  return {
    theme,
    dark: theme === 'obsidian',
    setTheme,
    toggle,
  };
}
