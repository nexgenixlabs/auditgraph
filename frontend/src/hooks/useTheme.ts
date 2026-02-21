import { useThemeContext } from '../contexts/ThemeContext';

/**
 * Thin wrapper around ThemeContext.
 * `dark` is true when theme is 'dark', false for 'natural'.
 * `toggle` cycles between dark and natural.
 */
export function useTheme() {
  const { theme, setTheme } = useThemeContext();

  const toggle = () => {
    setTheme(theme === 'dark' ? 'natural' : 'dark');
  };

  return {
    theme,
    dark: theme === 'dark',
    setTheme,
    toggle,
  };
}
