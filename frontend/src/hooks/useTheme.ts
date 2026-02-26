import { useThemeContext } from '../contexts/ThemeContext';

/**
 * Thin wrapper around ThemeContext.
 * `dark` is true when theme is 'sentinel', false for 'arctic'.
 * `toggle` cycles between sentinel and arctic.
 */
export function useTheme() {
  const { theme, setTheme } = useThemeContext();

  const toggle = () => {
    setTheme(theme === 'sentinel' ? 'arctic' : 'sentinel');
  };

  return {
    theme,
    dark: theme === 'sentinel',
    setTheme,
    toggle,
  };
}
