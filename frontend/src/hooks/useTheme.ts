import { useThemeContext } from '../contexts/ThemeContext';

/**
 * Obsidian Command — dark-only theme.
 * `dark` is always true. `toggle` is a no-op.
 */
export function useTheme() {
  const { theme, setTheme } = useThemeContext();

  return {
    theme,
    dark: true,
    setTheme,
    toggle: () => {},
  };
}
