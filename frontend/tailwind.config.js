/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#2563EB',
        danger: '#DC2626',
        warning: '#F59E0B',
        success: '#10B981',
        // Obsidian Command palette
        'ob-deep':    '#06090f',
        'ob-surface': '#0c1220',
        'ob-raised':  '#111a2e',
        'ob-elevated': '#162038',
        'ob-hover':   '#1a2744',
        'ob-active':  '#1f2f52',
        'ob-border':  '#1e2d4a',
        'ob-accent':  '#2563eb',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'monospace'],
      },
      spacing: {
        'sidebar': '220px',
        'sidebar-collapsed': '56px',
        'header': '56px',
      },
      borderRadius: {
        'card': '12px',
        'inner': '8px',
      },
    },
  },
  plugins: [],
}
