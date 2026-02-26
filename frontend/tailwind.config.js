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
      }
    },
  },
  plugins: [],
}
