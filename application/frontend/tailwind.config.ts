import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#ffffff',
        foreground: '#0f172a',
        primary: '#2563eb',
        'primary-dark': '#1e40af',
        'primary-light': '#3b82f6',
        secondary: '#60a5fa',
        accent: '#1e3a8a',
        muted: '#64748b',
        'muted-light': '#e2e8f0',
        border: '#cbd5e1',
      },
    },
  },
  plugins: [],
}

export default config
