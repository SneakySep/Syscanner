import type { Config } from 'tailwindcss';

const config: Config = {
  // The shared UI package ships Tailwind class names, so its source must be
  // scanned too or those classes would be purged from the build.
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', '../../packages/ui/src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: '#0b1120',
        panel: '#111827',
      },
    },
  },
  plugins: [],
};

export default config;
