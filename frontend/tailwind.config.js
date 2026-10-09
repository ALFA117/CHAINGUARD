/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: token('bg'),
        surface: token('surface'),
        surface2: token('surface-2'),
        line: token('line'),
        ink: token('ink'),
        muted: token('muted'),
        accent: token('accent'),
        'on-accent': token('on-accent'),
        // Severity, one hue per level, each measured to 4.5:1 in both themes
        crit: token('crit'),
        warn: token('warn'),
        low: token('low'),
        info: token('info'),
      },
      fontFamily: {
        display: ['"Bricolage Grotesque"', 'system-ui', 'sans-serif'],
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        soft: '0 1px 2px rgb(var(--shadow) / 0.12), 0 10px 28px -14px rgb(var(--shadow) / 0.45)',
        lift: '0 2px 6px rgb(var(--shadow) / 0.16), 0 28px 56px -24px rgb(var(--shadow) / 0.6)',
      },
    },
  },
  plugins: [],
};
