/** @type {import('tailwindcss').Config} */
// Every colour comes from a CSS token in src/index.css. Components never use
// raw hex values, so the palette can be tuned in one place.
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  // Severity classes are built dynamically (`sev-${severity}`).
  safelist: ['sev-HIGH', 'sev-MEDIUM', 'sev-LOW', 'sev-INFO'],
  theme: {
    extend: {
      colors: {
        paper: token('paper'),
        surface: token('surface'),
        sunken: token('sunken'),
        ink: token('ink'),
        'ink-2': token('ink-2'),
        muted: token('muted'),
        line: token('line'),
        accent: token('accent'),
        'accent-strong': token('accent-strong'),
        'accent-soft': token('accent-soft'),
        code: token('code'),
        'code-line': token('code-line'),
        'code-text': token('code-text'),
        'code-muted': token('code-muted'),
        high: token('high'),
        'high-soft': token('high-soft'),
        medium: token('medium'),
        'medium-soft': token('medium-soft'),
        low: token('low'),
        'low-soft': token('low-soft'),
        info: token('info'),
        'info-soft': token('info-soft'),
        pass: token('pass'),
        'pass-soft': token('pass-soft'),
      },
      fontFamily: {
        display: ['"Source Serif 4"', 'Georgia', 'serif'],
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '6px',
        md: '6px',
        lg: '8px',
      },
      boxShadow: {
        hard: '4px 4px 0 0 rgb(var(--ink))',
        'hard-sm': '2px 2px 0 0 rgb(var(--ink))',
      },
      maxWidth: {
        page: '1200px',
      },
    },
  },
  plugins: [],
};
