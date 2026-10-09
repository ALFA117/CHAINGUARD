import { useCallback, useEffect, useState } from 'react';

export type Theme = 'dark' | 'light';
const KEY = 'cg-theme';

// index.html stamps the theme before first paint; this reads it back and toggles it.
export function useTheme() {
  const [theme, setTheme] = useState<Theme>('dark');
  useEffect(() => {
    const t = document.documentElement.dataset.theme;
    if (t === 'light' || t === 'dark') setTheme(t);
  }, []);
  const toggle = useCallback(() => {
    setTheme((prev) => {
      const next: Theme = prev === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem(KEY, next); } catch { /* private mode: this visit only */ }
      return next;
    });
  }, []);
  return { theme, toggle };
}

// Follows the theme attribute wherever it is changed (used by Monaco).
export function useDocTheme(): Theme {
  const read = (): Theme => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
  const [t, setT] = useState<Theme>(read);
  useEffect(() => {
    const mo = new MutationObserver(() => setT(read()));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => mo.disconnect();
  }, []);
  return t;
}
