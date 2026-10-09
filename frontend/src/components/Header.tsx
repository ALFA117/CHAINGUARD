import { motion, AnimatePresence } from 'motion/react';
import { Moon, ShieldCheck, Sun, ScanSearch } from 'lucide-react';
import { useTheme } from '../lib/theme';
import { springSnappy } from '../lib/motion';

interface HeaderProps {
  totalVulns: number;
  totalContracts: number;
}

export default function Header({ totalVulns, totalContracts }: HeaderProps) {
  const { theme, toggle } = useTheme();

  return (
    <header className="sticky top-0 z-40 px-3 pt-3 sm:px-5" style={{ paddingTop: 'max(12px, env(safe-area-inset-top))' }}>
      <div className="card mx-auto flex max-w-7xl items-center gap-3 px-3 py-2 sm:px-4">
        <a href="#top" className="flex min-h-[44px] min-w-0 items-center gap-2.5 rounded-xl pr-1" aria-label="ChainGuard, back to top">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <ShieldCheck className="h-5 w-5" aria-hidden />
          </span>
          <span className="flex min-w-0 flex-col leading-none">
            <span className="font-display text-lg font-bold tracking-tight">ChainGuard</span>
            <span className="hidden truncate pt-1 font-mono text-xs text-muted sm:block">Solidity vulnerability scanner</span>
          </span>
        </a>

        <div className="ml-auto flex shrink-0 items-center gap-2">
          {/* Real, per-session totals; nothing is stored or reported anywhere */}
          <AnimatePresence>
            {totalContracts > 0 && (
              <motion.p
                key="session"
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="hidden font-mono text-xs text-muted md:block"
                aria-live="polite"
              >
                This session: <span className="font-semibold text-ink">{totalContracts}</span> scanned ·{' '}
                <span className="font-semibold text-ink">{totalVulns}</span> findings
              </motion.p>
            )}
          </AnimatePresence>

          <motion.button
            type="button"
            onClick={toggle}
            className="btn-icon"
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            whileTap={{ scale: 0.92 }}
            transition={springSnappy}
          >
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={theme}
                className="flex"
                initial={{ opacity: 0, rotate: -90, scale: 0.6 }}
                animate={{ opacity: 1, rotate: 0, scale: 1 }}
                exit={{ opacity: 0, rotate: 90, scale: 0.6 }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              >
                {theme === 'dark' ? <Sun className="h-4 w-4" aria-hidden /> : <Moon className="h-4 w-4" aria-hidden />}
              </motion.span>
            </AnimatePresence>
          </motion.button>

          <motion.a
            href="#scanner"
            className="btn-primary px-4"
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.96 }}
            transition={springSnappy}
            aria-label="Go to the scanner"
          >
            <ScanSearch className="h-4 w-4" aria-hidden />
            <span className="hidden min-[400px]:inline">Scan</span>
          </motion.a>
        </div>
      </div>
    </header>
  );
}
