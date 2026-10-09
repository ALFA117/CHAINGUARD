import { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion, stagger, useReducedMotion, type Variants } from 'motion/react';
import { ArrowDown, RefreshCw, ScanSearch, WifiOff } from 'lucide-react';
import { REENTRANCY_EXAMPLE } from './CodeEditor';
import { analyzeContract } from '../api/analyze';
import SecurityScore from './SecurityScore';
import { AnalysisResult } from '../types';
import { SEVERITY } from '../lib/severity';
import { springSnappy } from '../lib/motion';

const list: Variants = { hidden: {}, show: { transition: { delayChildren: stagger(0.08, { startDelay: 0.05 }) } } };
const item: Variants = { hidden: { opacity: 0, y: 16 }, show: { opacity: 1, y: 0, transition: { duration: 0.45, ease: [0.16, 1, 0.3, 1] as const } } };

// The two incidents below are the classes ChainGuard actually checks for.
const LOSSES = [
  { amount: '$60M', what: 'The DAO, 2016', rule: 'Reentrancy · SWC-107' },
  { amount: '$150M', what: 'Parity multisig, 2017 — frozen', rule: 'Unprotected selfdestruct · SWC-106' },
];

// withdraw() of the example contract, lines 11–20, shown verbatim
const SRC_LINES = REENTRANCY_EXAMPLE.split('\n');
const FROM = 11;
const TO = 20;

export default function LandingHero() {
  const reduce = useReducedMotion();
  const [preview, setPreview] = useState<AnalysisResult | null>(null);
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading');

  // A real scan of the same example the scanner below opens with — never a mockup.
  const run = useCallback(() => {
    setState('loading');
    analyzeContract(REENTRANCY_EXAMPLE)
      .then((res) => { setPreview(res); setState('ready'); })
      .catch(() => setState('error'));
  }, []);
  useEffect(() => { run(); }, [run]);

  const flagged = new Set(preview?.vulnerabilities.map((v) => v.line).filter((l): l is number => l !== null));
  const top = preview?.vulnerabilities[0];

  return (
    <section id="top" className="relative mx-auto grid max-w-7xl scroll-mt-24 items-center gap-12 px-4 pb-16 pt-10 sm:px-6 sm:pt-16 lg:grid-cols-[1.1fr_1fr] lg:gap-14">
      <motion.div variants={reduce ? undefined : list} initial={reduce ? false : 'hidden'} animate="show">
        <motion.p variants={item} className="t-eyebrow mb-5">HackOWASP 8.0 · Web3 security</motion.p>
        <motion.h1 variants={item} className="t-display max-w-[14ch]">
          Find the bug before it <span className="text-accent">costs millions.</span>
        </motion.h1>
        <motion.p variants={item} className="t-body mt-6 max-w-xl text-lg">
          Paste a Solidity contract and get a security report in under a second: six vulnerability
          classes from the SWC Registry, the line each one is on, and how to fix it. Nothing to install.
        </motion.p>
        <motion.div variants={item} className="mt-8 flex flex-col gap-3 min-[440px]:flex-row">
          <motion.a href="#scanner" className="btn-primary" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.96 }} transition={springSnappy}>
            <ScanSearch className="h-4 w-4" aria-hidden /> Scan a contract
          </motion.a>
          <motion.a href="https://github.com/ALFA117/CHAINGUARD" target="_blank" rel="noopener noreferrer" className="btn-secondary" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.96 }} transition={springSnappy}>
            Read the source
          </motion.a>
        </motion.div>

        <motion.dl variants={item} className="mt-12 grid gap-6 border-t border-line/70 pt-6 sm:grid-cols-2">
          {LOSSES.map((l) => (
            <div key={l.what}>
              <dt className="font-mono text-3xl font-semibold tabular-nums text-ink">{l.amount}</dt>
              <dd className="mt-1 text-sm text-muted">{l.what}</dd>
              <dd className="mt-1 font-mono text-xs text-accent">{l.rule}</dd>
            </div>
          ))}
        </motion.dl>
      </motion.div>

      {/* Live scan of withdraw(): the beam sweeps, the analyzer's own finding lights the line */}
      <motion.div
        initial={reduce ? false : { opacity: 0, y: 24, rotateX: 8 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={{ type: 'spring', stiffness: 140, damping: 20, delay: 0.25 }}
        style={{ transformPerspective: 1000 }}
        className="card overflow-hidden"
      >
        <div className="flex items-center gap-2 border-b border-line/70 px-4 py-3">
          <span className="font-mono text-sm text-ink">ReentrancyVuln.sol</span>
          <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-xs text-muted">
            <span className={`h-2 w-2 rounded-full ${state === 'ready' ? 'bg-accent' : state === 'error' ? 'bg-crit' : 'bg-warn'}`} aria-hidden />
            {state === 'ready' ? 'Live scan · real result' : state === 'error' ? 'Analyzer offline' : 'Scanning…'}
          </span>
        </div>

        <div className="relative overflow-x-auto overflow-y-hidden bg-bg/60 py-3 font-mono text-[13px] leading-6">
          {SRC_LINES.slice(FROM - 1, TO).map((code, i) => {
            const n = FROM + i;
            const hit = flagged.has(n);
            return (
              <div key={n} className={`relative flex gap-4 px-4 transition-colors duration-500 ${hit ? 'bg-crit/10' : ''}`}>
                {hit && <span className="absolute inset-y-0 left-0 w-[3px] bg-crit" aria-hidden />}
                <span className="w-6 shrink-0 select-none text-right text-muted/70">{n}</span>
                <span className={`whitespace-pre ${hit ? 'text-ink' : 'text-muted'}`}>{code || ' '}</span>
              </div>
            );
          })}
          {!reduce && (
            <motion.div
              aria-hidden
              className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-transparent via-accent/15 to-transparent"
              animate={{ y: ['-4rem', '16rem'] }}
              transition={{ duration: 2.8, repeat: Infinity, ease: 'easeInOut', repeatDelay: 0.6 }}
            />
          )}
        </div>

        <div className="min-h-[124px] border-t border-line/70 p-4" aria-live="polite">
          <AnimatePresence mode="wait">
            {state === 'loading' && (
              <motion.div key="l" exit={{ opacity: 0 }} className="flex items-center gap-4" aria-label="Scanning">
                <div className="skeleton h-20 w-20 rounded-full" />
                <div className="flex-1 space-y-2"><div className="skeleton h-4 w-2/3" /><div className="skeleton h-3 w-1/2" /></div>
              </motion.div>
            )}
            {state === 'error' && (
              <motion.div key="e" role="alert" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex flex-wrap items-center gap-4">
                <WifiOff className="h-5 w-5 text-crit" aria-hidden />
                <p className="flex-1 text-sm text-muted">The analyzer did not answer, so there is no result to show here — not a made-up one either.</p>
                <motion.button type="button" onClick={run} className="btn-secondary" whileTap={{ scale: 0.96 }} transition={springSnappy}>
                  <RefreshCw className="h-4 w-4" aria-hidden /> Retry
                </motion.button>
              </motion.div>
            )}
            {state === 'ready' && preview && (
              <motion.div key="r" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-4">
                <SecurityScore score={preview.score} compact worst={top?.severity ?? null} />
                <div className="min-w-0">
                  <p className="font-display text-lg font-bold">{preview.totalFound} finding{preview.totalFound !== 1 ? 's' : ''}</p>
                  {top && (
                    <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-muted">
                      <span className={`chip ${SEVERITY[top.severity].chip}`}>{SEVERITY[top.severity].label}</span>
                      {top.title}{top.line !== null && <span className="font-mono text-xs">line {top.line}</span>}
                    </p>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>

      <a href="#why" className="absolute bottom-2 left-1/2 hidden min-h-[44px] -translate-x-1/2 items-center gap-1 font-mono text-xs text-muted hover:text-ink lg:inline-flex">
        Why ChainGuard <ArrowDown className="h-3.5 w-3.5" aria-hidden />
      </a>
    </section>
  );
}
