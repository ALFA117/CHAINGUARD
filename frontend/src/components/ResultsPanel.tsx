import { AnimatePresence, motion } from 'motion/react';
import { AlertTriangle, RefreshCw, ShieldCheck, ShieldQuestion } from 'lucide-react';
import { AnalysisResult } from '../types';
import SecurityScore from './SecurityScore';
import VulnerabilityCard from './VulnerabilityCard';
import ExportButton from './ExportButton';
import { ORDER, RULES, SEVERITY } from '../lib/severity';
import { springSnappy } from '../lib/motion';

interface ResultsPanelProps {
  isLoading: boolean;
  result: AnalysisResult | null;
  error: string | null;
  onRetry: () => void;
}

const fade = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -6, transition: { duration: 0.15 } },
  transition: { duration: 0.25, ease: [0.16, 1, 0.3, 1] as const },
};

function Loading() {
  return (
    <motion.div key="loading" {...fade} className="space-y-3" role="status" aria-label="Scanning the contract">
      <div className="card flex items-center gap-4 p-5">
        <div className="skeleton h-[104px] w-[104px] shrink-0 rounded-full" />
        <div className="flex-1 space-y-3">
          <div className="skeleton h-5 w-1/2" />
          <div className="flex flex-wrap gap-1.5">
            {RULES.map((r, i) => (
              <motion.span
                key={r.id}
                className="chip border-line text-muted"
                initial={{ opacity: 0.3 }}
                animate={{ opacity: [0.3, 1, 0.3] }}
                transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.12 }}
              >
                {r.id}
              </motion.span>
            ))}
          </div>
        </div>
      </div>
      {[0, 1, 2].map((i) => (
        <div key={i} className="card flex items-center gap-3 p-4">
          <div className="skeleton h-6 w-16" /><div className="skeleton h-5 flex-1" /><div className="skeleton h-5 w-20" />
        </div>
      ))}
    </motion.div>
  );
}

export default function ResultsPanel({ isLoading, result, error, onRetry }: ResultsPanelProps) {
  let content;

  if (isLoading) {
    content = <Loading />;
  } else if (error) {
    content = (
      <motion.div key="error" {...fade} role="alert" className="card border-crit/40 p-6">
        <div className="flex items-start gap-4">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-crit/10 text-crit">
            <AlertTriangle className="h-5 w-5" aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <h3 className="t-heading">The scan did not finish</h3>
            <p className="mt-1 break-words font-mono text-sm text-crit">{error}</p>
            <p className="t-body mt-3 text-sm">
              Usually the analyzer was unreachable for a moment. Check your connection and run it again;
              your code is still in the editor.
            </p>
            <motion.button type="button" onClick={onRetry} className="btn-secondary mt-4" whileTap={{ scale: 0.96 }} transition={springSnappy}>
              <RefreshCw className="h-4 w-4" aria-hidden /> Try again
            </motion.button>
          </div>
        </div>
      </motion.div>
    );
  } else if (!result) {
    content = (
      <motion.div key="empty" {...fade} className="card flex min-h-[440px] flex-col items-center justify-center gap-5 p-8 text-center">
        <motion.span
          className="flex h-16 w-16 items-center justify-center rounded-2xl border border-line bg-surface2 text-accent"
          animate={{ y: [0, -6, 0] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
        >
          <ShieldQuestion className="h-8 w-8" aria-hidden />
        </motion.span>
        <div>
          <h3 className="t-heading">Nothing scanned yet</h3>
          <p className="t-body mx-auto mt-2 max-w-sm">
            Pick an example above or paste your own Solidity, then press <span className="font-semibold text-ink">Scan contract</span>.
          </p>
        </div>
        <ol className="flex flex-wrap justify-center gap-x-5 gap-y-2 font-mono text-sm text-muted">
          <li><span className="text-accent">1</span> Paste</li>
          <li><span className="text-accent">2</span> Scan</li>
          <li><span className="text-accent">3</span> Fix and export</li>
        </ol>
      </motion.div>
    );
  } else {
    const counts = ORDER.map((s) => ({ s, n: result.vulnerabilities.filter((v) => v.severity === s).length }));
    const total = result.totalFound;
    content = (
      <motion.div key={`result-${result.analyzedAt}`} {...fade} className="space-y-3">
        <div className="card flex flex-col items-center gap-5 p-5 sm:flex-row sm:items-center">
          <SecurityScore score={result.score} worst={counts.find((c) => c.n > 0)?.s ?? null} />
          <div className="w-full min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <p className="truncate font-display text-xl font-bold">{result.contractName}</p>
              <span className="font-mono text-xs text-muted">{new Date(result.analyzedAt).toLocaleTimeString()}</span>
            </div>
            <p className="text-muted">
              {total === 0 ? 'None of the six rules matched.' : `${total} finding${total !== 1 ? 's' : ''} across the six rules.`}
            </p>
            {total > 0 && (
              <>
                <div className="flex flex-wrap gap-1.5">
                  {counts.filter((c) => c.n > 0).map(({ s, n }) => (
                    <span key={s} className={`chip ${SEVERITY[s].chip}`}>{n} {SEVERITY[s].label}</span>
                  ))}
                </div>
                <div className="flex h-2 w-full overflow-hidden rounded-full bg-surface2" aria-hidden>
                  {counts.filter((c) => c.n > 0).map(({ s, n }) => (
                    <motion.div
                      key={s}
                      className={`${SEVERITY[s].bar} h-full origin-left`}
                      style={{ width: `${(n / total) * 100}%` }}
                      initial={{ scaleX: 0 }}
                      animate={{ scaleX: 1 }}
                      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                    />
                  ))}
                </div>
              </>
            )}
          </div>
          <ExportButton result={result} />
        </div>

        {result.vulnerabilities.length === 0 ? (
          <div className="card border-accent/40 p-6 text-center">
            <ShieldCheck className="mx-auto h-8 w-8 text-accent" aria-hidden />
            <p className="t-heading mt-3">No findings from the six rules</p>
            <p className="t-body mt-1 text-sm">That rules out these patterns, not every bug. Logic errors and economic attacks need a human review.</p>
          </div>
        ) : (
          <ul className="space-y-2.5">
            {result.vulnerabilities.map((v, i) => <VulnerabilityCard key={v.id} vuln={v} index={i} />)}
          </ul>
        )}
      </motion.div>
    );
  }

  return (
    <div aria-live="polite">
      <AnimatePresence mode="wait">{content}</AnimatePresence>
    </div>
  );
}
