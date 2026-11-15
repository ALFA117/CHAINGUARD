import { useCallback, useEffect, useState } from 'react';
import { analyzeContract } from '../api/analyze';
import { REENTRANCY_EXAMPLE } from '../examples';
import { AnalysisResult } from '../types';
import { SEVERITY_LABEL, verdict } from '../lib/severity';
import SecurityScore from './SecurityScore';
import { AlertIcon, ArrowRightIcon, GithubIcon, RefreshIcon } from './Icons';

// Historical incidents caused by these bug classes. Public figures, rounded.
const INCIDENTS = [
  { amount: '$60M', name: 'The DAO, 2016', cause: 'Reentrancy' },
  { amount: '$150M', name: 'Parity Wallet, 2017', cause: 'Unprotected access' },
  { amount: '$625M', name: 'Ronin Bridge, 2022', cause: 'Key compromise' },
];

const SOURCE_LINES = REENTRANCY_EXAMPLE.split('\n');

/**
 * The preview on the right is a REAL scan: it calls the same analyzeContract()
 * the scanner uses, against ReentrancyVuln.sol. If the request fails it shows
 * an error with a retry, never invented numbers.
 */
function LivePreview() {
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading');
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const run = useCallback(() => {
    let cancelled = false;
    setState('loading');
    analyzeContract(REENTRANCY_EXAMPLE)
      .then((res) => { if (!cancelled) { setResult(res); setState('ready'); } })
      .catch(() => { if (!cancelled) setState('error'); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => run(), [run]);

  const top = result?.vulnerabilities[0];
  const flagged = top?.line ?? null;
  // Show a window of the source around the flagged line.
  const from = flagged ? Math.max(1, flagged - 4) : 11;
  const to = Math.min(SOURCE_LINES.length, from + 8);
  const excerpt = SOURCE_LINES.slice(from - 1, to).map((text, i) => ({ n: from + i, text }));
  const v = result ? verdict(result) : null;

  return (
    <figure className="overflow-hidden rounded-lg border border-ink bg-code text-code-text shadow-hard">
      <figcaption className="flex items-center justify-between gap-3 border-b border-code-line px-4 py-3">
        <span className="truncate font-mono text-[13px] text-code-text">ReentrancyVuln.sol</span>
        <span className="flex shrink-0 items-center gap-2 font-mono text-[12px] text-code-muted">
          <span className={`h-1.5 w-1.5 rounded-full ${state === 'error' ? 'bg-high' : 'bg-[#7D9BFF] live-dot'}`} />
          Live result<span className="hidden sm:inline"> from /api/analyze</span>
        </span>
      </figcaption>

      {/* Source excerpt with the flagged line marked */}
      <div className="code-scroll overflow-x-auto py-3 font-mono text-[13px] leading-[1.7]">
        {excerpt.map((l) => {
          const hit = state === 'ready' && l.n === flagged;
          return (
            <div
              key={l.n}
              className={`flex min-w-max pr-4 ${hit ? 'bg-high/25' : ''}`}
            >
              <span className={`w-12 shrink-0 select-none pr-4 text-right ${hit ? 'text-white' : 'text-code-muted/70'}`}>{l.n}</span>
              <span className={`whitespace-pre ${l.text.trim().startsWith('//') ? 'text-code-muted' : ''} ${hit ? 'text-white' : ''}`}>
                {l.text || ' '}
              </span>
            </div>
          );
        })}
      </div>

      <div className="border-t border-code-line p-4" aria-live="polite">
        {state === 'loading' && (
          <div className="flex items-center gap-4" aria-label="Running scan">
            <div className="skeleton-dark h-16 w-16 rounded-full" />
            <div className="flex-1 space-y-2">
              <div className="skeleton-dark h-3.5 w-40" />
              <div className="skeleton-dark h-3 w-56 max-w-full" />
            </div>
          </div>
        )}

        {state === 'error' && (
          <div className="flex flex-wrap items-center gap-3" role="alert">
            <AlertIcon size={18} className="text-[#FF8A80]" />
            <p className="flex-1 text-[14px] text-code-text">The live scan could not reach the analyzer.</p>
            <button onClick={run} className="btn min-h-[44px] border border-code-line px-3 text-[14px] text-white hover:bg-code-line">
              <RefreshIcon size={16} /> Retry
            </button>
          </div>
        )}

        {state === 'ready' && result && v && (
          <div className="enter flex items-center gap-4">
            <SecurityScore score={result.score} tone={v.tone} size={64} dark />
            <div className="min-w-0 flex-1">
              <p className="text-[15px] font-medium text-white">
                {v.label}
                <span className="font-normal text-code-muted"> · {result.totalFound} finding{result.totalFound !== 1 ? 's' : ''}</span>
              </p>
              {top ? (
                <p className="mt-1 truncate font-mono text-[13px] text-code-muted">
                  <span className="text-[#FF8A80]">{SEVERITY_LABEL[top.severity]}</span>
                  {' · '}{top.swcId}{top.line ? ` · line ${top.line}` : ''}
                </p>
              ) : (
                <p className="mt-1 text-[13px] text-code-muted">No pattern matched.</p>
              )}
            </div>
          </div>
        )}
      </div>
    </figure>
  );
}

export default function LandingHero() {
  return (
    <section id="top" className="border-b border-line">
      <div className="container-page grid grid-cols-1 items-center gap-12 py-14 sm:py-20 lg:grid-cols-[1.05fr_1fr] lg:gap-16 lg:py-24">
        <div>
          <p className="eyebrow enter">Static analysis for Solidity · 6 SWC rules</p>
          <h1 className="enter enter-1 mt-4 font-display text-[40px] font-semibold leading-[1.05] tracking-[-0.02em] text-ink sm:text-[56px] lg:text-[64px]">
            Find the bug before it costs millions.
          </h1>
          <p className="enter enter-2 mt-6 max-w-[52ch] text-[17px] leading-relaxed text-ink-2 sm:text-[18px]">
            Paste a Solidity contract and get a first-pass security check in under a second:
            six vulnerability classes from the SWC Registry, the line that triggered each one,
            and a PDF you can share. Nothing to install.
          </p>

          <div className="enter enter-3 mt-8 flex flex-col gap-3 sm:flex-row">
            <a href="#scanner" className="btn-accent px-6">
              Scan a contract <ArrowRightIcon size={18} />
            </a>
            <a
              href="https://github.com/ALFA117/CHAINGUARD"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary px-6"
            >
              <GithubIcon size={16} /> View source
            </a>
          </div>

          <p className="enter enter-4 mt-6 max-w-[52ch] border-l-2 border-line pl-4 text-[14px] leading-relaxed text-muted">
            Pattern-based, not a formal audit. Use it to catch known mistakes early, then get
            a professional review before real funds are at stake.
          </p>
        </div>

        <div className="enter enter-2 min-w-0">
          <LivePreview />
        </div>
      </div>

      {/* Incident ledger */}
      <div className="border-t border-line bg-surface">
        <div className="container-page">
          <p className="eyebrow pt-6">Losses from bug classes like these</p>
          <dl className="grid grid-cols-1 divide-y divide-line sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            {INCIDENTS.map((it, i) => (
              <div key={it.name} className={`flex items-baseline justify-between gap-4 py-4 sm:block sm:py-5 ${i > 0 ? 'sm:pl-6' : ''} sm:pr-6`}>
                <dt className="text-[14px] text-ink-2">
                  {it.name} <span className="text-muted">· {it.cause}</span>
                </dt>
                <dd className="shrink-0 font-mono text-[22px] sm:mt-1 sm:text-[28px] font-medium tracking-[-0.02em] text-ink">{it.amount}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </section>
  );
}
