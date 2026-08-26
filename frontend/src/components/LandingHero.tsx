import { useEffect, useState } from 'react';
import { REENTRANCY_EXAMPLE } from './CodeEditor';
import { analyzeContract } from '../api/analyze';
import SecurityScore from './SecurityScore';
import { AnalysisResult } from '../types';

const SEVERITY_BADGE: Record<string, string> = {
  HIGH: 'bg-red-900/70 text-red-300 border-red-700/60',
  MEDIUM: 'bg-orange-900/70 text-orange-300 border-orange-700/60',
  LOW: 'bg-yellow-900/70 text-yellow-300 border-yellow-700/60',
  INFO: 'bg-blue-900/70 text-blue-300 border-blue-700/60',
};
const SEVERITY_BORDER: Record<string, string> = {
  HIGH: 'border-l-red-500',
  MEDIUM: 'border-l-orange-500',
  LOW: 'border-l-yellow-500',
  INFO: 'border-l-blue-500',
};

export default function LandingHero() {
  const [preview, setPreview] = useState<AnalysisResult | null>(null);

  // The hero preview is a REAL scan, not a mockup: it runs the same
  // analyzeContract() the "Analyze Contract" button below uses, against the
  // same ReentrancyVuln.sol example in the dropdown. If it fails (e.g. local
  // dev without `vercel dev` serving /api), it just stays a skeleton instead
  // of falling back to invented numbers.
  useEffect(() => {
    let cancelled = false;
    analyzeContract(REENTRANCY_EXAMPLE)
      .then((res) => { if (!cancelled) setPreview(res); })
      .catch(() => { /* stays as skeleton — never show a fabricated result */ });
    return () => { cancelled = true; };
  }, []);

  function scrollToScanner() {
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  return (
    <section className="relative overflow-hidden border-b border-gray-800/60 px-6 py-14 sm:py-20">
      {/* Ambient glow, matches the header's accent treatment */}
      <div className="pointer-events-none absolute -top-24 left-1/4 h-72 w-72 rounded-full bg-indigo-600/10 blur-3xl" />
      <div className="pointer-events-none absolute top-10 right-0 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl" />

      <div className="relative max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-[1.15fr_1fr] gap-10 lg:gap-16 items-center">
        {/* Left: message */}
        <div className="animate-fade-in-up">
          <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight text-white">
            Find the bug before it costs millions.
          </h1>
          <p className="mt-4 text-gray-400 text-base sm:text-lg leading-relaxed max-w-lg">
            Paste a Solidity contract, get a security audit in under a second.
            Six vulnerability classes from the SWC Registry, zero install.
          </p>

          <div className="mt-7 flex flex-wrap items-center gap-3">
            <button
              onClick={scrollToScanner}
              className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm
                transition-all duration-200 hover:scale-[1.03] active:scale-[0.98]
                shadow-lg shadow-indigo-950/50"
            >
              Analyze a contract
            </button>
            <a
              href="https://github.com/ALFA117/CHAINGUARD"
              target="_blank"
              rel="noopener noreferrer"
              className="px-5 py-2.5 rounded-lg border border-gray-700 hover:border-gray-500 text-gray-300 hover:text-white
                font-semibold text-sm transition-colors duration-200"
            >
              View source
            </a>
          </div>

          {/* Real losses this class of bug has caused - grounds the pitch */}
          <div className="mt-10 flex flex-wrap gap-x-8 gap-y-4 border-t border-gray-800/60 pt-6">
            {[
              { amount: '$60M', label: 'The DAO, reentrancy' },
              { amount: '$150M', label: 'Parity Wallet, access control' },
              { amount: '$625M', label: 'Ronin Bridge, key compromise' },
            ].map((stat) => (
              <div key={stat.label}>
                <p className="text-2xl font-extrabold text-white font-mono">{stat.amount}</p>
                <p className="text-xs text-gray-500 mt-0.5">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Right: a live scan of ReentrancyVuln.sol via the real analyzer -- not a mockup */}
        <div className="animate-fade-in-up delay-150 relative">
          <div className="glass rounded-2xl p-4 shadow-2xl shadow-black/40 border border-gray-700/50">
            <div className="flex items-center gap-2 px-1 pb-3 border-b border-gray-800/60 mb-3">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
              <span className="ml-2 text-xs text-gray-600 font-mono">ReentrancyVuln.sol</span>
              <span className="ml-auto text-[10px] uppercase tracking-wide text-gray-600">Live scan</span>
            </div>

            {!preview ? (
              <div className="space-y-2 animate-pulse" aria-hidden="true">
                <div className="flex items-center gap-4 mb-3">
                  <div className="h-16 w-16 rounded-full bg-gray-800/80 shrink-0" />
                  <div className="space-y-2">
                    <div className="h-3 w-28 rounded bg-gray-800/80" />
                    <div className="h-2.5 w-20 rounded bg-gray-800/60" />
                  </div>
                </div>
                <div className="h-10 rounded-lg bg-gray-800/60" />
                <div className="h-10 rounded-lg bg-gray-800/60" />
              </div>
            ) : (
              <>
                <div className="flex items-center gap-4 mb-3">
                  <SecurityScore score={preview.score} />
                  <div>
                    <p className="text-white font-bold text-sm">
                      {preview.totalFound} issue{preview.totalFound !== 1 ? 's' : ''} detected
                    </p>
                    <p className="text-gray-500 text-xs mt-0.5">Real scan, not a mockup</p>
                  </div>
                </div>

                <div className="space-y-2">
                  {preview.vulnerabilities.slice(0, 2).map((v) => (
                    <div
                      key={v.id}
                      className={`rounded-lg border-l-4 ${SEVERITY_BORDER[v.severity]} bg-gray-800/60 border border-gray-700/50 px-3 py-2.5`}
                    >
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_BADGE[v.severity]}`}>
                          {v.severity}
                        </span>
                        <span className="text-xs font-semibold text-gray-200">{v.title}</span>
                        <span className="text-[10px] font-mono text-gray-600 ml-auto">{v.swcId}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
