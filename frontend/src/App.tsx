import { useCallback, useRef, useState } from 'react';
import { analyzeContract } from './api/analyze';
import { AnalysisResult } from './types';
import { EXAMPLES } from './examples';
import Header, { Logo } from './components/Header';
import LandingHero from './components/LandingHero';
import WhyChainGuard from './components/WhyChainGuard';
import CodeEditor from './components/CodeEditor';
import AnalyzeButton from './components/AnalyzeButton';
import ResultsPanel from './components/ResultsPanel';
import { ChevronDownIcon, GithubIcon, InstagramIcon } from './components/Icons';

const CUSTOM = '__custom__';

export default function App() {
  const [exampleFile, setExampleFile] = useState(EXAMPLES[0].file);
  const [code, setCode] = useState(EXAMPLES[0].code);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState({ scans: 0, findings: 0 });
  const resultsRef = useRef<HTMLDivElement>(null);

  const handleAnalyze = useCallback(async () => {
    if (!code.trim() || isLoading) return;
    setIsLoading(true);
    setError(null);
    setResult(null);

    // On narrow screens the report sits below the editor: bring it into view.
    if (window.matchMedia('(max-width: 1023px)').matches) {
      requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    }

    try {
      const res = await analyzeContract(code);
      setResult(res);
      setSession((s) => ({ scans: s.scans + 1, findings: s.findings + res.totalFound }));
    } catch (err: any) {
      const raw = err?.response?.data?.error ?? err?.response?.data?.message ?? err?.message;
      setError(
        typeof raw === 'string' && raw.trim()
          ? raw
          : 'Could not reach the analysis server.',
      );
    } finally {
      setIsLoading(false);
    }
  }, [code, isLoading]);

  function handleExampleSelect(e: React.ChangeEvent<HTMLSelectElement>) {
    const chosen = EXAMPLES.find((ex) => ex.file === e.target.value);
    if (!chosen) return;
    setExampleFile(chosen.file);
    setCode(chosen.code);
    setResult(null);
    setError(null);
  }

  function handleCodeChange(next: string) {
    setCode(next);
    const current = EXAMPLES.find((ex) => ex.file === exampleFile);
    if (current && next !== current.code) setExampleFile(CUSTOM);
  }

  const fileName = exampleFile === CUSTOM ? 'contract.sol' : exampleFile;

  return (
    <div className="flex min-h-[100dvh] flex-col">
      <Header />

      <main className="flex-1">
        <LandingHero />

        <section id="scanner" className="scroll-mt-16 border-b border-line bg-paper">
          <div className="container-page py-16 sm:py-24">
            <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
              <div className="max-w-[44ch]">
                <p className="eyebrow">Scanner</p>
                <h2 className="mt-3 font-display text-[32px] font-semibold leading-[1.1] tracking-[-0.015em] sm:text-[40px]">
                  Run a scan.
                </h2>
                <p className="mt-3 text-[16px] leading-relaxed text-ink-2">
                  The editor starts with a contract that has a known reentrancy bug. Edit it, swap in
                  another example, or paste your own.
                </p>
              </div>
              {session.scans > 0 && (
                <p className="font-mono text-[13px] text-muted" aria-live="polite">
                  This session: {session.scans} scan{session.scans !== 1 ? 's' : ''} · {session.findings} finding{session.findings !== 1 ? 's' : ''}
                </p>
              )}
            </div>

            {/* Tool frame */}
            <div className="panel mt-8 p-3 sm:p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <label className="flex min-w-0 flex-1 flex-col gap-1.5">
                  <span className="text-[13px] font-medium text-ink-2">Load an example</span>
                  <span className="relative">
                    <select
                      value={exampleFile}
                      onChange={handleExampleSelect}
                      className="min-h-[44px] w-full cursor-pointer appearance-none rounded border border-ink/70 bg-surface pl-3 pr-10 font-mono text-[14px] text-ink transition-colors hover:border-ink"
                    >
                      {exampleFile === CUSTOM && <option value={CUSTOM}>contract.sol (edited)</option>}
                      {EXAMPLES.map((ex) => (
                        <option key={ex.file} value={ex.file}>
                          {ex.file} — {ex.note}
                        </option>
                      ))}
                    </select>
                    <ChevronDownIcon size={18} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-ink-2" />
                  </span>
                </label>
                <AnalyzeButton
                  onClick={handleAnalyze}
                  isLoading={isLoading}
                  disabled={!code.trim()}
                  className="w-full sm:w-auto"
                />
              </div>

              <div className="mt-3 grid grid-cols-1 gap-3 lg:mt-4 lg:grid-cols-2 lg:gap-4">
                <CodeEditor value={code} fileName={fileName} onChange={handleCodeChange} onRun={handleAnalyze} />
                <div ref={resultsRef} className="min-w-0 scroll-mt-20">
                  <ResultsPanel isLoading={isLoading} result={result} error={error} onRetry={handleAnalyze} />
                </div>
              </div>
            </div>

            {!code.trim() && (
              <p className="mt-3 text-[14px] text-medium" role="status">The editor is empty. Paste a contract to enable the scan.</p>
            )}
          </div>
        </section>

        <WhyChainGuard />
      </main>

      <footer className="border-t border-line bg-surface">
        <div className="container-page flex flex-col gap-6 py-10 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <Logo />
            <p className="mt-2 text-[14px] text-muted">
              Built for HackOWASP 8.0. A pattern-based first pass, not a substitute for an audit.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-1">
            <a
              href="https://github.com/ALFA117/CHAINGUARD"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-ghost text-[14px]"
            >
              <GithubIcon size={16} /> GitHub
            </a>
            <a
              href="https://www.instagram.com/alfa_edg_/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-ghost text-[14px]"
            >
              <InstagramIcon size={16} /> @alfa_edg_
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
