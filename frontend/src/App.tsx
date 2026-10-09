import { useEffect, useState } from 'react';
import { MotionConfig } from 'motion/react';
import { ArrowUpRight, ShieldCheck } from 'lucide-react';
import { analyzeContract } from './api/analyze';
import { AnalysisResult } from './types';
import Header from './components/Header';
import LandingHero from './components/LandingHero';
import WhyChainGuard from './components/WhyChainGuard';
import CodeEditor, { REENTRANCY_EXAMPLE } from './components/CodeEditor';
import AnalyzeButton from './components/AnalyzeButton';
import ResultsPanel from './components/ResultsPanel';
import AmbientBackground from './components/AmbientBackground';
import { EXAMPLES } from './examples';

export default function App() {
  const [code, setCode] = useState(REENTRANCY_EXAMPLE);
  const [fileName, setFileName] = useState(EXAMPLES[0].label);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [calm, setCalm] = useState(false);

  // Running totals across all analyses this session
  const [sessionVulns, setSessionVulns] = useState(0);
  const [sessionContracts, setSessionContracts] = useState(0);

  // The background quiets down while the scanner is the thing on screen
  useEffect(() => {
    const el = document.getElementById('scanner');
    if (!el) return;
    const io = new IntersectionObserver(([e]) => setCalm(e.isIntersecting), { threshold: 0.25 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  async function handleAnalyze() {
    if (!code.trim()) return;
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await analyzeContract(code);
      setResult(res);
      setSessionVulns((v) => v + res.totalFound);
      setSessionContracts((c) => c + 1);
    } catch (err: any) {
      const raw =
        err?.response?.data?.error ??
        err?.response?.data?.message ??
        err?.message;
      const msg = typeof raw === 'string' && raw.trim()
        ? raw
        : 'Failed to reach the analysis server.';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }

  function handleExampleSelect(e: React.ChangeEvent<HTMLSelectElement>) {
    const chosen = EXAMPLES.find((ex) => ex.label === e.target.value);
    if (chosen) {
      setCode(chosen.code);
      setFileName(chosen.label.replace(' (clean)', ''));
      setResult(null);
      setError(null);
    }
  }

  return (
    <MotionConfig reducedMotion="user">
      <AmbientBackground calm={calm} />
      <a href="#scanner" className="skip-link">Skip to the scanner</a>
      <div className="flex min-h-dvh flex-col">
        <Header totalVulns={sessionVulns} totalContracts={sessionContracts} />

        <main className="flex-1">
          <LandingHero />
          <WhyChainGuard />

          <section id="scanner" aria-labelledby="scanner-title" className="mx-auto w-full max-w-7xl scroll-mt-24 px-4 py-16 sm:px-6">
            <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <p className="t-eyebrow mb-3">Scanner</p>
                <h2 id="scanner-title" className="t-title">Paste a contract, press scan.</h2>
              </div>
              <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-end lg:w-auto">
                <div className="flex-1 lg:w-72">
                  <label htmlFor="example" className="mb-1.5 block text-sm font-semibold">Start from an example</label>
                  <select
                    id="example"
                    onChange={handleExampleSelect}
                    className="min-h-[44px] w-full cursor-pointer rounded-xl border border-line bg-surface px-3 font-mono text-sm text-ink focus:border-accent focus:outline-none"
                  >
                    {EXAMPLES.map((ex) => (
                      <option key={ex.label} value={ex.label}>{ex.label}</option>
                    ))}
                  </select>
                </div>
                <AnalyzeButton onClick={handleAnalyze} isLoading={isLoading} disabled={!code.trim()} />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <div className="min-w-0">
                <h3 className="sr-only">Contract source</h3>
                <CodeEditor value={code} onChange={setCode} fileName={fileName} />
              </div>
              <div className="min-w-0">
                <h3 className="sr-only">Results</h3>
                <ResultsPanel isLoading={isLoading} result={result} error={error} onRetry={handleAnalyze} />
              </div>
            </div>
          </section>
        </main>

        <footer className="border-t border-line/70 bg-surface/70 backdrop-blur-sm" style={{ paddingBottom: 'env(safe-area-inset-bottom)' }}>
          <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-8 sm:flex-row sm:items-center sm:justify-between sm:px-6">
            <p className="flex items-center gap-2 text-sm text-muted">
              <ShieldCheck className="h-4 w-4 text-accent" aria-hidden />
              ChainGuard — built for HackOWASP 8.0 · MIT licensed
            </p>
            <nav aria-label="Links" className="flex flex-wrap gap-x-6">
              <a href="https://github.com/ALFA117/CHAINGUARD" target="_blank" rel="noopener noreferrer" className="inline-flex min-h-[44px] items-center gap-1 text-sm text-muted hover:text-ink">
                Source on GitHub <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
              </a>
              <a href="https://www.instagram.com/alfa_edg_/" target="_blank" rel="noopener noreferrer" className="inline-flex min-h-[44px] items-center gap-1 text-sm text-muted hover:text-ink">
                @ALFA_EDG_ <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
              </a>
            </nav>
          </div>
        </footer>
      </div>
    </MotionConfig>
  );
}
