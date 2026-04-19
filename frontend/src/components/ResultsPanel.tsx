import { AnalysisResult } from '../types';
import SecurityScore from './SecurityScore';
import VulnerabilityCard from './VulnerabilityCard';
import ExportButton from './ExportButton';

interface ResultsPanelProps {
  isLoading: boolean;
  result: AnalysisResult | null;
  error: string | null;
}

function SkeletonCard({ delay }: { delay: string }) {
  return (
    <div className={`animate-fade-in-up ${delay} bg-gray-800/60 rounded-xl border border-gray-700/50 p-4`}>
      <div className="flex items-center gap-3">
        <div className="skeleton w-14 h-5 rounded-md shrink-0" />
        <div className="skeleton h-4 flex-1" />
        <div className="skeleton w-16 h-4 shrink-0" />
      </div>
    </div>
  );
}

export default function ResultsPanel({ isLoading, result, error }: ResultsPanelProps) {

  /* ── Loading ─────────────────────────────────────────────────────── */
  if (isLoading) {
    return (
      <div className="space-y-4 animate-fade-in">
        <div className="scan-container bg-gray-800/60 rounded-xl border border-indigo-500/30 border-glow-indigo p-5">
          <div className="scan-line" />
          <div className="flex items-center gap-4">
            <div className="relative w-16 h-16 shrink-0">
              <svg className="w-16 h-16 -rotate-90" viewBox="0 0 64 64">
                <circle cx="32" cy="32" r="26" fill="none" stroke="#1f2937" strokeWidth="6" />
                <circle
                  cx="32" cy="32" r="26" fill="none"
                  stroke="#6366f1" strokeWidth="6"
                  strokeDasharray="163"
                  strokeDashoffset="163"
                  strokeLinecap="round"
                  style={{ animation: 'rotateSlow 1.2s linear infinite' }}
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <svg className="w-6 h-6 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
            </div>
            <div className="flex-1 space-y-2">
              <p className="text-white font-semibold">Scanning contract…</p>
              <p className="text-gray-400 text-sm">Running 6 security rules via regex engine</p>
              <div className="flex gap-1 flex-wrap mt-2">
                {['Reentrancy','tx.origin','Overflow','Call','Selfdestruct','Visibility'].map((r, i) => (
                  <span
                    key={r}
                    className="text-xs px-1.5 py-0.5 rounded bg-indigo-900/50 text-indigo-400 border border-indigo-700/30"
                    style={{ animationDelay: `${i * 150}ms`, animation: 'fadeIn 0.3s ease both' }}
                  >
                    {r}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
        <SkeletonCard delay="delay-75" />
        <SkeletonCard delay="delay-150" />
        <SkeletonCard delay="delay-225" />
      </div>
    );
  }

  /* ── Error ───────────────────────────────────────────────────────── */
  if (error) {
    return (
      <div className="animate-fade-in-up bg-red-950/50 border border-red-700/60 rounded-xl p-5 backdrop-blur-sm">
        <div className="flex items-start gap-3">
          <div className="shrink-0 w-8 h-8 rounded-full bg-red-900/60 border border-red-700 flex items-center justify-center mt-0.5">
            <svg className="w-4 h-4 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <div>
            <p className="text-red-300 font-semibold mb-1">Analysis Error</p>
            <p className="text-red-400/80 text-sm leading-relaxed">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  /* ── Empty / ready ───────────────────────────────────────────────── */
  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center h-72 gap-5 text-center animate-fade-in px-4">
        {/* Floating shield */}
        <div className="relative">
          <div className="animate-float w-20 h-20 rounded-full bg-gray-800/70 border border-gray-700/60 flex items-center justify-center shadow-lg shadow-black/20">
            <svg className="w-10 h-10 text-gray-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div className="absolute inset-0 rounded-full border border-indigo-500/15 animate-pulse" style={{ transform: 'scale(1.5)' }} />
          <div className="absolute inset-0 rounded-full border border-cyan-500/08" style={{ transform: 'scale(1.85)' }} />
        </div>

        {/* Text */}
        <div>
          <p className="text-gray-300 font-semibold text-base">Ready to scan</p>
          <p className="text-gray-600 text-sm mt-1.5 max-w-xs leading-relaxed">
            Select a contract from the dropdown or paste your own Solidity code, then click{' '}
            <span className="text-indigo-400 font-medium">Analyze Contract</span>
          </p>
        </div>

        {/* How it works — 3 steps */}
        <div className="flex items-center gap-2 text-xs text-gray-600">
          <div className="flex items-center gap-1.5 animate-fade-in-up delay-75">
            <span className="w-5 h-5 rounded-full bg-gray-800/80 border border-gray-700 text-gray-500 text-[10px] font-bold flex items-center justify-center shrink-0">1</span>
            <span>Paste contract</span>
          </div>
          <span className="text-gray-700">›</span>
          <div className="flex items-center gap-1.5 animate-fade-in-up delay-150">
            <span className="w-5 h-5 rounded-full bg-gray-800/80 border border-gray-700 text-gray-500 text-[10px] font-bold flex items-center justify-center shrink-0">2</span>
            <span>Click Analyze</span>
          </div>
          <span className="text-gray-700">›</span>
          <div className="flex items-center gap-1.5 animate-fade-in-up delay-225">
            <span className="w-5 h-5 rounded-full bg-gray-800/80 border border-gray-700 text-gray-500 text-[10px] font-bold flex items-center justify-center shrink-0">3</span>
            <span>Get instant report</span>
          </div>
        </div>

        {/* SWC coverage badges */}
        <div className="flex gap-1.5 flex-wrap justify-center">
          {['SWC-107','SWC-115','SWC-101','SWC-104','SWC-106','SWC-100'].map((swc) => (
            <span key={swc} className="text-xs px-2 py-0.5 rounded-full border border-gray-700/60 text-gray-600 font-mono bg-gray-900/30">
              {swc}
            </span>
          ))}
        </div>
      </div>
    );
  }

  /* ── Results ─────────────────────────────────────────────────────── */
  const highs   = result.vulnerabilities.filter(v => v.severity === 'HIGH').length;
  const mediums = result.vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
  const lows    = result.vulnerabilities.filter(v => v.severity === 'LOW').length;
  const infos   = result.vulnerabilities.filter(v => v.severity === 'INFO').length;
  const total   = result.totalFound;

  return (
    <div className="space-y-3 animate-fade-in">
      {/* Summary card */}
      <div className="glass rounded-xl p-4 flex flex-col sm:flex-row items-center gap-4 animate-fade-in-up">
        <SecurityScore score={result.score} />

        <div className="flex-1 space-y-1.5 min-w-0 w-full">
          {/* Contract name + time */}
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-white font-bold text-base truncate">{result.contractName}</p>
            <span className="text-xs text-gray-500 shrink-0 font-mono">
              {new Date(result.analyzedAt).toLocaleTimeString()}
            </span>
          </div>

          {/* Issues summary */}
          <p className="text-gray-400 text-sm">
            {total === 0
              ? 'No issues found — contract looks clean'
              : `${total} issue${total !== 1 ? 's' : ''} detected`}
          </p>

          {/* Severity pill badges */}
          {total > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              {highs > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-red-900/60 text-red-300 border border-red-700/50 font-semibold">
                  {highs} HIGH
                </span>
              )}
              {mediums > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-orange-900/60 text-orange-300 border border-orange-700/50 font-semibold">
                  {mediums} MEDIUM
                </span>
              )}
              {lows > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-900/60 text-yellow-300 border border-yellow-700/50 font-semibold">
                  {lows} LOW
                </span>
              )}
              {infos > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-900/60 text-blue-300 border border-blue-700/50 font-semibold">
                  {infos} INFO
                </span>
              )}
            </div>
          )}

          {/* Severity distribution bar */}
          {total > 0 && (
            <div className="w-full h-1.5 rounded-full overflow-hidden bg-gray-800/80 flex mt-1">
              {highs   > 0 && <div className="bg-red-500    h-full transition-all duration-700" style={{ width: `${(highs/total)*100}%`   }} />}
              {mediums > 0 && <div className="bg-orange-500 h-full transition-all duration-700" style={{ width: `${(mediums/total)*100}%` }} />}
              {lows    > 0 && <div className="bg-yellow-500 h-full transition-all duration-700" style={{ width: `${(lows/total)*100}%`    }} />}
              {infos   > 0 && <div className="bg-blue-500   h-full transition-all duration-700" style={{ width: `${(infos/total)*100}%`   }} />}
            </div>
          )}
        </div>

        <ExportButton result={result} />
      </div>

      {/* Vulnerability list or clean badge */}
      {result.vulnerabilities.length === 0 ? (
        <div className="animate-fade-in-up delay-75 bg-emerald-950/40 border border-emerald-700/40 rounded-xl p-6 text-center">
          <div className="animate-pop-in w-12 h-12 rounded-full bg-emerald-900/40 border border-emerald-700/40 flex items-center justify-center mx-auto mb-3">
            <svg className="w-6 h-6 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <p className="text-emerald-300 font-semibold text-base">No vulnerabilities detected</p>
          <p className="text-emerald-600 text-sm mt-1">This contract passed all 6 security checks.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {result.vulnerabilities.map((v, i) => (
            <VulnerabilityCard key={v.id} vuln={v} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}
