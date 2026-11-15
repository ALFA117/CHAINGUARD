import { AnalysisResult } from '../types';
import { RULES, SEVERITY_LABEL, SEVERITY_ORDER, SEVERITY_TONE, VERDICT_TONE, countBySeverity, verdict } from '../lib/severity';
import SecurityScore from './SecurityScore';
import VulnerabilityCard from './VulnerabilityCard';
import ExportButton from './ExportButton';
import { AlertIcon, RefreshIcon, ShieldAlertIcon, ShieldCheckIcon, ShieldIcon } from './Icons';

interface ResultsPanelProps {
  isLoading: boolean;
  result: AnalysisResult | null;
  error: string | null;
  onRetry: () => void;
}

function Frame({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <div className="flex min-h-[300px] min-w-0 flex-col overflow-hidden rounded-lg border border-ink bg-surface lg:min-h-[482px]">
      <div className="flex min-h-[45px] items-center justify-between gap-3 border-b border-line bg-sunken px-4 py-2">
        <span className="font-mono text-[13px] text-ink-2">{label}</span>
        <span className="font-mono text-[12px] text-muted">6 rules · SWC</span>
      </div>
      {children}
    </div>
  );
}

export default function ResultsPanel({ isLoading, result, error, onRetry }: ResultsPanelProps) {
  /* ── Loading: skeleton with the shape of the report ───────────────── */
  if (isLoading) {
    return (
      <Frame label="Scanning…">
        <div className="progress-track" role="progressbar" aria-label="Scanning contract">
          <div className="progress-bar" />
        </div>
        <div className="space-y-6 p-5" aria-hidden="true">
          <div className="flex items-center gap-4">
            <div className="skeleton h-20 w-20 rounded-full" />
            <div className="flex-1 space-y-2.5">
              <div className="skeleton h-5 w-32" />
              <div className="skeleton h-3.5 w-56 max-w-full" />
            </div>
          </div>
          <div className="grid grid-cols-4 gap-2">
            {[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-14" />)}
          </div>
          {[0, 1, 2].map((i) => <div key={i} className="skeleton h-12" />)}
        </div>
        <p className="sr-only" aria-live="polite">Running 6 rules against the contract.</p>
      </Frame>
    );
  }

  /* ── Error: cause, what to do, retry ──────────────────────────────── */
  if (error) {
    return (
      <Frame label="Scan failed">
        <div className="enter flex flex-1 flex-col items-start gap-4 p-6" role="alert">
          <span className="flex h-10 w-10 items-center justify-center rounded bg-high-soft text-high">
            <AlertIcon size={20} />
          </span>
          <div>
            <h3 className="text-[17px] font-semibold text-ink">The analyzer did not return a result</h3>
            <p className="mt-1.5 max-w-[48ch] text-[15px] leading-relaxed text-ink-2">{error}</p>
            <p className="mt-2 max-w-[48ch] text-[14px] leading-relaxed text-muted">
              Check your connection and try again. Your code in the editor is kept as it is.
            </p>
          </div>
          <button type="button" onClick={onRetry} className="btn-secondary">
            <RefreshIcon size={16} /> Try again
          </button>
        </div>
      </Frame>
    );
  }

  /* ── Empty: what will happen ──────────────────────────────────────── */
  if (!result) {
    return (
      <Frame label="Report">
        <div className="flex flex-1 flex-col p-6">
          <span className="flex h-10 w-10 items-center justify-center rounded bg-sunken text-ink-2">
            <ShieldIcon size={20} />
          </span>
          <h3 className="mt-4 text-[17px] font-semibold text-ink">No scan yet</h3>
          <p className="mt-1.5 max-w-[46ch] text-[15px] leading-relaxed text-ink-2">
            Pick an example or paste your own contract, then press <strong className="font-semibold text-ink">Run scan</strong>
            <span className="hidden md:inline"> (or <kbd className="rounded border border-line bg-paper px-1.5 py-0.5 font-mono text-[12px]">Ctrl</kbd> + <kbd className="rounded border border-line bg-paper px-1.5 py-0.5 font-mono text-[12px]">Enter</kbd> in the editor)</span>.
          </p>
          <ul className="mt-6 divide-y divide-line border-y border-line">
            {RULES.map((r) => (
              <li key={r.id} className="flex items-center justify-between gap-3 py-2.5">
                <span className="min-w-0 truncate text-[14px] text-ink-2">{r.name}</span>
                <span className="shrink-0 font-mono text-[12px] text-muted">{r.id}</span>
              </li>
            ))}
          </ul>
        </div>
      </Frame>
    );
  }

  /* ── Result ───────────────────────────────────────────────────────── */
  const counts = countBySeverity(result);
  const v = verdict(result);
  const tone = VERDICT_TONE[v.tone];
  const VerdictIcon = v.tone === 'pass' ? ShieldCheckIcon : ShieldAlertIcon;
  const sorted = [...result.vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  return (
    <Frame label={`Report · ${result.contractName}`}>
      <div className="enter border-b border-line p-5">
        <div className="flex items-center gap-5">
          <SecurityScore score={result.score} tone={v.tone} size={84} />
          <div className="min-w-0 flex-1">
            <p className={`inline-flex items-center gap-1.5 text-[18px] font-semibold ${tone.text}`}>
              <VerdictIcon size={18} /> {v.label}
            </p>
            <p className="mt-1 text-[14px] leading-relaxed text-ink-2">{v.detail}</p>
            <p className="mt-1 font-mono text-[12px] text-muted">
              {new Date(result.analyzedAt).toLocaleString()}
            </p>
          </div>
        </div>

        <dl className="mt-5 grid grid-cols-4 overflow-hidden rounded border border-line">
          {SEVERITY_ORDER.map((s, i) => (
            <div key={s} className={`px-3 py-2.5 ${i > 0 ? 'border-l border-line' : ''} ${counts[s] > 0 ? SEVERITY_TONE[s].soft : ''}`}>
              <dt className={`font-mono text-[12px] ${counts[s] > 0 ? SEVERITY_TONE[s].text : 'text-muted'}`}>{SEVERITY_LABEL[s]}</dt>
              <dd className={`font-mono text-[20px] font-medium tabular-nums ${counts[s] > 0 ? 'text-ink' : 'text-muted'}`}>{counts[s]}</dd>
            </div>
          ))}
        </dl>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-[13px] text-muted">Score: 100 minus 20 per High, 10 per Medium, 5 per Low.</p>
          <ExportButton result={result} />
        </div>
      </div>

      {sorted.length === 0 ? (
        <div className="enter enter-1 flex flex-1 items-start gap-3 bg-pass-soft/60 p-5">
          <ShieldCheckIcon size={20} className="mt-0.5 shrink-0 text-pass" />
          <p className="text-[15px] leading-relaxed text-ink">
            None of the six patterns matched. Keep in mind this scanner only knows these six; logic bugs,
            oracle issues and economic attacks are out of scope.
          </p>
        </div>
      ) : (
        <ul className="enter enter-1" aria-label="Findings">
          {sorted.map((vuln, i) => (
            <VulnerabilityCard key={vuln.id} vuln={vuln} defaultOpen={i === 0} />
          ))}
        </ul>
      )}
    </Frame>
  );
}
