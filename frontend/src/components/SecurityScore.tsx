import { useEffect, useState } from 'react';
import { VERDICT_TONE, VerdictTone } from '../lib/severity';

interface SecurityScoreProps {
  score: number;
  tone: VerdictTone;
  size?: number;
  /** Dark variant for use on code-coloured surfaces. */
  dark?: boolean;
}

function prefersReducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
}

export default function SecurityScore({ score, tone, size = 80, dark = false }: SecurityScoreProps) {
  const target = Math.max(0, Math.min(100, Math.round(score)));
  const [shown, setShown] = useState(prefersReducedMotion() ? target : 0);

  useEffect(() => {
    if (prefersReducedMotion()) { setShown(target); return; }
    let raf = 0;
    const start = performance.now();
    const duration = 700;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setShown(Math.round(target * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target]);

  const stroke = 6;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (shown / 100) * c;

  return (
    <div
      className="relative shrink-0"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Score ${target} out of 100`}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke}
          className={dark ? 'stroke-code-line' : 'stroke-sunken'}
        />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke}
          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="butt"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className={VERDICT_TONE[tone].ring}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none">
        <span className={`font-mono font-semibold tabular-nums ${dark ? 'text-white' : 'text-ink'}`} style={{ fontSize: size * 0.28 }}>
          {shown}
        </span>
        <span className={`mt-1 font-mono text-[11px] ${dark ? 'text-code-muted' : 'text-muted'}`}>/100</span>
      </div>
    </div>
  );
}
