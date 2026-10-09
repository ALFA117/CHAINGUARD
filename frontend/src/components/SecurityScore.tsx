import { useEffect, useState } from 'react';
import { animate, useReducedMotion } from 'motion/react';
import type { SeverityLevel } from '../types';

interface SecurityScoreProps {
  score: number;
  compact?: boolean;
  /** Worst severity found. A High finding outranks a good-looking number. */
  worst?: SeverityLevel | null;
}

// 100 minus 20 per High, 10 per Medium, 5 per Low, 1 per Info (utils/scoreCalculator.ts).
function band(score: number, worst?: SeverityLevel | null) {
  if (worst === 'HIGH') return { stroke: 'rgb(var(--crit))', text: 'text-crit', label: 'Fix before deploying' };
  if (worst === 'MEDIUM') return { stroke: 'rgb(var(--warn))', text: 'text-warn', label: 'Needs review' };
  if (score < 50) return { stroke: 'rgb(var(--crit))', text: 'text-crit', label: 'Critical' };
  if (score < 80) return { stroke: 'rgb(var(--warn))', text: 'text-warn', label: 'Needs review' };
  return { stroke: 'rgb(var(--accent))', text: 'text-accent', label: 'No major issues' };
}

export default function SecurityScore({ score, compact = false, worst = null }: SecurityScoreProps) {
  const clamped = Math.max(0, Math.min(100, score));
  const reduce = useReducedMotion();
  const [shown, setShown] = useState(reduce ? clamped : 0);

  useEffect(() => {
    if (reduce) { setShown(clamped); return; }
    const controls = animate(0, clamped, {
      duration: 0.9,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setShown(Math.round(v)),
    });
    return () => controls.stop();
  }, [clamped, reduce]);

  const size = compact ? 80 : 104;
  const r = compact ? 32 : 42;
  const c = 2 * Math.PI * r;
  const b = band(clamped, worst);

  return (
    <div className="flex shrink-0 flex-col items-center gap-1" role="img" aria-label={`Security score ${clamped} out of 100: ${b.label}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(var(--line))" strokeWidth="7" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={b.stroke}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c - (shown / 100) * c}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text x="50%" y="47%" textAnchor="middle" dominantBaseline="middle" fill="rgb(var(--ink))"
          fontSize={compact ? 22 : 28} fontWeight="700" fontFamily="'IBM Plex Mono', monospace">
          {shown}
        </text>
        <text x="50%" y="68%" textAnchor="middle" dominantBaseline="middle" fill="rgb(var(--muted))"
          fontSize="12" fontFamily="'IBM Plex Mono', monospace">
          /100
        </text>
      </svg>
      {!compact && <p className={`text-sm font-semibold ${b.text}`}>{b.label}</p>}
    </div>
  );
}
