import { useEffect, useState } from 'react';

interface SecurityScoreProps { score: number; }

export default function SecurityScore({ score }: SecurityScoreProps) {
  const [displayed, setDisplayed] = useState(0);
  const clamped = Math.max(0, Math.min(100, score));

  // Count-up animation
  useEffect(() => {
    setDisplayed(0);
    const steps = 40;
    const increment = clamped / steps;
    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= clamped) { setDisplayed(clamped); clearInterval(timer); }
      else setDisplayed(Math.round(current));
    }, 18);
    return () => clearInterval(timer);
  }, [clamped]);

  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const progress = circumference - (displayed / 100) * circumference;

  let color = '#22c55e';
  let trackColor = '#14532d';
  let label = 'Secure';
  let labelColor = 'text-emerald-400';

  if (clamped < 50) {
    color = '#ef4444'; trackColor = '#450a0a'; label = 'Critical'; labelColor = 'text-red-400';
  } else if (clamped < 80) {
    color = '#eab308'; trackColor = '#422006'; label = 'Needs Review'; labelColor = 'text-yellow-400';
  }

  return (
    <div className="flex flex-col items-center gap-1.5 shrink-0 animate-count-up">
      <div
        className="relative rounded-full p-2"
        style={{ background: `radial-gradient(circle, ${trackColor}80, transparent)` }}
      >
        <svg width="96" height="96" viewBox="0 0 96 96">
          {/* Track */}
          <circle cx="48" cy="48" r={radius} fill="none" stroke="#1f2937" strokeWidth="7" />
          {/* Glow layer */}
          <circle cx="48" cy="48" r={radius} fill="none"
            stroke={color} strokeWidth="7" strokeOpacity="0.15"
            strokeDasharray={circumference} strokeDashoffset="0"
          />
          {/* Progress */}
          <circle cx="48" cy="48" r={radius} fill="none"
            stroke={color} strokeWidth="7"
            strokeDasharray={circumference}
            strokeDashoffset={progress}
            strokeLinecap="round"
            transform="rotate(-90 48 48)"
            style={{ transition: 'stroke-dashoffset 0.05s linear' }}
            filter="url(#glow)"
          />
          <defs>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>
          {/* Score number */}
          <text x="48" y="44" textAnchor="middle" dominantBaseline="middle"
            fill="white" fontSize="22" fontWeight="800" fontFamily="system-ui">
            {displayed}
          </text>
          <text x="48" y="62" textAnchor="middle" dominantBaseline="middle"
            fill="#6b7280" fontSize="9" fontFamily="system-ui">
            / 100
          </text>
        </svg>
      </div>
      <div className="text-center">
        <p className={`text-xs font-bold ${labelColor}`}>{label}</p>
        <p className="text-xs text-gray-600">Security Score</p>
      </div>
    </div>
  );
}
