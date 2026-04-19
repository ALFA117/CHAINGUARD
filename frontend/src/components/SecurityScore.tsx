interface SecurityScoreProps {
  score: number;
}

export default function SecurityScore({ score }: SecurityScoreProps) {
  const clampedScore = Math.max(0, Math.min(100, score));
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const progress = circumference - (clampedScore / 100) * circumference;

  let color = '#22c55e'; // green-500
  let bgColor = '#14532d'; // green-950
  let label = 'Secure';

  if (clampedScore < 50) {
    color = '#ef4444'; // red-500
    bgColor = '#450a0a';
    label = 'Critical';
  } else if (clampedScore < 80) {
    color = '#eab308'; // yellow-500
    bgColor = '#422006';
    label = 'Needs Review';
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className="rounded-full p-3"
        style={{ backgroundColor: bgColor }}
      >
        <svg width="100" height="100" viewBox="0 0 100 100">
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke="#374151"
            strokeWidth="8"
          />
          {/* Progress arc */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={progress}
            strokeLinecap="round"
            transform="rotate(-90 50 50)"
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
          {/* Score text */}
          <text
            x="50"
            y="46"
            textAnchor="middle"
            dominantBaseline="middle"
            fill="white"
            fontSize="20"
            fontWeight="bold"
          >
            {clampedScore}
          </text>
          <text
            x="50"
            y="63"
            textAnchor="middle"
            dominantBaseline="middle"
            fill="#9ca3af"
            fontSize="9"
          >
            / 100
          </text>
        </svg>
      </div>
      <div className="text-center">
        <p className="text-sm font-semibold" style={{ color }}>
          {label}
        </p>
        <p className="text-xs text-gray-500">Security Score</p>
      </div>
    </div>
  );
}
