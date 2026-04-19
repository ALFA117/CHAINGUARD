interface HeaderProps {
  totalVulns: number;
  totalContracts: number;
}

export default function Header({ totalVulns, totalContracts }: HeaderProps) {
  return (
    <header className="bg-gray-900 border-b border-gray-800 px-6 py-4">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <svg
            className="w-9 h-9 text-indigo-400 shrink-0"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">ChainGuard</h1>
            <p className="text-xs text-gray-400">Smart Contract Vulnerability Scanner</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-900 text-blue-300 border border-blue-700">
            Web3
          </span>
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-green-900 text-green-300 border border-green-700">
            Cybersecurity
          </span>
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-orange-900 text-orange-300 border border-orange-700">
            OWASP
          </span>
          {totalContracts > 0 && (
            <span className="ml-2 text-xs text-gray-400">
              <span className="text-white font-semibold">{totalVulns}</span> vulns found across{' '}
              <span className="text-white font-semibold">{totalContracts}</span> contract
              {totalContracts !== 1 ? 's' : ''} analyzed
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
