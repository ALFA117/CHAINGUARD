interface HeaderProps {
  totalVulns: number;
  totalContracts: number;
}

export default function Header({ totalVulns, totalContracts }: HeaderProps) {
  return (
    <header className="relative border-b border-gray-800/60 bg-gradient-to-r from-gray-950 via-gray-900 to-indigo-950/40 px-6 py-4 overflow-hidden">
      {/* Subtle top accent line */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent" />

      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        {/* Logo + title */}
        <div className="flex items-center gap-3 animate-fade-in">
          <div className="relative animate-glow-indigo rounded-xl p-1.5 bg-indigo-500/10 border border-indigo-500/20">
            <svg
              className="w-8 h-8 text-indigo-400"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" strokeWidth="2.5" className="text-cyan-400" stroke="#22d3ee" />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-r from-white via-indigo-200 to-cyan-300 bg-clip-text text-transparent">
              ChainGuard
            </h1>
            <p className="text-xs text-gray-500 tracking-wide">Smart Contract Vulnerability Scanner</p>
          </div>
        </div>

        {/* Right side */}
        <div className="flex flex-wrap items-center gap-2 animate-fade-in delay-150">
          {/* Hackathon badge */}
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-indigo-950 text-indigo-300 border border-indigo-700/50 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse inline-block" />
            HackOWASP 8.0
          </span>
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-950 text-blue-300 border border-blue-700/50">
            Web3
          </span>
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-700/50">
            Cybersecurity
          </span>
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-orange-950 text-orange-300 border border-orange-700/50">
            OWASP
          </span>

          {/* Session counter */}
          {totalContracts > 0 && (
            <span className="ml-1 text-xs text-gray-500 animate-fade-in">
              <span className="text-indigo-300 font-bold">{totalVulns}</span> vulns ·{' '}
              <span className="text-indigo-300 font-bold">{totalContracts}</span> contract{totalContracts !== 1 ? 's' : ''}
            </span>
          )}

          {/* Instagram */}
          <a
            href="https://www.instagram.com/alfa_edg_/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium
              bg-gradient-to-r from-purple-950 to-pink-950 text-pink-300
              border border-pink-700/40 hover:border-pink-500/70
              transition-all duration-200 hover:scale-105"
          >
            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/>
            </svg>
            @ALFA_EDG_
          </a>
        </div>
      </div>
    </header>
  );
}
