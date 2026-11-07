export default function WhyChainGuard() {
  return (
    <section className="border-b border-gray-800/60 px-6 py-14 bg-gray-950/40">
      <div className="max-w-7xl mx-auto">
        <h2 className="text-2xl sm:text-3xl font-extrabold text-white max-w-lg">
          Professional audits cost weeks and thousands of dollars. A first check takes one paste.
        </h2>

        <div className="mt-8 grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Highlighted tile, spans 2 columns */}
          <div className="md:col-span-2 rounded-2xl border border-indigo-700/40 bg-gradient-to-br from-indigo-950/60 to-gray-900/60 p-6 flex flex-col justify-between min-h-[180px]">
            <svg className="w-7 h-7 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <div>
              <p className="text-white font-bold text-lg mt-4">PDF report, one click</p>
              <p className="text-gray-400 text-sm mt-1.5 leading-relaxed">
                Export a shareable report for a client, a DAO vote, or your own records.
                MythX charges for this. ChainGuard does not.
              </p>
            </div>
          </div>

          <div className="rounded-2xl border border-gray-700/50 bg-gray-900/50 p-6 flex flex-col justify-between min-h-[180px]">
            <svg className="w-7 h-7 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <div>
              <p className="text-white font-bold mt-4">Under a second</p>
              <p className="text-gray-400 text-sm mt-1.5 leading-relaxed">No queue, no CI pipeline to wait on.</p>
            </div>
          </div>

          <div className="rounded-2xl border border-gray-700/50 bg-gray-900/50 p-6 flex flex-col justify-between min-h-[180px]">
            <svg className="w-7 h-7 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <div>
              <p className="text-white font-bold mt-4">No install</p>
              <p className="text-gray-400 text-sm mt-1.5 leading-relaxed">Runs in the browser. No Python, no CLI, no API key.</p>
            </div>
          </div>
        </div>

        <h3 className="mt-14 text-sm font-semibold text-gray-300">What it actually checks for</h3>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[
            { id: 'SWC-107', name: 'Reentrancy', desc: 'An external call happens before the contract updates its own state.' },
            { id: 'SWC-115', name: 'tx.origin auth', desc: 'Access control checks tx.origin instead of msg.sender.' },
            { id: 'SWC-101', name: 'Integer overflow', desc: 'Arithmetic with no overflow protection, below Solidity 0.8.0.' },
            { id: 'SWC-104', name: 'Unchecked call', desc: 'A .call() or .send() return value is never checked.' },
            { id: 'SWC-106', name: 'Unprotected selfdestruct', desc: 'selfdestruct() is reachable with no access control.' },
            { id: 'SWC-100', name: 'Missing visibility', desc: 'A function has no explicit visibility modifier.' },
          ].map((rule) => (
            <div key={rule.id} className="rounded-xl border border-gray-800/60 bg-gray-900/30 px-4 py-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-gray-600">{rule.id}</span>
                <span className="text-sm font-semibold text-gray-200">{rule.name}</span>
              </div>
              <p className="text-xs text-gray-500 mt-1 leading-relaxed">{rule.desc}</p>
            </div>
          ))}
        </div>

        <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-4 rounded-2xl border border-gray-800/60 bg-gray-900/30 px-6 py-5 flex flex-wrap items-center justify-between gap-4">
            <p className="text-gray-400 text-sm">
              Free and open source, MIT licensed. Every rule maps to the SWC Registry, the Web3 equivalent of the OWASP Top 10.
            </p>
            <a
              href="https://github.com/ALFA117/CHAINGUARD"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-semibold text-indigo-400 hover:text-indigo-300 transition-colors shrink-0"
            >
              Read the source →
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
