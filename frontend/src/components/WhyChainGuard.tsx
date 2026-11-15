import { RULES, SEVERITY_LABEL } from '../lib/severity';
import { FileTextIcon, MonitorIcon, ScaleIcon, TimerIcon } from './Icons';

const STEPS = [
  { n: '01', title: 'Paste or pick a contract', body: 'Any single-file Solidity source, or one of the six examples.' },
  { n: '02', title: 'Run the scan', body: 'Six regex-based rules run on the server. Results come back in well under a second.' },
  { n: '03', title: 'Read the findings', body: 'Each finding names the SWC entry, the line, the snippet and a suggested fix.' },
];

export default function WhyChainGuard() {
  return (
    <>
      {/* How it works + why, as an uneven grid */}
      <section id="how" className="scroll-mt-20 border-b border-line">
        <div className="container-page py-16 sm:py-24">
          <div className="max-w-[40ch]">
            <p className="eyebrow">How it works</p>
            <h2 className="mt-3 font-display text-[32px] font-semibold leading-[1.1] tracking-[-0.015em] sm:text-[40px]">
              Professional audits take weeks. A first check takes one paste.
            </h2>
          </div>

          <ol className="mt-10 grid grid-cols-1 border-y border-line md:grid-cols-3">
            {STEPS.map((s, i) => (
              <li key={s.n} className={`py-6 md:py-8 ${i > 0 ? 'border-t border-line md:border-l md:border-t-0 md:pl-8' : ''} md:pr-8`}>
                <span className="font-mono text-[13px] text-accent">{s.n}</span>
                <h3 className="mt-2 text-[18px] font-semibold text-ink">{s.title}</h3>
                <p className="mt-2 text-[15px] leading-relaxed text-ink-2">{s.body}</p>
              </li>
            ))}
          </ol>

          <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-6">
            <article className="rounded-lg border border-ink bg-ink p-6 text-paper md:col-span-3 md:row-span-2 md:p-8">
              <FileTextIcon size={22} className="text-[#A9BCFF]" />
              <h3 className="mt-6 font-display text-[26px] font-semibold leading-tight">A PDF report in one click</h3>
              <p className="mt-3 max-w-[46ch] text-[15px] leading-relaxed text-paper/80">
                Export the score, every finding and its recommendation as a document you can attach to a
                pull request, a DAO proposal or a client hand-off. Generated in your browser, free.
              </p>
            </article>
            <article className="rounded-lg border border-line bg-surface p-6 md:col-span-3">
              <TimerIcon size={22} className="text-accent" />
              <h3 className="mt-4 text-[17px] font-semibold">Under a second</h3>
              <p className="mt-1.5 text-[15px] leading-relaxed text-ink-2">No queue and no CI pipeline to wait on.</p>
            </article>
            <article className="rounded-lg border border-line bg-surface p-6 md:col-span-2">
              <MonitorIcon size={22} className="text-accent" />
              <h3 className="mt-4 text-[17px] font-semibold">No install</h3>
              <p className="mt-1.5 text-[15px] leading-relaxed text-ink-2">No Python, no CLI, no API key.</p>
            </article>
            <article className="rounded-lg border border-line bg-sunken p-6 md:col-span-1">
              <ScaleIcon size={22} className="text-ink-2" />
              <h3 className="mt-4 text-[17px] font-semibold">MIT</h3>
              <p className="mt-1.5 text-[15px] leading-relaxed text-ink-2">Open source.</p>
            </article>
          </div>
        </div>
      </section>

      {/* Rules as a reference table */}
      <section id="rules" className="scroll-mt-20 border-b border-line bg-surface">
        <div className="container-page py-16 sm:py-24">
          <div className="flex flex-col justify-between gap-6 md:flex-row md:items-end">
            <div className="max-w-[44ch]">
              <p className="eyebrow">What it checks</p>
              <h2 className="mt-3 font-display text-[32px] font-semibold leading-[1.1] tracking-[-0.015em] sm:text-[40px]">
                Six rules, each mapped to the SWC Registry.
              </h2>
            </div>
            <p className="max-w-[44ch] text-[15px] leading-relaxed text-ink-2">
              The SWC Registry is the closest thing Web3 has to the OWASP Top 10. Anything outside these
              six patterns is not checked.
            </p>
          </div>

          <div className="mt-10 overflow-hidden rounded-lg border border-ink">
            <table className="w-full border-collapse text-left">
              <thead className="hidden bg-sunken md:table-header-group">
                <tr className="font-mono text-[12px] text-muted">
                  <th scope="col" className="w-[120px] px-5 py-3 font-medium">ID</th>
                  <th scope="col" className="w-[260px] px-5 py-3 font-medium">Rule</th>
                  <th scope="col" className="px-5 py-3 font-medium">Triggers when</th>
                  <th scope="col" className="w-[120px] px-5 py-3 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {RULES.map((r, i) => (
                  <tr key={r.id} className={`grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 px-5 py-4 md:table-row md:p-0 ${i > 0 ? 'border-t border-line' : ''}`}>
                    <td className="order-1 font-mono text-[13px] text-muted md:px-5 md:py-4">{r.id}</td>
                    <th scope="row" className="order-3 col-span-2 text-[16px] font-semibold text-ink md:px-5 md:py-4">{r.name}</th>
                    <td className="order-4 col-span-2 text-[15px] leading-relaxed text-ink-2 md:px-5 md:py-4">{r.trigger}</td>
                    <td className="order-2 justify-self-end md:px-5 md:py-4">
                      <span className={`sev sev-${r.severity}`}>{SEVERITY_LABEL[r.severity]}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </>
  );
}
