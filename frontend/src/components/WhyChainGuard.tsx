import { motion, useReducedMotion } from 'motion/react';
import { FileDown, Timer, PackageOpen, ArrowUpRight } from 'lucide-react';
import { RULES } from '../lib/severity';

const POINTS = [
  { icon: FileDown, title: 'A PDF report in one click', text: 'Share the findings with a client, a DAO vote or your own records. MythX charges for this; ChainGuard does not.' },
  { icon: Timer, title: 'Under a second', text: 'Six rules over the source, no queue and no pipeline to wait on.' },
  { icon: PackageOpen, title: 'Nothing to install', text: 'No Python, no CLI, no API key. It runs from this page.' },
];

export default function WhyChainGuard() {
  const reduce = useReducedMotion();
  const reveal = (i: number) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 18 },
          whileInView: { opacity: 1, y: 0 },
          viewport: { once: true, margin: '0px 0px -60px 0px' },
          transition: { type: 'spring' as const, stiffness: 260, damping: 26, delay: i * 0.04 },
        };

  return (
    <section id="why" aria-labelledby="why-title" className="mx-auto max-w-7xl scroll-mt-24 px-4 py-16 sm:px-6">
      <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr]">
        <div>
          <p className="t-eyebrow mb-4">Why it exists</p>
          <h2 id="why-title" className="t-title">Professional audits take weeks and thousands of dollars. This takes one paste.</h2>
          <ul className="mt-8 space-y-5">
            {POINTS.map(({ icon: Icon, title, text }, i) => (
              <motion.li key={title} {...reveal(i)} className="flex gap-4">
                <span className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-line bg-surface text-accent">
                  <Icon className="h-5 w-5" aria-hidden />
                </span>
                <div>
                  <h3 className="t-heading">{title}</h3>
                  <p className="t-body mt-1">{text}</p>
                </div>
              </motion.li>
            ))}
          </ul>
        </div>

        {/* The rulebook: exactly what is checked, nothing implied beyond it */}
        <motion.div {...reveal(1)} className="card overflow-hidden">
          <div className="flex items-baseline justify-between gap-4 border-b border-line/70 px-5 py-4">
            <h3 className="t-heading">What it checks — and only this</h3>
            <span className="font-mono text-xs text-muted">6 rules · SWC Registry</span>
          </div>
          <ol className="divide-y divide-line/60">
            {RULES.map((rule) => (
              <li key={rule.id} className="grid grid-cols-[88px_1fr] gap-3 px-5 py-3.5 sm:grid-cols-[96px_1fr]">
                <span className="font-mono text-sm font-medium text-accent">{rule.id}</span>
                <div>
                  <p className="font-semibold">{rule.name}</p>
                  <p className="text-sm leading-relaxed text-muted">{rule.desc}</p>
                </div>
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line/70 bg-surface2/40 px-5 py-4">
            <p className="text-sm text-muted">Pattern-based rules: a clean result is not a full audit.</p>
            <a href="https://github.com/ALFA117/CHAINGUARD" target="_blank" rel="noopener noreferrer"
              className="inline-flex min-h-[44px] items-center gap-1 text-sm font-semibold text-accent hover:underline">
              Read the rules <ArrowUpRight className="h-4 w-4" aria-hidden />
            </a>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
