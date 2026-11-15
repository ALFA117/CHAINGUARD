import { GithubIcon } from './Icons';

export function Logo({ className = '' }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
        <rect width="32" height="32" rx="7" className="fill-ink" />
        <path d="M16 26s7-3.5 7-8.75V10.5L16 8l-7 2.5v6.75C9 22.5 16 26 16 26z" fill="none" className="stroke-paper" strokeWidth="2" strokeLinejoin="round" />
        <path d="M12.75 16.5l2.25 2.25 4.25-4.5" fill="none" stroke="#7D9BFF" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="font-display text-[20px] font-semibold tracking-[-0.01em] text-ink">ChainGuard</span>
    </span>
  );
}

const NAV = [
  { href: '#scanner', label: 'Scanner' },
  { href: '#how', label: 'How it works' },
  { href: '#rules', label: 'Rules' },
];

export default function Header() {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-paper/[0.97]">
      <div className="container-page flex h-16 items-center justify-between gap-4">
        <a href="#top" className="-my-1 rounded py-2" aria-label="ChainGuard, back to top">
          <Logo />
        </a>

        <nav aria-label="Main" className="hidden items-center gap-1 md:flex">
          {NAV.map((item) => (
            <a key={item.href} href={item.href} className="btn-ghost text-[14px]">
              {item.label}
            </a>
          ))}
          <a
            href="https://github.com/ALFA117/CHAINGUARD"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-ghost text-[14px]"
          >
            <GithubIcon size={16} />
            Source
          </a>
        </nav>

        <div className="flex items-center gap-3">
          <span className="hidden font-mono text-[12px] text-muted lg:inline">HackOWASP 8.0</span>
          <a href="#scanner" className="btn-primary px-4 text-[14px]">
            Scan a contract
          </a>
        </div>
      </div>
    </header>
  );
}
