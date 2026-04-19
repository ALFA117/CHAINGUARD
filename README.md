# ChainGuard — Smart Contract Vulnerability Scanner

> Real-time security auditing for Solidity smart contracts.
> Built for **HackOWASP 8.0** — Web3 + Cybersecurity track.

**Live Demo:** https://chainguard-pi.vercel.app  
**Repo:** https://github.com/ALFA117/CHAINGUARD  
**Author:** [@ALFA_EDG_](https://www.instagram.com/alfa_edg_/)

---

## Why ChainGuard? Why not the competition?

### The problem

Smart contracts are **immutable once deployed**. A single vulnerability can lose millions of dollars — the DAO hack ($60M), Parity Wallet ($150M), Ronin Bridge ($625M). Most developers don't have access to professional audit tools: Slither requires Python + CLI setup, MythX costs $400+/month, and manual audits take weeks.

### What ChainGuard does differently

| Feature | ChainGuard | Slither | MythX | Remix Analyzer |
|---------|-----------|---------|-------|----------------|
| Zero install — runs in browser | ✅ | ❌ needs Python | ❌ needs CLI | ✅ |
| Instant results (< 1 second) | ✅ | ⚠️ slow on large contracts | ❌ minutes | ✅ |
| PDF audit report export | ✅ | ❌ | ✅ paid | ❌ |
| Security score (0–100) | ✅ | ❌ | ⚠️ partial | ❌ |
| Line-level code snippets | ✅ | ✅ | ✅ | ⚠️ |
| Fix recommendations per issue | ✅ | ⚠️ terse | ✅ | ⚠️ |
| Free & open source | ✅ | ✅ | ❌ | ✅ |
| Deployable as SaaS | ✅ | ❌ | ✅ | ❌ |

### What favors ChainGuard in this hackathon

1. **Accessibility** — No install, no account, no API key. Paste and scan in 1 click. Any developer, anywhere.
2. **Built for Web3 developers, not security experts** — Descriptions are written in plain language with copy-paste fix recommendations.
3. **PDF reports** — Developers can share audit evidence with clients, teams, or DAOs without paying an auditing firm.
4. **Full-stack in < 12 hours solo** — Proves the concept is buildable and deployable by a single developer.
5. **Open source** — Can be extended by the community, integrated into CI/CD pipelines, or embedded in IDEs.
6. **OWASP alignment** — All rules map directly to the SWC Registry (the Web3 equivalent of OWASP Top 10).

---

## What It Does

Paste or upload any `.sol` file and get an instant security audit:

- Detects **6 vulnerability classes** from the SWC Registry
- Shows **Security Score** (0–100) with animated visualization
- Highlights **affected line + code snippet** for each issue
- Provides **actionable fix recommendations**
- Exports a professional **PDF audit report**
- 5 built-in example contracts for live demo

---

## Vulnerabilities Detected

| Rule | SWC ID | Severity | Description |
|------|--------|----------|-------------|
| Reentrancy | SWC-107 | HIGH | External call before state update |
| tx.origin Auth | SWC-115 | HIGH | Auth via tx.origin instead of msg.sender |
| Integer Overflow | SWC-101 | HIGH | Arithmetic without protection in < 0.8.0 |
| Unchecked Return Value | SWC-104 | MEDIUM | .call()/.send() return bool ignored |
| Unprotected Selfdestruct | SWC-106 | HIGH | selfdestruct() without access control |
| Missing Visibility | SWC-100 | LOW | Function without explicit modifier |

---

## Architecture

```
Frontend (React + Vite + TypeScript)    Vercel Serverless Function (Node.js)
┌──────────────────────────────┐        ┌──────────────────────────────────┐
│  Monaco Editor (Solidity)    │        │  /api/analyze                    │
│  Example contract selector   │ POST   │  analyze.js — zero-dep regex     │
│  SecurityScore (SVG + anim)  │──────► │  6 vulnerability rules           │
│  VulnerabilityCard (expand)  │◄────── │  score calculator                │
│  PDF export (jsPDF)          │  JSON  │  returns AnalysisResult JSON     │
└──────────────────────────────┘        └──────────────────────────────────┘
         Vercel (same domain — no CORS)
```

---

## Local Setup

```bash
git clone https://github.com/ALFA117/CHAINGUARD
cd CHAINGUARD/frontend
npm install
npm run dev   # → http://localhost:5173
```

No backend needed locally — the API route runs via `vercel dev` or directly on Vercel.

For local API:
```bash
npm install -g vercel
vercel dev    # serves both frontend and /api/analyze
```

---

## Deploy

Frontend + API both deploy to **Vercel** from the `frontend/` directory.

```bash
cd frontend
vercel --prod
```

Supabase Edge Function (optional fallback):
```bash
supabase functions deploy analyze --project-ref igtgbxghiqfqvlcqnula
```

---

## Roadmap

- [ ] File upload (.sol drag-and-drop)
- [ ] Slither integration for deeper analysis
- [ ] CI/CD GitHub Action — comment on PR with audit results
- [ ] Multi-contract / multi-file analysis
- [ ] VS Code extension
- [ ] Historical scan tracking per wallet/project

---

## License

MIT — Built with ❤️ by [@ALFA_EDG_](https://www.instagram.com/alfa_edg_/) for HackOWASP 8.0
