# ChainGuard — Smart Contract Vulnerability Scanner

> Real-time static analysis for Solidity smart contracts.
> Built for **HackOWASP 8.0** — Web3 + Cybersecurity track.

**Repo:** https://github.com/ALFA117/CHAINGUARD.git

---

## What It Does

Paste or upload any `.sol` file and get an instant security audit:

- Detects 6 vulnerability classes from the **SWC Registry**
- Assigns **Security Score** (0–100) based on severity of findings
- Shows affected **line number + code snippet** for each issue
- Provides actionable **fix recommendations**
- Exports a professional **PDF audit report**

---

## Vulnerabilities Detected

| Rule | SWC ID | Severity | Description |
|------|--------|----------|-------------|
| Reentrancy | SWC-107 | HIGH | External call before state update |
| tx.origin Auth | SWC-115 | HIGH | Authorization via tx.origin instead of msg.sender |
| Integer Overflow | SWC-101 | HIGH / INFO | Arithmetic without SafeMath in Solidity < 0.8 |
| Unchecked Return Value | SWC-104 | MEDIUM | .call()/.send() return value ignored |
| Unprotected Selfdestruct | SWC-106 | HIGH | selfdestruct() with no access control |
| Missing Visibility | SWC-100 | LOW | Function without explicit visibility modifier |

---

## Architecture

```
Frontend (React + Vite + TypeScript)    Backend (Node + Express + TypeScript)
┌──────────────────────────────┐        ┌────────────────────────────────────┐
│  Monaco Editor (Solidity)    │        │  POST /api/analyze                 │
│  Example contract selector   │ ─────► │  analyzer/parser.ts  (AST)         │
│  SecurityScore (SVG circle)  │        │  rules/reentrancy.ts               │
│  VulnerabilityCard (expand)  │ ◄───── │  rules/txOrigin.ts                 │
│  PDF export (jsPDF)          │        │  rules/integerOverflow.ts          │
└──────────────────────────────┘        │  rules/uncheckedCall.ts            │
                                        │  rules/selfdestruct.ts             │
  Vercel (frontend)                     │  rules/visibility.ts               │
  Railway (backend)                     └────────────────────────────────────┘
```

---

## Local Setup

```bash
# 1. Clone
git clone https://github.com/ALFA117/CHAINGUARD.git
cd CHAINGUARD

# 2. Backend
cd backend
npm install
npm run dev          # → http://localhost:3001

# 3. Frontend (new terminal)
cd frontend
npm install
npm run dev          # → http://localhost:5173
```

### Test the backend directly

```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"source": "pragma solidity ^0.7.0; contract Foo { function bar() { uint x = 0; x += 1; } }"}'
```

---

## Demo Contracts

Five vulnerable contracts are included in `contracts/vulnerable/` for live demo:

| Contract | Triggers |
|----------|---------|
| `ReentrancyVuln.sol` | SWC-107 |
| `TxOriginVuln.sol` | SWC-115 |
| `OverflowVuln.sol` | SWC-101 |
| `UncheckedCallVuln.sol` | SWC-104 |
| `SelfdestructVuln.sol` | SWC-106 |

---

## Deploy

### Backend → Railway
```bash
npm i -g @railway/cli
railway login && railway link
# Set env var FRONTEND_URL=https://chainguard.vercel.app in Railway dashboard
railway up
```

### Frontend → Vercel
```bash
npm i -g vercel
cd frontend && vercel
# Set env var VITE_API_URL=https://<your-backend>.up.railway.app/api in Vercel dashboard
vercel --prod
```

Update `frontend/vercel.json` and `frontend/.env.production` with your actual Railway URL.

---

## Roadmap

- [ ] Slither / MythX integration for deeper analysis
- [ ] File upload (.sol drag-and-drop)
- [ ] Multi-contract / multi-file support
- [ ] GitHub PR comment bot
- [ ] VS Code extension

---

## Video Script (2 min)

- **0:00–0:20** — "ChainGuard is a real-time vulnerability scanner for Solidity smart contracts, built for HackOWASP 8.0"
- **0:20–0:50** — Demo: load `ReentrancyVuln.sol`, click Analyze, show results
- **0:50–1:15** — Expand HIGH card, show description + recommendation
- **1:15–1:35** — Export PDF and show it briefly
- **1:35–2:00** — Switch to `TxOriginVuln.sol`, show different score and finding

---

## DoraHacks Submission Description (280 chars)

> ChainGuard is a real-time smart contract vulnerability scanner. Paste any Solidity contract and instantly detect reentrancy, tx.origin auth, integer overflow, unchecked calls, and more — with actionable fix recommendations and a PDF audit report.

---

## License

MIT
