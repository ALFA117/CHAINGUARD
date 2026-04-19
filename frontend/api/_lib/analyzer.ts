// Regex-based analyzer — zero external dependencies, works in any Node.js env

export type SeverityLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Vulnerability {
  id: string;
  title: string;
  severity: SeverityLevel;
  swcId: string;
  description: string;
  recommendation: string;
  line: number | null;
  snippet: string | null;
}

export interface AnalysisResult {
  contractName: string;
  vulnerabilities: Vulnerability[];
  totalFound: number;
  score: number;
  analyzedAt: string;
}

function lineOf(source: string, idx: number): number {
  return source.substring(0, idx).split('\n').length;
}

function snippet(source: string, line: number): string {
  return source.split('\n')[line - 1]?.trim() ?? '';
}

function solidityMinor(source: string): number {
  const m = source.match(/pragma\s+solidity\s+[^;]*?0\.(\d+)/);
  return m ? parseInt(m[1], 10) : 8;
}

function contractName(source: string): string {
  return source.match(/contract\s+(\w+)/)?.[1] ?? 'UnknownContract';
}

// ── SWC-107: Reentrancy ───────────────────────────────────────────────────────
function detectReentrancy(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Extract function bodies
  const fnRe = /function\s+(\w+)\s*\([^)]*\)[^{]*\{/g;
  let m: RegExpExecArray | null;
  while ((m = fnRe.exec(source)) !== null) {
    const start = m.index + m[0].length;
    // Find matching closing brace
    let depth = 1, i = start;
    while (i < source.length && depth > 0) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') depth--;
      i++;
    }
    const body = source.slice(start, i - 1);
    // Check: external call exists AND state update comes after it
    const callMatch = body.match(/\.(call|send)\s*[({]/);
    if (!callMatch) continue;
    const callPos = body.indexOf(callMatch[0]);
    const afterCall = body.slice(callPos);
    // State update after call: assignment to mapping or balance variable
    if (!/balances\[|deposits\[|\w+\s*=\s*0/.test(afterCall)) continue;
    const line = lineOf(source, m.index);
    results.push({
      id: `reentrancy-${line}`,
      title: 'Reentrancy Vulnerability',
      severity: 'HIGH',
      swcId: 'SWC-107',
      description: `Function "${m[1]}" performs an external call before updating state. An attacker can re-enter and drain funds (TheDAO-style attack).`,
      recommendation: 'Use Checks-Effects-Interactions: update all state BEFORE external calls. Add OpenZeppelin ReentrancyGuard.',
      line,
      snippet: snippet(source, line),
    });
  }
  return results;
}

// ── SWC-115: tx.origin ────────────────────────────────────────────────────────
function detectTxOrigin(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  const re = /(?:require\s*\(|if\s*\()[^;)]*tx\.origin[^;)]*[;)]/g;
  let m: RegExpExecArray | null;
  const seen = new Set<number>();
  while ((m = re.exec(source)) !== null) {
    const line = lineOf(source, m.index);
    if (seen.has(line)) continue;
    seen.add(line);
    results.push({
      id: `txorigin-${line}`,
      title: 'Authorization via tx.origin',
      severity: 'HIGH',
      swcId: 'SWC-115',
      description: 'tx.origin is the original transaction initiator. A malicious intermediate contract can bypass this check by tricking the legitimate owner.',
      recommendation: 'Replace tx.origin with msg.sender for all authorization checks.',
      line,
      snippet: snippet(source, line),
    });
  }
  return results;
}

// ── SWC-101: Integer Overflow ─────────────────────────────────────────────────
function detectOverflow(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  const minor = solidityMinor(source);
  if (minor >= 8) return results; // built-in protection
  const re = /\w+\s*(\+=|-=|\*=)/g;
  let m: RegExpExecArray | null;
  const seen = new Set<number>();
  while ((m = re.exec(source)) !== null) {
    const line = lineOf(source, m.index);
    if (seen.has(line)) continue;
    const snip = snippet(source, line);
    if (snip.toLowerCase().includes('safemath')) continue;
    seen.add(line);
    results.push({
      id: `overflow-${line}`,
      title: 'Integer Overflow / Underflow',
      severity: 'HIGH',
      swcId: 'SWC-101',
      description: `Arithmetic in Solidity 0.${minor}.x has no built-in overflow protection. Values can silently wrap around.`,
      recommendation: 'Use OpenZeppelin SafeMath or upgrade to Solidity >= 0.8.0.',
      line,
      snippet: snip,
    });
  }
  return results;
}

// ── SWC-104: Unchecked Call ───────────────────────────────────────────────────
function detectUncheckedCall(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Match lines where .call( or .send( is a statement (not an assignment)
  const lines = source.split('\n');
  lines.forEach((ln, idx) => {
    const trimmed = ln.trim();
    if (/\.(call|send)\s*[({]/.test(trimmed) && !/^\s*(bool|var|let|const|\()/.test(trimmed) && !trimmed.startsWith('(')) {
      const line = idx + 1;
      results.push({
        id: `unchecked-${line}`,
        title: 'Unchecked Return Value (.call / .send)',
        severity: 'MEDIUM',
        swcId: 'SWC-104',
        description: '.call()/.send() return a boolean. Ignoring it means silent failures — ETH may not transfer.',
        recommendation: '`(bool ok,) = addr.call{value: v}(""); require(ok, "Failed");`',
        line,
        snippet: trimmed,
      });
    }
  });
  return results;
}

// ── SWC-106: Selfdestruct ─────────────────────────────────────────────────────
function detectSelfdestruct(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  const re = /function\s+(\w+)\s*\([^)]*\)\s*(public|external)([^{]*)\{[^}]*selfdestruct/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const modifiers = m[3].toLowerCase();
    if (/only|owner|admin|auth/.test(modifiers)) continue;
    const line = lineOf(source, m.index);
    results.push({
      id: `selfdestruct-${line}`,
      title: 'Unprotected selfdestruct',
      severity: 'HIGH',
      swcId: 'SWC-106',
      description: `Function "${m[1]}" calls selfdestruct() without access control. Anyone can destroy this contract.`,
      recommendation: 'Add onlyOwner or equivalent access control to any function containing selfdestruct().',
      line,
      snippet: snippet(source, line),
    });
  }
  return results;
}

// ── SWC-100: Missing Visibility ───────────────────────────────────────────────
function detectVisibility(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Functions missing public/private/internal/external
  const re = /function\s+(\w+)\s*\([^)]*\)\s*(?!(public|private|internal|external|view|pure|payable|\s*\{|\s*returns|\s*virtual|\s*override))/g;
  let m: RegExpExecArray | null;
  const seen = new Set<string>();
  while ((m = re.exec(source)) !== null) {
    const name = m[1];
    if (['constructor', 'fallback', 'receive'].includes(name) || seen.has(name)) continue;
    seen.add(name);
    const line = lineOf(source, m.index);
    results.push({
      id: `visibility-${name}-${line}`,
      title: `Missing visibility on "${name}"`,
      severity: 'LOW',
      swcId: 'SWC-100',
      description: `Function "${name}" has no explicit visibility modifier. Defaults to public in Solidity < 0.5.0.`,
      recommendation: 'Always specify visibility: public, private, internal, or external.',
      line,
      snippet: snippet(source, line),
    });
  }
  return results;
}

// ── Score ─────────────────────────────────────────────────────────────────────
function score(vulns: Vulnerability[]): number {
  let s = 100;
  for (const v of vulns) {
    if (v.severity === 'HIGH') s -= 20;
    else if (v.severity === 'MEDIUM') s -= 10;
    else if (v.severity === 'LOW') s -= 5;
    else if (v.severity === 'INFO') s -= 1;
  }
  return Math.max(0, s);
}

// ── Export ────────────────────────────────────────────────────────────────────
export function analyzeContract(source: string): AnalysisResult {
  const rules = [
    detectReentrancy,
    detectTxOrigin,
    detectOverflow,
    detectUncheckedCall,
    detectSelfdestruct,
    detectVisibility,
  ];
  const vulnerabilities: Vulnerability[] = [];
  for (const rule of rules) {
    try { vulnerabilities.push(...rule(source)); } catch { /* rule errors don't abort */ }
  }
  return {
    contractName: contractName(source),
    vulnerabilities,
    totalFound: vulnerabilities.length,
    score: score(vulnerabilities),
    analyzedAt: new Date().toISOString(),
  };
}
