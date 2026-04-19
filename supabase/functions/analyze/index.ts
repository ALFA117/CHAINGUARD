// Supabase Edge Function — ChainGuard analyzer (Deno runtime)
// Uses regex-based detection (no npm AST parser dependency)

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// ── Types ────────────────────────────────────────────────────────────────────

type SeverityLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface Vulnerability {
  id: string;
  title: string;
  severity: SeverityLevel;
  swcId: string;
  description: string;
  recommendation: string;
  line: number | null;
  snippet: string | null;
}

interface AnalysisResult {
  contractName: string;
  vulnerabilities: Vulnerability[];
  totalFound: number;
  score: number;
  analyzedAt: string;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function getLine(source: string, index: number): number {
  return source.substring(0, index).split('\n').length;
}

function getSnippet(source: string, lineNum: number): string {
  return source.split('\n')[lineNum - 1]?.trim() ?? '';
}

function getSolidityMinorVersion(source: string): number {
  const m = source.match(/pragma\s+solidity\s+[^;]*?(\d+)\.(\d+)/);
  if (!m) return 8; // assume safe default
  return parseInt(m[2], 10);
}

function extractContractName(source: string): string {
  const m = source.match(/contract\s+(\w+)/);
  return m?.[1] ?? 'UnknownContract';
}

// ── Rules (regex-based) ───────────────────────────────────────────────────────

function detectReentrancy(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Match function bodies containing an external call before a state assignment
  const funcRe = /function\s+(\w+)\s*\([^)]*\)[^{]*\{([\s\S]*?)\n\s*\}/g;
  let fm: RegExpExecArray | null;
  while ((fm = funcRe.exec(source)) !== null) {
    const body = fm[2];
    const callMatch = body.match(/\.(call|send|transfer)\s*[({]/);
    const stateMatch = body.match(/\w+\s*[\[\(][^\]]*[\]\)]\s*=|balances\[|deposits\[/);
    if (!callMatch || !stateMatch) continue;

    const callIdx = body.indexOf(callMatch[0]);
    const stateIdx = body.lastIndexOf(stateMatch[0]);
    if (callIdx >= stateIdx) continue; // call is not before state update

    const absIdx = fm.index + fm[0].indexOf(callMatch[0]);
    const line = getLine(source, absIdx);
    results.push({
      id: `reentrancy-${line}`,
      title: 'Reentrancy Vulnerability',
      severity: 'HIGH',
      swcId: 'SWC-107',
      description: `Function "${fm[1]}" performs an external call before updating state variables. An attacker can re-enter the function before state is updated, enabling fund draining attacks.`,
      recommendation:
        'Apply Checks-Effects-Interactions pattern: update all state BEFORE external calls. Use OpenZeppelin ReentrancyGuard for extra protection.',
      line,
      snippet: getSnippet(source, line),
    });
  }
  return results;
}

function detectTxOrigin(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  const re = /(?:require\s*\(|if\s*\()[^)]*tx\.origin[^)]*\)?/g;
  let m: RegExpExecArray | null;
  const seen = new Set<number>();
  while ((m = re.exec(source)) !== null) {
    const line = getLine(source, m.index);
    if (seen.has(line)) continue;
    seen.add(line);
    results.push({
      id: `txorigin-${line}`,
      title: 'Authorization via tx.origin',
      severity: 'HIGH',
      swcId: 'SWC-115',
      description:
        'tx.origin refers to the original external account that started the transaction. A malicious intermediate contract can bypass this check by tricking the legitimate owner into initiating a transaction.',
      recommendation:
        'Replace tx.origin with msg.sender. msg.sender is the direct caller and is not vulnerable to phishing via intermediate contracts.',
      line,
      snippet: getSnippet(source, line),
    });
  }
  return results;
}

function detectIntegerOverflow(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  const minor = getSolidityMinorVersion(source);
  const isVuln = minor < 8;
  const re = /\b\w+\s*(\+=|-=|\*=|\+\+|--|[^=!<>]=\s*\w+\s*[+\-*]\s*\w+)/g;
  let m: RegExpExecArray | null;
  const seen = new Set<number>();
  while ((m = re.exec(source)) !== null) {
    const line = getLine(source, m.index);
    if (seen.has(line)) continue;
    // Skip lines inside SafeMath calls
    const snip = getSnippet(source, line);
    if (snip.toLowerCase().includes('safemath') || snip.includes('//')) { seen.add(line); continue; }
    seen.add(line);
    results.push({
      id: `overflow-${line}`,
      title: isVuln ? 'Integer Overflow / Underflow' : 'Arithmetic Operation (overflow protected)',
      severity: isVuln ? 'HIGH' : 'INFO',
      swcId: 'SWC-101',
      description: isVuln
        ? `Arithmetic operation in Solidity 0.${minor}.x — no built-in overflow protection. Integer values can silently wrap around to unexpected amounts.`
        : `Arithmetic operation in Solidity 0.${minor}.x which has built-in overflow protection (reverts on overflow).`,
      recommendation: isVuln
        ? 'Use OpenZeppelin SafeMath or upgrade to Solidity >= 0.8.0 which includes native overflow checks.'
        : 'No action needed. Solidity >= 0.8.0 reverts automatically on overflow.',
      line,
      snippet: snip,
    });
  }
  return results;
}

function detectUncheckedCall(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Detect bare .call( or .send( not assigned to anything
  const re = /^\s*[^=\n(]*\.(call|send)\s*[({][^;]*;/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    // Skip if there's an assignment (bool success = ...)
    if (/=/.test(m[0])) continue;
    const line = getLine(source, m.index);
    results.push({
      id: `unchecked-call-${line}`,
      title: 'Unchecked Return Value (.call / .send)',
      severity: 'MEDIUM',
      swcId: 'SWC-104',
      description:
        '.call() and .send() return a boolean indicating success. Ignoring this value means silent failures — ETH may not transfer but execution continues normally.',
      recommendation:
        'Always check the return value: `(bool success,) = addr.call{value: v}(""); require(success, "Failed");`',
      line,
      snippet: getSnippet(source, line),
    });
  }
  return results;
}

function detectSelfdestruct(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Find function blocks containing selfdestruct without access modifier
  const funcRe = /function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?\s*([\w\s]*?)\{([^}]*selfdestruct[^}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = funcRe.exec(source)) !== null) {
    const modifiers = (m[4] ?? '').toLowerCase();
    const hasAccess =
      modifiers.includes('only') ||
      modifiers.includes('owner') ||
      modifiers.includes('admin') ||
      modifiers.includes('auth');
    if (hasAccess) continue;

    const sdIdx = source.indexOf('selfdestruct', m.index);
    const line = getLine(source, sdIdx);
    results.push({
      id: `selfdestruct-${line}`,
      title: 'Unprotected selfdestruct',
      severity: 'HIGH',
      swcId: 'SWC-106',
      description: `Function "${m[1]}" calls selfdestruct() without access control. Any address can destroy the contract and forward all its Ether.`,
      recommendation:
        'Restrict selfdestruct to privileged roles. Add an onlyOwner modifier or similar access control.',
      line,
      snippet: getSnippet(source, line),
    });
  }
  return results;
}

function detectMissingVisibility(source: string): Vulnerability[] {
  const results: Vulnerability[] = [];
  // Functions without an explicit visibility keyword after the parameter list
  const re = /function\s+(\w+)\s*\([^)]*\)\s*(?!(public|private|internal|external|view|pure|payable|\s*\{))/g;
  let m: RegExpExecArray | null;
  const seen = new Set<string>();
  while ((m = re.exec(source)) !== null) {
    const name = m[1];
    if (['constructor', 'fallback', 'receive'].includes(name)) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    const line = getLine(source, m.index);
    results.push({
      id: `visibility-${name}-${line}`,
      title: `Missing visibility modifier on "${name}"`,
      severity: 'LOW',
      swcId: 'SWC-100',
      description: `Function "${name}" has no explicit visibility modifier. In Solidity < 0.5.0 this defaults to public, potentially exposing internal logic.`,
      recommendation:
        'Always declare visibility explicitly: public, private, internal, or external.',
      line,
      snippet: getSnippet(source, line),
    });
  }
  return results;
}

// ── Score ─────────────────────────────────────────────────────────────────────

function calculateScore(vulns: Vulnerability[]): number {
  let score = 100;
  for (const v of vulns) {
    if (v.severity === 'HIGH') score -= 20;
    else if (v.severity === 'MEDIUM') score -= 10;
    else if (v.severity === 'LOW') score -= 5;
    else if (v.severity === 'INFO') score -= 1;
  }
  return Math.max(0, score);
}

// ── Main analyzer ─────────────────────────────────────────────────────────────

function analyzeContract(source: string): AnalysisResult {
  const rules = [
    detectReentrancy,
    detectTxOrigin,
    detectIntegerOverflow,
    detectUncheckedCall,
    detectSelfdestruct,
    detectMissingVisibility,
  ];

  const vulnerabilities: Vulnerability[] = [];
  for (const rule of rules) {
    try {
      vulnerabilities.push(...rule(source));
    } catch {
      // Individual rule failures must not abort the analysis
    }
  }

  return {
    contractName: extractContractName(source),
    vulnerabilities,
    totalFound: vulnerabilities.length,
    score: calculateScore(vulnerabilities),
    analyzedAt: new Date().toISOString(),
  };
}

// ── Edge Function handler ─────────────────────────────────────────────────────

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await req.json() as { source?: string };
    const source = body?.source;

    if (!source || typeof source !== 'string' || source.trim().length === 0) {
      return new Response(
        JSON.stringify({ error: 'Request body must include a non-empty "source" field.' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    if (new TextEncoder().encode(source).length > 50 * 1024) {
      return new Response(
        JSON.stringify({ error: 'Contract source exceeds the 50 KB limit.' }),
        { status: 413, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const result = analyzeContract(source);
    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unexpected error';
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
