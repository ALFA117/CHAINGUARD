// Self-contained ChainGuard analyzer for Vercel API Routes (Node.js)
// Uses @solidity-parser/parser for accurate AST-based detection

import { parse, visit } from '@solidity-parser/parser';

// ── Types ─────────────────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────────

function getSnippet(source: string, line: number | null): string | null {
  if (line === null) return null;
  return source.split('\n')[line - 1]?.trim() ?? null;
}

function getSolidityMinorVersion(ast: any): number {
  let minor = 8;
  visit(ast, {
    PragmaDirective(node: any) {
      if (node.name !== 'solidity') return;
      const m = node.value?.match(/(\d+)\.(\d+)/);
      if (m) minor = parseInt(m[2], 10);
    },
  });
  return minor;
}

function extractContractName(ast: any, source: string): string {
  if (ast?.children) {
    for (const node of ast.children) {
      if (node.type === 'ContractDefinition' && node.name) return node.name;
    }
  }
  return source.match(/contract\s+(\w+)/)?.[1] ?? 'UnknownContract';
}

// ── Rule: Reentrancy (SWC-107) ────────────────────────────────────────────────

function detectReentrancy(ast: any, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    FunctionDefinition(node: any) {
      if (!node.body?.statements) return;
      const stmts = node.body.statements;
      let callLine: number | null = null;
      let stateAfter = false;

      for (const stmt of stmts) {
        const s = JSON.stringify(stmt);
        const isCall = s.includes('"call"') || s.includes('"send"') || s.includes('"transfer"');
        const isAssign =
          stmt.type === 'ExpressionStatement' &&
          (stmt.expression?.operator === '=' ||
            stmt.expression?.operator === '-=' ||
            stmt.expression?.operator === '+=');

        if (isCall && callLine === null) {
          callLine = stmt.loc?.start?.line ?? null;
        }
        if (callLine !== null && isAssign) {
          stateAfter = true;
        }
      }

      if (callLine !== null && stateAfter) {
        vulns.push({
          id: `reentrancy-${callLine}`,
          title: 'Reentrancy Vulnerability',
          severity: 'HIGH',
          swcId: 'SWC-107',
          description: `Function "${node.name ?? '(anonymous)'}" performs an external call before updating state variables. An attacker can re-enter before state is updated, enabling fund draining (TheDAO-style attack).`,
          recommendation:
            'Apply Checks-Effects-Interactions: update all state BEFORE external calls. Use OpenZeppelin ReentrancyGuard for defense-in-depth.',
          line: callLine,
          snippet: lines[callLine - 1]?.trim() ?? null,
        });
      }
    },
  });
  return vulns;
}

// ── Rule: tx.origin (SWC-115) ─────────────────────────────────────────────────

function detectTxOrigin(ast: any, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const lines = source.split('\n');
  const seen = new Set<number>();

  function hasTxOrigin(node: any): boolean {
    if (!node) return false;
    if (node.type === 'MemberAccess' && node.memberName === 'origin' &&
        node.expression?.name === 'tx') return true;
    return Object.values(node).some(v => typeof v === 'object' && v !== null && hasTxOrigin(v as any));
  }

  visit(ast, {
    FunctionCall(node: any) {
      const fn = node.expression?.name || node.expression?.memberName;
      if (fn !== 'require') return;
      if (!node.arguments?.some((a: any) => hasTxOrigin(a))) return;
      const line = node.loc?.start?.line ?? null;
      if (line === null || seen.has(line)) return;
      seen.add(line);
      vulns.push({
        id: `txorigin-${line}`,
        title: 'Authorization via tx.origin',
        severity: 'HIGH',
        swcId: 'SWC-115',
        description:
          'tx.origin is the original transaction initiator. A malicious contract called by the legitimate owner will still pass tx.origin checks, enabling phishing attacks.',
        recommendation: 'Replace tx.origin with msg.sender for all authorization checks.',
        line,
        snippet: lines[line - 1]?.trim() ?? null,
      });
    },
    IfStatement(node: any) {
      if (!hasTxOrigin(node.condition)) return;
      const line = node.loc?.start?.line ?? null;
      if (line === null || seen.has(line)) return;
      seen.add(line);
      vulns.push({
        id: `txorigin-if-${line}`,
        title: 'Authorization via tx.origin (if condition)',
        severity: 'HIGH',
        swcId: 'SWC-115',
        description: 'tx.origin in an if-condition is vulnerable to phishing attacks through intermediate contracts.',
        recommendation: 'Replace tx.origin with msg.sender.',
        line,
        snippet: lines[line - 1]?.trim() ?? null,
      });
    },
  });
  return vulns;
}

// ── Rule: Integer Overflow (SWC-101) ──────────────────────────────────────────

function detectIntegerOverflow(ast: any, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const lines = source.split('\n');
  const minor = getSolidityMinorVersion(ast);
  const isVuln = minor < 8;
  const seen = new Set<number>();

  visit(ast, {
    BinaryOperation(node: any) {
      if (!['+', '-', '*'].includes(node.operator)) return;
      const line = node.loc?.start?.line ?? null;
      if (line === null || seen.has(line)) return;
      seen.add(line);
      vulns.push({
        id: `overflow-${line}`,
        title: isVuln ? 'Integer Overflow / Underflow' : 'Arithmetic (overflow protected)',
        severity: isVuln ? 'HIGH' : 'INFO',
        swcId: 'SWC-101',
        description: isVuln
          ? `Arithmetic (${node.operator}) in Solidity 0.${minor}.x — no built-in overflow protection. Values can silently wrap around.`
          : `Arithmetic in Solidity 0.${minor}.x — overflow reverts automatically.`,
        recommendation: isVuln
          ? 'Use OpenZeppelin SafeMath or upgrade to Solidity >= 0.8.0.'
          : 'No action needed. Solidity >= 0.8.0 protects against overflow natively.',
        line,
        snippet: lines[line - 1]?.trim() ?? null,
      });
    },
  });
  return vulns;
}

// ── Rule: Unchecked Call (SWC-104) ────────────────────────────────────────────

function detectUncheckedCall(ast: any, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    ExpressionStatement(node: any) {
      const expr = node.expression;
      if (
        expr?.type === 'FunctionCall' &&
        expr.expression?.type === 'MemberAccess' &&
        ['call', 'send'].includes(expr.expression?.memberName)
      ) {
        const line = node.loc?.start?.line ?? null;
        vulns.push({
          id: `unchecked-${line}`,
          title: 'Unchecked Return Value (.call / .send)',
          severity: 'MEDIUM',
          swcId: 'SWC-104',
          description:
            '.call()/.send() return a boolean. Ignoring it means silent failures — Ether may not transfer but execution continues.',
          recommendation:
            '`(bool ok,) = addr.call{value: v}(""); require(ok, "Failed");`',
          line,
          snippet: lines[(line ?? 1) - 1]?.trim() ?? null,
        });
      }
    },
  });
  return vulns;
}

// ── Rule: Selfdestruct (SWC-106) ──────────────────────────────────────────────

function detectSelfdestruct(ast: any, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    FunctionDefinition(node: any) {
      const mods = (node.modifiers ?? []).map((m: any) => (m.name ?? '').toLowerCase());
      const hasAccess = mods.some((m: string) =>
        m.includes('owner') || m.includes('admin') || m.includes('only') || m.includes('auth')
      );

      visit(node, {
        FunctionCall(call: any) {
          const callee = call.expression?.name || call.expression?.memberName;
          if (callee !== 'selfdestruct' && callee !== 'suicide') return;
          if (hasAccess) return;
          const line = call.loc?.start?.line ?? null;
          vulns.push({
            id: `selfdestruct-${line}`,
            title: 'Unprotected selfdestruct',
            severity: 'HIGH',
            swcId: 'SWC-106',
            description: `selfdestruct() in "${node.name ?? 'function'}" has no access control — anyone can destroy the contract.`,
            recommendation:
              'Add onlyOwner or equivalent modifier. Consider if selfdestruct is necessary at all.',
            line,
            snippet: lines[(line ?? 1) - 1]?.trim() ?? null,
          });
        },
      });
    },
  });
  return vulns;
}

// ── Rule: Missing Visibility (SWC-100) ────────────────────────────────────────

function detectVisibility(ast: any, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    FunctionDefinition(node: any) {
      if (node.isConstructor || node.isFallback || node.isReceiveEther || node.name === null) return;
      if (!node.visibility || node.visibility === 'default') {
        const line = node.loc?.start?.line ?? null;
        vulns.push({
          id: `visibility-${node.name}-${line}`,
          title: `Missing visibility on "${node.name}"`,
          severity: 'LOW',
          swcId: 'SWC-100',
          description: `Function "${node.name}" has no explicit visibility. Solidity < 0.5.0 defaults to public.`,
          recommendation: 'Always specify: public, private, internal, or external.',
          line,
          snippet: lines[(line ?? 1) - 1]?.trim() ?? null,
        });
      }
    },
  });
  return vulns;
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

// ── Main export ───────────────────────────────────────────────────────────────

export function analyzeContract(source: string): AnalysisResult {
  let ast: any;
  try {
    ast = parse(source, { loc: true, range: true, tolerant: false });
  } catch (err: any) {
    const msg = Array.isArray(err?.errors)
      ? err.errors.map((e: any) => `Line ${e.line}: ${e.message}`).join('; ')
      : (err?.message ?? String(err));
    throw new Error(`Parse error — ${msg}`);
  }

  const rules = [
    detectReentrancy,
    detectTxOrigin,
    detectIntegerOverflow,
    detectUncheckedCall,
    detectSelfdestruct,
    detectVisibility,
  ];

  const vulnerabilities: Vulnerability[] = [];
  for (const rule of rules) {
    try { vulnerabilities.push(...rule(ast, source)); } catch { /* rule errors don't abort */ }
  }

  return {
    contractName: extractContractName(ast, source),
    vulnerabilities,
    totalFound: vulnerabilities.length,
    score: calculateScore(vulnerabilities),
    analyzedAt: new Date().toISOString(),
  };
}
