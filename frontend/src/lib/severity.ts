import { AnalysisResult, SeverityLevel } from '../types';

export const SEVERITY_ORDER: SeverityLevel[] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const SEVERITY_LABEL: Record<SeverityLevel, string> = {
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

/** Tailwind text/bg classes per severity (tokens defined in index.css). */
export const SEVERITY_TONE: Record<SeverityLevel, { text: string; soft: string; bar: string }> = {
  HIGH:   { text: 'text-high',   soft: 'bg-high-soft',   bar: 'bg-high' },
  MEDIUM: { text: 'text-medium', soft: 'bg-medium-soft', bar: 'bg-medium' },
  LOW:    { text: 'text-low',    soft: 'bg-low-soft',    bar: 'bg-low' },
  INFO:   { text: 'text-info',   soft: 'bg-info-soft',   bar: 'bg-info' },
};

export function countBySeverity(result: AnalysisResult): Record<SeverityLevel, number> {
  const counts: Record<SeverityLevel, number> = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const v of result.vulnerabilities) counts[v.severity] += 1;
  return counts;
}

export type VerdictTone = 'high' | 'medium' | 'pass';

/**
 * The numeric score alone can read "80 / 100" for a contract with a
 * reentrancy bug. The verdict lets a single High finding outrank the score so
 * the headline never says "secure" while a High issue is open.
 */
export function verdict(result: AnalysisResult): { label: string; detail: string; tone: VerdictTone } {
  const c = countBySeverity(result);
  if (c.HIGH > 0) {
    return {
      label: 'High risk',
      detail: `${c.HIGH} high-severity finding${c.HIGH > 1 ? 's' : ''} to fix before deploying.`,
      tone: 'high',
    };
  }
  if (c.MEDIUM > 0 || result.score < 80) {
    return { label: 'Needs review', detail: 'No high-severity findings, but some issues need attention.', tone: 'medium' };
  }
  if (result.totalFound > 0) {
    return { label: 'Minor issues', detail: 'Only low-severity findings. Worth tidying up.', tone: 'pass' };
  }
  return { label: 'No findings', detail: 'Passed all 6 pattern checks. That is not proof the contract is safe.', tone: 'pass' };
}

export const VERDICT_TONE: Record<VerdictTone, { text: string; soft: string; ring: string }> = {
  high:   { text: 'text-high',   soft: 'bg-high-soft',   ring: 'stroke-high' },
  medium: { text: 'text-medium', soft: 'bg-medium-soft', ring: 'stroke-medium' },
  pass:   { text: 'text-pass',   soft: 'bg-pass-soft',   ring: 'stroke-pass' },
};

/** The six rules implemented in frontend/api/analyze.js, with their severities. */
export const RULES: { id: string; name: string; severity: SeverityLevel; trigger: string }[] = [
  { id: 'SWC-107', name: 'Reentrancy',               severity: 'HIGH',   trigger: 'An external call runs before the contract updates its own state.' },
  { id: 'SWC-115', name: 'Authorization via tx.origin', severity: 'HIGH', trigger: 'Access control compares tx.origin instead of msg.sender.' },
  { id: 'SWC-101', name: 'Integer overflow',         severity: 'HIGH',   trigger: 'Unchecked arithmetic in contracts compiled below Solidity 0.8.0.' },
  { id: 'SWC-106', name: 'Unprotected selfdestruct', severity: 'HIGH',   trigger: 'selfdestruct() is reachable without an access check.' },
  { id: 'SWC-104', name: 'Unchecked call return',    severity: 'MEDIUM', trigger: 'The result of .call() or .send() is never checked.' },
  { id: 'SWC-100', name: 'Missing visibility',       severity: 'LOW',    trigger: 'A function is declared without an explicit visibility keyword.' },
];
