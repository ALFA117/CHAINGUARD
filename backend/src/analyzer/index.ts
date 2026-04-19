import { parseContract } from './parser';
import { ALL_RULES } from './rules';
import { AnalysisResult, Vulnerability } from '../types';

function extractContractName(ast: any, source: string): string {
  if (ast?.children) {
    for (const node of ast.children) {
      if (node.type === 'ContractDefinition' && node.name) {
        return node.name;
      }
    }
  }
  // Fallback: parse from source text
  const match = source.match(/contract\s+(\w+)/);
  return match?.[1] ?? 'UnknownContract';
}

function calculateScore(vulnerabilities: Vulnerability[]): number {
  let score = 100;
  for (const v of vulnerabilities) {
    if (v.severity === 'HIGH') score -= 20;
    else if (v.severity === 'MEDIUM') score -= 10;
    else if (v.severity === 'LOW') score -= 5;
    else if (v.severity === 'INFO') score -= 1;
  }
  return Math.max(0, score);
}

export function analyzeContract(source: string): AnalysisResult {
  const { ast, error } = parseContract(source);

  if (error || !ast) {
    throw new Error(error ?? 'Failed to parse contract');
  }

  const vulnerabilities: Vulnerability[] = [];
  for (const rule of ALL_RULES) {
    try {
      const findings = rule(ast, source);
      vulnerabilities.push(...findings);
    } catch {
      // Individual rule failures must not abort the whole analysis
    }
  }

  return {
    contractName: extractContractName(ast, source),
    vulnerabilities,
    totalFound: vulnerabilities.length,
    score: calculateScore(vulnerabilities),
    analyzedAt: new Date().toISOString(),
  };
}
