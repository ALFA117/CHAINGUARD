import { visit } from '@solidity-parser/parser';
import { Vulnerability } from '../../types';

/**
 * SWC-101: Integer Overflow and Underflow
 * Flags arithmetic operations in Solidity < 0.8.0 (no built-in overflow check).
 * In >= 0.8.0, overflow is caught at runtime — reported as INFO.
 */
export function detectIntegerOverflow(ast: any, source: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = source.split('\n');

  // Extract pragma version from AST
  let majorMinor = { major: 0, minor: 8 }; // default safe assumption
  visit(ast, {
    PragmaDirective(node: any) {
      if (node.name !== 'solidity') return;
      const match = node.value?.match(/(\d+)\.(\d+)/);
      if (match) {
        majorMinor = { major: parseInt(match[1], 10), minor: parseInt(match[2], 10) };
      }
    },
  });

  const isVulnerableVersion = majorMinor.major === 0 && majorMinor.minor < 8;
  const seen = new Set<number>();

  visit(ast, {
    BinaryOperation(node: any) {
      if (!['+', '-', '*'].includes(node.operator)) return;
      const line = node.loc?.start?.line ?? null;
      if (line === null || seen.has(line)) return;

      // Skip if inside a SafeMath call (heuristic: parent identifiers containing 'SafeMath' or 'safe')
      seen.add(line);

      vulnerabilities.push({
        id: `overflow-${line}`,
        title: isVulnerableVersion
          ? 'Integer Overflow / Underflow'
          : 'Arithmetic Operation (overflow protected)',
        severity: isVulnerableVersion ? 'HIGH' : 'INFO',
        swcId: 'SWC-101',
        description: isVulnerableVersion
          ? `Arithmetic operation (${node.operator}) on line ${line} in Solidity ${majorMinor.major}.${majorMinor.minor}.x — this version has NO built-in overflow protection. An attacker may wrap integer values to unexpected amounts.`
          : `Arithmetic operation detected. Solidity ${majorMinor.major}.${majorMinor.minor}.x has built-in overflow/underflow protection (reverts on overflow).`,
        recommendation: isVulnerableVersion
          ? 'Use OpenZeppelin SafeMath library or upgrade to Solidity >= 0.8.0 which includes native overflow checks.'
          : 'No action required. Solidity >= 0.8.0 reverts automatically on overflow. You may use unchecked{} blocks for gas optimization only when overflow is intentionally impossible.',
        line,
        snippet: lines[line - 1]?.trim() ?? null,
      });
    },

    UnaryOperation(node: any) {
      if (!['++', '--'].includes(node.operator)) return;
      const line = node.loc?.start?.line ?? null;
      if (line === null || seen.has(line) || !isVulnerableVersion) return;
      seen.add(line);

      vulnerabilities.push({
        id: `overflow-unary-${line}`,
        title: 'Integer Overflow via Increment/Decrement',
        severity: 'HIGH',
        swcId: 'SWC-101',
        description: `Unary ${node.operator} on line ${line} in Solidity < 0.8.0 can overflow silently.`,
        recommendation: 'Use SafeMath.add/sub or upgrade to Solidity >= 0.8.0.',
        line,
        snippet: lines[line - 1]?.trim() ?? null,
      });
    },
  });

  return vulnerabilities;
}
