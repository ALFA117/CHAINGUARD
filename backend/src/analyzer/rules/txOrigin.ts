import { visit } from '@solidity-parser/parser';
import { Vulnerability } from '../../types';

/**
 * SWC-115: Authorization through tx.origin
 * Detects tx.origin used inside require() calls or if-conditions.
 */
export function detectTxOrigin(ast: any, source: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = source.split('\n');
  const seen = new Set<number>();

  function containsTxOrigin(node: any): boolean {
    if (!node) return false;
    if (node.type === 'MemberAccess' && node.memberName === 'origin') {
      const expr = node.expression;
      if (expr?.type === 'Identifier' && expr?.name === 'tx') return true;
    }
    return Object.values(node).some(
      (v) => typeof v === 'object' && v !== null && containsTxOrigin(v as any)
    );
  }

  visit(ast, {
    FunctionCall(node: any) {
      const fnName =
        node.expression?.name ||
        node.expression?.memberName;
      if (fnName !== 'require') return;

      const hasTxOrigin = node.arguments?.some((arg: any) => containsTxOrigin(arg));
      if (!hasTxOrigin) return;

      const line = node.loc?.start?.line ?? null;
      if (line !== null && !seen.has(line)) {
        seen.add(line);
        vulnerabilities.push({
          id: `txorigin-${line}`,
          title: 'Authorization via tx.origin',
          severity: 'HIGH',
          swcId: 'SWC-115',
          description:
            'tx.origin refers to the original external account that initiated the transaction. If a malicious contract is called by the legitimate owner, tx.origin will still equal the owner, bypassing the check.',
          recommendation:
            'Replace tx.origin with msg.sender for authorization checks. msg.sender is the immediate caller and is not vulnerable to phishing via intermediate contracts.',
          line,
          snippet: lines[line - 1]?.trim() ?? null,
        });
      }
    },

    IfStatement(node: any) {
      if (!containsTxOrigin(node.condition)) return;
      const line = node.loc?.start?.line ?? null;
      if (line !== null && !seen.has(line)) {
        seen.add(line);
        vulnerabilities.push({
          id: `txorigin-if-${line}`,
          title: 'Authorization via tx.origin (if condition)',
          severity: 'HIGH',
          swcId: 'SWC-115',
          description:
            'tx.origin is used in an if-condition for authorization. This is vulnerable to phishing attacks through intermediate contract calls.',
          recommendation: 'Replace tx.origin with msg.sender.',
          line,
          snippet: lines[line - 1]?.trim() ?? null,
        });
      }
    },
  });

  return vulnerabilities;
}
