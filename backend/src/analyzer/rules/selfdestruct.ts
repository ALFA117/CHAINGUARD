import { visit } from '@solidity-parser/parser';
import { Vulnerability } from '../../types';

/**
 * SWC-106: Unprotected Selfdestruct
 * Detects selfdestruct() calls in functions that lack access control modifiers
 * (onlyOwner, onlyAdmin, or similar naming conventions).
 */
export function detectSelfdestruct(ast: any, source: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    FunctionDefinition(node: any) {
      const modifiers: string[] = (node.modifiers ?? []).map(
        (m: any) => m.name?.toLowerCase() ?? ''
      );
      const hasAccessControl = modifiers.some(
        (m) =>
          m.includes('owner') ||
          m.includes('admin') ||
          m.includes('only') ||
          m.includes('auth') ||
          m.includes('role')
      );

      // Walk function body looking for selfdestruct calls
      visit(node, {
        FunctionCall(callNode: any) {
          const callee =
            callNode.expression?.name || callNode.expression?.memberName;
          if (callee !== 'selfdestruct' && callee !== 'suicide') return;

          const line = callNode.loc?.start?.line ?? null;

          if (!hasAccessControl) {
            vulnerabilities.push({
              id: `selfdestruct-${line}`,
              title: 'Unprotected selfdestruct',
              severity: 'HIGH',
              swcId: 'SWC-106',
              description:
                'selfdestruct() is callable without access control. Any address can destroy this contract and forward all its Ether to an arbitrary address.',
              recommendation:
                'Restrict selfdestruct to privileged roles only. Add an onlyOwner (or equivalent) modifier. Consider whether selfdestruct is necessary at all — it is deprecated in newer EVM versions.',
              line,
              snippet: lines[(line ?? 1) - 1]?.trim() ?? null,
            });
          }
        },
      });
    },
  });

  return vulnerabilities;
}
