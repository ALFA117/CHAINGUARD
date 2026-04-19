import { visit } from '@solidity-parser/parser';
import { Vulnerability } from '../../types';

/**
 * SWC-104: Unchecked Call Return Value
 * Detects .call() and .send() whose boolean return value is not captured or checked.
 */
export function detectUncheckedCall(ast: any, source: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    ExpressionStatement(node: any) {
      const expr = node.expression;
      if (!expr) return;

      // Bare call/send as expression statement — return value discarded
      const isBareCall =
        expr.type === 'FunctionCall' &&
        expr.expression?.type === 'MemberAccess' &&
        ['call', 'send'].includes(expr.expression?.memberName);

      if (isBareCall) {
        const line = node.loc?.start?.line ?? null;
        vulnerabilities.push({
          id: `unchecked-call-${line}`,
          title: 'Unchecked Return Value (.call / .send)',
          severity: 'MEDIUM',
          swcId: 'SWC-104',
          description:
            '.call() and .send() return a boolean indicating success or failure. Ignoring this value means silent failures — ETH may not be transferred but execution continues.',
          recommendation:
            'Always check the return value: `(bool success, ) = addr.call{value: v}(""); require(success, "Transfer failed");`. Prefer using .transfer() for simple ETH sends (reverts automatically), or handle the bool explicitly.',
          line,
          snippet: lines[(line ?? 1) - 1]?.trim() ?? null,
        });
      }
    },
  });

  return vulnerabilities;
}
