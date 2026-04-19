import { visit } from '@solidity-parser/parser';
import { Vulnerability } from '../../types';

/**
 * SWC-107: Reentrancy
 * Detects functions that perform external calls (.call / .send / .transfer)
 * before updating state variables — the classic checks-effects-interactions violation.
 */
export function detectReentrancy(ast: any, source: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    FunctionDefinition(node: any) {
      if (!node.body || !node.body.statements) return;

      const statements = node.body.statements;
      let externalCallLine: number | null = null;
      let externalCallSnippet: string | null = null;
      let stateUpdateAfterCall = false;

      for (const stmt of statements) {
        const stmtStr = JSON.stringify(stmt);

        const isExternalCall =
          stmtStr.includes('"call"') ||
          stmtStr.includes('"send"') ||
          stmtStr.includes('"transfer"');

        const isStateUpdate =
          stmt.type === 'ExpressionStatement' &&
          stmt.expression?.type === 'BinaryOperation' &&
          stmt.expression?.operator === '=';

        const isStateUpdateAssignment =
          stmt.type === 'ExpressionStatement' &&
          (stmt.expression?.type === 'AssignmentExpression' ||
            stmt.expression?.operator === '-=' ||
            stmt.expression?.operator === '+=');

        if (isExternalCall && externalCallLine === null) {
          externalCallLine = stmt.loc?.start?.line ?? null;
          if (externalCallLine !== null) {
            externalCallSnippet = lines[externalCallLine - 1]?.trim() ?? null;
          }
        }

        if (externalCallLine !== null && (isStateUpdate || isStateUpdateAssignment)) {
          stateUpdateAfterCall = true;
        }
      }

      if (externalCallLine !== null && stateUpdateAfterCall) {
        const fnName = node.name ?? '(anonymous)';
        vulnerabilities.push({
          id: `reentrancy-${externalCallLine}`,
          title: 'Reentrancy Vulnerability',
          severity: 'HIGH',
          swcId: 'SWC-107',
          description: `Function "${fnName}" performs an external call before updating state variables. An attacker can re-enter the function before the state is updated, draining funds or corrupting state.`,
          recommendation:
            'Apply the Checks-Effects-Interactions pattern: update all state variables BEFORE making external calls. Consider using OpenZeppelin ReentrancyGuard.',
          line: externalCallLine,
          snippet: externalCallSnippet,
        });
      }
    },
  });

  return vulnerabilities;
}
