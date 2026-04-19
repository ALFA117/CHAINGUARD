import { visit } from '@solidity-parser/parser';
import { Vulnerability } from '../../types';

/**
 * SWC-100: Function Default Visibility
 * Detects functions with no explicit visibility modifier.
 * In Solidity < 0.5.0 the default was public; this is a common footgun.
 */
export function detectMissingVisibility(ast: any, source: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = source.split('\n');

  visit(ast, {
    FunctionDefinition(node: any) {
      // Constructors and fallback/receive functions don't require visibility
      if (node.isConstructor || node.isFallback || node.isReceiveEther) return;
      if (node.name === null) return; // unnamed = fallback

      if (!node.visibility || node.visibility === 'default') {
        const line = node.loc?.start?.line ?? null;
        vulnerabilities.push({
          id: `visibility-${node.name}-${line}`,
          title: `Missing visibility modifier on "${node.name}"`,
          severity: 'LOW',
          swcId: 'SWC-100',
          description: `Function "${node.name}" has no explicit visibility modifier. In Solidity < 0.5.0 this defaults to public, potentially exposing internal logic.`,
          recommendation:
            'Always specify visibility explicitly: public, private, internal, or external. Use the most restrictive visibility that still satisfies functional requirements.',
          line,
          snippet: lines[(line ?? 1) - 1]?.trim() ?? null,
        });
      }
    },
  });

  return vulnerabilities;
}
