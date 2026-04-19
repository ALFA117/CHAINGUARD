import { parse } from '@solidity-parser/parser';

export interface ParseResult {
  ast: any;
  error: string | null;
}

export function parseContract(source: string): ParseResult {
  try {
    const ast = parse(source, { loc: true, range: true, tolerant: false });
    return { ast, error: null };
  } catch (err: any) {
    // @solidity-parser/parser throws objects with an `errors` array on parse failure
    if (Array.isArray(err?.errors) && err.errors.length > 0) {
      const msg = err.errors
        .map((e: any) => `Line ${e.line ?? '?'}: ${e.message ?? e}`)
        .join('; ');
      return { ast: null, error: `Parse error — ${msg}` };
    }
    const message = err?.message ?? String(err);
    return { ast: null, error: `Parse error — ${message}` };
  }
}
