import { Vulnerability } from '../../types';
import { detectReentrancy } from './reentrancy';
import { detectTxOrigin } from './txOrigin';
import { detectIntegerOverflow } from './integerOverflow';
import { detectUncheckedCall } from './uncheckedCall';
import { detectSelfdestruct } from './selfdestruct';
import { detectMissingVisibility } from './visibility';

export type RuleFn = (ast: any, source: string) => Vulnerability[];

export const ALL_RULES: RuleFn[] = [
  detectReentrancy,
  detectTxOrigin,
  detectIntegerOverflow,
  detectUncheckedCall,
  detectSelfdestruct,
  detectMissingVisibility,
];
