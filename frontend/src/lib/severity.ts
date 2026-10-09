import type { SeverityLevel } from '../types';

// One place that maps a severity to its token, label and weight in the score.
// Colour is never the only signal: every chip also carries the level's name.
export const SEVERITY: Record<SeverityLevel, { text: string; chip: string; bar: string; rail: string; label: string }> = {
  HIGH:   { text: 'text-crit', chip: 'border-crit/40 bg-crit/10 text-crit', bar: 'bg-crit', rail: 'before:bg-crit', label: 'High' },
  MEDIUM: { text: 'text-warn', chip: 'border-warn/40 bg-warn/10 text-warn', bar: 'bg-warn', rail: 'before:bg-warn', label: 'Medium' },
  LOW:    { text: 'text-low',  chip: 'border-low/40 bg-low/10 text-low',    bar: 'bg-low',  rail: 'before:bg-low',  label: 'Low' },
  INFO:   { text: 'text-info', chip: 'border-info/40 bg-info/10 text-info', bar: 'bg-info', rail: 'before:bg-info', label: 'Info' },
};

export const ORDER: SeverityLevel[] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const RULES = [
  { id: 'SWC-107', name: 'Reentrancy', desc: 'An external call happens before the contract updates its own state.' },
  { id: 'SWC-115', name: 'tx.origin auth', desc: 'Access control checks tx.origin instead of msg.sender.' },
  { id: 'SWC-101', name: 'Integer overflow', desc: 'Arithmetic with no overflow protection, below Solidity 0.8.0.' },
  { id: 'SWC-104', name: 'Unchecked call', desc: 'A .call() or .send() return value is never checked.' },
  { id: 'SWC-106', name: 'Unprotected selfdestruct', desc: 'selfdestruct() is reachable with no access control.' },
  { id: 'SWC-100', name: 'Missing visibility', desc: 'A function has no explicit visibility modifier.' },
];
