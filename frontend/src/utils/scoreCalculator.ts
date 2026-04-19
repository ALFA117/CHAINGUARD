import { Vulnerability } from '../types';

export function calculateScore(vulnerabilities: Vulnerability[]): number {
  let score = 100;
  for (const v of vulnerabilities) {
    if (v.severity === 'HIGH') score -= 20;
    else if (v.severity === 'MEDIUM') score -= 10;
    else if (v.severity === 'LOW') score -= 5;
    else if (v.severity === 'INFO') score -= 1;
  }
  return Math.max(0, score);
}
