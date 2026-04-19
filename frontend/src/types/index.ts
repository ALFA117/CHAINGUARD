export type SeverityLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Vulnerability {
  id: string;
  title: string;
  severity: SeverityLevel;
  swcId: string;
  description: string;
  recommendation: string;
  line: number | null;
  snippet: string | null;
}

export interface AnalysisResult {
  contractName: string;
  vulnerabilities: Vulnerability[];
  totalFound: number;
  score: number;
  analyzedAt: string;
}
