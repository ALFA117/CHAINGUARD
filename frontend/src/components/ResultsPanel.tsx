import { AnalysisResult } from '../types';
import SecurityScore from './SecurityScore';
import VulnerabilityCard from './VulnerabilityCard';
import ExportButton from './ExportButton';

interface ResultsPanelProps {
  isLoading: boolean;
  result: AnalysisResult | null;
  error: string | null;
}

export default function ResultsPanel({ isLoading, result, error }: ResultsPanelProps) {
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <div className="w-10 h-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-gray-400 text-sm">Analyzing contract...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-950 border border-red-700 rounded-lg p-5">
        <p className="text-red-400 font-semibold mb-1">Analysis Error</p>
        <p className="text-red-300 text-sm">{error}</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4 text-center">
        <svg
          className="w-14 h-14 text-gray-700"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
          />
        </svg>
        <div>
          <p className="text-gray-400 font-medium">No contract analyzed yet</p>
          <p className="text-gray-600 text-sm mt-1">
            Paste a Solidity contract and click Analyze
          </p>
        </div>
      </div>
    );
  }

  const highs = result.vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const mediums = result.vulnerabilities.filter((v) => v.severity === 'MEDIUM').length;
  const lows = result.vulnerabilities.filter((v) => v.severity === 'LOW').length;
  const infos = result.vulnerabilities.filter((v) => v.severity === 'INFO').length;

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="bg-gray-800 rounded-lg p-4 flex flex-col sm:flex-row items-center gap-4">
        <SecurityScore score={result.score} />
        <div className="flex-1 space-y-1">
          <p className="text-white font-semibold text-sm">{result.contractName}</p>
          <p className="text-gray-400 text-xs">
            {result.totalFound} issue{result.totalFound !== 1 ? 's' : ''} found
          </p>
          <div className="flex flex-wrap gap-2 mt-2">
            {highs > 0 && (
              <span className="text-xs px-2 py-0.5 rounded bg-red-900 text-red-300 border border-red-700">
                {highs} HIGH
              </span>
            )}
            {mediums > 0 && (
              <span className="text-xs px-2 py-0.5 rounded bg-orange-900 text-orange-300 border border-orange-700">
                {mediums} MEDIUM
              </span>
            )}
            {lows > 0 && (
              <span className="text-xs px-2 py-0.5 rounded bg-yellow-900 text-yellow-300 border border-yellow-700">
                {lows} LOW
              </span>
            )}
            {infos > 0 && (
              <span className="text-xs px-2 py-0.5 rounded bg-blue-900 text-blue-300 border border-blue-700">
                {infos} INFO
              </span>
            )}
          </div>
        </div>
        <ExportButton result={result} />
      </div>

      {/* Vulnerability list */}
      {result.vulnerabilities.length === 0 ? (
        <div className="bg-green-950 border border-green-800 rounded-lg p-5 text-center">
          <p className="text-green-400 font-semibold">No vulnerabilities detected</p>
          <p className="text-green-600 text-sm mt-1">
            This contract passed all security checks.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {result.vulnerabilities.map((v) => (
            <VulnerabilityCard key={v.id} vuln={v} />
          ))}
        </div>
      )}
    </div>
  );
}
