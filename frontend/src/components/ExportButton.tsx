import { AnalysisResult } from '../types';
import { exportToPDF } from '../utils/pdfExport';

interface ExportButtonProps {
  result: AnalysisResult;
}

export default function ExportButton({ result }: ExportButtonProps) {
  return (
    <button
      onClick={() => exportToPDF(result)}
      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
        bg-gray-700 hover:bg-gray-600 active:bg-gray-800
        text-gray-200 transition-colors shrink-0"
    >
      <svg
        className="w-4 h-4"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="7 10 12 15 17 10" />
        <line x1="12" y1="15" x2="12" y2="3" />
      </svg>
      Export PDF
    </button>
  );
}
