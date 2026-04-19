import { AnalysisResult } from '../types';
import { exportToPDF } from '../utils/pdfExport';

interface ExportButtonProps { result: AnalysisResult; }

export default function ExportButton({ result }: ExportButtonProps) {
  return (
    <button
      onClick={() => exportToPDF(result)}
      className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold
        bg-gray-700/60 hover:bg-gray-600/80 active:bg-gray-700
        text-gray-200 border border-gray-600/40 hover:border-gray-500/60
        transition-all duration-200 hover:scale-[1.02] active:scale-[0.98]
        shadow-sm hover:shadow-md shrink-0"
    >
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
        <polyline points="7 10 12 15 17 10" />
        <line x1="12" y1="15" x2="12" y2="3" />
      </svg>
      Export PDF
    </button>
  );
}
