import { useState } from 'react';
import { AnalysisResult } from '../types';
import { DownloadIcon } from './Icons';

interface ExportButtonProps { result: AnalysisResult; }

export default function ExportButton({ result }: ExportButtonProps) {
  const [state, setState] = useState<'idle' | 'busy' | 'done' | 'error'>('idle');

  async function handleExport() {
    setState('busy');
    try {
      // jsPDF is only downloaded when someone actually exports.
      const { exportToPDF } = await import('../utils/pdfExport');
      exportToPDF(result);
      setState('done');
    } catch {
      setState('error');
    }
    setTimeout(() => setState('idle'), 2400);
  }

  const label = { idle: 'Export PDF', busy: 'Preparing PDF…', done: 'PDF downloaded', error: 'Export failed, retry' }[state];

  return (
    <button
      type="button"
      onClick={handleExport}
      disabled={state === 'busy'}
      className="btn-secondary w-full px-4 text-[14px] sm:w-auto"
    >
      <DownloadIcon size={16} />
      <span aria-live="polite">{label}</span>
    </button>
  );
}
