import { motion } from 'motion/react';
import { FileDown } from 'lucide-react';
import { AnalysisResult } from '../types';
import { springSnappy } from '../lib/motion';

interface ExportButtonProps { result: AnalysisResult; }

export default function ExportButton({ result }: ExportButtonProps) {
  return (
    <motion.button
      type="button"
      // jsPDF is heavy; it is only downloaded when someone actually exports
      onClick={() => import('../utils/pdfExport').then((m) => m.exportToPDF(result))}
      className="btn-secondary shrink-0"
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.97 }}
      transition={springSnappy}
    >
      <FileDown className="h-4 w-4" aria-hidden />
      Export PDF
    </motion.button>
  );
}
