import { AnimatePresence, motion } from 'motion/react';
import { Loader2, ScanSearch } from 'lucide-react';
import { springSnappy } from '../lib/motion';

interface AnalyzeButtonProps {
  onClick: () => void;
  isLoading: boolean;
  disabled: boolean;
}

export default function AnalyzeButton({ onClick, isLoading, disabled }: AnalyzeButtonProps) {
  return (
    <motion.button
      type="button"
      onClick={onClick}
      disabled={disabled || isLoading}
      aria-busy={isLoading}
      className="btn-primary w-full min-w-[200px] sm:w-auto"
      whileHover={disabled || isLoading ? undefined : { scale: 1.02 }}
      whileTap={disabled || isLoading ? undefined : { scale: 0.97 }}
      transition={springSnappy}
    >
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={isLoading ? 'busy' : 'idle'}
          className="inline-flex items-center gap-2"
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.15 }}
        >
          {isLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <ScanSearch className="h-4 w-4" aria-hidden />}
          {isLoading ? 'Scanning…' : 'Scan contract'}
        </motion.span>
      </AnimatePresence>
    </motion.button>
  );
}
