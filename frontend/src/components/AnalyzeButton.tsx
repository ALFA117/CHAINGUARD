import { ScanIcon } from './Icons';

interface AnalyzeButtonProps {
  onClick: () => void;
  isLoading: boolean;
  disabled: boolean;
  className?: string;
}

export default function AnalyzeButton({ onClick, isLoading, disabled, className = '' }: AnalyzeButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || isLoading}
      aria-busy={isLoading}
      className={`btn-accent px-6 ${isLoading ? 'cursor-wait' : ''} ${className}`}
    >
      {isLoading ? (
        <>
          <span className="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-white/30 border-t-white" aria-hidden="true" />
          Scanning…
        </>
      ) : (
        <>
          <ScanIcon size={18} />
          Run scan
        </>
      )}
    </button>
  );
}
