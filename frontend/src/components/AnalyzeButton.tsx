interface AnalyzeButtonProps {
  onClick: () => void;
  isLoading: boolean;
  disabled: boolean;
}

export default function AnalyzeButton({ onClick, isLoading, disabled }: AnalyzeButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`
        relative flex items-center justify-center gap-2
        px-6 py-2.5 rounded-xl font-semibold text-sm
        transition-all duration-200 w-full sm:w-auto
        overflow-hidden
        ${isLoading
          ? 'bg-indigo-700 cursor-wait'
          : disabled
            ? 'bg-gray-800 text-gray-600 cursor-not-allowed border border-gray-700'
            : 'bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-cyan-500 text-white shadow-lg shadow-indigo-500/20 hover:shadow-indigo-500/40 hover:scale-[1.02] active:scale-[0.98]'
        }
      `}
    >
      {/* Shimmer sweep on hover (non-loading) */}
      {!isLoading && !disabled && (
        <span className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full hover:translate-x-full transition-transform duration-700 pointer-events-none" />
      )}

      {isLoading ? (
        <>
          {/* Dual ring spinner */}
          <span className="relative w-4 h-4 shrink-0">
            <span className="absolute inset-0 rounded-full border-2 border-indigo-300/30" />
            <span className="absolute inset-0 rounded-full border-2 border-white border-t-transparent animate-spin" />
          </span>
          <span className="text-indigo-200">Analyzing...</span>
        </>
      ) : (
        <>
          <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          Analyze Contract
        </>
      )}
    </button>
  );
}
