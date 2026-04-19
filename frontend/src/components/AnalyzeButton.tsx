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
      className="flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-semibold text-sm
        bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700
        disabled:opacity-50 disabled:cursor-not-allowed
        transition-colors w-full sm:w-auto"
    >
      {isLoading ? (
        <>
          <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
          Analyzing...
        </>
      ) : (
        <>
          <svg
            className="w-4 h-4"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          Analyze Contract
        </>
      )}
    </button>
  );
}
