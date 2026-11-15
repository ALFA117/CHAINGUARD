import { useCallback, useEffect, useRef, useState } from 'react';
import Editor, { BeforeMount, OnMount } from '@monaco-editor/react';
import { CheckIcon, CopyIcon } from './Icons';

interface CodeEditorProps {
  value: string;
  fileName: string;
  onChange: (value: string) => void;
  /** Ctrl/Cmd + Enter inside the editor. */
  onRun: () => void;
}

// Editor palette matches the --code tokens in index.css.
const defineTheme: BeforeMount = (monaco) => {
  monaco.editor.defineTheme('chainguard', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'comment', foreground: '7C8597', fontStyle: 'italic' },
      { token: 'keyword', foreground: 'A9BCFF' },
      { token: 'string', foreground: 'B8D8A8' },
      { token: 'number', foreground: 'E8C27A' },
      { token: 'type', foreground: '8FD3D6' },
    ],
    colors: {
      'editor.background': '#0F1218',
      'editor.foreground': '#D6DAE2',
      'editorLineNumber.foreground': '#4A5262',
      'editorLineNumber.activeForeground': '#D6DAE2',
      'editor.lineHighlightBackground': '#171B23',
      'editor.lineHighlightBorder': '#171B23',
      'editor.selectionBackground': '#2B3C78',
      'editorCursor.foreground': '#A9BCFF',
      'editorIndentGuide.background1': '#1E232D',
      'scrollbarSlider.background': '#252A3580',
    },
  });
};

export default function CodeEditor({ value, fileName, onChange, onRun }: CodeEditorProps) {
  const [copied, setCopied] = useState(false);
  const runRef = useRef(onRun);
  useEffect(() => { runRef.current = onRun; }, [onRun]);

  const lineCount = value.split('\n').length;

  const handleMount: OnMount = (editor, monaco) => {
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => runRef.current());
  };

  const handleCopy = useCallback(() => {
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    }).catch(() => {});
  }, [value]);

  return (
    <div className="flex min-w-0 flex-col overflow-hidden rounded-lg border border-ink bg-code">
      <div className="flex items-center gap-3 border-b border-code-line px-4 py-2">
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-code-text">{fileName}</span>
        <span className="hidden font-mono text-[12px] text-code-muted sm:inline">{lineCount} lines</span>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex min-h-[44px] items-center gap-1.5 rounded px-2.5 text-[13px] text-code-muted transition-colors hover:bg-code-line hover:text-white"
          aria-label="Copy source code"
        >
          {copied ? <CheckIcon size={15} /> : <CopyIcon size={15} />}
          <span aria-live="polite">{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      <Editor
        height="min(440px, 62vh)"
        defaultLanguage="sol"
        theme="chainguard"
        beforeMount={defineTheme}
        onMount={handleMount}
        value={value}
        onChange={(v) => onChange(v ?? '')}
        loading={<div className="h-full w-full bg-code p-4"><div className="skeleton-dark h-3 w-2/3" /></div>}
        options={{
          fontSize: 13,
          lineHeight: 21,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          wordWrap: 'on',
          lineNumbers: 'on',
          lineNumbersMinChars: 3,
          padding: { top: 12, bottom: 12 },
          fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
          renderLineHighlight: 'line',
          overviewRulerLanes: 0,
          scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
          automaticLayout: true,
          ariaLabel: 'Solidity source code editor',
        }}
      />
    </div>
  );
}
