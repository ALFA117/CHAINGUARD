import { useState, useCallback } from 'react';
import Editor from '@monaco-editor/react';

const REENTRANCY_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract ReentrancyVuln {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // External call BEFORE state update — vulnerable to reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // Too late!
    }
}`;

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
}

export default function CodeEditor({ value, onChange }: CodeEditorProps) {
  const [copied, setCopied] = useState(false);
  const lineCount = (value || REENTRANCY_EXAMPLE).split('\n').length;

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(value || REENTRANCY_EXAMPLE).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }, [value]);

  return (
    <div className="flex flex-col rounded-xl overflow-hidden border border-gray-700/60 shadow-xl shadow-black/30">
      {/* Mac-style toolbar */}
      <div className="flex items-center gap-3 px-4 py-2.5 bg-gray-900/90 border-b border-gray-700/60">
        {/* Traffic light dots */}
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="w-3 h-3 rounded-full bg-red-500/60 hover:bg-red-500 transition-colors cursor-default" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/60 hover:bg-yellow-500 transition-colors cursor-default" />
          <span className="w-3 h-3 rounded-full bg-green-500/60 hover:bg-green-500 transition-colors cursor-default" />
        </div>

        {/* File name */}
        <div className="flex items-center gap-1.5 flex-1 justify-center">
          <svg className="w-3.5 h-3.5 text-indigo-400/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
            <polyline points="14 2 14 8 20 8" />
          </svg>
          <span className="text-xs text-gray-400 font-mono">contract.sol</span>
        </div>

        {/* Right side controls */}
        <div className="flex items-center gap-2 shrink-0">
          <span className="hidden sm:block text-xs text-gray-600 tabular-nums">{lineCount}L</span>
          <span className="text-xs px-2 py-0.5 rounded bg-indigo-900/50 text-indigo-300 border border-indigo-700/30 font-mono">
            Solidity
          </span>
          <button
            onClick={handleCopy}
            title="Copy source code"
            className="flex items-center gap-1 text-xs px-2 py-0.5 rounded
              bg-gray-800/80 hover:bg-gray-700/80 border border-gray-700/50 hover:border-gray-600/60
              text-gray-500 hover:text-gray-200 transition-all duration-200 select-none"
          >
            {copied ? (
              <>
                <svg className="w-3 h-3 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" />
                  <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                </svg>
                Copy
              </>
            )}
          </button>
        </div>
      </div>

      {/* Monaco editor */}
      <div className="flex-1 overflow-hidden bg-gray-950">
        <Editor
          height="420px"
          defaultLanguage="sol"
          theme="vs-dark"
          value={value || REENTRANCY_EXAMPLE}
          onChange={(v) => onChange(v ?? '')}
          options={{
            fontSize: 13,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            lineNumbers: 'on',
            padding: { top: 12, bottom: 12 },
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            renderLineHighlight: 'gutter',
          }}
        />
      </div>
    </div>
  );
}

export { REENTRANCY_EXAMPLE };
