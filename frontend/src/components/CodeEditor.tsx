import { useState, useCallback } from 'react';
import Editor from '@monaco-editor/react';
import { motion } from 'motion/react';
import { Check, Copy, FileCode2 } from 'lucide-react';
import { useDocTheme } from '../lib/theme';
import { springSnappy } from '../lib/motion';

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
  fileName: string;
}

export default function CodeEditor({ value, onChange, fileName }: CodeEditorProps) {
  const [copied, setCopied] = useState(false);
  const theme = useDocTheme();
  const lineCount = (value || '').split('\n').length;

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }, [value]);

  return (
    <div className="card cg-editor flex flex-col overflow-hidden">
      <div className="flex items-center gap-3 border-b border-line/70 px-4 py-2">
        <FileCode2 className="h-4 w-4 shrink-0 text-accent" aria-hidden />
        <span className="min-w-0 flex-1 truncate font-mono text-sm">{fileName}</span>
        <span className="hidden font-mono text-xs tabular-nums text-muted sm:block">{lineCount} lines</span>
        <motion.button
          type="button"
          onClick={handleCopy}
          className="inline-flex min-h-[44px] items-center gap-1.5 rounded-lg px-3 font-mono text-xs text-muted transition-colors hover:text-ink"
          whileTap={{ scale: 0.95 }}
          transition={springSnappy}
          aria-label="Copy the contract source"
        >
          {copied ? <><Check className="h-3.5 w-3.5 text-accent" aria-hidden /> <span className="text-accent">Copied</span></> : <><Copy className="h-3.5 w-3.5" aria-hidden /> Copy</>}
        </motion.button>
      </div>
      <div className="bg-surface">
        <Editor
          height="440px"
          defaultLanguage="sol"
          theme={theme === 'light' ? 'vs' : 'vs-dark'}
          value={value}
          onChange={(v) => onChange(v ?? '')}
          loading={<div className="flex h-[440px] items-center justify-center font-mono text-sm text-muted">Loading editor…</div>}
          options={{
            fontSize: 14,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            lineNumbers: 'on',
            padding: { top: 12, bottom: 12 },
            fontFamily: "'IBM Plex Mono', monospace",
            renderLineHighlight: 'gutter',
            ariaLabel: 'Solidity contract source',
          }}
        />
      </div>
    </div>
  );
}

export { REENTRANCY_EXAMPLE };
