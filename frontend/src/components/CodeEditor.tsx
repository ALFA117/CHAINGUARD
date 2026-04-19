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
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-3 py-2 bg-gray-800 border-b border-gray-700 rounded-t-lg">
        <span className="text-xs text-gray-400 font-mono">contract.sol</span>
        <span className="text-xs text-gray-500">Solidity</span>
      </div>
      <div className="flex-1 rounded-b-lg overflow-hidden border border-gray-700 border-t-0">
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
          }}
        />
      </div>
    </div>
  );
}

export { REENTRANCY_EXAMPLE };
