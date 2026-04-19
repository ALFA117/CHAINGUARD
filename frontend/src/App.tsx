import { useState } from 'react';
import { analyzeContract } from './api/analyze';
import { AnalysisResult } from './types';
import Header from './components/Header';
import CodeEditor, { REENTRANCY_EXAMPLE } from './components/CodeEditor';
import AnalyzeButton from './components/AnalyzeButton';
import ResultsPanel from './components/ResultsPanel';

// ── Example contracts for demo dropdown ───────────────────────────────────────

const TX_ORIGIN_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginVuln {
    address public owner;

    constructor() { owner = msg.sender; }

    function transferFunds(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Not owner");
        _to.transfer(_amount);
    }

    receive() external payable {}
}`;

const OVERFLOW_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract OverflowVuln {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }

    function mint(address _to, uint256 _amount) public {
        balances[_to] += _amount;
        totalSupply += _amount;
    }
}`;

const UNCHECKED_CALL_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCallVuln {
    address public owner;

    constructor() { owner = msg.sender; }

    function sendEther(address payable _to, uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        _to.call{value: _amount}("");
    }

    function execute(address _target, bytes memory _data) public {
        require(msg.sender == owner, "Not owner");
        _target.call(_data);
    }

    receive() external payable {}
}`;

const SELFDESTRUCT_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SelfdestructVuln {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() { owner = msg.sender; }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    function kill() public {
        selfdestruct(payable(owner));
    }
}`;

const EXAMPLES: { label: string; code: string }[] = [
  { label: 'ReentrancyVuln.sol', code: REENTRANCY_EXAMPLE },
  { label: 'TxOriginVuln.sol', code: TX_ORIGIN_EXAMPLE },
  { label: 'OverflowVuln.sol', code: OVERFLOW_EXAMPLE },
  { label: 'UncheckedCallVuln.sol', code: UNCHECKED_CALL_EXAMPLE },
  { label: 'SelfdestructVuln.sol', code: SELFDESTRUCT_EXAMPLE },
];

// ── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const [code, setCode] = useState(REENTRANCY_EXAMPLE);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Running totals across all analyses this session
  const [sessionVulns, setSessionVulns] = useState(0);
  const [sessionContracts, setSessionContracts] = useState(0);

  async function handleAnalyze() {
    if (!code.trim()) return;
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await analyzeContract(code);
      setResult(res);
      setSessionVulns((v) => v + res.totalFound);
      setSessionContracts((c) => c + 1);
    } catch (err: any) {
      const raw =
        err?.response?.data?.error ??
        err?.response?.data?.message ??
        err?.message;
      const msg = typeof raw === 'string' && raw.trim()
        ? raw
        : 'Failed to reach the analysis server. Is the backend running?';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }

  function handleExampleSelect(e: React.ChangeEvent<HTMLSelectElement>) {
    const chosen = EXAMPLES.find((ex) => ex.label === e.target.value);
    if (chosen) {
      setCode(chosen.code);
      setResult(null);
      setError(null);
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-gray-950">
      <Header totalVulns={sessionVulns} totalContracts={sessionContracts} />

      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-6">
        {/* Toolbar row */}
        <div className="flex flex-col sm:flex-row gap-3 mb-4">
          <select
            onChange={handleExampleSelect}
            className="bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2
              focus:outline-none focus:ring-2 focus:ring-indigo-500 cursor-pointer"
          >
            {EXAMPLES.map((ex) => (
              <option key={ex.label} value={ex.label}>
                {ex.label}
              </option>
            ))}
          </select>
          <AnalyzeButton
            onClick={handleAnalyze}
            isLoading={isLoading}
            disabled={!code.trim()}
          />
        </div>

        {/* Two-column layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Editor column */}
          <div className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">
              Contract Source
            </h2>
            <CodeEditor value={code} onChange={setCode} />
          </div>

          {/* Results column */}
          <div className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">
              Analysis Results
            </h2>
            <ResultsPanel isLoading={isLoading} result={result} error={error} />
          </div>
        </div>
      </main>
    </div>
  );
}
