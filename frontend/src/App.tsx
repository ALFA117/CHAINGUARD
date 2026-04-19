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

const SAFE_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SafeVault — Secure ETH deposit/withdraw pattern
contract SafeVault {
    address public immutable owner;
    mapping(address => uint256) private balances;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    error NotOwner();
    error InsufficientBalance();
    error ZeroAmount();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        if (balances[msg.sender] < amount) revert InsufficientBalance();
        if (amount == 0) revert ZeroAmount();
        // Checks-Effects-Interactions: state update BEFORE external call
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}`;

const EXAMPLES: { label: string; code: string }[] = [
  { label: 'ReentrancyVuln.sol',    code: REENTRANCY_EXAMPLE },
  { label: 'TxOriginVuln.sol',      code: TX_ORIGIN_EXAMPLE },
  { label: 'OverflowVuln.sol',      code: OVERFLOW_EXAMPLE },
  { label: 'UncheckedCallVuln.sol', code: UNCHECKED_CALL_EXAMPLE },
  { label: 'SelfdestructVuln.sol',  code: SELFDESTRUCT_EXAMPLE },
  { label: '✅ SafeVault.sol',       code: SAFE_EXAMPLE },
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
    <div className="min-h-screen flex flex-col">
      <Header totalVulns={sessionVulns} totalContracts={sessionContracts} />

      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-6">
        {/* Toolbar row */}
        <div className="flex flex-col sm:flex-row gap-3 mb-5 animate-fade-in">
          <div className="flex items-center gap-2 flex-1 bg-gray-900/60 border border-gray-700/60 rounded-xl px-3 py-1 backdrop-blur-sm">
            <svg className="w-3.5 h-3.5 text-gray-600 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <span className="text-xs text-gray-600 shrink-0">Example</span>
            <div className="w-px h-4 bg-gray-700/60 shrink-0" />
            <select
              onChange={handleExampleSelect}
              className="flex-1 bg-transparent text-gray-300 text-sm py-2
                focus:outline-none cursor-pointer transition-colors hover:text-gray-100"
            >
              {EXAMPLES.map((ex) => (
                <option key={ex.label} value={ex.label} className="bg-gray-900">{ex.label}</option>
              ))}
            </select>
          </div>
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
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest flex items-center gap-2">
                <span className="w-1.5 h-3 bg-indigo-500 rounded-full inline-block" />
                Contract Source
              </h2>
              <span className="text-xs text-gray-700">Solidity · Monaco Editor</span>
            </div>
            <CodeEditor value={code} onChange={setCode} />
          </div>

          {/* Results column */}
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest flex items-center gap-2">
                <span className="w-1.5 h-3 bg-cyan-500 rounded-full inline-block" />
                Analysis Results
              </h2>
              <span className="text-xs text-gray-700">6 rules · SWC Registry</span>
            </div>
            <ResultsPanel isLoading={isLoading} result={result} error={error} />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/60 bg-gray-950/80 px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-gray-600">
          <div className="flex items-center gap-2">
            <svg className="w-3.5 h-3.5 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span className="text-gray-500">
              ChainGuard — Built for <span className="text-indigo-400 font-medium">HackOWASP 8.0</span>
            </span>
          </div>
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/ALFA117/CHAINGUARD"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 hover:text-gray-400 transition-colors"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
              </svg>
              GitHub
            </a>
            <a
              href="https://www.instagram.com/alfa_edg_/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 hover:text-pink-400 transition-colors"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/>
              </svg>
              @ALFA_EDG_
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
