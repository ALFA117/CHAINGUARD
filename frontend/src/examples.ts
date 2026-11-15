// Sample contracts for the scanner's example picker. Each one is meant to
// trigger (or, for SafeVault, pass) specific rules in api/analyze.js.

export const REENTRANCY_EXAMPLE = `// SPDX-License-Identifier: MIT
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

export const TX_ORIGIN_EXAMPLE = `// SPDX-License-Identifier: MIT
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

export const OVERFLOW_EXAMPLE = `// SPDX-License-Identifier: MIT
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

export const UNCHECKED_CALL_EXAMPLE = `// SPDX-License-Identifier: MIT
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

export const SELFDESTRUCT_EXAMPLE = `// SPDX-License-Identifier: MIT
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

export const SAFE_EXAMPLE = `// SPDX-License-Identifier: MIT
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

export interface Example {
  file: string;
  note: string;
  code: string;
}

export const EXAMPLES: Example[] = [
  { file: 'ReentrancyVuln.sol',    note: 'External call before state update', code: REENTRANCY_EXAMPLE },
  { file: 'TxOriginVuln.sol',      note: 'Auth with tx.origin',               code: TX_ORIGIN_EXAMPLE },
  { file: 'OverflowVuln.sol',      note: 'Solidity 0.7 arithmetic',           code: OVERFLOW_EXAMPLE },
  { file: 'UncheckedCallVuln.sol', note: 'Ignored .call() result',            code: UNCHECKED_CALL_EXAMPLE },
  { file: 'SelfdestructVuln.sol',  note: 'Anyone can selfdestruct',           code: SELFDESTRUCT_EXAMPLE },
  { file: 'SafeVault.sol',         note: 'Reference: should pass',            code: SAFE_EXAMPLE },
];
