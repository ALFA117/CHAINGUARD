// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * VULNERABLE: Integer overflow without SafeMath
 * SWC-101 — Solidity 0.7.x has no built-in overflow protection.
 * Adding uint256 max + 1 wraps around to 0.
 */
contract OverflowVuln {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    // VULNERABLE: no overflow check on transfer
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        balances[_to] += _amount; // can overflow if _to already has max uint256
    }

    // VULNERABLE: minting can overflow totalSupply
    function mint(address _to, uint256 _amount) public {
        balances[_to] += _amount;
        totalSupply += _amount;
    }
}
