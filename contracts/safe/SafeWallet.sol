// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * SAFE: Wallet using Checks-Effects-Interactions + reentrancy guard.
 * Fixes all issues present in ReentrancyVuln.sol.
 */
contract SafeWallet {
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: state updated BEFORE external call (Checks-Effects-Interactions)
    function withdraw() public nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // Effect: zero out balance before any interaction
        balances[msg.sender] = 0;

        // Interaction: external call happens last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
