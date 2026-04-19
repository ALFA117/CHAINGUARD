// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * VULNERABLE: Authorization via tx.origin
 * SWC-115 — a phishing contract can trick the owner into calling it,
 * which then calls this contract with tx.origin == owner.
 */
contract TxOriginVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: uses tx.origin instead of msg.sender
    function transferFunds(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Not owner");
        _to.transfer(_amount);
    }

    receive() external payable {}
}
