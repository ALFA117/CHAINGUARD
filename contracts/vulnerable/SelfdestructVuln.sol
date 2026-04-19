// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * VULNERABLE: Unprotected selfdestruct
 * SWC-106 — anyone can call kill() and destroy the contract,
 * sending all remaining Ether to an arbitrary address.
 */
contract SelfdestructVuln {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    // VULNERABLE: no access control — any address can call this
    function kill() public {
        selfdestruct(payable(owner));
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
