// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * VULNERABLE: Classic reentrancy (TheDAO-style)
 * SWC-107 — external call happens BEFORE balance is set to 0.
 */
contract ReentrancyVuln {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: sends ETH before zeroing the balance
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // External call first — attacker re-enters here
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER the call — too late!
        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
