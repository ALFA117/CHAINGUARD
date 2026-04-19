// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * VULNERABLE: Unchecked return value from low-level call
 * SWC-104 — .call() returns (bool, bytes) but the bool is ignored here.
 * If the external call fails, execution continues silently.
 */
contract UncheckedCallVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: return value of .call() is not checked
    function sendEther(address payable _to, uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        _to.call{value: _amount}(""); // bool return is discarded
    }

    // VULNERABLE: same issue with a raw call carrying data
    function execute(address _target, bytes memory _data) public {
        require(msg.sender == owner, "Not owner");
        _target.call(_data); // return value ignored
    }

    receive() external payable {}
}
