// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice DELIBERATELY INSECURE (attack-lab placeholder): anyone can overwrite `owner`.
/// @dev Step-1 smoke test for compiling contracts under attacks/. Removed with lab 01.
contract SmokeVulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: missing access control.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
