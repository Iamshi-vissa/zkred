// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title ZKRED reward token
/// @notice Only the CredentialGate that deploys this token can mint.
/// @dev The deployer (the gate) receives MINTER_ROLE and NO admin role is
///      granted to anyone, so MINTER_ROLE can never be granted or revoked
///      afterwards: the gate is the sole, permanent minter.
contract ZKredToken is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() ERC20("ZKred", "ZKRED") {
        _grantRole(MINTER_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }
}
