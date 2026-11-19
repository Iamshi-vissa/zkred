// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Step-1 toolchain smoke test: proves contracts/ compiles and deploys.
/// @dev Removed in Step 4, when the real Registry/Gate contracts land.
contract Smoke {
    function ping() external pure returns (string memory) {
        return "zkred";
    }
}
