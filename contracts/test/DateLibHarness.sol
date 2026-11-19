// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {DateLib} from "../DateLib.sol";

/// @notice Test-only harness exposing DateLib for cross-checks against JavaScript.
contract DateLibHarness {
    function toYYYYMMDD(uint256 timestamp) external pure returns (uint256) {
        return DateLib.toYYYYMMDD(timestamp);
    }

    function toYYYYMMDDBatch(uint256[] calldata timestamps) external pure returns (uint256[] memory out) {
        out = new uint256[](timestamps.length);
        for (uint256 i = 0; i < timestamps.length; i++) out[i] = DateLib.toYYYYMMDD(timestamps[i]);
    }
}
