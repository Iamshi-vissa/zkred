// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BokkyPooBahsDateTimeLibrary as DT} from "./vendor/BokkyPooBahsDateTimeLibrary.sol";

/// @notice block.timestamp -> YYYYMMDD (UTC), the date encoding used by the circuit.
library DateLib {
    function toYYYYMMDD(uint256 timestamp) internal pure returns (uint256) {
        (uint256 y, uint256 m, uint256 d) = DT.timestampToDate(timestamp);
        return y * 10000 + m * 100 + d;
    }
}
