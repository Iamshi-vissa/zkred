// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Registry} from "./Registry.sol";
import {ZKredToken} from "./ZKredToken.sol";
import {DateLib} from "./DateLib.sol";
import {ICredentialVerifier} from "./interfaces/ICredentialVerifier.sol";

/// @title CredentialGate
/// @notice Pays REWARD ZKRED to any student who proves, in zero knowledge,
///         that they hold a credential of `credentialType` in a known Registry
///         root and are at least 18 - once per student (nullifier), with the
///         proof bound to msg.sender.
///
/// The circuit proves membership/age/nullifier for WHATEVER public inputs it is
/// given; this contract decides what those inputs must be:
///   root           must be known to the Registry (published, recent, not revoked)
///   nullifierHash  must be unused here
///   scope          fixed by THIS contract: keccak256(chainid, address(this), actionId) mod r
///   credentialType fixed by THIS contract
///   currentDate    must be today or yesterday (UTC) per block.timestamp
///   recipient      msg.sender
contract CredentialGate {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant REWARD = 100 ether; // 100 ZKRED (18 decimals)

    Registry public immutable registry;
    ICredentialVerifier public immutable verifier;
    ZKredToken public immutable token;
    uint256 public immutable scope;
    uint256 public immutable credentialType;

    mapping(uint256 nullifierHash => bool) public nullifierUsed;

    event Claimed(address indexed recipient, uint256 nullifierHash);

    error UnknownRoot();
    error NullifierAlreadyUsed();
    error InvalidDate(uint256 given);
    error InvalidProof();

    constructor(Registry registry_, ICredentialVerifier verifier_, uint256 actionId, uint256 credentialType_) {
        registry = registry_;
        verifier = verifier_;
        credentialType = credentialType_;
        // Domain-separates nullifiers per chain, per deployment, per action:
        // a proof made for another gate or chain has a different scope and fails.
        scope = uint256(keccak256(abi.encode(block.chainid, address(this), actionId))) % SNARK_SCALAR_FIELD;
        // The gate deploys its own token and is therefore its only minter.
        token = new ZKredToken();
    }

    function claim(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256 root,
        uint256 nullifierHash,
        uint256 currentDate
    ) external {
        if (!registry.isKnownRoot(root)) revert UnknownRoot();
        if (nullifierUsed[nullifierHash]) revert NullifierAlreadyUsed();
        if (!isAcceptableDate(currentDate)) revert InvalidDate(currentDate);

        uint256[6] memory pub = [root, nullifierHash, scope, credentialType, currentDate, uint256(uint160(msg.sender))];
        // The generated verifier also rejects any public input >= r, so a
        // nullifier cannot be replayed as nullifierHash + r.
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();

        nullifierUsed[nullifierHash] = true;
        emit Claimed(msg.sender, nullifierHash);
        token.mint(msg.sender, REWARD);
    }

    /// @notice Today or yesterday (UTC). Yesterday tolerates a proof made just
    ///         before midnight and mined just after. Tomorrow is NOT accepted:
    ///         that would let someone claim the day before turning 18.
    function isAcceptableDate(uint256 currentDate) public view returns (bool) {
        return currentDate == DateLib.toYYYYMMDD(block.timestamp)
            || currentDate == DateLib.toYYYYMMDD(block.timestamp - 1 days);
    }
}
