// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Registry} from "../../contracts/Registry.sol";
import {ZKredToken} from "../../contracts/ZKredToken.sol";
import {DateLib} from "../../contracts/DateLib.sol";

/// @notice Verifier interface for the lab 01b circuits: one public output
/// (isAdult) followed by the six public inputs.
interface IAdultFlagVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[7] calldata pubSignals
    ) external view returns (bool);
}

/// @title AdultFlagGate (lab 01b support contract)
/// @notice Same checks as contracts/CredentialGate.sol, for circuits that
///         export the age result as a public `isAdult` output. The gate itself
///         is correct: it requires isAdult == 1. Whether that means anything
///         depends entirely on the circuit behind `verifier`:
///           Lab01bVerifier       (isAdult <-- geq.out)  -> exploitable
///           Lab01bFixedVerifier  (isAdult <== geq.out)  -> sound
contract AdultFlagGate {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant REWARD = 100 ether;

    Registry public immutable registry;
    IAdultFlagVerifier public immutable verifier;
    ZKredToken public immutable token;
    uint256 public immutable scope;
    uint256 public immutable credentialType;

    mapping(uint256 => bool) public nullifierUsed;

    event Claimed(address indexed recipient, uint256 nullifierHash);

    error UnknownRoot();
    error NullifierAlreadyUsed();
    error InvalidDate(uint256 given);
    error InvalidProof();

    constructor(Registry registry_, IAdultFlagVerifier verifier_, uint256 actionId, uint256 credentialType_) {
        registry = registry_;
        verifier = verifier_;
        credentialType = credentialType_;
        scope = uint256(keccak256(abi.encode(block.chainid, address(this), actionId))) % SNARK_SCALAR_FIELD;
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
        if (currentDate != DateLib.toYYYYMMDD(block.timestamp) && currentDate != DateLib.toYYYYMMDD(block.timestamp - 1 days)) {
            revert InvalidDate(currentDate);
        }
        // pubSignals[0] is the circuit's isAdult output: the gate demands 1.
        uint256[7] memory pub =
            [uint256(1), root, nullifierHash, scope, credentialType, currentDate, uint256(uint160(msg.sender))];
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();

        nullifierUsed[nullifierHash] = true;
        emit Claimed(msg.sender, nullifierHash);
        token.mint(msg.sender, REWARD);
    }
}
