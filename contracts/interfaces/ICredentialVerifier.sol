// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Interface of the snarkjs-generated Groth16 verifier
/// (contracts/verifiers/CredentialVerifier.sol, produced by `npm run setup`).
/// pubSignals order: root, nullifierHash, scope, credentialType, currentDate, recipient.
interface ICredentialVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata pubSignals
    ) external view returns (bool);
}
