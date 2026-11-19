// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title ZKred credential Registry
/// @notice Holds the Merkle roots of credential commitments published by the
///         university's issuer key.
///
/// Roles
///  - issuer: an off-chain key that signs RootUpdate(root, epoch) (EIP-712).
///    Anyone may relay a signed update; only the signature authorises it.
///  - owner (Ownable2Step, e.g. university administration): can rotate the
///    issuer key and revoke individual roots, the incident response to an
///    issuer-key compromise (lab 04). The owner can NOT publish roots.
///
/// Root validity: a root is known if it was published within the last
/// ROOT_HISTORY_SIZE epochs and has not been revoked. Keeping a short history
/// lets proofs generated just before a root rotation still verify.
contract Registry is EIP712, Ownable2Step {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint64 public constant ROOT_HISTORY_SIZE = 30;
    bytes32 public constant ROOT_UPDATE_TYPEHASH = keccak256("RootUpdate(uint256 root,uint64 epoch)");

    address public issuer;
    /// @notice Epoch of the most recently published root (0 = none yet).
    uint64 public epoch;
    /// @notice Most recently published root.
    uint256 public latestRoot;
    /// @notice Epoch at which a root was (last) published; 0 = never.
    mapping(uint256 root => uint64) public rootEpoch;
    mapping(uint256 root => bool) public revokedRoot;

    event RootUpdated(uint256 indexed root, uint64 indexed epoch, bytes signature);
    event IssuerRotated(address indexed previousIssuer, address indexed newIssuer);
    event RootRevoked(uint256 indexed root);

    error ZeroAddress();
    error InvalidRoot();
    error RootIsRevoked();
    error BadEpoch(uint64 expected, uint64 got);
    error BadIssuerSignature(address recovered);
    error AlreadyRevoked();

    constructor(address initialOwner, address initialIssuer) EIP712("ZKred Registry", "1") Ownable(initialOwner) {
        if (initialIssuer == address(0)) revert ZeroAddress();
        issuer = initialIssuer;
        emit IssuerRotated(address(0), initialIssuer);
    }

    /// @notice Publishes `root` as epoch `newEpoch`, authorised by the issuer's signature.
    /// @dev The signature is emitted and sits in public calldata; with a sound
    ///      ECDSA nonce that is harmless (lab 04 shows the unsound case).
    function updateRoot(uint256 root, uint64 newEpoch, bytes calldata signature) external {
        if (root == 0 || root >= SNARK_SCALAR_FIELD) revert InvalidRoot();
        if (revokedRoot[root]) revert RootIsRevoked();
        // Strictly sequential epochs: an old signature can never be replayed,
        // and a stolen key cannot pre-sign far-future updates that survive rotation.
        if (newEpoch != epoch + 1) revert BadEpoch(epoch + 1, newEpoch);

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(ROOT_UPDATE_TYPEHASH, root, newEpoch)));
        // OZ ECDSA.recover rejects malformed and high-s (malleable) signatures.
        address signer = ECDSA.recover(digest, signature);
        if (signer != issuer) revert BadIssuerSignature(signer);

        epoch = newEpoch;
        latestRoot = root;
        rootEpoch[root] = newEpoch;
        emit RootUpdated(root, newEpoch, signature);
    }

    /// @notice True if `root` is published, recent enough and not revoked.
    function isKnownRoot(uint256 root) public view returns (bool) {
        uint64 published = rootEpoch[root];
        if (root == 0 || published == 0 || revokedRoot[root]) return false;
        return epoch - published < ROOT_HISTORY_SIZE;
    }

    /// @notice Incident response: replace a compromised or retired issuer key.
    function rotateIssuer(address newIssuer) external onlyOwner {
        if (newIssuer == address(0)) revert ZeroAddress();
        emit IssuerRotated(issuer, newIssuer);
        issuer = newIssuer;
    }

    /// @notice Incident response: permanently invalidate a root (e.g. one
    ///         forged with a stolen issuer key). Proofs against it stop
    ///         verifying, and it can never be re-published.
    function revokeRoot(uint256 root) external onlyOwner {
        if (revokedRoot[root]) revert AlreadyRevoked();
        revokedRoot[root] = true;
        emit RootRevoked(root);
    }

    /// @notice EIP-712 domain separator (for off-chain signers and tests).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
