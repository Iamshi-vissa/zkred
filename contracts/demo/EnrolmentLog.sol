// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Registry} from "../Registry.sol";

/// @title EnrolmentLog (live demo only, D28)
/// @notice Public, append-only list of credential leaves, so anyone (the
///         browser) can rebuild the issuer's Merkle tree from chain data.
///
/// `enrol` logs one leaf AND publishes the issuer-signed root for the tree
/// that now includes it, in the same transaction. Either both happen or
/// neither does, so the logged leaves and the Registry's latest root can't
/// drift apart.
///
/// Trust: this contract can't check that `newRoot` really is the tree of the
/// logged leaves (that would need Poseidon on-chain). The issuer's signature
/// is what vouches for the root, exactly as in the Registry. A wrong root just
/// makes proofs fail; it can't let anyone in who isn't in the signed tree.
///
/// Only the relayer may enrol, so a stranger can't fill the tree with junk
/// leaves. The owner (Ownable2Step) can replace a leaked relayer key.
contract EnrolmentLog is Ownable2Step {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    Registry public immutable registry;
    /// @notice Maximum number of leaves: 2^MERKLE_DEPTH.
    uint256 public immutable capacity;
    /// @notice Block this contract was deployed in (where log scans start).
    uint256 public immutable deployBlock;

    address public relayer;
    /// @notice Number of leaves logged; the next leaf gets this index.
    uint256 public count;
    mapping(uint256 leaf => bool) public isEnrolled;

    event Enrolled(uint256 indexed index, uint256 leaf, uint256 root);
    event RelayerChanged(address indexed previous, address indexed current);

    error NotRelayer();
    error ZeroAddress();
    error InvalidLeaf();
    error AlreadyEnrolled();
    error TreeFull();

    constructor(address initialOwner, Registry registry_, address initialRelayer, uint256 capacity_) Ownable(initialOwner) {
        if (address(registry_) == address(0) || initialRelayer == address(0)) revert ZeroAddress();
        registry = registry_;
        capacity = capacity_;
        deployBlock = block.number;
        relayer = initialRelayer;
        emit RelayerChanged(address(0), initialRelayer);
    }

    /// @notice Logs `leaf` at index `count` and publishes `newRoot` (epoch
    ///         `newEpoch`, signed by the issuer) to the Registry, atomically.
    function enrol(uint256 leaf, uint256 newRoot, uint64 newEpoch, bytes calldata signature) external returns (uint256 index) {
        if (msg.sender != relayer) revert NotRelayer();
        // Leaves are field elements; 0 is the empty-leaf value of the tree.
        if (leaf == 0 || leaf >= SNARK_SCALAR_FIELD) revert InvalidLeaf();
        // One leaf per credential: a duplicate would just waste a slot.
        if (isEnrolled[leaf]) revert AlreadyEnrolled();
        index = count;
        if (index >= capacity) revert TreeFull();

        isEnrolled[leaf] = true;
        count = index + 1;
        emit Enrolled(index, leaf, newRoot);
        // Reverts (and so undoes the log entry) on a bad signature, epoch or root.
        registry.updateRoot(newRoot, newEpoch, signature);
    }

    /// @notice Incident response: replace a leaked or retired relayer key.
    function setRelayer(address newRelayer) external onlyOwner {
        if (newRelayer == address(0)) revert ZeroAddress();
        emit RelayerChanged(relayer, newRelayer);
        relayer = newRelayer;
    }
}
