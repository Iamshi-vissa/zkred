pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "./lib/merkle.circom";
include "./lib/age.circom";

// ZKred credential circuit (SECURE VERSION).
//
// Statement proved, without revealing which student:
//   "I know (nullifierSecret, trapdoor, birthDate, credentialType, path) such that
//      leaf = H4(DOMAIN_LEAF, H3(DOMAIN_IDENTITY, nullifierSecret, trapdoor), birthDate, credentialType)
//      is in the Merkle tree with root `root`,
//      the leaf's credentialType equals the public `credentialType`,
//      currentDate - birthDate >= 18 years (YYYYMMDD arithmetic),
//      nullifierHash = H3(DOMAIN_NULLIFIER, nullifierSecret, scope),
//    and this proof is for `recipient`."
//
// Domain tags must match scripts/lib/identity.js and scripts/lib/credential.js.
// Every constraint is listed with its rationale in docs/circuit-constraints.md.
template Credential(depth) {
    var DOMAIN_IDENTITY = 1;
    var DOMAIN_NULLIFIER = 2;
    var DOMAIN_LEAF = 3;
    var MIN_AGE_YEARS = 18;

    // ---- public inputs (order fixes the verifier's public-signal order) ----
    signal input root;            // Merkle root published in the Registry
    signal input nullifierHash;   // one-time tag per (student, scope)
    signal input scope;           // computed by the contract (chain, address, action)
    signal input credentialType;  // e.g. 1 = enrolled student; checked by the contract
    signal input currentDate;     // YYYYMMDD; checked by the contract vs block.timestamp
    signal input recipient;       // uint160(msg.sender); checked by the contract

    // ---- private inputs ----
    signal input nullifierSecret;
    signal input trapdoor;
    signal input birthDate;       // YYYYMMDD
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // [C1] Identity commitment: proves knowledge of the secrets behind the
    // credential. Without it, anyone who learns a leaf's contents could prove
    // ownership of it.
    signal idCommitment <== Poseidon(3)([DOMAIN_IDENTITY, nullifierSecret, trapdoor]);

    // [C2] Leaf: binds birthDate and credentialType to the identity exactly as
    // the issuer committed them. Without it, the prover could claim any
    // birthDate/credentialType. credentialType here is the PUBLIC input, so
    // the proof also shows the leaf has that type.
    signal leaf <== Poseidon(4)([DOMAIN_LEAF, idCommitment, birthDate, credentialType]);

    // [C3]-[C5] Merkle inclusion (see lib/merkle.circom), then
    // [C5b] the recomputed root must equal the public root.
    // Without it, the prover could use a tree the issuer never published.
    signal computedRoot <== MerkleInclusion(depth)(leaf, pathElements, pathIndices);
    computedRoot === root;

    // [C6]-[C7] Over 18 (see lib/age.circom).
    AgeAtLeast(MIN_AGE_YEARS)(birthDate, currentDate);

    // [C8] Nullifier: deterministic per (nullifierSecret, scope).
    // Without this equality the prover could submit a fresh random
    // nullifierHash each time and reuse one credential forever (lab 03).
    signal computedNullifier <== Poseidon(3)([DOMAIN_NULLIFIER, nullifierSecret, scope]);
    computedNullifier === nullifierHash;

    // [C9] Recipient binding. Public inputs are bound by the Groth16
    // verification equation even if unused, but an unused signal is easy to
    // lose to optimisation or refactoring. This quadratic constraint keeps
    // `recipient` explicitly in the R1CS, so a proof made for one address
    // fails verification for any other (lab 02, front-running).
    signal recipientSquare <== recipient * recipient;
}
