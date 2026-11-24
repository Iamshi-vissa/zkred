pragma circom 2.1.6;

// =====================================================================
// DELIBERATELY INSECURE - attack lab 01a (under-constrained circuit).
// Never use outside attacks/. The secure version is circuits/credential.circom.
//
// BUG: the age comparison is COMPUTED but its result is never ENFORCED.
// The developer wired up GreaterEqThan correctly and then forgot
// `geq.out === 1`. A 17-year-old's witness simply has geq.out = 0 and
// still satisfies every constraint, so the ordinary prover produces a
// valid proof for them - no tricks needed.
// =====================================================================

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "../../../circuits/lib/merkle.circom";

template CredentialVuln01a(depth) {
    var DOMAIN_IDENTITY = 1;
    var DOMAIN_NULLIFIER = 2;
    var DOMAIN_LEAF = 3;

    signal input root;
    signal input nullifierHash;
    signal input scope;
    signal input credentialType;
    signal input currentDate;
    signal input recipient;

    signal input nullifierSecret;
    signal input trapdoor;
    signal input birthDate;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal idCommitment <== Poseidon(3)([DOMAIN_IDENTITY, nullifierSecret, trapdoor]);
    signal leaf <== Poseidon(4)([DOMAIN_LEAF, idCommitment, birthDate, credentialType]);
    signal computedRoot <== MerkleInclusion(depth)(leaf, pathElements, pathIndices);
    computedRoot === root;

    component birthBits = Num2Bits(32);
    birthBits.in <== birthDate;
    component currentBits = Num2Bits(32);
    currentBits.in <== currentDate;
    component geq = GreaterEqThan(33);
    geq.in[0] <== currentDate;
    geq.in[1] <== birthDate + 18 * 10000;
    // VULNERABLE: missing `geq.out === 1;`

    signal computedNullifier <== Poseidon(3)([DOMAIN_NULLIFIER, nullifierSecret, scope]);
    computedNullifier === nullifierHash;

    signal recipientSquare <== recipient * recipient;
}
