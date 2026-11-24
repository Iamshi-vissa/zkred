pragma circom 2.1.6;

// =====================================================================
// DELIBERATELY INSECURE - circomspect probe for attack lab 01.
// Never use outside attacks/. Analysed only (no setup, not deployed).
//
// 01a, disguised: the comparator output is copied into an intermediate signal
// that nothing uses. The bug is unchanged (the result is never enforced), but
// the "unused component output" symptom circomspect detected in 01a is gone.
// =====================================================================

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "../../../../circuits/lib/merkle.circom";

template CredentialProbeP1(depth) {
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
    signal isAdult <== geq.out;   // VULNERABLE: computed, still never enforced

    signal computedNullifier <== Poseidon(3)([DOMAIN_NULLIFIER, nullifierSecret, scope]);
    computedNullifier === nullifierHash;

    signal recipientSquare <== recipient * recipient;
}
