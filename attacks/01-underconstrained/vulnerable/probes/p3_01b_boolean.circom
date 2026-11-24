pragma circom 2.1.6;

// =====================================================================
// DELIBERATELY INSECURE - circomspect probe for attack lab 01.
// Never use outside attacks/. Analysed only (no setup, not deployed).
//
// 01b plus a booleanity check on isAdult. It LOOKS constrained, but
// `isAdult * (isAdult - 1) === 0` only says "isAdult is 0 or 1", not
// "isAdult equals the comparison". Patching it to 1 still satisfies the R1CS.
// =====================================================================

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "../../../../circuits/lib/merkle.circom";

template CredentialProbeP3(depth) {
    var DOMAIN_IDENTITY = 1;
    var DOMAIN_NULLIFIER = 2;
    var DOMAIN_LEAF = 3;

    signal output isAdult;   // public output, checked == 1 by VulnGate01b

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
    isAdult <-- geq.out;     // VULNERABLE: hint
    isAdult * (isAdult - 1) === 0;   // only "isAdult is a bit"

    signal computedNullifier <== Poseidon(3)([DOMAIN_NULLIFIER, nullifierSecret, scope]);
    computedNullifier === nullifierHash;

    signal recipientSquare <== recipient * recipient;
}
