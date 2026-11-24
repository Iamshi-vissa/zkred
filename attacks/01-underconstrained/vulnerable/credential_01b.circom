pragma circom 2.1.6;

// =====================================================================
// DELIBERATELY INSECURE - attack lab 01b (under-constrained circuit).
// Never use outside attacks/. Reference fix: ../fixed/credential_01b_fixed.circom
//
// Design: the circuit exposes a public output `isAdult`, and the gate
// contract checks isAdult == 1.
// BUG: `isAdult <-- geq.out` uses the ASSIGNMENT-ONLY operator. `<--` tells
// the witness generator what to compute but adds NO constraint, so isAdult
// is a free wire: an attacker computes an honest witness (isAdult = 0),
// overwrites that one wire with 1 in the .wtns file, and proves. The R1CS
// is still satisfied, so the proof verifies.
// The fix is one character: `<==` (assign AND constrain).
// =====================================================================

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "../../../circuits/lib/merkle.circom";

template CredentialVuln01b(depth) {
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
    isAdult <-- geq.out;     // VULNERABLE: should be `isAdult <== geq.out;`

    signal computedNullifier <== Poseidon(3)([DOMAIN_NULLIFIER, nullifierSecret, scope]);
    computedNullifier === nullifierHash;

    signal recipientSquare <== recipient * recipient;
}
