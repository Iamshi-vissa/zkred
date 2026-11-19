pragma circom 2.1.6;

// Test fixture only: exposes circomlib's Poseidon so tests can check that the
// off-chain hash (circomlibjs) and the in-circuit hash agree bit for bit.
include "circomlib/circuits/poseidon.circom";

template PoseidonParity(n) {
    signal input inputs[n];
    signal output out;
    out <== Poseidon(n)(inputs);
}
