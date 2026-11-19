pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

// MerkleInclusion(depth): recomputes the root of a fixed-depth binary
// Poseidon Merkle tree from a leaf and its authentication path.
//
// Mirrors scripts/lib/merkle.js exactly:
//   pathIndices[i] = 0  -> running hash is the LEFT  child at level i
//   pathIndices[i] = 1  -> running hash is the RIGHT child at level i
//
// The depth is a template parameter, so it is fixed at compile time. That is
// what stops an internal node plus a shorter path being accepted as a leaf
// (see test "rejects an internal node presented as a leaf" in test/lib).
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    signal nodes[depth + 1];
    nodes[0] <== leaf;

    component mux[depth];
    component hashers[depth];

    for (var i = 0; i < depth; i++) {
        // [C3] Each path index must be a bit.
        // Without it the selector below is a free field element s, and
        //   left  = cur + s*(sib - cur),  right = sib + s*(cur - sib)
        // become arbitrary linear mixes of the two children, giving the prover
        // extra freedom that no honest tree position corresponds to.
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // [C4] Order the pair (left, right) according to the bit, using
        // circomlib's MultiMux1: out = (c[1] - c[0]) * s + c[0].
        //   s = 0: (left, right) = (cur, sibling)
        //   s = 1: (left, right) = (sibling, cur)
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== nodes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== nodes[i];
        mux[i].s <== pathIndices[i];

        // [C5a] Parent = Poseidon(left, right). Poseidon(2) for internal nodes;
        // leaves use Poseidon(4), a different parameter set (see credential.circom).
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        nodes[i + 1] <== hashers[i].out;
    }

    root <== nodes[depth];
}
