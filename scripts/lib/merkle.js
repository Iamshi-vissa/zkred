// Fixed-depth binary Merkle tree with Poseidon(2) internal nodes.
//
// - Empty slots hold ZERO_VALUE; zeros[i] is the root of an empty subtree of
//   height i, so a depth-20 tree never materialises 2^20 leaves.
// - Leaves (Poseidon of 4 inputs in ZKred, see Step 2) and internal nodes
//   (Poseidon of 2 inputs) use different Poseidon parameter sets, so an
//   internal node cannot be passed off as a leaf (second-preimage trick).
// - pathIndices[i] = bit i of the leaf index: 0 means the running hash is the
//   LEFT child at level i, 1 means it is the RIGHT child. The circuit must
//   constrain each index to {0,1} (Step 2) - this library mirrors that check.

import { initPoseidon, poseidonSync } from "./poseidon.js";
import { toFieldElement } from "./field.js";
import { MERKLE_DEPTH } from "../../zkred.config.js";

export const ZERO_VALUE = 0n;
const MAX_DEPTH = 32;

function hashPair(left, right) {
  return poseidonSync([left, right]);
}

export class MerkleTree {
  /** Use `await MerkleTree.create(...)` (Poseidon must be initialised). */
  constructor(depth, zeros) {
    this.depth = depth;
    this.zeros = zeros; // zeros[0] = ZERO_VALUE ... zeros[depth] = empty root
    this.layers = Array.from({ length: depth + 1 }, () => []);
  }

  static async create({ depth = MERKLE_DEPTH, leaves = [] } = {}) {
    if (!Number.isInteger(depth) || depth < 1 || depth > MAX_DEPTH) {
      throw new RangeError(`depth must be an integer in [1, ${MAX_DEPTH}]`);
    }
    await initPoseidon();
    const zeros = [ZERO_VALUE];
    for (let i = 0; i < depth; i++) zeros.push(hashPair(zeros[i], zeros[i]));
    const tree = new MerkleTree(depth, zeros);
    for (const leaf of leaves) tree.insert(leaf);
    return tree;
  }

  get capacity() {
    return 2 ** this.depth;
  }

  get size() {
    return this.layers[0].length;
  }

  get root() {
    return this.layers[this.depth][0] ?? this.zeros[this.depth];
  }

  get leaves() {
    return [...this.layers[0]];
  }

  /** Appends a leaf, updates the path to the root, returns its index. */
  insert(leaf) {
    const value = toFieldElement(leaf, "leaf");
    if (this.size >= this.capacity) throw new RangeError("Merkle tree is full");
    const index = this.size;
    this.layers[0].push(value);
    let i = index;
    for (let level = 0; level < this.depth; level++) {
      const parent = i >> 1;
      const left = this.layers[level][parent * 2] ?? this.zeros[level];
      const right = this.layers[level][parent * 2 + 1] ?? this.zeros[level];
      this.layers[level + 1][parent] = hashPair(left, right);
      i = parent;
    }
    return index;
  }

  indexOf(leaf) {
    return this.layers[0].indexOf(toFieldElement(leaf, "leaf"));
  }

  /** Inclusion proof in the exact shape the circuit takes as private input. */
  proof(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.size) {
      throw new RangeError(`leaf index ${index} out of range [0, ${this.size})`);
    }
    const pathElements = [];
    const pathIndices = [];
    let i = index;
    for (let level = 0; level < this.depth; level++) {
      const sibling = i ^ 1;
      pathElements.push(this.layers[level][sibling] ?? this.zeros[level]);
      pathIndices.push(i & 1);
      i >>= 1;
    }
    return { leaf: this.layers[0][index], pathElements, pathIndices, root: this.root };
  }
}

/**
 * Recomputes the root from a proof; returns false on any malformed input.
 * `depth` is required and must match exactly, as in the circuit: otherwise an
 * internal node plus a shorter path would also hash to the root.
 */
export async function verifyProof({ leaf, pathElements, pathIndices }, root, depth = MERKLE_DEPTH) {
  await initPoseidon();
  try {
    if (!Array.isArray(pathElements) || !Array.isArray(pathIndices)) return false;
    if (pathElements.length !== depth || pathIndices.length !== depth) return false;
    let node = toFieldElement(leaf, "leaf");
    for (let level = 0; level < pathElements.length; level++) {
      const bit = pathIndices[level];
      if (bit !== 0 && bit !== 1) return false; // mirrors the circuit's bit constraint
      const sibling = toFieldElement(pathElements[level], "pathElement");
      node = bit === 0 ? hashPair(node, sibling) : hashPair(sibling, node);
    }
    return node === toFieldElement(root, "root");
  } catch {
    return false;
  }
}
