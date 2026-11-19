import { expect } from "chai";
import path from "node:path";
import { compileCircuit, expectWitnessRejected, ROOT } from "./helpers.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";

const DEPTH = 4;

describe("circuit: lib/merkle.circom MerkleInclusion", function () {
  this.timeout(180_000);
  let circuit;
  let tree;

  before(async () => {
    circuit = await compileCircuit(path.join(ROOT, "circuits/lib/merkle.circom"), {
      templateName: "MerkleInclusion",
      templateParams: [DEPTH],
    });
    tree = await MerkleTree.create({ depth: DEPTH, leaves: Array.from({ length: 11 }, (_, i) => BigInt(500 + i)) });
  });

  const input = (p) => ({ leaf: p.leaf, pathElements: p.pathElements, pathIndices: p.pathIndices });

  it("[C4,C5a] computes the same root as scripts/lib/merkle.js for every leaf", async () => {
    for (let i = 0; i < tree.size; i++) {
      const w = await circuit.calculateWitness(input(tree.proof(i)), true);
      await circuit.checkConstraints(w);
      await circuit.assertOut(w, { root: tree.root });
    }
  });

  it("[C3] negative: a non-binary path index is rejected", async () => {
    for (const bad of [2n, 3n, -1n]) {
      const p = tree.proof(3);
      const pathIndices = [...p.pathIndices];
      pathIndices[1] = bad;
      await expectWitnessRejected(circuit, { ...input(p), pathIndices }, `index=${bad}`);
    }
  });

  it("[C4] negative: flipping a path bit changes the root", async () => {
    const p = tree.proof(6);
    const pathIndices = [...p.pathIndices];
    pathIndices[0] ^= 1;
    const w = await circuit.calculateWitness({ ...input(p), pathIndices }, true);
    const out = await circuit.getOutput(w, { root: 1 });
    expect(BigInt(out.root)).to.not.equal(tree.root);
  });

  it("[C5a] negative: a wrong sibling changes the root", async () => {
    const p = tree.proof(6);
    const pathElements = [...p.pathElements];
    pathElements[2] += 1n;
    const w = await circuit.calculateWitness({ ...input(p), pathElements }, true);
    const out = await circuit.getOutput(w, { root: 1 });
    expect(BigInt(out.root)).to.not.equal(tree.root);
  });
});
