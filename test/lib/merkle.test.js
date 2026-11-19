import { expect } from "chai";
import { MerkleTree, verifyProof, ZERO_VALUE } from "../../scripts/lib/merkle.js";
import { poseidon, initPoseidon } from "../../scripts/lib/poseidon.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";
import { MERKLE_DEPTH } from "../../zkred.config.js";

const leavesOf = (n) => Array.from({ length: n }, (_, i) => BigInt(1000 + i));

describe("lib/merkle", () => {
  before(initPoseidon);

  it("defaults to MERKLE_DEPTH from zkred.config.js", async () => {
    const tree = await MerkleTree.create({ leaves: [7n] });
    expect(tree.depth).to.equal(MERKLE_DEPTH);
    expect(await verifyProof(tree.proof(0), tree.root)).to.equal(true); // depth defaults too
  });

  it("empty-tree root is the chain of zero hashes", async () => {
    const tree = await MerkleTree.create({ depth: 2 });
    const z1 = await poseidon([ZERO_VALUE, ZERO_VALUE]);
    expect(tree.root).to.equal(await poseidon([z1, z1]));
  });

  it("root matches a hand computation for a depth-2 tree", async () => {
    const [a, b, c] = [1n, 2n, 3n];
    const tree = await MerkleTree.create({ depth: 2, leaves: [a, b, c] });
    const left = await poseidon([a, b]);
    const right = await poseidon([c, ZERO_VALUE]);
    expect(tree.root).to.equal(await poseidon([left, right]));
  });

  it("incremental inserts give the same root as bulk construction", async () => {
    const leaves = leavesOf(9);
    const bulk = await MerkleTree.create({ depth: 4, leaves });
    const inc = await MerkleTree.create({ depth: 4 });
    for (const l of leaves) inc.insert(l);
    expect(inc.root).to.equal(bulk.root);
  });

  it("proof for EVERY leaf of a full depth-4 tree verifies", async () => {
    const tree = await MerkleTree.create({ depth: 4, leaves: leavesOf(16) });
    for (let i = 0; i < 16; i++) {
      const p = tree.proof(i);
      expect(p.pathElements).to.have.length(4);
      expect(await verifyProof(p, tree.root, tree.depth), `leaf ${i}`).to.equal(true);
    }
  });

  it("pathIndices are the little-endian bits of the leaf index", async () => {
    const tree = await MerkleTree.create({ depth: 4, leaves: leavesOf(16) });
    expect(tree.proof(11).pathIndices).to.deep.equal([1, 1, 0, 1]); // 11 = 0b1011
  });

  it("proofs verify in a sparse depth-16 tree (first, middle, last inserted)", async () => {
    const tree = await MerkleTree.create({ depth: 16, leaves: leavesOf(37) });
    for (const i of [0, 18, 36]) {
      expect(await verifyProof(tree.proof(i), tree.root, tree.depth)).to.equal(true);
    }
  });

  it("depth-20 tree stays sparse (no 2^20 materialisation)", async () => {
    const tree = await MerkleTree.create({ depth: 20, leaves: leavesOf(3) });
    expect(tree.layers[0]).to.have.length(3);
    expect(await verifyProof(tree.proof(2), tree.root, tree.depth)).to.equal(true);
  });

  describe("negative cases", () => {
    let tree;
    let good;
    beforeEach(async () => {
      tree = await MerkleTree.create({ depth: 4, leaves: leavesOf(10) });
      good = tree.proof(5);
    });

    it("rejects a wrong leaf", async () => {
      expect(await verifyProof({ ...good, leaf: good.leaf + 1n }, tree.root, tree.depth)).to.equal(false);
    });

    it("rejects a wrong sibling at any level", async () => {
      for (let level = 0; level < 4; level++) {
        const pathElements = [...good.pathElements];
        pathElements[level] += 1n;
        expect(await verifyProof({ ...good, pathElements }, tree.root, tree.depth), `level ${level}`).to.equal(false);
      }
    });

    it("rejects a flipped path bit at any level", async () => {
      for (let level = 0; level < 4; level++) {
        const pathIndices = [...good.pathIndices];
        pathIndices[level] ^= 1;
        expect(await verifyProof({ ...good, pathIndices }, tree.root, tree.depth), `level ${level}`).to.equal(false);
      }
    });

    it("rejects a non-binary path index (e.g. 2)", async () => {
      const pathIndices = [...good.pathIndices];
      pathIndices[0] = 2;
      expect(await verifyProof({ ...good, pathIndices }, tree.root, tree.depth)).to.equal(false);
    });

    it("rejects a wrong root", async () => {
      expect(await verifyProof(good, tree.root + 1n, tree.depth)).to.equal(false);
    });

    it("rejects a proof against a stale root after a new insert", async () => {
      const oldRoot = tree.root;
      tree.insert(424242n);
      expect(await verifyProof(tree.proof(5), oldRoot, tree.depth)).to.equal(false);
      expect(await verifyProof(tree.proof(5), tree.root, tree.depth)).to.equal(true);
    });

    it("rejects truncated / mismatched path arrays", async () => {
      expect(await verifyProof({ ...good, pathElements: good.pathElements.slice(1) }, tree.root, tree.depth)).to.equal(false);
      expect(await verifyProof({ ...good, pathElements: [], pathIndices: [] }, tree.root, tree.depth)).to.equal(false);
    });

    it("rejects an internal node presented as a leaf (shorter path)", async () => {
      // The level-1 node above leaf 5 plus the remaining path DOES hash to the
      // root; only the fixed depth stops it. The circuit has a fixed depth too.
      const node = await poseidon([tree.layers[0][4], tree.layers[0][5]]);
      const forged = { leaf: node, pathElements: good.pathElements.slice(1), pathIndices: good.pathIndices.slice(1) };
      expect(await verifyProof(forged, tree.root, tree.depth - 1)).to.equal(true); // sanity: it really is a valid shorter path
      expect(await verifyProof(forged, tree.root, tree.depth)).to.equal(false);
    });

    it("rejects out-of-field elements", async () => {
      const pathElements = [...good.pathElements];
      pathElements[0] = SNARK_FIELD_SIZE;
      expect(await verifyProof({ ...good, pathElements }, tree.root, tree.depth)).to.equal(false);
      expect(() => tree.insert(SNARK_FIELD_SIZE)).to.throw(RangeError);
    });

    it("proof() throws for out-of-range or non-integer indices", () => {
      for (const bad of [-1, 10, 1.5, "1"]) expect(() => tree.proof(bad)).to.throw(RangeError);
    });

    it("insert() throws once the tree is full", async () => {
      const small = await MerkleTree.create({ depth: 1, leaves: [1n, 2n] });
      expect(() => small.insert(3n)).to.throw(RangeError, /full/);
    });

    it("create() rejects invalid depths", async () => {
      for (const depth of [0, 33, 2.5]) {
        try {
          await MerkleTree.create({ depth });
          expect.fail(`depth ${depth} accepted`);
        } catch (e) {
          expect(e).to.be.instanceOf(RangeError);
        }
      }
    });
  });
});
