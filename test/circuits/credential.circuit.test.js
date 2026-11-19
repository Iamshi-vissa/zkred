import { expect } from "chai";
import { compileCircuit, expectWitnessRejected, expectTamperRejected } from "./helpers.js";
import { writeMain, PUBLIC_SIGNALS } from "../../scripts/circuits/compile.js";
import { MERKLE_DEPTH } from "../../zkred.config.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";
import { createIdentity, nullifierHash } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

const TODAY = 20261119;
const SCOPE = 123456789n;
const RECIPIENT = 0x70997970c51812dc3a010c7d01b50e0d17dc79c8n; // Hardhat account #1 (public)
const { ENROLLED_STUDENT, GRADUATE } = CREDENTIAL_TYPES;

// R1CS size snapshot (circom 2.2.2, --O2). A change here means a constraint
// was added or removed: review docs/circuit-constraints.md before updating.
const CONSTRAINT_SNAPSHOT = { 10: 3338 };

describe(`circuit: credential.circom Credential(${MERKLE_DEPTH})`, function () {
  this.timeout(300_000);
  let circuit;
  let tree;
  let students;

  before(async () => {
    circuit = await compileCircuit(writeMain(MERKLE_DEPTH));
    students = {
      alice: { identity: await createIdentity(), birthDate: 20000115, credentialType: ENROLLED_STUDENT },
      bob: { identity: await createIdentity(), birthDate: 20090601, credentialType: ENROLLED_STUDENT }, // 17
      carol: { identity: await createIdentity(), birthDate: 20081119, credentialType: GRADUATE }, // 18 today
    };
    tree = await MerkleTree.create();
    for (const s of Object.values(students)) {
      s.leafIndex = tree.insert(await credentialLeaf({ idCommitment: s.identity.commitment, ...s }));
    }
  });

  const inputFor = (s, overrides = {}) =>
    buildCircuitInput({ ...s, tree, scope: SCOPE, currentDate: TODAY, recipient: RECIPIENT, ...overrides });

  const honestWitness = async (s = students.alice) => {
    const w = await circuit.calculateWitness(await inputFor(s), true);
    await circuit.checkConstraints(w);
    return w;
  };

  describe("positive", () => {
    it("an adult student with a valid credential satisfies every constraint", async () => {
      await honestWitness(students.alice);
    });

    it("a student turning 18 today is accepted", async () => {
      await honestWitness(students.carol);
    });

    it("public signals are exactly [root, nullifierHash, scope, credentialType, currentDate, recipient] in that order", async () => {
      const input = await inputFor(students.alice);
      const w = await honestWitness(students.alice);
      // witness[0] is the constant 1; then outputs (none), then public inputs.
      expect(w.slice(1, 1 + PUBLIC_SIGNALS.length)).to.deep.equal(PUBLIC_SIGNALS.map((k) => input[k]));
    });

    it(`R1CS size matches the snapshot`, async function () {
      if (!(MERKLE_DEPTH in CONSTRAINT_SNAPSHOT)) this.skip();
      await circuit.loadConstraints();
      expect(circuit.constraints.length).to.equal(CONSTRAINT_SNAPSHOT[MERKLE_DEPTH]);
    });
  });

  describe("negative (one or more per constraint)", () => {
    it("[C1] wrong nullifierSecret: identity commitment, hence root, mismatch", async () => {
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, nullifierSecret: input.nullifierSecret + 1n });
    });

    it("[C1] wrong trapdoor: root mismatch", async () => {
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, trapdoor: input.trapdoor + 1n });
    });

    it("[C2] lying about birthDate (17-year-old claims an older date): root mismatch", async () => {
      const input = await inputFor(students.bob);
      await expectWitnessRejected(circuit, { ...input, birthDate: 20000101n });
    });

    it("[C2] lying about credentialType: root mismatch", async () => {
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, credentialType: GRADUATE });
    });

    it("[C3] non-binary path index is rejected", async () => {
      const input = await inputFor(students.alice);
      const pathIndices = [...input.pathIndices];
      pathIndices[0] = 2n;
      await expectWitnessRejected(circuit, { ...input, pathIndices });
    });

    it("[C4] flipped path bit: root mismatch", async () => {
      const input = await inputFor(students.carol);
      const pathIndices = [...input.pathIndices];
      pathIndices[0] = 1n - pathIndices[0];
      await expectWitnessRejected(circuit, { ...input, pathIndices });
    });

    it("[C5] wrong sibling: root mismatch", async () => {
      const input = await inputFor(students.alice);
      const pathElements = [...input.pathElements];
      pathElements[3] += 1n;
      await expectWitnessRejected(circuit, { ...input, pathElements });
    });

    it("[C5] root the issuer never published is rejected", async () => {
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, root: input.root + 1n });
    });

    it("[C5] a leaf that is not in the tree is rejected", async () => {
      const outsider = await createIdentity();
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, nullifierSecret: outsider.nullifierSecret, trapdoor: outsider.trapdoor });
    });

    it("[C6] currentDate >= 2^32 is rejected", async () => {
      const input = await inputFor(students.bob);
      await expectWitnessRejected(circuit, { ...input, currentDate: 2n ** 32n + 20261119n });
    });

    it("[C6] currentDate in the field's 'negative' range is rejected", async () => {
      const input = await inputFor(students.bob);
      await expectWitnessRejected(circuit, { ...input, currentDate: SNARK_FIELD_SIZE - 1n });
    });

    it("[C7] a 17-year-old with a genuine credential is rejected", async () => {
      await expectWitnessRejected(circuit, await inputFor(students.bob));
    });

    it("[C7] one day before the 18th birthday is rejected", async () => {
      await expectWitnessRejected(circuit, await inputFor(students.carol, { currentDate: 20261118 }));
    });

    it("[C8] a nullifierHash that does not match (nullifierSecret, scope) is rejected", async () => {
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, nullifierHash: input.nullifierHash + 1n });
    });

    it("[C8] changing scope without recomputing the nullifier is rejected", async () => {
      const input = await inputFor(students.alice);
      await expectWitnessRejected(circuit, { ...input, scope: SCOPE + 1n });
    });

    it("[C8] the nullifier changes with scope (unlinkable across apps)", async () => {
      const a = await inputFor(students.alice);
      const b = await inputFor(students.alice, { scope: SCOPE + 1n });
      expect(a.nullifierHash).to.not.equal(b.nullifierHash);
      expect(b.nullifierHash).to.equal(await nullifierHash(students.alice.identity, SCOPE + 1n));
    });
  });

  describe("witness tampering (attacker edits the .wtns, bypassing the generator)", () => {
    // Lab 01 preview: in the secure circuit, patching any of these signals in
    // a valid witness breaks the R1CS, so no valid proof can be produced.
    const cases = [
      ["[C2,C7] birthDate", "birthDate", 20250101n],
      ["[C6,C7] currentDate", "currentDate", 20000101n],
      ["[C2] credentialType", "credentialType", 999n],
      ["[C3] pathIndices[0]", "pathIndices[0]", 2n],
      ["[C5] root", "root", 42n],
      ["[C8] nullifierHash", "nullifierHash", 42n],
      ["[C8] scope", "scope", 42n],
      ["[C9] recipient", "recipient", 0xdeadn],
      ["[C9] recipientSquare", "recipientSquare", 7n],
    ];
    for (const [label, signal, value] of cases) {
      it(`${label}: patched value violates the constraints`, async () => {
        const w = await honestWitness(students.alice);
        await expectTamperRejected(circuit, w, signal, value);
      });
    }
  });
});
