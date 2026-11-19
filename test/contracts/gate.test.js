// CredentialGate with real Groth16 proofs.
import { expect } from "chai";
import { Wallet } from "ethers";
import { deployZkred, TODAY, YESTERDAY, NOON_TODAY } from "../helpers/fixtures.js";
import { computeScope, publishRoot } from "../../scripts/lib/issuer.js";
import { releaseCurves } from "../../scripts/circuits/setup.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";
import { createIdentity } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { prove, toSolidityArgs } from "../../scripts/lib/prover.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

const REWARD = 100n * 10n ** 18n;

describe("contracts: CredentialGate (real proofs)", function () {
  this.timeout(300_000);
  after(releaseCurves);

  describe("happy path", () => {
    let f, alice, proof, receipt;
    before(async () => {
      f = await deployZkred();
      alice = await f.enrol("alice");
      await f.enrol("someoneElse");
      await f.publish();
      proof = await f.proofFor(alice, { recipient: f.alice });
      receipt = await (await f.gate.connect(f.alice).claim(...f.claimArgs(proof))).wait();
    });

    it("pays 100 ZKRED to msg.sender and emits Claimed(recipient, nullifierHash)", async () => {
      expect(await f.token.balanceOf(f.alice.address)).to.equal(REWARD);
      const ev = receipt.logs.map((l) => f.gate.interface.parseLog(l)).find((e) => e?.name === "Claimed");
      expect(ev.args.recipient).to.equal(f.alice.address);
      expect(ev.args.nullifierHash).to.equal(proof.nullifierHash);
      expect(await f.gate.nullifierUsed(proof.nullifierHash)).to.equal(true);
      console.log(`      claim gas used: ${receipt.gasUsed}`);
    });

    it("the claim reveals nothing identifying: calldata has no leaf, commitment or birth date", async () => {
      const tx = await f.ethers.provider.getTransaction(receipt.hash);
      const hex = tx.data.toLowerCase();
      for (const secret of [alice.identity.commitment, alice.identity.nullifierSecret, alice.identity.trapdoor, f.tree.leaves[alice.leafIndex]]) {
        expect(hex.includes(secret.toString(16).padStart(64, "0"))).to.equal(false);
      }
    });

    it("scope matches keccak256(chainid, gate, actionId) mod r", async () => {
      const { chainId } = await f.ethers.provider.getNetwork();
      expect(await f.gate.scope()).to.equal(computeScope(chainId, await f.gate.getAddress(), 1n));
    });

    it("negative: the same student cannot claim twice (nullifier), even with a fresh proof", async () => {
      const again = await f.proofFor(alice, { recipient: f.alice });
      await expect(f.gate.connect(f.alice).claim(...f.claimArgs(again))).to.be.revertedWithCustomError(f.gate, "NullifierAlreadyUsed");
    });

    it("negative: nor to a different address of their own", async () => {
      const toBob = await f.proofFor(alice, { recipient: f.bob });
      await expect(f.gate.connect(f.bob).claim(...f.claimArgs(toBob))).to.be.revertedWithCustomError(f.gate, "NullifierAlreadyUsed");
    });

    it("negative: nullifierHash + r (same field element) is rejected, not treated as new", async () => {
      const aliased = f.claimArgs(proof);
      aliased[4] = proof.nullifierHash + SNARK_FIELD_SIZE;
      await expect(f.gate.connect(f.alice).claim(...aliased)).to.be.revertedWithCustomError(f.gate, "InvalidProof");
    });

    it("a second student can still claim", async () => {
      const p = await f.proofFor(f.students.someoneElse, { recipient: f.bob });
      await f.gate.connect(f.bob).claim(...f.claimArgs(p));
      expect(await f.token.balanceOf(f.bob.address)).to.equal(REWARD);
    });
  });

  describe("rejections", () => {
    let f, alice;
    beforeEach(async () => {
      f = await deployZkred();
      alice = await f.enrol("alice");
      await f.publish();
    });

    it("front-running: mallory resubmitting alice's proof from the mempool gets InvalidProof", async () => {
      const p = await f.proofFor(alice, { recipient: f.alice });
      await expect(f.gate.connect(f.mallory).claim(...f.claimArgs(p))).to.be.revertedWithCustomError(f.gate, "InvalidProof");
      await f.gate.connect(f.alice).claim(...f.claimArgs(p)); // alice's own tx still works
    });

    it("unknown root (tree the issuer never published)", async () => {
      await f.enrol("late"); // tree changed, root not published
      const p = await f.proofFor(f.students.late, { recipient: f.alice });
      await expect(f.gate.connect(f.alice).claim(...f.claimArgs(p))).to.be.revertedWithCustomError(f.gate, "UnknownRoot");
    });

    it("an older root within the history window still works after a new root is published", async () => {
      const p = await f.proofFor(alice, { recipient: f.alice }); // against root #1
      await f.enrol("newcomer");
      await f.publish(); // root #2
      await f.gate.connect(f.alice).claim(...f.claimArgs(p));
    });

    it("dates: yesterday accepted, tomorrow and two days ago rejected", async () => {
      expect(await f.gate.isAcceptableDate(TODAY)).to.equal(true);
      expect(await f.gate.isAcceptableDate(YESTERDAY)).to.equal(true);
      for (const d of [20270316, 20270313, 20260315]) expect(await f.gate.isAcceptableDate(d), d).to.equal(false);
      const p = await f.proofFor(alice, { recipient: f.alice, currentDate: 20270316 });
      await expect(f.gate.connect(f.alice).claim(...f.claimArgs(p))).to.be.revertedWithCustomError(f.gate, "InvalidDate");
    });

    it("dates: a proof made yesterday evening is accepted just after midnight", async () => {
      const p = await f.proofFor(alice, { recipient: f.alice, currentDate: TODAY });
      await f.networkHelpers.time.increaseTo(NOON_TODAY + 12 * 3600 + 60); // 00:01 next day
      await f.gate.connect(f.alice).claim(...f.claimArgs(p));
    });

    it("a student turning 18 TOMORROW cannot claim today by claiming tomorrow's date", async () => {
      const almost = await f.enrol("almost18", { birthDate: 20090316 });
      await f.publish();
      // With today's date the circuit refuses to prove at all...
      let threw = false;
      try {
        await f.proofFor(almost, { recipient: f.alice, currentDate: TODAY });
      } catch {
        threw = true;
      }
      expect(threw).to.equal(true);
      // ...and with tomorrow's date the proof exists but the contract refuses the date.
      const p = await f.proofFor(almost, { recipient: f.alice, currentDate: 20270316 });
      await expect(f.gate.connect(f.alice).claim(...f.claimArgs(p))).to.be.revertedWithCustomError(f.gate, "InvalidDate");
    });

    it("wrong credential type: a GRADUATE-only gate rejects an enrolled student's proof", async () => {
      const gradGate = await f.ethers.deployContract("CredentialGate", [f.registry, f.verifier, 1n, CREDENTIAL_TYPES.GRADUATE]);
      // Build a proof whose public credentialType is ENROLLED but submit to the graduate gate.
      const p = await f.proofFor(alice, { recipient: f.alice, gateContract: gradGate });
      await expect(gradGate.connect(f.alice).claim(...f.claimArgs(p))).to.be.revertedWithCustomError(gradGate, "InvalidProof");
    });

    it("cross-gate replay: a proof for gate A (scope A) is rejected by gate B", async () => {
      const gateB = await f.ethers.deployContract("CredentialGate", [f.registry, f.verifier, 1n, CREDENTIAL_TYPES.ENROLLED_STUDENT]);
      expect(await gateB.scope()).to.not.equal(await f.gate.scope());
      const p = await f.proofFor(alice, { recipient: f.alice }); // scope of gate A
      await expect(gateB.connect(f.alice).claim(...f.claimArgs(p))).to.be.revertedWithCustomError(gateB, "InvalidProof");
    });

    it("same student, different gates: both claims succeed with unlinkable nullifiers", async () => {
      const gateB = await f.ethers.deployContract("CredentialGate", [f.registry, f.verifier, 2n, CREDENTIAL_TYPES.ENROLLED_STUDENT]);
      const pA = await f.proofFor(alice, { recipient: f.alice });
      const pB = await f.proofFor(alice, { recipient: f.alice, gateContract: gateB });
      await f.gate.connect(f.alice).claim(...f.claimArgs(pA));
      await gateB.connect(f.alice).claim(...f.claimArgs(pB));
      expect(pA.nullifierHash).to.not.equal(pB.nullifierHash);
    });

    it("garbage proof is rejected", async () => {
      const p = await f.proofFor(alice, { recipient: f.alice });
      const args = f.claimArgs(p);
      args[0] = [1n, 2n]; // generator point instead of A
      await expect(f.gate.connect(f.alice).claim(...args)).to.be.revertedWithCustomError(f.gate, "InvalidProof");
    });
  });

  describe("incident response: forged root from a stolen issuer key (lab 04 preview)", () => {
    it("forged root lets a fake student claim; owner revokes it and rotates the key; forged proofs then fail", async () => {
      const f = await deployZkred();
      const honest = await f.enrol("honest");
      await f.publish();

      // Attacker holds the issuer key (lab 04 recovers it from nonce reuse).
      const stolenKey = f.issuer;
      const fakeTree = await MerkleTree.create({ leaves: f.tree.leaves }); // copy honest leaves to look legit
      const fake = { identity: await createIdentity(), birthDate: 19900101, credentialType: CREDENTIAL_TYPES.ENROLLED_STUDENT };
      fake.leafIndex = fakeTree.insert(await credentialLeaf({ idCommitment: fake.identity.commitment, ...fake }));
      await publishRoot(f.registry, stolenKey, fakeTree.root, { relayer: f.mallory });

      const forgedProof = async (recipient) => {
        const input = await buildCircuitInput({ ...fake, tree: fakeTree, scope: await f.gate.scope(), currentDate: TODAY, recipient: recipient.address });
        const { proof, publicSignals } = await prove(input);
        const { a, b, c } = toSolidityArgs(proof, publicSignals);
        return [a, b, c, publicSignals[0], publicSignals[1], publicSignals[4]];
      };

      // 1. The forgery works: on-chain it is indistinguishable from a real credential.
      await f.gate.connect(f.mallory).claim(...(await forgedProof(f.mallory)));
      expect(await f.token.balanceOf(f.mallory.address)).to.equal(REWARD);

      // 2. Response: revoke the forged root, rotate the issuer key.
      await f.registry.connect(f.owner).revokeRoot(fakeTree.root);
      const newIssuer = Wallet.createRandom();
      await f.registry.connect(f.owner).rotateIssuer(newIssuer.address);

      // 3. The forged root is dead: a second fake identity in it cannot claim.
      await expect(f.gate.connect(f.bob).claim(...(await forgedProof(f.bob)))).to.be.revertedWithCustomError(f.gate, "UnknownRoot");
      // 4. The stolen key can no longer publish anything.
      await expect(publishRoot(f.registry, stolenKey, 424242n, { relayer: f.mallory })).to.be.revertedWithCustomError(f.registry, "BadIssuerSignature");
      // 5. Honest students are unaffected (their root was never revoked).
      const p = await f.proofFor(honest, { recipient: f.alice });
      await f.gate.connect(f.alice).claim(...f.claimArgs(p));
      expect(await f.token.balanceOf(f.alice.address)).to.equal(REWARD);
      // Note: tokens already minted from the forgery are NOT clawed back (see docs/threat-model.md).
    });
  });
});
