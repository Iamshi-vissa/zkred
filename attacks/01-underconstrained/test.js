// Lab 01 test: each exploit SUCCEEDS against the vulnerable circuit and FAILS
// against the secure / fixed one. The wtns check output is printed as well.
import { expect } from "chai";
import { network } from "hardhat";
import { setupLab, attack01a, attack01b } from "./lab.js";
import { releaseCurves } from "../../scripts/circuits/setup.js";

const REWARD = 100n * 10n ** 18n;

describe("attacks/01-underconstrained: forged age proofs", function () {
  this.timeout(600_000);
  let lab;
  before(async () => {
    const { ethers } = await network.create();
    lab = await setupLab(ethers);
  });
  after(releaseCurves);

  describe("01a: age comparison computed but never enforced", () => {
    let r;
    before(async () => (r = await attack01a(lab, () => {})));

    it("EXPLOIT: a 17-year-old's ordinary proof verifies and claims 100 ZKRED from the (secure) gate contract", () => {
      expect(r.vulnProofVerifies).to.equal(true);
      expect(r.vulnClaim.ok).to.equal(true);
      expect(r.vulnBalance).to.equal(REWARD);
    });

    it("FIX: with the secure circuit the minor cannot even compute a witness", () => {
      expect(r.secureWitness.ok).to.equal(false);
      expect(r.secureWitness.reason).to.match(/Assert Failed/);
    });
  });

  describe("01b: isAdult assigned with <-- (witness patching)", () => {
    let r;
    before(async () => {
      const lines = [];
      r = await attack01b(lab, (l) => lines.push(l));
      // Show the wtns check transcript in the test output, as the exploit does.
      console.log(lines.filter((l) => /wtns check|WITNESS IS|aborting|constraint \d+ of/.test(l)).map((l) => "      " + l.trim()).join("\n"));
    });

    it("the honest witness says isAdult = 0; the patched one says 1", () => {
      expect(r.honestIsAdult).to.equal(0n);
      expect(r.patchedIsAdult).to.equal(1n);
    });

    it("vulnerable and fixed circuits have the same wire layout (fair comparison)", () => {
      expect(r.wires.vulnerable).to.equal(r.wires.fixed);
    });

    it("EXPLOIT: `snarkjs wtns check` ACCEPTS the patched witness against the vulnerable circuit", () => {
      expect(r.checkVulnerable.ok).to.equal(true);
      expect(r.checkVulnerable.lines.join("\n")).to.include("WITNESS IS CORRECT");
    });

    it("FIX: `snarkjs wtns check` REJECTS the patched witness against the fixed circuit, at the isAdult === geq.out constraint", () => {
      expect(r.checkFixed.ok).to.equal(false);
      expect(r.checkFixed.lines.join("\n")).to.include("WITNESS IS NOT CORRECT");
      expect(r.failedConstraintSignals).to.have.members(["main.isAdult", "main.geq.out"]);
    });

    it("EXPLOIT: the proof from the patched witness has public isAdult = 1 and claims 100 ZKRED", () => {
      expect(r.vulnPublicIsAdult).to.equal(1n);
      expect(r.vulnClaim.ok).to.equal(true);
      expect(r.vulnBalance).to.equal(REWARD);
    });

    it("FIX: the same patched witness proven with the fixed zkey does not verify; the fixed gate reverts InvalidProof", () => {
      expect(r.fixedVerifiesOffchain).to.equal(false);
      expect(r.fixedClaim).to.deep.equal({ ok: false, reason: "InvalidProof" });
    });
  });
});
