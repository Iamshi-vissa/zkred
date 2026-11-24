import { expect } from "chai";
import { network } from "hardhat";
import { runDemo } from "../../scripts/lib/demo.js";
import { releaseCurves } from "../../scripts/circuits/setup.js";

describe("e2e: scripts/lib/demo.js", function () {
  this.timeout(300_000);
  let r;
  before(async () => {
    const { ethers } = await network.create();
    r = await runDemo(ethers, { log: () => {} });
  });
  after(releaseCurves);

  it("published root is known", () => expect(r.rootKnown).to.equal(true));
  it("front-run copy of alice's proof is rejected", () => {
    expect(r.frontRun.ok).to.equal(false);
    expect(r.frontRun.reason).to.equal("InvalidProof");
  });
  it("alice claims 100 ZKRED", () => {
    expect(r.aliceClaim.ok).to.equal(true);
    expect(r.aliceBalance).to.equal(100n * 10n ** 18n);
  });
  it("alice's second claim is rejected by the nullifier", () => {
    expect(r.aliceAgain).to.deep.equal({ ok: false, reason: "NullifierAlreadyUsed" });
  });
  it("17-year-old charlie cannot produce a proof", () => expect(r.charlieProved).to.equal(false));
  it("bob claims", () => expect(r.bobClaim.ok).to.equal(true));
  it("exactly two Claimed events with distinct nullifiers", () => {
    expect(r.claimEvents).to.have.length(2);
    expect(r.claimEvents[0].nullifierHash).to.not.equal(r.claimEvents[1].nullifierHash);
  });
});
