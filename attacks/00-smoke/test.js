import { expect } from "chai";
import { network } from "hardhat";

describe("attacks/00-smoke: attack-lab plumbing", () => {
  it("contracts under attacks/*/vulnerable compile, deploy and can be 'exploited'", async () => {
    const { ethers } = await network.create();
    const [deployer, attacker] = await ethers.getSigners();
    const c = await ethers.deployContract("SmokeVulnerable");
    expect(await c.owner()).to.equal(deployer.address);
    await c.connect(attacker).setOwner(attacker.address);
    expect(await c.owner()).to.equal(attacker.address);
  });
});
