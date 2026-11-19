import { expect } from "chai";
import { network } from "hardhat";

describe("smoke: Hardhat 3 + ethers", () => {
  it("compiles and deploys a contract from contracts/", async () => {
    const { ethers } = await network.create();
    const smoke = await ethers.deployContract("Smoke");
    expect(await smoke.ping()).to.equal("zkred");
  });

  it("negative: an unknown artifact name is rejected", async () => {
    const { ethers } = await network.create();
    let threw = false;
    try {
      await ethers.deployContract("DoesNotExist");
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
