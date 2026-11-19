import { expect } from "chai";
import { deployZkred } from "../helpers/fixtures.js";

describe("contracts: ZKredToken", () => {
  let f;
  before(async () => (f = await deployZkred()));

  it("is ZKred / ZKRED with 18 decimals, zero initial supply", async () => {
    expect(await f.token.name()).to.equal("ZKred");
    expect(await f.token.symbol()).to.equal("ZKRED");
    expect(await f.token.decimals()).to.equal(18n);
    expect(await f.token.totalSupply()).to.equal(0n);
  });

  it("the gate is the only minter", async () => {
    const MINTER = await f.token.MINTER_ROLE();
    expect(await f.token.hasRole(MINTER, await f.gate.getAddress())).to.equal(true);
    for (const s of [f.deployer, f.owner, f.alice]) expect(await f.token.hasRole(MINTER, s.address)).to.equal(false);
  });

  it("negative: deployer, registry owner and random accounts cannot mint", async () => {
    for (const s of [f.deployer, f.owner, f.mallory]) {
      await expect(f.token.connect(s).mint(s.address, 1n)).to.be.revertedWithCustomError(f.token, "AccessControlUnauthorizedAccount");
    }
  });

  it("negative: nobody holds the admin role, so MINTER_ROLE can never be granted", async () => {
    const ADMIN = await f.token.DEFAULT_ADMIN_ROLE();
    const MINTER = await f.token.MINTER_ROLE();
    for (const s of [f.deployer, f.owner]) {
      expect(await f.token.hasRole(ADMIN, s.address)).to.equal(false);
      await expect(f.token.connect(s).grantRole(MINTER, s.address)).to.be.revertedWithCustomError(f.token, "AccessControlUnauthorizedAccount");
    }
  });
});
