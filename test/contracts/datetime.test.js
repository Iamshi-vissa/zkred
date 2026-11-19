import { expect } from "chai";
import { network } from "hardhat";
import { timestampToYYYYMMDD } from "../../scripts/lib/dates.js";

describe("contracts: DateLib (vendored BokkyPooBah DateTime)", () => {
  let harness;
  before(async () => {
    const { ethers } = await network.create();
    harness = await ethers.deployContract("DateLibHarness");
  });

  it("matches JavaScript Date for every day boundary 1970-2100 (sampled), incl. leap days", async () => {
    const day = 86_400;
    const ts = [];
    // Every 7th day plus the first and last second of each sampled day.
    for (let d = 0; d < 47_847; d += 7) ts.push(d * day, d * day + day - 1);
    // Leap-day edge cases.
    for (const iso of ["2000-02-29", "2024-02-29", "2100-02-28", "2100-03-01", "1972-02-29", "2027-03-15"]) {
      ts.push(Date.parse(`${iso}T00:00:00Z`) / 1000, Date.parse(`${iso}T23:59:59Z`) / 1000);
    }
    for (let i = 0; i < ts.length; i += 1000) {
      const chunk = ts.slice(i, i + 1000);
      const got = await harness.toYYYYMMDDBatch(chunk);
      chunk.forEach((t, j) => expect(Number(got[j]), new Date(t * 1000).toISOString()).to.equal(timestampToYYYYMMDD(t)));
    }
  });
});
