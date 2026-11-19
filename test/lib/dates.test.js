import { expect } from "chai";
import { isValidYYYYMMDD, toYYYYMMDD, timestampToYYYYMMDD, isAtLeastAge } from "../../scripts/lib/dates.js";

describe("lib/dates", () => {
  it("validates real calendar dates", () => {
    for (const d of [20240229, 20000229, 19991231, 20260101]) expect(isValidYYYYMMDD(d), d).to.equal(true);
  });

  it("negative: rejects impossible dates and junk", () => {
    for (const d of [20230229, 19000229, 20261301, 20260431, 20260100, 20260000, 2026111, 100000000, -20261119, 20261119.5, "20261119"]) {
      expect(isValidYYYYMMDD(d), String(d)).to.equal(false);
    }
  });

  it("converts Dates and unix timestamps (UTC)", () => {
    expect(toYYYYMMDD(new Date("2026-11-19T23:59:59Z"))).to.equal(20261119);
    expect(timestampToYYYYMMDD(0)).to.equal(19700101);
    expect(timestampToYYYYMMDD(1_772_323_200)).to.equal(20260301); // 2026-03-01T00:00:00Z
    expect(() => toYYYYMMDD("not a date")).to.throw(RangeError);
  });

  it("age rule: exact birthday, one day short, 29 Feb", () => {
    expect(isAtLeastAge(20081119, 20261119)).to.equal(true);
    expect(isAtLeastAge(20081120, 20261119)).to.equal(false);
    expect(isAtLeastAge(20080229, 20260228)).to.equal(false);
    expect(isAtLeastAge(20080229, 20260301)).to.equal(true);
  });

  it("YYYYMMDD difference agrees with a calendar-based age for every day of 2026", () => {
    const birth = new Date(Date.UTC(2008, 5, 15)); // 2008-06-15
    for (let t = Date.UTC(2026, 0, 1); t < Date.UTC(2027, 0, 1); t += 86_400_000) {
      const now = new Date(t);
      const eighteenth = new Date(Date.UTC(2026, 5, 15));
      expect(isAtLeastAge(toYYYYMMDD(birth), toYYYYMMDD(now)), now.toISOString()).to.equal(now >= eighteenth);
    }
  });

  it("negative: rejects invalid dates instead of comparing garbage", () => {
    expect(() => isAtLeastAge(20230229, 20261119)).to.throw(RangeError);
  });
});
