import { expect } from "chai";
import { SNARK_FIELD_SIZE, toFieldElement, randomFieldElement } from "../../scripts/lib/field.js";

describe("lib/field", () => {
  it("accepts bigint, number and numeric strings inside [0, r)", () => {
    expect(toFieldElement(0n)).to.equal(0n);
    expect(toFieldElement(42)).to.equal(42n);
    expect(toFieldElement("42")).to.equal(42n);
    expect(toFieldElement("0x2a")).to.equal(42n);
    expect(toFieldElement(SNARK_FIELD_SIZE - 1n)).to.equal(SNARK_FIELD_SIZE - 1n);
  });

  it("rejects r and above instead of silently reducing (aliasing)", () => {
    expect(() => toFieldElement(SNARK_FIELD_SIZE)).to.throw(RangeError);
    expect(() => toFieldElement(SNARK_FIELD_SIZE + 5n)).to.throw(RangeError);
  });

  it("rejects negatives, non-integers and junk", () => {
    expect(() => toFieldElement(-1n)).to.throw(RangeError);
    expect(() => toFieldElement(-1)).to.throw(RangeError);
    expect(() => toFieldElement(1.5)).to.throw(TypeError);
    expect(() => toFieldElement(2 ** 60)).to.throw(TypeError); // unsafe integer
    expect(() => toFieldElement("12abc")).to.throw(TypeError);
    expect(() => toFieldElement(null)).to.throw(TypeError);
  });

  it("randomFieldElement is non-zero, in range and not repeating", () => {
    const seen = new Set();
    for (let i = 0; i < 200; i++) {
      const v = randomFieldElement();
      expect(v > 0n && v < SNARK_FIELD_SIZE).to.equal(true);
      seen.add(v);
    }
    expect(seen.size).to.equal(200);
  });
});
