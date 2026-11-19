import { expect } from "chai";
import { poseidon, poseidonSync, initPoseidon } from "../../scripts/lib/poseidon.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

// Reference vectors from circomlib's own test suite (test/poseidoncircuit.js).
const VECTORS = [
  { in: [1n, 2n], out: 7853200120776062878684798364095072458815029376092732009249414926327459813530n },
  { in: [3n, 4n], out: 14763215145315200506921711489642608356394854266165572616578112107564877678998n },
  { in: [1n, 2n, 0n, 0n, 0n], out: 1018317224307729531995786483840663576608797660851238720571059489595066344487n },
  { in: [3n, 4n, 5n, 10n, 23n], out: 13034429309846638789535561449942021891039729847501137143363028890275222221409n },
];

describe("lib/poseidon", () => {
  before(initPoseidon);

  for (const v of VECTORS) {
    it(`matches circomlib vector for Poseidon(${v.in.join(",")})`, async () => {
      expect(await poseidon(v.in)).to.equal(v.out);
      expect(poseidonSync(v.in)).to.equal(v.out);
    });
  }

  it("different arity gives a different hash (independent parameter sets)", async () => {
    expect(await poseidon([1n, 2n])).to.not.equal(await poseidon([1n, 2n, 0n]));
  });

  it("is order-sensitive", async () => {
    expect(await poseidon([1n, 2n])).to.not.equal(await poseidon([2n, 1n]));
  });

  it("rejects inputs >= r instead of reducing them (x and x+r must not collide)", async () => {
    await expectReject(poseidon([SNARK_FIELD_SIZE + 1n, 2n]), RangeError);
  });

  it("rejects empty and oversized input arrays", async () => {
    await expectReject(poseidon([]), RangeError);
    await expectReject(poseidon(new Array(17).fill(1n)), RangeError);
  });
});

async function expectReject(promise, ErrorType) {
  try {
    await promise;
  } catch (e) {
    expect(e).to.be.instanceOf(ErrorType);
    return;
  }
  expect.fail("expected promise to reject");
}
