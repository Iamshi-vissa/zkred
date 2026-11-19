import { expect } from "chai";
import {
  createIdentity,
  nullifierHash,
  DOMAIN_IDENTITY,
  DOMAIN_NULLIFIER,
} from "../../scripts/lib/identity.js";
import { poseidon } from "../../scripts/lib/poseidon.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

describe("lib/identity", () => {
  it("commitment = Poseidon(DOMAIN_IDENTITY, nullifierSecret, trapdoor)", async () => {
    const id = await createIdentity({ nullifierSecret: 11n, trapdoor: 22n });
    expect(id.commitment).to.equal(await poseidon([DOMAIN_IDENTITY, 11n, 22n]));
  });

  it("is deterministic given the same secrets", async () => {
    const a = await createIdentity({ nullifierSecret: 5n, trapdoor: 6n });
    const b = await createIdentity({ nullifierSecret: 5n, trapdoor: 6n });
    expect(a.commitment).to.equal(b.commitment);
  });

  it("random identities differ", async () => {
    const a = await createIdentity();
    const b = await createIdentity();
    expect(a.commitment).to.not.equal(b.commitment);
    expect(a.nullifierSecret).to.not.equal(b.nullifierSecret);
  });

  it("identity objects are frozen", async () => {
    const id = await createIdentity();
    expect(Object.isFrozen(id)).to.equal(true);
  });

  it("rejects zero or out-of-field secrets", async () => {
    await expectReject(createIdentity({ nullifierSecret: 0n, trapdoor: 1n }));
    await expectReject(createIdentity({ nullifierSecret: 1n, trapdoor: SNARK_FIELD_SIZE }));
  });

  describe("nullifierHash", () => {
    it("= Poseidon(DOMAIN_NULLIFIER, nullifierSecret, scope)", async () => {
      const id = await createIdentity({ nullifierSecret: 7n, trapdoor: 8n });
      expect(await nullifierHash(id, 99n)).to.equal(await poseidon([DOMAIN_NULLIFIER, 7n, 99n]));
    });

    it("same identity + same scope => same nullifier (enables double-use detection)", async () => {
      const id = await createIdentity();
      expect(await nullifierHash(id, 1n)).to.equal(await nullifierHash(id, 1n));
    });

    it("same identity + different scope => different, unlinkable nullifiers", async () => {
      const id = await createIdentity();
      expect(await nullifierHash(id, 1n)).to.not.equal(await nullifierHash(id, 2n));
    });

    it("different identities never share a nullifier in the same scope", async () => {
      const seen = new Set();
      for (let i = 0; i < 50; i++) seen.add(await nullifierHash(await createIdentity(), 1n));
      expect(seen.size).to.equal(50);
    });

    it("does not depend on the trapdoor", async () => {
      const a = await createIdentity({ nullifierSecret: 3n, trapdoor: 4n });
      const b = await createIdentity({ nullifierSecret: 3n, trapdoor: 5n });
      expect(await nullifierHash(a, 1n)).to.equal(await nullifierHash(b, 1n));
    });

    it("domain separation: scope == trapdoor does not reveal the commitment", async () => {
      const id = await createIdentity({ nullifierSecret: 9n, trapdoor: 10n });
      expect(await nullifierHash(id, 10n)).to.not.equal(id.commitment);
    });

    it("rejects an out-of-field scope", async () => {
      const id = await createIdentity();
      await expectReject(nullifierHash(id, SNARK_FIELD_SIZE));
    });
  });
});

async function expectReject(promise) {
  try {
    await promise;
  } catch {
    return;
  }
  expect.fail("expected promise to reject");
}
