import { expect } from "chai";
import { credentialLeaf, buildCircuitInput, DOMAIN_LEAF, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { createIdentity, nullifierHash } from "../../scripts/lib/identity.js";
import { poseidon } from "../../scripts/lib/poseidon.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";

describe("lib/credential", () => {
  it("leaf = Poseidon(DOMAIN_LEAF, idCommitment, birthDate, credentialType)", async () => {
    const id = await createIdentity();
    const leaf = await credentialLeaf({ idCommitment: id.commitment, birthDate: 20000115, credentialType: 1n });
    expect(leaf).to.equal(await poseidon([DOMAIN_LEAF, id.commitment, 20000115n, 1n]));
  });

  it("negative: invalid birth date or zero credential type is rejected", async () => {
    const id = await createIdentity();
    for (const bad of [{ birthDate: 20230229, credentialType: 1n }, { birthDate: 20000115, credentialType: 0n }]) {
      let threw = false;
      try {
        await credentialLeaf({ idCommitment: id.commitment, ...bad });
      } catch {
        threw = true;
      }
      expect(threw, JSON.stringify(bad, (_, v) => (typeof v === "bigint" ? v.toString() : v))).to.equal(true);
    }
  });

  it("buildCircuitInput assembles public + private inputs consistently", async () => {
    const identity = await createIdentity();
    const s = { identity, birthDate: 20000115, credentialType: CREDENTIAL_TYPES.ENROLLED_STUDENT };
    const tree = await MerkleTree.create({ depth: 4 });
    const leafIndex = tree.insert(await credentialLeaf({ idCommitment: identity.commitment, ...s }));
    const input = await buildCircuitInput({ ...s, tree, leafIndex, scope: 7n, currentDate: 20261119, recipient: "0x00000000000000000000000000000000000000aa" });
    expect(input.root).to.equal(tree.root);
    expect(input.nullifierHash).to.equal(await nullifierHash(identity, 7n));
    expect(input.recipient).to.equal(0xaan);
    expect(input.pathElements).to.have.length(4);
  });

  it("negative: refuses to build input for someone else's leaf", async () => {
    const [a, b] = [await createIdentity(), await createIdentity()];
    const tree = await MerkleTree.create({ depth: 4 });
    tree.insert(await credentialLeaf({ idCommitment: a.commitment, birthDate: 20000115, credentialType: 1n }));
    let threw = false;
    try {
      await buildCircuitInput({ identity: b, birthDate: 20000115, credentialType: 1n, tree, leafIndex: 0, scope: 1n, currentDate: 20261119, recipient: 1n });
    } catch (e) {
      threw = /does not belong/.test(e.message);
    }
    expect(threw).to.equal(true);
  });
});
