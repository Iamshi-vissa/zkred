// Proof-level tests: real Groth16 proofs against snarkjs and the generated
// on-chain verifier (contracts/verifiers/CredentialVerifier.sol).
import { expect } from "chai";
import { network } from "hardhat";
import { performance } from "node:perf_hooks";
import { MERKLE_DEPTH } from "../../zkred.config.js";
import { PUBLIC_SIGNALS } from "../../scripts/circuits/compile.js";
import { releaseCurves } from "../../scripts/circuits/setup.js";
import { prove, verifyOffchain, toSolidityArgs } from "../../scripts/lib/prover.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";
import { createIdentity } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

const IDX = Object.fromEntries(PUBLIC_SIGNALS.map((k, i) => [k, i]));

describe(`Groth16 proofs (depth ${MERKLE_DEPTH})`, function () {
  this.timeout(300_000);
  let ethers, verifier, alice, bob, tree, student, proof, publicSignals;

  before(async () => {
    ({ ethers } = await network.create());
    [, alice, bob] = await ethers.getSigners();
    verifier = await ethers.deployContract("CredentialVerifier");

    student = { identity: await createIdentity(), birthDate: 20000115, credentialType: CREDENTIAL_TYPES.ENROLLED_STUDENT };
    tree = await MerkleTree.create();
    tree.insert(123n);
    student.leafIndex = tree.insert(await credentialLeaf({ idCommitment: student.identity.commitment, ...student }));

    const input = await buildCircuitInput({ ...student, tree, scope: 42n, currentDate: 20261119, recipient: alice.address });
    const t0 = performance.now();
    ({ proof, publicSignals } = await prove(input));
    console.log(`      proving time: ${(performance.now() - t0).toFixed(0)} ms`);
  });

  after(releaseCurves);

  const onchain = (pub, p = proof) => {
    const { a, b, c, pubSignals } = toSolidityArgs(p, pub);
    return verifier.verifyProof(a, b, c, pubSignals);
  };
  const withSignal = (name, value) => publicSignals.map((v, i) => (i === IDX[name] ? value : v));

  it("an honest proof verifies off-chain (snarkjs) and on-chain", async () => {
    expect(await verifyOffchain(proof, publicSignals)).to.equal(true);
    expect(await onchain(publicSignals)).to.equal(true);
    const { a, b, c, pubSignals } = toSolidityArgs(proof, publicSignals);
    const gas = await verifier.verifyProof.estimateGas(a, b, c, pubSignals);
    console.log(`      verifyProof gas (estimate, incl. 21k base): ${gas}`);
  });

  it("public signals carry recipient = uint160(alice)", () => {
    expect(publicSignals[IDX.recipient]).to.equal(BigInt(alice.address));
  });

  it("[C9] negative: alice's proof is rejected when recipient is bob (front-running defence)", async () => {
    const forBob = withSignal("recipient", BigInt(bob.address));
    expect(await verifyOffchain(proof, forBob)).to.equal(false);
    expect(await onchain(forBob)).to.equal(false);
  });

  for (const name of PUBLIC_SIGNALS) {
    it(`negative: changing public input '${name}' invalidates the proof`, async () => {
      const changed = withSignal(name, publicSignals[IDX[name]] + 1n);
      expect(await verifyOffchain(proof, changed)).to.equal(false);
      expect(await onchain(changed)).to.equal(false);
    });
  }

  it("negative: a public input >= r is rejected on-chain (no x / x + r aliasing)", async () => {
    // x + r is the same field element as x; the verifier's checkField must
    // reject it, or the contract could treat two encodings of one nullifier
    // as different values.
    const aliased = withSignal("nullifierHash", publicSignals[IDX.nullifierHash] + SNARK_FIELD_SIZE);
    expect(await onchain(aliased)).to.equal(false);
  });

  it("negative: a tampered proof point is rejected", async () => {
    const bad = structuredClone(proof);
    bad.pi_c[0] = ((BigInt(bad.pi_c[0]) + 1n) % SNARK_FIELD_SIZE).toString();
    expect(await onchain(publicSignals, bad)).to.equal(false);
  });

  it("negative: swapping proof elements A and C is rejected", async () => {
    const bad = structuredClone(proof);
    [bad.pi_a, bad.pi_c] = [bad.pi_c, bad.pi_a];
    expect(await onchain(publicSignals, bad)).to.equal(false);
  });

  it("negative: an unsatisfiable input (17-year-old) cannot produce a proof at all", async () => {
    const minor = { identity: await createIdentity(), birthDate: 20090601, credentialType: CREDENTIAL_TYPES.ENROLLED_STUDENT };
    minor.leafIndex = tree.insert(await credentialLeaf({ idCommitment: minor.identity.commitment, ...minor }));
    const input = await buildCircuitInput({ ...minor, tree, scope: 42n, currentDate: 20261119, recipient: alice.address });
    let threw = false;
    try {
      await prove(input);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
