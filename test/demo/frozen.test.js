// Step 1 of the live demo: the frozen demo setup (D27).
//
// The browser proves with web/public/circuit/credential.zkey and Sepolia runs
// contracts/demo/DemoCredentialVerifier.sol. These tests check that the two
// belong together, that they match the current circuit, and that a swapped or
// edited file is caught.
import { expect } from "chai";
import { copyFileSync, cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { network } from "hardhat";
import { Wallet } from "ethers";
import * as snarkjs from "snarkjs";
import { MERKLE_DEPTH } from "../../zkred.config.js";
import { circuitPaths } from "../../scripts/circuits/compile.js";
import { ensurePtau, releaseCurves } from "../../scripts/circuits/setup.js";
import { PUBLIC_SIGNALS } from "../../scripts/circuits/registry.js";
import { checkFrozen, frozenPaths, loadManifest, DEMO_VERIFIER_SOL } from "../../scripts/demo/frozen.js";
import { freeze } from "../../scripts/demo/freeze.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";
import { createIdentity } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { publishRoot } from "../../scripts/lib/issuer.js";
import { toSolidityArgs } from "../../scripts/lib/prover.js";
import { deploySystem, revertReason } from "../../scripts/lib/deploy.js";

const TODAY = 20270315;
const NOON_TODAY = Date.UTC(2027, 2, 15, 12) / 1000;

/** Copies the frozen set and demo verifier to a temp dir so tests can tamper with them. */
function tempCopy() {
  const dir = mkdtempSync(path.join(tmpdir(), "zkred-frozen-"));
  cpSync(frozenPaths().dir, dir, { recursive: true });
  const sol = path.join(dir, "DemoCredentialVerifier.sol");
  copyFileSync(DEMO_VERIFIER_SOL, sol);
  return { dir, sol };
}

function flipByte(file, offset) {
  const buf = readFileSync(file);
  buf[offset] ^= 0xff;
  writeFileSync(file, buf);
}

describe("demo: frozen setup (D27)", function () {
  const p = frozenPaths();
  const manifest = loadManifest();
  after(releaseCurves);
  let ctx; // one deployed demo system + one frozen-key proof, shared by the on-chain tests

  before(async () => {
    const conn = await network.create();
    const { ethers, networkHelpers } = conn;
    const [deployer, owner, alice, bob] = await ethers.getSigners();
    const issuer = Wallet.createRandom();
    const sys = await deploySystem(ethers, { owner, issuerAddress: issuer.address, verifierName: "DemoCredentialVerifier" });
    await networkHelpers.time.increaseTo(NOON_TODAY);

    const tree = await MerkleTree.create();
    const identity = await createIdentity();
    const student = { identity, birthDate: 20000115, credentialType: CREDENTIAL_TYPES.ENROLLED_STUDENT };
    student.leafIndex = tree.insert(await credentialLeaf({ idCommitment: identity.commitment, ...student }));
    await publishRoot(sys.registry, issuer, tree.root, { relayer: deployer });

    const input = await buildCircuitInput({ ...student, tree, scope: await sys.gate.scope(), currentDate: TODAY, recipient: alice.address });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, p.wasm, p.zkey); // the FROZEN files
    ctx = { ethers, alice, bob, tree, input, proof, publicSignals: publicSignals.map(BigInt), ...sys };
  });

  it("every frozen file matches manifest.json, and the circuit has not changed since freezing", () => {
    expect(checkFrozen({ r1cs: circuitPaths(MERKLE_DEPTH).r1cs })).to.deep.equal([]);
    expect(manifest.depth).to.equal(MERKLE_DEPTH);
    expect(manifest.publicSignals).to.deep.equal(PUBLIC_SIGNALS);
  });

  it("the frozen zkey is a valid Phase 2 for this circuit and the pinned ptau (snarkjs zkey verify)", async () => {
    const ptau = await ensurePtau(Number(/_(\d+)\.ptau$/.exec(manifest.ptau)[1]), () => {});
    expect(await snarkjs.zKey.verifyFromR1cs(circuitPaths(MERKLE_DEPTH).r1cs, ptau, p.zkey)).to.equal(true);
  });

  it("vkey.json is exactly the verification key inside the frozen zkey", async () => {
    const fromZkey = await snarkjs.zKey.exportVerificationKey(p.zkey);
    expect(JSON.parse(readFileSync(p.vkey, "utf8"))).to.deep.equal(JSON.parse(JSON.stringify(fromZkey)));
  });

  it("a proof made with the frozen wasm + zkey verifies off-chain and with DemoCredentialVerifier", async () => {
    const vkey = JSON.parse(readFileSync(p.vkey, "utf8"));
    expect(await snarkjs.groth16.verify(vkey, ctx.publicSignals.map(String), ctx.proof)).to.equal(true);
    const { a, b, c, pubSignals } = toSolidityArgs(ctx.proof, ctx.publicSignals);
    expect(await ctx.verifier.verifyProof(a, b, c, pubSignals)).to.equal(true);
  });

  it("negative: the same proof sent from another account is rejected before it is ever claimed (bound to the recipient)", async () => {
    const { a, b, c } = toSolidityArgs(ctx.proof, ctx.publicSignals);
    const [root, nullifierHash, , , currentDate] = ctx.publicSignals;
    const err = await ctx.gate.connect(ctx.bob).claim(a, b, c, root, nullifierHash, currentDate).catch((e) => e);
    expect(revertReason(err, ctx.gate)).to.equal("InvalidProof");
  });

  it("end to end: CredentialGate wired to DemoCredentialVerifier pays 100 ZKRED for a frozen-key proof", async () => {
    const { a, b, c } = toSolidityArgs(ctx.proof, ctx.publicSignals);
    const [root, nullifierHash, , , currentDate] = ctx.publicSignals;
    await expect(ctx.gate.connect(ctx.alice).claim(a, b, c, root, nullifierHash, currentDate))
      .to.emit(ctx.gate, "Claimed")
      .withArgs(ctx.alice.address, nullifierHash);
    expect(await ctx.token.balanceOf(ctx.alice.address)).to.equal(100n * 10n ** 18n);
  });

  it("negative: claiming the same proof again is rejected (nullifier spent)", async () => {
    const { a, b, c } = toSolidityArgs(ctx.proof, ctx.publicSignals);
    const [root, nullifierHash, , , currentDate] = ctx.publicSignals;
    const err = await ctx.gate.connect(ctx.alice).claim(a, b, c, root, nullifierHash, currentDate).catch((e) => e);
    expect(revertReason(err, ctx.gate)).to.equal("NullifierAlreadyUsed");
  });

  it("negative: a key from a different Phase 2 does not match the frozen verifier, and vice versa", async function () {
    this.timeout(300_000);
    const dir = mkdtempSync(path.join(tmpdir(), "zkred-other-"));
    const r1cs = circuitPaths(MERKLE_DEPTH).r1cs;
    const ptau = await ensurePtau(Number(/_(\d+)\.ptau$/.exec(manifest.ptau)[1]), () => {});
    const z0 = path.join(dir, "0.zkey");
    const z1 = path.join(dir, "1.zkey");
    await snarkjs.zKey.newZKey(r1cs, ptau, z0);
    await snarkjs.zKey.contribute(z0, z1, "someone else", randomBytes(32).toString("hex"));
    const otherVkey = await snarkjs.zKey.exportVerificationKey(z1);

    // frozen-key proof vs. the other vkey
    expect(await snarkjs.groth16.verify(otherVkey, ctx.publicSignals.map(String), ctx.proof)).to.equal(false);
    // other-key proof vs. the frozen on-chain verifier
    const other = await snarkjs.groth16.fullProve(ctx.input, p.wasm, z1);
    const { a, b, c, pubSignals } = toSolidityArgs(other.proof, other.publicSignals);
    expect(await ctx.verifier.verifyProof(a, b, c, pubSignals)).to.equal(false);
  });

  it("negative: one flipped byte in the zkey, wasm or vkey is caught by the manifest check", () => {
    for (const [file, offset] of [["credential.zkey", 4096], ["credential.wasm", 100], ["vkey.json", 10]]) {
      const { dir, sol } = tempCopy();
      flipByte(path.join(dir, file), offset);
      expect(checkFrozen({ dir, verifierSol: sol }), file).to.deep.equal([`${file} does not match its manifest hash`]);
    }
  });

  it("negative: an edited Solidity verifier is caught by the manifest check", () => {
    const { dir, sol } = tempCopy();
    writeFileSync(sol, readFileSync(sol, "utf8").replace(/uint256 constant alphax\s*=\s*\d/, (m) => m.slice(0, -1) + "9"));
    expect(checkFrozen({ dir, verifierSol: sol })).to.deep.equal(["DemoCredentialVerifier.sol does not match its manifest hash"]);
  });

  it("negative: a different compiled circuit is reported as needing a re-freeze", () => {
    const { dir, sol } = tempCopy();
    const fakeR1cs = path.join(dir, "other.r1cs");
    writeFileSync(fakeR1cs, "not the frozen circuit");
    expect(checkFrozen({ dir, verifierSol: sol, r1cs: fakeR1cs })[0]).to.match(/re-freeze/);
  });

  it("negative: freeze refuses to overwrite an existing frozen set without --force", async () => {
    const { dir, sol } = tempCopy();
    let err;
    try {
      await freeze({ dir, verifierSol: sol, log: () => {} });
    } catch (e) {
      err = e;
    }
    expect(err?.message).to.match(/already exists.*--force/);
  });
});
