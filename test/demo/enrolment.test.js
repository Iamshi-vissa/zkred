// Live demo step 2: EnrolmentLog + deployDemo, on a local Hardhat chain.
//
// Mirrors what Sepolia will do: the relayer enrols leaves (one tx per leaf,
// root published atomically), the "browser" rebuilds the tree from events
// alone, proves with the FROZEN files, and claims.
import { expect } from "chai";
import { network } from "hardhat";
import { Wallet } from "ethers";
import * as snarkjs from "snarkjs";
import { releaseCurves } from "../../scripts/circuits/setup.js";
import { frozenPaths } from "../../scripts/demo/frozen.js";
import { deployDemo } from "../../scripts/demo/deploy-demo.js";
import { enrolLeaf, enrolledLeaves, rebuildTree } from "../../scripts/demo/enrolment.js";
import { createIdentity } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { signRootUpdate } from "../../scripts/lib/issuer.js";
import { toSolidityArgs } from "../../scripts/lib/prover.js";
import { revertReason } from "../../scripts/lib/deploy.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";
import { MERKLE_DEPTH } from "../../zkred.config.js";

const TODAY = 20270315;
const NOON_TODAY = Date.UTC(2027, 2, 15, 12) / 1000;

async function student(birthDate = 20000115) {
  const identity = await createIdentity();
  const credentialType = CREDENTIAL_TYPES.ENROLLED_STUDENT;
  return { identity, birthDate, credentialType, leaf: await credentialLeaf({ idCommitment: identity.commitment, birthDate, credentialType }) };
}

async function freshDemo() {
  const { ethers, networkHelpers } = await network.create();
  const [deployer, owner, relayer, alice, bob, mallory] = await ethers.getSigners();
  const issuer = Wallet.createRandom(); // runtime only
  const sys = await deployDemo(ethers, { owner, issuerAddress: issuer.address, relayerAddress: relayer.address, deployer });
  await networkHelpers.time.increaseTo(NOON_TODAY);
  const enrol = (leaf, opts = {}) => enrolLeaf({ log: sys.log, registry: sys.registry, issuer, relayer, leaf, ...opts });
  return { ethers, deployer, owner, relayer, alice, bob, mallory, issuer, enrol, ...sys };
}

const errOf = (p) => p.then(() => null, (e) => e);

describe("demo: EnrolmentLog + deployDemo (live demo step 2)", function () {
  after(releaseCurves);

  describe("deployDemo", () => {
    it("deploys the demo system and returns the public address record", async () => {
      const d = await freshDemo();
      expect(d.record).to.include({ merkleDepth: MERKLE_DEPTH, owner: d.owner.address, issuer: d.issuer.address, relayer: d.relayer.address });
      expect(await d.registry.owner()).to.equal(d.owner.address);
      expect(await d.registry.issuer()).to.equal(d.issuer.address);
      expect(await d.gate.verifier()).to.equal(d.record.verifier);
      expect(await d.log.relayer()).to.equal(d.relayer.address);
      expect(await d.log.capacity()).to.equal(2n ** BigInt(MERKLE_DEPTH));
      expect(d.record.scope).to.equal((await d.gate.scope()).toString());
      // the record must never carry a key
      expect(JSON.stringify(d.record)).to.not.match(/0x[0-9a-fA-F]{64}/);
    });

    it("negative: refuses a missing or malformed issuer / relayer address", async () => {
      const { ethers } = await network.create();
      const [deployer] = await ethers.getSigners();
      for (const bad of [{ issuerAddress: undefined, relayerAddress: deployer.address }, { issuerAddress: deployer.address, relayerAddress: "0x1234" }]) {
        const err = await errOf(deployDemo(ethers, { owner: deployer, ...bad }));
        expect(err?.message).to.match(/must be an address/);
      }
    });

    it("negative: refuses to deploy if the frozen setup is not intact", async () => {
      const { ethers } = await network.create();
      const [deployer] = await ethers.getSigners();
      const err = await errOf(
        deployDemo(ethers, { owner: deployer, issuerAddress: deployer.address, relayerAddress: deployer.address, frozenCheck: () => ["credential.zkey does not match its manifest hash"] }),
      );
      expect(err?.message).to.match(/frozen demo setup is not intact/);
    });
  });

  describe("enrol", () => {
    it("logs the leaf and publishes the new root in the same transaction", async () => {
      const d = await freshDemo();
      const s = await student();
      const { index, root, receipt } = await d.enrol(s.leaf);
      expect(index).to.equal(0n);
      expect(await d.registry.latestRoot()).to.equal(root);
      expect(await d.registry.epoch()).to.equal(1n);
      expect(await d.log.count()).to.equal(1n);
      expect(await d.log.isEnrolled(s.leaf)).to.equal(true);
      const topics = receipt.logs.map((l) => l.address);
      expect(topics).to.include(d.record.enrolmentLog).and.to.include(d.record.registry);
    });

    it("the tree rebuilt from events alone matches the Registry root after several enrolments", async () => {
      const d = await freshDemo();
      const leaves = [];
      for (let i = 0; i < 3; i++) {
        const s = await student();
        leaves.push(s.leaf);
        await d.enrol(s.leaf);
      }
      expect(await enrolledLeaves(d.log)).to.deep.equal(leaves);
      const tree = await rebuildTree(d.log, d.registry);
      expect(tree.root).to.equal(await d.registry.latestRoot());
    });

    it("end to end: enrol, rebuild from events, prove with the frozen files, claim 100 ZKRED", async () => {
      const d = await freshDemo();
      await d.enrol((await student()).leaf); // someone else first
      const s = await student();
      const { index } = await d.enrol(s.leaf);

      const tree = await rebuildTree(d.log, d.registry); // what the browser will do
      const input = await buildCircuitInput({ ...s, tree, leafIndex: Number(index), scope: await d.gate.scope(), currentDate: TODAY, recipient: d.alice.address });
      const f = frozenPaths();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, f.wasm, f.zkey);
      const pub = publicSignals.map(BigInt);
      const { a, b, c } = toSolidityArgs(proof, pub);
      await expect(d.gate.connect(d.alice).claim(a, b, c, pub[0], pub[1], pub[4])).to.emit(d.gate, "Claimed").withArgs(d.alice.address, pub[1]);
      expect(await d.token.balanceOf(d.alice.address)).to.equal(100n * 10n ** 18n);
    });

    it("negative: only the relayer can enrol", async () => {
      const d = await freshDemo();
      const s = await student();
      const epoch = (await d.registry.epoch()) + 1n;
      const sig = await signRootUpdate(d.issuer, { chainId: d.record.chainId, registry: d.record.registry, root: 123n, epoch });
      const err = await errOf(d.log.connect(d.mallory).enrol(s.leaf, 123n, epoch, sig));
      expect(revertReason(err, d.log)).to.equal("NotRelayer");
    });

    it("negative: a root not signed by the issuer reverts the whole enrolment (no leaf is logged)", async () => {
      const d = await freshDemo();
      const s = await student();
      const err = await errOf(d.enrol(s.leaf, { issuer: Wallet.createRandom() }));
      expect(revertReason(err, d.registry)).to.equal("BadIssuerSignature");
      expect(await d.log.count()).to.equal(0n);
      expect(await d.log.isEnrolled(s.leaf)).to.equal(false);
      expect(await d.registry.epoch()).to.equal(0n);
    });

    it("negative: leaf 0 and leaves outside the field are rejected", async () => {
      const d = await freshDemo();
      for (const leaf of [0n, SNARK_FIELD_SIZE, SNARK_FIELD_SIZE + 1n]) {
        const err = await errOf(d.log.connect(d.relayer).enrol(leaf, 1n, 1n, "0x"));
        expect(revertReason(err, d.log), String(leaf)).to.equal("InvalidLeaf");
      }
    });

    it("negative: the same leaf can't be enrolled twice", async () => {
      const d = await freshDemo();
      const s = await student();
      await d.enrol(s.leaf);
      const err = await errOf(d.log.connect(d.relayer).enrol(s.leaf, 1n, 2n, "0x"));
      expect(revertReason(err, d.log)).to.equal("AlreadyEnrolled");
    });

    it("negative: enrolment stops at capacity (TreeFull)", async () => {
      const d = await freshDemo();
      const small = await d.ethers.deployContract("EnrolmentLog", [d.owner.address, d.registry, d.relayer.address, 1n]);
      const enrolSmall = (leaf) => enrolLeaf({ log: small, registry: d.registry, issuer: d.issuer, relayer: d.relayer, leaf });
      await enrolSmall((await student()).leaf);
      const err = await errOf(small.connect(d.relayer).enrol((await student()).leaf, 1n, 2n, "0x"));
      expect(revertReason(err, small)).to.equal("TreeFull");
    });

    it("negative: rebuildTree refuses a log that disagrees with the Registry root", async () => {
      const d = await freshDemo();
      await d.enrol((await student()).leaf);
      // The issuer (or a thief of its key) publishes a root directly, bypassing the log.
      const epoch = (await d.registry.epoch()) + 1n;
      const sig = await signRootUpdate(d.issuer, { chainId: d.record.chainId, registry: d.record.registry, root: 999n, epoch });
      await d.registry.updateRoot(999n, epoch, sig);
      const err = await errOf(rebuildTree(d.log, d.registry));
      expect(err?.message).to.match(/does not match Registry.latestRoot/);
    });
  });

  describe("relayer rotation", () => {
    it("the owner can replace the relayer; the old one is then rejected", async () => {
      const d = await freshDemo();
      await expect(d.log.connect(d.owner).setRelayer(d.bob.address)).to.emit(d.log, "RelayerChanged").withArgs(d.relayer.address, d.bob.address);
      const err = await errOf(d.enrol((await student()).leaf)); // still sends from the old relayer
      expect(revertReason(err, d.log)).to.equal("NotRelayer");
      const { index } = await enrolLeaf({ log: d.log, registry: d.registry, issuer: d.issuer, relayer: d.bob, leaf: (await student()).leaf });
      expect(index).to.equal(0n);
    });

    it("negative: nobody but the owner can change the relayer, and not to the zero address", async () => {
      const d = await freshDemo();
      const err = await errOf(d.log.connect(d.mallory).setRelayer(d.mallory.address));
      expect(revertReason(err, d.log)).to.equal("OwnableUnauthorizedAccount");
      const err2 = await errOf(d.log.connect(d.owner).setRelayer("0x0000000000000000000000000000000000000000"));
      expect(revertReason(err2, d.log)).to.equal("ZeroAddress");
    });
  });
});
