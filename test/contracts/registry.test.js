import { expect } from "chai";
import { Wallet, Signature } from "ethers";
import { deployZkred } from "../helpers/fixtures.js";
import { signRootUpdate } from "../../scripts/lib/issuer.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

describe("contracts: Registry", () => {
  let f, chainId, registryAddr;

  beforeEach(async () => {
    f = await deployZkred();
    chainId = (await f.ethers.provider.getNetwork()).chainId;
    registryAddr = await f.registry.getAddress();
  });

  const sign = (signer, root, epoch, overrides = {}) =>
    signRootUpdate(signer, { chainId, registry: registryAddr, root, epoch, ...overrides });

  describe("root updates", () => {
    it("accepts an issuer-signed root, relayed by anyone, and emits the signature", async () => {
      const sig = await sign(f.issuer, 111n, 1n);
      await expect(f.registry.connect(f.mallory).updateRoot(111n, 1n, sig)).to.emit(f.registry, "RootUpdated").withArgs(111n, 1n, sig);
      expect(await f.registry.isKnownRoot(111n)).to.equal(true);
      expect(await f.registry.latestRoot()).to.equal(111n);
      expect(await f.registry.epoch()).to.equal(1n);
    });

    it("negative: a signature from a non-issuer key is rejected", async () => {
      const sig = await sign(Wallet.createRandom(), 111n, 1n);
      await expect(f.registry.updateRoot(111n, 1n, sig)).to.be.revertedWithCustomError(f.registry, "BadIssuerSignature");
    });

    it("negative: a signature for a different root/epoch does not transfer", async () => {
      const sig = await sign(f.issuer, 111n, 1n);
      await expect(f.registry.updateRoot(222n, 1n, sig)).to.be.revertedWithCustomError(f.registry, "BadIssuerSignature");
    });

    it("negative: replaying an old signature fails (strict epochs)", async () => {
      const sig1 = await sign(f.issuer, 111n, 1n);
      await f.registry.updateRoot(111n, 1n, sig1);
      await f.registry.updateRoot(222n, 2n, await sign(f.issuer, 222n, 2n));
      await expect(f.registry.updateRoot(111n, 1n, sig1)).to.be.revertedWithCustomError(f.registry, "BadEpoch").withArgs(3n, 1n);
    });

    it("negative: skipping an epoch fails", async () => {
      await expect(f.registry.updateRoot(111n, 2n, await sign(f.issuer, 111n, 2n))).to.be.revertedWithCustomError(f.registry, "BadEpoch");
    });

    it("negative: EIP-712 domain separation (other chain id / other registry address)", async () => {
      const wrongChain = await sign(f.issuer, 111n, 1n, { chainId: chainId + 1n });
      const wrongContract = await sign(f.issuer, 111n, 1n, { registry: f.alice.address });
      for (const sig of [wrongChain, wrongContract]) {
        await expect(f.registry.updateRoot(111n, 1n, sig)).to.be.revertedWithCustomError(f.registry, "BadIssuerSignature");
      }
    });

    it("negative: high-s (malleable) twin of a valid signature is rejected by OpenZeppelin ECDSA", async () => {
      const sig = Signature.from(await sign(f.issuer, 111n, 1n));
      const highS = "0x" + (SECP256K1_N - BigInt(sig.s)).toString(16).padStart(64, "0");
      const twin = sig.r + highS.slice(2) + (sig.v === 27 ? "1c" : "1b");
      await expect(f.registry.updateRoot(111n, 1n, twin)).to.be.revertedWithCustomError(f.registry, "ECDSAInvalidSignatureS");
    });

    it("negative: root 0 and roots >= r are rejected", async () => {
      for (const root of [0n, SNARK_FIELD_SIZE, SNARK_FIELD_SIZE + 5n]) {
        await expect(f.registry.updateRoot(root, 1n, await sign(f.issuer, root, 1n))).to.be.revertedWithCustomError(f.registry, "InvalidRoot");
      }
    });

    it("root history: a root stays valid for ROOT_HISTORY_SIZE epochs, then expires", async () => {
      const N = Number(await f.registry.ROOT_HISTORY_SIZE());
      await f.registry.updateRoot(1000n, 1n, await sign(f.issuer, 1000n, 1n));
      for (let e = 2; e <= N; e++) await f.registry.updateRoot(BigInt(1000 + e), BigInt(e), await sign(f.issuer, BigInt(1000 + e), BigInt(e)));
      expect(await f.registry.isKnownRoot(1000n)).to.equal(true); // published N-1 epochs ago
      await f.registry.updateRoot(5000n, BigInt(N + 1), await sign(f.issuer, 5000n, BigInt(N + 1)));
      expect(await f.registry.isKnownRoot(1000n)).to.equal(false); // now N epochs old
    });

    it("unknown roots are not known", async () => {
      expect(await f.registry.isKnownRoot(0n)).to.equal(false);
      expect(await f.registry.isKnownRoot(999n)).to.equal(false);
    });
  });

  describe("owner: issuer key rotation", () => {
    it("owner rotates the issuer; the new key works and the OLD key stops working", async () => {
      const newIssuer = Wallet.createRandom();
      await f.registry.updateRoot(111n, 1n, await sign(f.issuer, 111n, 1n));
      await expect(f.registry.connect(f.owner).rotateIssuer(newIssuer.address))
        .to.emit(f.registry, "IssuerRotated").withArgs(f.issuer.address, newIssuer.address);
      await expect(f.registry.updateRoot(222n, 2n, await sign(f.issuer, 222n, 2n))).to.be.revertedWithCustomError(f.registry, "BadIssuerSignature");
      await f.registry.updateRoot(222n, 2n, await sign(newIssuer, 222n, 2n));
      expect(await f.registry.isKnownRoot(222n)).to.equal(true);
    });

    it("negative: an attacker's pre-signed future update (stolen key) is useless after rotation", async () => {
      const preSigned = await sign(f.issuer, 666n, 1n); // signed before rotation
      await f.registry.connect(f.owner).rotateIssuer(Wallet.createRandom().address);
      await expect(f.registry.updateRoot(666n, 1n, preSigned)).to.be.revertedWithCustomError(f.registry, "BadIssuerSignature");
    });

    it("negative: only the owner can rotate; zero address rejected", async () => {
      for (const s of [f.deployer, f.mallory]) {
        await expect(f.registry.connect(s).rotateIssuer(s.address)).to.be.revertedWithCustomError(f.registry, "OwnableUnauthorizedAccount");
      }
      await expect(f.registry.connect(f.owner).rotateIssuer("0x" + "00".repeat(20))).to.be.revertedWithCustomError(f.registry, "ZeroAddress");
    });

    it("negative: the issuer key itself cannot rotate or revoke (it is not the owner)", async () => {
      const issuerOnChain = f.issuer.connect(f.ethers.provider);
      await f.deployer.sendTransaction({ to: f.issuer.address, value: 10n ** 18n });
      await expect(f.registry.connect(issuerOnChain).rotateIssuer(f.mallory.address)).to.be.revertedWithCustomError(f.registry, "OwnableUnauthorizedAccount");
      await expect(f.registry.connect(issuerOnChain).revokeRoot(1n)).to.be.revertedWithCustomError(f.registry, "OwnableUnauthorizedAccount");
    });

    it("ownership transfer is two-step (Ownable2Step)", async () => {
      await f.registry.connect(f.owner).transferOwnership(f.alice.address);
      expect(await f.registry.owner()).to.equal(f.owner.address); // not yet
      await expect(f.registry.connect(f.mallory).acceptOwnership()).to.be.revertedWithCustomError(f.registry, "OwnableUnauthorizedAccount");
      await f.registry.connect(f.alice).acceptOwnership();
      expect(await f.registry.owner()).to.equal(f.alice.address);
      await expect(f.registry.connect(f.owner).rotateIssuer(f.owner.address)).to.be.revertedWithCustomError(f.registry, "OwnableUnauthorizedAccount");
    });
  });

  describe("owner: root revocation", () => {
    it("owner revokes a root: it stops being known, other roots stay valid", async () => {
      await f.registry.updateRoot(111n, 1n, await sign(f.issuer, 111n, 1n));
      await f.registry.updateRoot(222n, 2n, await sign(f.issuer, 222n, 2n));
      await expect(f.registry.connect(f.owner).revokeRoot(222n)).to.emit(f.registry, "RootRevoked").withArgs(222n);
      expect(await f.registry.isKnownRoot(222n)).to.equal(false);
      expect(await f.registry.isKnownRoot(111n)).to.equal(true);
    });

    it("negative: a revoked root can never be re-published, even with a valid issuer signature", async () => {
      await f.registry.updateRoot(111n, 1n, await sign(f.issuer, 111n, 1n));
      await f.registry.connect(f.owner).revokeRoot(111n);
      await expect(f.registry.updateRoot(111n, 2n, await sign(f.issuer, 111n, 2n))).to.be.revertedWithCustomError(f.registry, "RootIsRevoked");
    });

    it("a root can be revoked pre-emptively (before it is published)", async () => {
      await f.registry.connect(f.owner).revokeRoot(777n);
      await expect(f.registry.updateRoot(777n, 1n, await sign(f.issuer, 777n, 1n))).to.be.revertedWithCustomError(f.registry, "RootIsRevoked");
    });

    it("negative: only the owner can revoke; double revocation rejected", async () => {
      await expect(f.registry.connect(f.mallory).revokeRoot(111n)).to.be.revertedWithCustomError(f.registry, "OwnableUnauthorizedAccount");
      await f.registry.connect(f.owner).revokeRoot(111n);
      await expect(f.registry.connect(f.owner).revokeRoot(111n)).to.be.revertedWithCustomError(f.registry, "AlreadyRevoked");
    });
  });
});
