// Issuer tooling: EIP-712 signatures over RootUpdate(root, epoch).
//
// ethers' signTypedData uses RFC 6979 deterministic nonces (k derived from the
// private key and the message hash), so two different messages never share a
// nonce. Lab 04 replaces this with a broken signer to show why that matters.

import { AbiCoder, keccak256 } from "ethers";
import { SNARK_FIELD_SIZE } from "./field.js";

export const ROOT_UPDATE_TYPES = Object.freeze({
  RootUpdate: [
    { name: "root", type: "uint256" },
    { name: "epoch", type: "uint64" },
  ],
});

export function registryDomain(chainId, registryAddress) {
  return { name: "ZKred Registry", version: "1", chainId, verifyingContract: registryAddress };
}

/** Signs a root update with an ethers signer/wallet (RFC 6979). */
export async function signRootUpdate(signer, { chainId, registry, root, epoch }) {
  return signer.signTypedData(registryDomain(chainId, registry), ROOT_UPDATE_TYPES, { root, epoch });
}

/** Signs and submits the next root update; returns the tx receipt. */
export async function publishRoot(registry, issuerSigner, root, { relayer } = {}) {
  const epoch = (await registry.epoch()) + 1n;
  const { chainId } = await registry.runner.provider.getNetwork();
  const signature = await signRootUpdate(issuerSigner, { chainId, registry: await registry.getAddress(), root, epoch });
  const r = relayer ? registry.connect(relayer) : registry;
  return (await r.updateRoot(root, epoch, signature)).wait();
}

/** Mirrors CredentialGate's scope: keccak256(abi.encode(chainid, gate, actionId)) mod r. */
export function computeScope(chainId, gateAddress, actionId) {
  const encoded = AbiCoder.defaultAbiCoder().encode(["uint256", "address", "uint256"], [chainId, gateAddress, actionId]);
  return BigInt(keccak256(encoded)) % SNARK_FIELD_SIZE;
}
