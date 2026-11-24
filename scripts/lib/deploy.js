// Deploys the ZKred system with an ethers instance (shared by scripts and tests).
import { CREDENTIAL_TYPES } from "./credential.js";

/**
 * Deploys Registry, CredentialVerifier and CredentialGate (which deploys ZKredToken).
 * `verifierName` selects the verifier contract: "CredentialVerifier" (this
 * machine's setup) or "DemoCredentialVerifier" (the frozen demo setup, D27).
 * @returns {{ registry, verifier, gate, token }}
 */
export async function deploySystem(ethers, { owner, issuerAddress, actionId = 1n, credentialType = CREDENTIAL_TYPES.ENROLLED_STUDENT, deployer, verifierName = "CredentialVerifier" } = {}) {
  if (!owner || !issuerAddress) throw new Error("deploySystem needs owner and issuerAddress");
  const ownerAddress = owner.address ?? owner;
  const registry = await ethers.deployContract("Registry", [ownerAddress, issuerAddress], deployer);
  const verifier = await ethers.deployContract(verifierName, [], deployer);
  const gate = await ethers.deployContract("CredentialGate", [registry, verifier, actionId, credentialType], deployer);
  await gate.waitForDeployment();
  const token = await ethers.getContractAt("ZKredToken", await gate.token());
  return { registry, verifier, gate, token };
}

/** Custom-error name of a revert (e.g. "InvalidProof"), or the shortest message available. */
export function revertReason(error, contract) {
  if (error?.revert?.name) return error.revert.name;
  if (contract && error?.data) {
    try {
      const parsed = contract.interface.parseError(error.data);
      if (parsed) return parsed.name;
    } catch {
      // not decodable with this ABI
    }
  }
  const m = /custom error '(\w+)\(/.exec(error?.message ?? "");
  if (m) return m[1];
  return error?.shortMessage ?? error?.message ?? String(error);
}
