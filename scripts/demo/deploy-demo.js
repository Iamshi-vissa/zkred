// Deploys the live-demo system (shared by scripts/deploy-sepolia.js and tests).
//
//   Registry(owner, issuer)
//   DemoCredentialVerifier      <- the frozen demo key (D27)
//   CredentialGate -> ZKredToken
//   EnrolmentLog(owner, registry, relayer, 2^depth)
//
// Only ADDRESSES of the issuer and relayer are needed here; their keys live in
// Vercel env vars. The returned record is public and is committed to
// web/src/deployments/<network>.json for the frontend.

import { isAddress } from "ethers";
import { MERKLE_DEPTH } from "../../zkred.config.js";
import { CREDENTIAL_TYPES } from "../lib/credential.js";
import { deploySystem } from "../lib/deploy.js";
import { checkFrozen, loadManifest } from "./frozen.js";

export async function deployDemo(ethers, { owner, issuerAddress, relayerAddress, actionId = 1n, deployer, frozenCheck = checkFrozen } = {}) {
  for (const [name, a] of Object.entries({ issuerAddress, relayerAddress })) {
    if (!isAddress(a)) throw new Error(`${name} must be an address, got ${JSON.stringify(a)}`);
  }
  const problems = frozenCheck();
  if (problems.length) throw new Error(`frozen demo setup is not intact:\n- ${problems.join("\n- ")}`);

  const ownerAddress = owner?.address ?? owner;
  const credentialType = CREDENTIAL_TYPES.ENROLLED_STUDENT;
  const { registry, verifier, gate, token } = await deploySystem(ethers, {
    owner: ownerAddress,
    issuerAddress,
    actionId,
    credentialType,
    deployer,
    verifierName: "DemoCredentialVerifier",
  });
  const log = await ethers.deployContract("EnrolmentLog", [ownerAddress, registry, relayerAddress, 2n ** BigInt(MERKLE_DEPTH)], deployer);
  await log.waitForDeployment();
  const { chainId } = await ethers.provider.getNetwork();
  const manifest = loadManifest();

  const record = {
    chainId: Number(chainId),
    merkleDepth: MERKLE_DEPTH,
    actionId: actionId.toString(),
    credentialType: credentialType.toString(),
    owner: ownerAddress,
    issuer: issuerAddress,
    relayer: relayerAddress,
    registry: await registry.getAddress(),
    verifier: await verifier.getAddress(),
    gate: await gate.getAddress(),
    token: await token.getAddress(),
    enrolmentLog: await log.getAddress(),
    deployBlock: Number(await log.deployBlock()),
    scope: (await gate.scope()).toString(),
    zkeySha256: manifest.files.zkey.sha256,
  };
  return { record, registry, verifier, gate, token, log };
}
