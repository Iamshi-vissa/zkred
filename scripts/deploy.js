// Deploys ZKred to a network and records the addresses.
//
// Local node:
//   npx hardhat node                                   # terminal 1
//   npx hardhat run scripts/deploy.js --network localhost   # terminal 2
//
// The issuer key is generated here and written to keys/issuer-<chainId>.json
// (gitignored, never committed). Registry owner = deployer account.
// Addresses go to build/deployments/<chainId>.json.

import { network } from "hardhat";
import { Wallet } from "ethers";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { deploySystem } from "./lib/deploy.js";
import { ROOT } from "./circuits/compile.js";
import { isSetupCurrent } from "./circuits/setup.js";
import { MERKLE_DEPTH } from "../zkred.config.js";

if (!isSetupCurrent(MERKLE_DEPTH)) throw new Error("run `npm run setup` first (verifier contract is generated)");

const { ethers } = await network.getOrCreate();
const [deployer] = await ethers.getSigners();
const { chainId } = await ethers.provider.getNetwork();

const keyFile = path.join(ROOT, "keys", `issuer-${chainId}.json`);
mkdirSync(path.dirname(keyFile), { recursive: true });
let issuer;
if (existsSync(keyFile)) {
  issuer = new Wallet(JSON.parse(readFileSync(keyFile, "utf8")).privateKey);
} else {
  issuer = Wallet.createRandom();
  writeFileSync(keyFile, JSON.stringify({ address: issuer.address, privateKey: issuer.privateKey }, null, 2), { mode: 0o600 });
}

const { registry, verifier, gate, token } = await deploySystem(ethers, { owner: deployer, issuerAddress: issuer.address });
const out = {
  chainId: chainId.toString(),
  merkleDepth: MERKLE_DEPTH,
  owner: deployer.address,
  issuer: issuer.address,
  registry: await registry.getAddress(),
  verifier: await verifier.getAddress(),
  gate: await gate.getAddress(),
  token: await token.getAddress(),
  scope: (await gate.scope()).toString(),
};
const outFile = path.join(ROOT, "build", "deployments", `${chainId}.json`);
mkdirSync(path.dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify(out, null, 2));
console.table(out);
console.log(`issuer key: ${path.relative(ROOT, keyFile)} (gitignored)\naddresses:  ${path.relative(ROOT, outFile)}`);
