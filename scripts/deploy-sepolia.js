// Deploys the live demo to Sepolia (live-demo step 2, docs/live-demo.md).
//
// Run on YOUR machine, after putting the RPC URL and deployer key in the
// encrypted Hardhat keystore:
//   npx hardhat keystore set SEPOLIA_RPC_URL
//   npx hardhat keystore set SEPOLIA_DEPLOYER_KEY
// then (issuer/relayer ADDRESSES only, never their keys):
//   ZKRED_ISSUER_ADDRESS=0x... ZKRED_RELAYER_ADDRESS=0x... npm run deploy:sepolia
//
// The deployer becomes the owner (rotate issuer, revoke roots, change relayer).
// Addresses go to web/src/deployments/sepolia.json, which is public and committed.

import { network } from "hardhat";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { ROOT } from "./circuits/compile.js";
import { deployDemo } from "./demo/deploy-demo.js";

const { ethers, networkName } = await network.getOrCreate();
const [deployer] = await ethers.getSigners();
const balance = await ethers.provider.getBalance(deployer.address);
console.log(`network ${networkName}, deployer ${deployer.address}, balance ${ethers.formatEther(balance)} ETH`);

const { record } = await deployDemo(ethers, {
  owner: deployer.address,
  issuerAddress: process.env.ZKRED_ISSUER_ADDRESS,
  relayerAddress: process.env.ZKRED_RELAYER_ADDRESS,
});

const outFile = path.join(ROOT, "web", "src", "deployments", `${networkName}.json`);
mkdirSync(path.dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify(record, null, 2) + "\n");
console.table(record);
console.log(`addresses written to ${path.relative(ROOT, outFile)}; commit it so the frontend uses them`);
