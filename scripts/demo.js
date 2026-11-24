// Narrated end-to-end demo on an in-process Hardhat network:
//   npm run demo
import { network } from "hardhat";
import { runDemo } from "./lib/demo.js";
import { releaseCurves } from "./circuits/setup.js";

const { ethers } = await network.getOrCreate();
try {
  await runDemo(ethers);
} finally {
  await releaseCurves();
}
