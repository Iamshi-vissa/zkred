import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.28",
    // Optional: use a local solc 0.8.28 binary instead of Hardhat's download
    // (for offline / firewalled machines). Unset = normal Hardhat behaviour.
    ...(process.env.ZKRED_SOLC_PATH ? { path: process.env.ZKRED_SOLC_PATH } : {}),
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  paths: {
    // Secure contracts live in contracts/. Deliberately vulnerable contracts
    // live only in attacks/<NN-name>/vulnerable/ (see attacks/README.md).
    sources: { solidity: ["contracts", "attacks"] },
    // Mocha discovers test/**; test/attacks.test.js imports attacks/*/test.js.
    tests: { mocha: "test" },
  },
  test: { mocha: { timeout: 120_000 } },
});
