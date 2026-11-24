import { configVariable, defineConfig } from "hardhat/config";
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
  networks: {
    // Live demo (docs/live-demo.md). Both values come from the encrypted
    // Hardhat keystore (`npx hardhat keystore set <NAME>`), never from a file
    // in the repo; they are only read when --network sepolia is used.
    sepolia: {
      type: "http",
      chainType: "l1",
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_DEPLOYER_KEY")],
    },
  },
});
