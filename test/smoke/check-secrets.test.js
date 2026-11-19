import { expect } from "chai";
import { scanContent } from "../../scripts/check-secrets.js";

// A random-looking key that is NOT a Hardhat dev key. Built at runtime so this
// test file itself never contains a key-shaped literal next to a keyword.
const FAKE = "0x" + "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d".split("").reverse().join("");
// Hardhat account #0 - public, published in Hardhat's docs.
const HH0 = "0x" + "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

describe("smoke: check-secrets", () => {
  it("flags a planted private key", () => {
    const f = scanContent(`const PRIVATE_KEY = "${FAKE}";`, "x.js");
    expect(f).to.have.length(1);
    expect(f[0].line).to.equal(1);
  });

  it("flags keys under other names (secret, mnemonic, signer key)", () => {
    for (const name of ["issuerSecret", "MNEMONIC_SEED", "signer_key"]) {
      expect(scanContent(`${name} = ${FAKE}`, "x.js"), name).to.have.length(1);
    }
  });

  it("flags PEM private keys", () => {
    expect(scanContent(["-----BEGIN", "EC PRIVATE KEY-----"].join(" "), "k.pem")).to.have.length(1);
  });

  it("flags .env files but not .env.example", () => {
    expect(scanContent("", ".env")).to.have.length(1);
    expect(scanContent("", "config/.env.local")).to.have.length(1);
    expect(scanContent("", ".env.example")).to.have.length(0);
  });

  it("allows Hardhat's public dev-account keys", () => {
    expect(scanContent(`privateKey: "${HH0}"`, "x.js")).to.have.length(0);
  });

  it("does not flag 32-byte hashes on lines without a key keyword", () => {
    expect(scanContent(`const expectedRoot = "${FAKE}";`, "x.js")).to.have.length(0);
  });

  it("respects the explicit allow marker", () => {
    expect(scanContent(`privateKey = "${FAKE}"; // check-secrets: allow`, "x.js")).to.have.length(0);
  });
});
