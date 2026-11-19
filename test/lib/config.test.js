import { expect } from "chai";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CONFIG = fileURLToPath(new URL("../../zkred.config.js", import.meta.url));

function depthWith(env) {
  return execFileSync(
    process.execPath,
    ["--input-type=module", "-e", `const c = await import(${JSON.stringify(CONFIG)}); console.log(c.MERKLE_DEPTH);`],
    { env: { ...process.env, ZKRED_MERKLE_DEPTH: env }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
}

describe("zkred.config.js", () => {
  it("MERKLE_DEPTH defaults to 10", () => {
    expect(depthWith("")).to.equal("10");
  });

  for (const d of ["16", "20"]) {
    it(`ZKRED_MERKLE_DEPTH=${d} is honoured`, () => {
      expect(depthWith(d)).to.equal(d);
    });
  }

  it("rejects unsupported depths", () => {
    for (const bad of ["12", "abc", "-1"]) {
      expect(() => depthWith(bad), bad).to.throw(/not supported/);
    }
  });
});
