import { expect } from "chai";
import { mkdtempSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { choosePower, checkSha256, isSetupCurrent, ensurePtau } from "../../scripts/circuits/setup.js";
import { MERKLE_DEPTH, PTAU } from "../../zkred.config.js";
import { CIRCUITS } from "../../scripts/circuits/registry.js";

describe("trusted setup tooling", () => {
  it("setup for every registered circuit is present and current (pretest ran it)", () => {
    for (const id of Object.keys(CIRCUITS)) expect(isSetupCurrent(MERKLE_DEPTH, id), id).to.equal(true);
  });

  it("choosePower picks the smallest pinned ptau that fits", () => {
    expect(choosePower({ nConstraints: 3338, nPubInputs: 6, nOutputs: 0 })).to.equal(12);
    expect(choosePower({ nConstraints: 4089, nPubInputs: 6, nOutputs: 0 })).to.equal(12); // 4096 rows exactly
    expect(choosePower({ nConstraints: 4090, nPubInputs: 6, nOutputs: 0 })).to.equal(13);
    expect(choosePower({ nConstraints: 10936, nPubInputs: 6, nOutputs: 1 })).to.equal(14); // lab 01b (--O0)
  });

  it("negative: choosePower refuses circuits larger than every pinned ptau", () => {
    expect(() => choosePower({ nConstraints: 2 ** 20, nPubInputs: 6, nOutputs: 0 })).to.throw(/no pinned ptau/);
  });

  it("the pinned 2^12 ptau on disk matches its SHA-256", async () => {
    const file = await ensurePtau(12, () => {});
    expect(() => checkSha256(file, PTAU[12].sha256)).to.not.throw();
  });

  it("negative: a tampered ptau file is rejected by its pinned hash", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "zkred-ptau-"));
    const copy = path.join(dir, "evil.ptau");
    copyFileSync(await ensurePtau(12, () => {}), copy);
    writeFileSync(copy, "x", { flag: "a" }); // append one byte
    expect(() => checkSha256(copy, PTAU[12].sha256)).to.throw(/sha256/);
  });
});
