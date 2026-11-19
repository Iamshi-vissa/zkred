import { expect } from "chai";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { poseidon } from "../../scripts/lib/poseidon.js";
import { randomFieldElement } from "../../scripts/lib/field.js";
import { DOMAIN_IDENTITY, DOMAIN_NULLIFIER } from "../../scripts/lib/identity.js";

const require = createRequire(import.meta.url);
const wasmTester = require("circom_tester").wasm;
const ROOT = fileURLToPath(new URL("../..", import.meta.url));

async function compile(n) {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), `zkred-poseidon${n}-`));
  return wasmTester(path.join(ROOT, "test/circuits/fixtures/poseidon_parity.circom"), {
    templateName: "PoseidonParity",
    templateParams: [n],
    include: [path.join(ROOT, "node_modules")],
    output,
  });
}

describe("circuit/JS parity: Poseidon", function () {
  this.timeout(180_000);

  // Arity 2: Merkle nodes. Arity 3: identity commitment and nullifier.
  for (const n of [2, 3]) {
    describe(`Poseidon(${n})`, () => {
      let circuit;
      before(async () => (circuit = await compile(n)));

      it("circuit output equals circomlibjs output on random inputs", async () => {
        for (let k = 0; k < 5; k++) {
          const inputs = Array.from({ length: n }, randomFieldElement);
          const w = await circuit.calculateWitness({ inputs }, true);
          await circuit.checkConstraints(w);
          await circuit.assertOut(w, { out: await poseidon(inputs) });
        }
      });

      if (n === 3) {
        it("matches lib/identity's domain-tagged commitment and nullifier formulas", async () => {
          for (const tag of [DOMAIN_IDENTITY, DOMAIN_NULLIFIER]) {
            const inputs = [tag, randomFieldElement(), randomFieldElement()];
            const w = await circuit.calculateWitness({ inputs }, true);
            await circuit.assertOut(w, { out: await poseidon(inputs) });
          }
        });
      }

      it("negative: a wrong claimed output fails the check", async () => {
        const inputs = Array.from({ length: n }, (_, i) => BigInt(i + 1));
        const w = await circuit.calculateWitness({ inputs }, true);
        let threw = false;
        try {
          await circuit.assertOut(w, { out: (await poseidon(inputs)) + 1n });
        } catch {
          threw = true;
        }
        expect(threw).to.equal(true);
      });
    });
  }
});
