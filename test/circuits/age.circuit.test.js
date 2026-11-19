import path from "node:path";
import { compileCircuit, expectWitnessRejected, ROOT } from "./helpers.js";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

describe("circuit: lib/age.circom AgeAtLeast(18)", function () {
  this.timeout(180_000);
  let circuit;

  before(async () => {
    circuit = await compileCircuit(path.join(ROOT, "circuits/lib/age.circom"), {
      templateName: "AgeAtLeast",
      templateParams: [18],
    });
  });

  const ok = async (birthDate, currentDate) => {
    const w = await circuit.calculateWitness({ birthDate, currentDate }, true);
    await circuit.checkConstraints(w);
  };

  it("[C7] accepts someone well over 18", () => ok(19900101, 20261119));
  it("[C7] accepts someone turning 18 exactly today", () => ok(20081119, 20261119));
  it("[C7] accepts a 29-Feb birthday on 1 Mar of the 18th (non-leap) year", () => ok(20080229, 20260301));
  it("[C7] accepts a 29-Feb birthday on 29 Feb of a leap 18th year", () => ok(20060229, 20240229));

  it("[C7] negative: one day short of 18 is rejected", () =>
    expectWitnessRejected(circuit, { birthDate: 20081120, currentDate: 20261119 }));

  it("[C7] negative: 29-Feb birthday is still 17 on 28 Feb", () =>
    expectWitnessRejected(circuit, { birthDate: 20080229, currentDate: 20260228 }));

  it("[C7] negative: born in the future is rejected", () =>
    expectWitnessRejected(circuit, { birthDate: 20300101, currentDate: 20261119 }));

  it("[C6] negative: birthDate = r - 1 ('negative one') is rejected, not wrapped into a huge age", () =>
    expectWitnessRejected(circuit, { birthDate: SNARK_FIELD_SIZE - 1n, currentDate: 20261119 }));

  it("[C6] negative: birthDate >= 2^32 is rejected", () =>
    expectWitnessRejected(circuit, { birthDate: 2n ** 32n, currentDate: 20261119 }));

  it("[C6] negative: currentDate >= 2^32 is rejected (prover can't claim a far-future date)", () =>
    expectWitnessRejected(circuit, { birthDate: 20081120, currentDate: 2n ** 32n + 20261119n }));
});
