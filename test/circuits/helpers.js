// Shared helpers for circuit tests (circom_tester, compiled with --O2 like
// the production build in scripts/circuits/compile.js).
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { expect } from "chai";
import { SNARK_FIELD_SIZE } from "../../scripts/lib/field.js";

const require = createRequire(import.meta.url);
const wasmTester = require("circom_tester").wasm;
export const ROOT = fileURLToPath(new URL("../..", import.meta.url));

/** Compiles a circuit file (with or without its own `main`). */
export async function compileCircuit(file, options = {}) {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), "zkred-circuit-"));
  return wasmTester(file, { include: [path.join(ROOT, "node_modules")], output, O: 2, ...options });
}

/** Asserts that honest witness generation rejects `input` (an assert / === fails). */
export async function expectWitnessRejected(circuit, input, label = "") {
  let error;
  try {
    await circuit.calculateWitness(input, true);
  } catch (e) {
    error = e;
  }
  expect(error, `witness generation should fail ${label}`).to.not.equal(undefined);
}

/**
 * Patches one signal in a valid witness and asserts the R1CS rejects it.
 * This models an attacker who skips the witness generator and edits the
 * .wtns file directly (lab 01): only the constraints stand in the way.
 */
export async function expectTamperRejected(circuit, witness, signal, newValue) {
  await circuit.loadSymbols();
  const sym = circuit.symbols[`main.${signal}`];
  expect(sym, `symbol main.${signal}`).to.not.equal(undefined);
  expect(sym.varIdx, `main.${signal} was optimised away`).to.be.greaterThan(0);
  const tampered = [...witness];
  tampered[sym.varIdx] = ((newValue % SNARK_FIELD_SIZE) + SNARK_FIELD_SIZE) % SNARK_FIELD_SIZE;
  expect(tampered[sym.varIdx]).to.not.equal(witness[sym.varIdx]);
  let error;
  try {
    await circuit.checkConstraints(tampered);
  } catch (e) {
    error = e;
  }
  expect(error, `tampering main.${signal} should violate a constraint`).to.not.equal(undefined);
}
