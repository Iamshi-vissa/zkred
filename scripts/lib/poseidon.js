// Poseidon hash over BN254, backed by circomlibjs (the reference JS
// implementation matching circomlib's Poseidon circuit, same constants).
//
// Poseidon is used instead of Keccak/SHA-256 because it is "arithmetization
// friendly": ~240 R1CS constraints for a 2-input hash vs ~150k for Keccak.
// Each arity (number of inputs) uses a different parameter set, so
// Poseidon(2) and Poseidon(3) behave as independent hash functions.

import { buildPoseidon } from "circomlibjs";
import { toFieldElement } from "./field.js";

let poseidonPromise;
let poseidonInstance;

/** Builds the hasher once; safe to call repeatedly. */
export async function initPoseidon() {
  poseidonPromise ??= buildPoseidon().then((p) => (poseidonInstance = p));
  return poseidonPromise;
}

/**
 * Poseidon over 1..16 field elements. Returns a bigint.
 * Inputs outside [0, r) are rejected rather than silently reduced.
 */
export async function poseidon(inputs) {
  return poseidonWith(await initPoseidon(), inputs);
}

/**
 * Synchronous variant; requires `await initPoseidon()` first.
 * Used by the Merkle tree to avoid thousands of awaits.
 */
export function poseidonSync(inputs) {
  if (!poseidonInstance) throw new Error("call await initPoseidon() first");
  return poseidonWith(poseidonInstance, inputs);
}

function poseidonWith(p, inputs) {
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > 16) {
    throw new RangeError("poseidon expects an array of 1..16 inputs");
  }
  const xs = inputs.map((x, i) => toFieldElement(x, `poseidon input[${i}]`));
  return p.F.toObject(p(xs));
}
