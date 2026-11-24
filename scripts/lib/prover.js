// Groth16 proving/verification helpers around snarkjs.

import { readFileSync } from "node:fs";
import * as snarkjs from "snarkjs";
import { MERKLE_DEPTH } from "../../zkred.config.js";
import { circuitPaths } from "../circuits/compile.js";
import { setupPaths, isSetupCurrent } from "../circuits/setup.js";

/** Paths (and parsed vkey) for a circuit's setup; `id` is a key of scripts/circuits/registry.js. */
export function artifacts(depth = MERKLE_DEPTH, id = "credential") {
  if (!isSetupCurrent(depth, id)) {
    throw new Error(`trusted setup for '${id}' at depth ${depth} is missing or stale: run \`npm run setup\``);
  }
  const { wasm, r1cs } = circuitPaths(depth, id);
  const { zkey, vkey } = setupPaths(depth, id);
  return { wasm, r1cs, zkey, vkey: JSON.parse(readFileSync(vkey, "utf8")) };
}

/** Witness + Groth16 proof. Throws if the input does not satisfy the circuit. */
export async function prove(input, depth = MERKLE_DEPTH, id = "credential") {
  const { wasm, zkey } = artifacts(depth, id);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  return { proof, publicSignals: publicSignals.map(BigInt) };
}

/** Off-chain verification with the verification key. */
export async function verifyOffchain(proof, publicSignals, depth = MERKLE_DEPTH, id = "credential") {
  const { vkey } = artifacts(depth, id);
  return snarkjs.groth16.verify(vkey, publicSignals.map(String), proof);
}

/**
 * Formats a snarkjs proof for the generated Solidity verifier:
 * verifyProof(uint[2] a, uint[2][2] b, uint[2] c, uint[N] pubSignals).
 * G2 coordinates are swapped: snarkjs stores Fp2 as (c0, c1), while the EVM
 * pairing precompile (EIP-197) expects (c1, c0).
 */
export function toSolidityArgs(proof, publicSignals) {
  const a = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
  const b = [
    [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
    [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
  ];
  const c = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
  return { a, b, c, pubSignals: publicSignals.map(BigInt) };
}

