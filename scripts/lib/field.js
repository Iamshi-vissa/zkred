// BN254 scalar field helpers.
//
// Every value that enters a Circom circuit is an element of the BN254 scalar
// field F_r. Values >= r silently wrap around inside the circuit, so off-chain
// code rejects them up front instead of letting them alias another value.

import { randomBytes } from "node:crypto";

/** BN254 scalar field modulus r (a.k.a. SNARK_SCALAR_FIELD). */
export const SNARK_FIELD_SIZE =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Converts `value` to a bigint and checks 0 <= value < r.
 * Accepts bigint, safe integer numbers and decimal/0x-hex strings.
 */
export function toFieldElement(value, name = "value") {
  let v;
  if (typeof value === "bigint") v = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError(`${name} must be a safe integer`);
    v = BigInt(value);
  } else if (typeof value === "string" && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) {
    v = BigInt(value);
  } else {
    throw new TypeError(`${name} must be a bigint, safe integer or numeric string`);
  }
  if (v < 0n || v >= SNARK_FIELD_SIZE) {
    throw new RangeError(`${name} is outside the BN254 scalar field [0, r)`);
  }
  return v;
}

/**
 * Uniformly random field element via rejection sampling: draw 254 bits and
 * retry if >= r. (Reducing 256 random bits mod r would bias small values.)
 */
export function randomFieldElement() {
  for (;;) {
    const bytes = randomBytes(32);
    bytes[0] &= 0x3f; // keep 254 bits
    const v = BigInt("0x" + bytes.toString("hex"));
    if (v < SNARK_FIELD_SIZE && v !== 0n) return v;
  }
}
