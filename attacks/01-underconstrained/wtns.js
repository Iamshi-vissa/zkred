// =====================================================================
// ATTACKER TOOLING for lab 01b - hand-rolled on purpose (attacks/ only).
//
// Reads and patches snarkjs/circom .wtns witness files. Format (iden3 binfile):
//   "wtns" | version u32 | nSections u32 | sections...
//   section = type u32 | size u64 | data
//   section 1 (header):  n8 u32 | prime q (n8 bytes LE) | nWitness u32
//   section 2 (values):  nWitness field elements, n8 bytes each, little-endian
// Wire 0 is the constant 1; public outputs come next, then public inputs.
// =====================================================================

import { readFileSync, writeFileSync } from "node:fs";

function parse(buf) {
  if (buf.toString("ascii", 0, 4) !== "wtns") throw new Error("not a .wtns file");
  const nSections = buf.readUInt32LE(8);
  let pos = 12;
  const sections = {};
  for (let i = 0; i < nSections; i++) {
    const type = buf.readUInt32LE(pos);
    const size = Number(buf.readBigUInt64LE(pos + 4));
    sections[type] = { start: pos + 12, size };
    pos += 12 + size;
  }
  const h = sections[1].start;
  const n8 = buf.readUInt32LE(h);
  const nWitness = buf.readUInt32LE(h + 4 + n8);
  return { n8, nWitness, valuesStart: sections[2].start };
}

const readLE = (buf, start, n8) => {
  let v = 0n;
  for (let i = n8 - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[start + i]);
  return v;
};

/** Returns { nWitness, values: bigint[] }. */
export function readWitness(file) {
  const buf = readFileSync(file);
  const { n8, nWitness, valuesStart } = parse(buf);
  const values = Array.from({ length: nWitness }, (_, i) => readLE(buf, valuesStart + i * n8, n8));
  return { nWitness, values };
}

/** Copies `inFile` to `outFile` with wire `index` overwritten by `value`. */
export function patchWitness(inFile, outFile, index, value) {
  const buf = Buffer.from(readFileSync(inFile));
  const { n8, nWitness, valuesStart } = parse(buf);
  if (index <= 0 || index >= nWitness) throw new RangeError(`wire ${index} out of range (1..${nWitness - 1})`);
  let v = BigInt(value);
  for (let i = 0; i < n8; i++) {
    buf[valuesStart + index * n8 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  writeFileSync(outFile, buf);
}

/** Wire index of a signal (e.g. "main.isAdult") from a circom .sym file; -1 if optimised away. */
export function wireIndex(symFile, signal) {
  for (const line of readFileSync(symFile, "utf8").split("\n")) {
    const [, varIdx, , name] = line.split(",");
    if (name === signal) return Number(varIdx);
  }
  throw new Error(`signal ${signal} not found in ${symFile}`);
}
