#!/usr/bin/env node
// Groth16 trusted setup for the credential circuit at MERKLE_DEPTH.
//
//   npm run setup                         # depth 10
//   ZKRED_MERKLE_DEPTH=16 npm run setup
//   npm run setup -- --force              # redo even if up to date
//
// Steps
//  1. compile the circuit (circom --O2)
//  2. phase 1: public PSE Perpetual Powers of Tau, SHA-256 pinned in zkred.config.js
//  3. phase 2 (circuit-specific): new zkey -> one local contribution with fresh
//     random entropy (never stored) -> random beacon -> verify against r1cs+ptau
//  4. export the verification key and the Solidity verifier
//     (contracts/verifiers/CredentialVerifier.sol, generated, not committed)
//
// Security note: phase 2 here has ONE local contributor. Its secret (δ) is
// discarded when this process exits, but nobody else can confirm that. A real
// deployment runs a multi-party phase 2 (see lab 05, toxic waste).
//
// Outputs are NOT committed (owner decision D15): every machine runs setup,
// so the verifier contract differs per machine. The manifest makes reruns
// idempotent: if the r1cs and ptau are unchanged, setup is skipped.

import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";
import * as snarkjs from "snarkjs";
import { MERKLE_DEPTH, PTAU } from "../../zkred.config.js";
import { compileCircuit, circuitPaths, ROOT } from "./compile.js";

export const PTAU_DIR = path.join(ROOT, "build", "ptau");
export const SETUP_DIR = path.join(ROOT, "build", "setup");
export const VERIFIER_SOL = path.join(ROOT, "contracts", "verifiers", "CredentialVerifier.sol");

export function setupPaths(depth = MERKLE_DEPTH) {
  const base = path.join(SETUP_DIR, `credential_d${depth}`);
  return {
    zkey0: `${base}_0000.zkey`,
    zkey1: `${base}_0001.zkey`,
    zkey: `${base}_final.zkey`,
    vkey: `${base}_vkey.json`,
    manifest: `${base}_manifest.json`,
  };
}

const sha256File = (f) => createHash("sha256").update(readFileSync(f)).digest("hex");

/** Smallest pinned power p with 2^p > constraints + public inputs + outputs. */
export function choosePower({ nConstraints, nPubInputs, nOutputs }) {
  const needed = nConstraints + nPubInputs + nOutputs + 1;
  const power = Object.keys(PTAU).map(Number).sort((a, b) => a - b).find((p) => 2 ** p >= needed);
  if (power === undefined) throw new Error(`circuit needs ${needed} rows; no pinned ptau is large enough`);
  return power;
}

/** Ensures the ptau for `power` exists locally and matches its pinned hash. */
export async function ensurePtau(power, log = console.log) {
  const { url, sha256 } = PTAU[power];
  const file = path.join(PTAU_DIR, path.basename(new URL(url).pathname));
  if (!existsSync(file)) {
    mkdirSync(PTAU_DIR, { recursive: true });
    log(`downloading ${url}`);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`ptau download failed: HTTP ${res.status}`);
    writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  }
  checkSha256(file, sha256);
  return file;
}

/** Throws unless `file` hashes to `expected` (guards against a swapped ptau). */
export function checkSha256(file, expected) {
  const actual = sha256File(file);
  if (actual !== expected) {
    throw new Error(`${file} has sha256 ${actual}, expected ${expected}; delete it and retry`);
  }
}

export function isSetupCurrent(depth = MERKLE_DEPTH) {
  const p = setupPaths(depth);
  const c = circuitPaths(depth);
  if (![p.manifest, p.zkey, p.vkey, c.r1cs, c.wasm, VERIFIER_SOL].every(existsSync)) return false;
  const m = JSON.parse(readFileSync(p.manifest, "utf8"));
  return m.depth === depth && m.r1csSha256 === sha256File(c.r1cs) && m.zkeySha256 === sha256File(p.zkey);
}

export async function runSetup({ depth = MERKLE_DEPTH, force = false, log = console.log } = {}) {
  // Always recompile: a circuit edit must invalidate the setup.
  log(`compiling Credential(${depth})`);
  const c = compileCircuit(depth, { quiet: true });
  if (!force && isSetupCurrent(depth)) {
    log("setup is up to date (r1cs unchanged); use --force to redo");
    return;
  }

  const p = setupPaths(depth);
  mkdirSync(SETUP_DIR, { recursive: true });
  mkdirSync(path.dirname(VERIFIER_SOL), { recursive: true });

  const info = await snarkjs.r1cs.info(c.r1cs);
  const power = choosePower(info);
  log(`${info.nConstraints} constraints, ${info.nPubInputs} public inputs -> ptau 2^${power}`);
  const ptau = await ensurePtau(power, log);

  log("phase 2: new zkey");
  await snarkjs.zKey.newZKey(c.r1cs, ptau, p.zkey0);

  log("phase 2: local contribution (entropy is random and discarded)");
  await snarkjs.zKey.contribute(p.zkey0, p.zkey1, "zkred local contributor", randomBytes(64).toString("hex"));

  const beacon = randomBytes(32).toString("hex");
  log("phase 2: beacon");
  await snarkjs.zKey.beacon(p.zkey1, p.zkey, "zkred final beacon", beacon, 10);
  rmSync(p.zkey0);
  rmSync(p.zkey1);

  log("verifying final zkey against r1cs + ptau");
  if (!(await snarkjs.zKey.verifyFromR1cs(c.r1cs, ptau, p.zkey))) throw new Error("zkey verification FAILED");

  const vkey = await snarkjs.zKey.exportVerificationKey(p.zkey);
  writeFileSync(p.vkey, JSON.stringify(vkey, null, 2));

  const template = readFileSync(path.join(ROOT, "node_modules/snarkjs/templates/verifier_groth16.sol.ejs"), "utf8");
  const sol = (await snarkjs.zKey.exportSolidityVerifier(p.zkey, { groth16: template }))
    .replace("contract Groth16Verifier", "contract CredentialVerifier");
  writeFileSync(
    VERIFIER_SOL,
    `// GENERATED by scripts/circuits/setup.js from ${path.basename(p.zkey)} (depth ${depth}).\n` +
      `// Do not edit; not committed. Rerun \`npm run setup\` to regenerate.\n` +
      sol,
  );

  writeFileSync(
    p.manifest,
    JSON.stringify(
      {
        depth,
        nConstraints: info.nConstraints,
        ptau: path.basename(ptau),
        ptauSha256: PTAU[power].sha256,
        r1csSha256: sha256File(c.r1cs),
        zkeySha256: sha256File(p.zkey),
        beacon,
        createdAt: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  log(`done: ${path.relative(ROOT, p.zkey)}, ${path.relative(ROOT, VERIFIER_SOL)}`);
}

/** snarkjs keeps worker threads alive; release them so node can exit. */
export async function releaseCurves() {
  await globalThis.curve_bn128?.terminate();
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await runSetup({ force: process.argv.includes("--force") });
  } finally {
    await releaseCurves();
  }
}
