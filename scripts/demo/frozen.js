// The frozen demo setup (D27): one fixed proving key + verifier for the live
// Sepolia demo, committed under web/public/circuit/ so the browser can prove
// and the deployed DemoCredentialVerifier always matches it.
//
// Local development is unchanged: `npm run setup` still makes a fresh,
// machine-specific zkey (D15). Only the demo uses these files.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { ROOT } from "../circuits/compile.js";

export const FROZEN_DIR = path.join(ROOT, "web", "public", "circuit");
export const DEMO_VERIFIER_SOL = path.join(ROOT, "contracts", "demo", "DemoCredentialVerifier.sol");
export const DEMO_VERIFIER_CONTRACT = "DemoCredentialVerifier";

/** The files the browser downloads, by role. */
export const FROZEN_FILES = Object.freeze({
  wasm: "credential.wasm",
  zkey: "credential.zkey",
  vkey: "vkey.json",
});

export const sha256File = (f) => createHash("sha256").update(readFileSync(f)).digest("hex");

export function frozenPaths(dir = FROZEN_DIR) {
  return {
    dir,
    manifest: path.join(dir, "manifest.json"),
    ...Object.fromEntries(Object.entries(FROZEN_FILES).map(([k, f]) => [k, path.join(dir, f)])),
  };
}

export function loadManifest(dir = FROZEN_DIR) {
  return JSON.parse(readFileSync(frozenPaths(dir).manifest, "utf8"));
}

/**
 * Checks the frozen set for tampering or drift. Returns a list of problems
 * (empty = OK):
 *  - every file exists and hashes to the value in manifest.json;
 *  - the committed Solidity verifier hashes to the recorded value;
 *  - if `r1cs` is given, the current compiled circuit is the one that was frozen
 *    (a circuit edit without a re-freeze would make the demo key prove the old circuit).
 */
export function checkFrozen({ dir = FROZEN_DIR, verifierSol = DEMO_VERIFIER_SOL, r1cs } = {}) {
  const p = frozenPaths(dir);
  if (!existsSync(p.manifest)) return ["manifest.json is missing: run `npm run demo:freeze`"];
  const m = loadManifest(dir);
  const problems = [];
  for (const [role, file] of Object.entries(FROZEN_FILES)) {
    const full = p[role];
    if (!existsSync(full)) problems.push(`${file} is missing`);
    else if (sha256File(full) !== m.files[role].sha256) problems.push(`${file} does not match its manifest hash`);
  }
  if (!existsSync(verifierSol)) problems.push(`${path.basename(verifierSol)} is missing`);
  else if (sha256File(verifierSol) !== m.verifierSha256) problems.push(`${path.basename(verifierSol)} does not match its manifest hash`);
  if (r1cs && sha256File(r1cs) !== m.r1csSha256) {
    problems.push("the compiled circuit differs from the frozen one: re-freeze with `npm run demo:freeze -- --force` and redeploy the verifier");
  }
  return problems;
}
