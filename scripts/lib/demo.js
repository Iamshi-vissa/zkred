// End-to-end ZKred walkthrough. Used by scripts/demo.js (narrated) and by
// test/e2e/demo.test.js (asserted). Runs on whatever network `ethers` is
// connected to; every key is generated at runtime.

import { Wallet, formatUnits } from "ethers";
import { performance } from "node:perf_hooks";
import { deploySystem, revertReason } from "./deploy.js";
import { MerkleTree } from "./merkle.js";
import { createIdentity } from "./identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "./credential.js";
import { publishRoot } from "./issuer.js";
import { prove, toSolidityArgs } from "./prover.js";
import { timestampToYYYYMMDD } from "./dates.js";

const short = (x) => {
  const s = typeof x === "bigint" ? "0x" + x.toString(16) : String(x);
  return s.length > 18 ? `${s.slice(0, 10)}…${s.slice(-6)}` : s;
};

export async function runDemo(ethers, { log = console.log } = {}) {
  const say = (msg = "") => log(msg);
  const results = {};
  const [deployer, admin, aliceWallet, bobWallet, mallory] = await ethers.getSigners();
  const issuer = Wallet.createRandom();

  say("1. University deploys ZKred");
  const { registry, gate, token } = await deploySystem(ethers, { owner: admin, issuerAddress: issuer.address });
  say(`   Registry ${await registry.getAddress()}   owner ${short(admin.address)}   issuer ${short(issuer.address)}`);
  say(`   Gate     ${await gate.getAddress()}   token ZKRED ${await token.getAddress()}`);

  const now = (await ethers.provider.getBlock("latest")).timestamp;
  const today = timestampToYYYYMMDD(now);
  const year = Math.floor(today / 10000);
  const mmdd = today % 10000;

  say("\n2. Issuer enrols students and builds the Merkle tree (off-chain)");
  const tree = await MerkleTree.create();
  const students = {};
  for (const [name, birthDate] of [["alice", (year - 26) * 10000 + 115], ["bob", (year - 19) * 10000 + 701], ["charlie", (year - 17) * 10000 + mmdd]]) {
    // Each student generates secrets locally and hands the issuer only idCommitment.
    const identity = await createIdentity();
    const s = { name, identity, birthDate, credentialType: CREDENTIAL_TYPES.ENROLLED_STUDENT };
    s.leafIndex = tree.insert(await credentialLeaf({ idCommitment: identity.commitment, ...s }));
    students[name] = s;
    say(`   ${name.padEnd(8)} born ${birthDate}  idCommitment ${short(identity.commitment)}  leaf #${s.leafIndex}`);
  }
  say(`   root ${short(tree.root)}  (depth ${tree.depth}, ${tree.size}/${tree.capacity} leaves)`);

  say("\n3. Issuer signs RootUpdate(root, epoch=1) with EIP-712; anyone relays it");
  await publishRoot(registry, issuer, tree.root, { relayer: deployer });
  results.rootKnown = await registry.isKnownRoot(tree.root);
  say(`   registry.isKnownRoot(root) = ${results.rootKnown}, epoch = ${await registry.epoch()}`);

  const scope = await gate.scope();
  async function proofFor(student, recipient) {
    const input = await buildCircuitInput({ ...student, tree, scope, currentDate: today, recipient: recipient.address });
    const t0 = performance.now();
    const { proof, publicSignals } = await prove(input);
    const ms = performance.now() - t0;
    const { a, b, c } = toSolidityArgs(proof, publicSignals);
    return { args: [a, b, c, publicSignals[0], publicSignals[1], publicSignals[4]], nullifierHash: publicSignals[1], ms };
  }
  async function tryClaim(signer, args) {
    try {
      const rc = await (await gate.connect(signer).claim(...args)).wait();
      return { ok: true, gas: rc.gasUsed };
    } catch (e) {
      return { ok: false, reason: revertReason(e, gate) };
    }
  }

  say(`\n4. Alice proves (in zero knowledge) "I'm in the tree, over 18, nullifier for this gate" for her fresh address`);
  const aliceProof = await proofFor(students.alice, aliceWallet);
  say(`   proof generated in ${aliceProof.ms.toFixed(0)} ms; nullifierHash ${short(aliceProof.nullifierHash)}`);

  say("\n5. Mallory copies Alice's proof from the mempool and submits it first");
  results.frontRun = await tryClaim(mallory, aliceProof.args);
  say(`   -> ${results.frontRun.ok ? "SUCCEEDED (bug!)" : `rejected: ${results.frontRun.reason}`} (proof is bound to Alice's address)`);

  say("\n6. Alice claims");
  results.aliceClaim = await tryClaim(aliceWallet, aliceProof.args);
  results.aliceBalance = await token.balanceOf(aliceWallet.address);
  say(`   -> ${results.aliceClaim.ok ? "OK" : results.aliceClaim.reason}, gas ${results.aliceClaim.gas}; balance ${formatUnits(results.aliceBalance, 18)} ZKRED`);

  say("\n7. Alice tries to claim again with a brand-new proof");
  results.aliceAgain = await tryClaim(aliceWallet, (await proofFor(students.alice, aliceWallet)).args);
  say(`   -> ${results.aliceAgain.ok ? "SUCCEEDED (bug!)" : `rejected: ${results.aliceAgain.reason}`} (same nullifier)`);

  say("\n8. Charlie (17, turns 18 a year from today) tries to prove");
  try {
    await proofFor(students.charlie, mallory);
    results.charlieProved = true;
  } catch {
    results.charlieProved = false;
  }
  say(`   -> ${results.charlieProved ? "proof produced (bug!)" : "no proof can be generated: the age constraint is unsatisfiable"}`);

  say("\n9. Bob claims");
  results.bobClaim = await tryClaim(bobWallet, (await proofFor(students.bob, bobWallet)).args);
  results.bobBalance = await token.balanceOf(bobWallet.address);
  say(`   -> ${results.bobClaim.ok ? "OK" : results.bobClaim.reason}; balance ${formatUnits(results.bobBalance, 18)} ZKRED`);

  say("\n10. What the chain learned");
  const claims = await gate.queryFilter(gate.filters.Claimed());
  results.claimEvents = claims.map((e) => ({ recipient: e.args.recipient, nullifierHash: e.args.nullifierHash }));
  for (const e of results.claimEvents) say(`   Claimed(recipient ${short(e.recipient)}, nullifierHash ${short(e.nullifierHash)})`);
  say("   Not on chain: names, idCommitments, leaves, birth dates, or which leaf each claim used.");
  say(`   Total supply: ${formatUnits(await token.totalSupply(), 18)} ZKRED`);
  return results;
}
