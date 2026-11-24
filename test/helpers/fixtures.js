// Deploys the full ZKred system on a fresh Hardhat network and provides
// helpers to enrol students and generate claim proofs.
import { network } from "hardhat";
import { Wallet } from "ethers";
import { MerkleTree } from "../../scripts/lib/merkle.js";
import { createIdentity } from "../../scripts/lib/identity.js";
import { credentialLeaf, buildCircuitInput, CREDENTIAL_TYPES } from "../../scripts/lib/credential.js";
import { publishRoot } from "../../scripts/lib/issuer.js";
import { prove, toSolidityArgs } from "../../scripts/lib/prover.js";
import { deploySystem } from "../../scripts/lib/deploy.js";

// Chain clock for tests: 2027-03-15 12:00:00 UTC (must be after "now").
export const TODAY = 20270315;
export const YESTERDAY = 20270314;
export const NOON_TODAY = Date.UTC(2027, 2, 15, 12) / 1000;

export async function deployZkred({ credentialType = CREDENTIAL_TYPES.ENROLLED_STUDENT, actionId = 1n } = {}) {
  const conn = await network.create();
  const { ethers, networkHelpers } = conn;
  const [deployer, owner, alice, bob, mallory] = await ethers.getSigners();
  const issuer = Wallet.createRandom(); // runtime key, never written to disk

  const { registry, verifier, gate, token } = await deploySystem(ethers, { owner, issuerAddress: issuer.address, actionId, credentialType });
  await networkHelpers.time.increaseTo(NOON_TODAY);

  const tree = await MerkleTree.create();
  const students = {};

  /** Adds a student leaf to the (off-chain) issuer tree. */
  async function enrol(name, { birthDate = 20000115, type = CREDENTIAL_TYPES.ENROLLED_STUDENT } = {}) {
    const identity = await createIdentity();
    const s = { name, identity, birthDate, credentialType: type };
    s.leafIndex = tree.insert(await credentialLeaf({ idCommitment: identity.commitment, ...s }));
    students[name] = s;
    return s;
  }

  /** Issuer signs and publishes the current tree root. */
  const publish = (signer = issuer) => publishRoot(registry, signer, tree.root, { relayer: deployer });

  /** Builds a proof for `student` claiming at `gateContract` as `recipient`. */
  async function proofFor(student, { recipient, gateContract = gate, currentDate = TODAY, scope } = {}) {
    const input = await buildCircuitInput({
      ...student,
      tree,
      scope: scope ?? (await gateContract.scope()),
      currentDate,
      recipient: recipient.address ?? recipient,
    });
    const { proof, publicSignals } = await prove(input);
    const { a, b, c } = toSolidityArgs(proof, publicSignals);
    return { a, b, c, root: publicSignals[0], nullifierHash: publicSignals[1], currentDate: publicSignals[4], publicSignals };
  }

  const claimArgs = (p) => [p.a, p.b, p.c, p.root, p.nullifierHash, p.currentDate];

  return { conn, ethers, networkHelpers, deployer, owner, alice, bob, mallory, issuer, registry, verifier, gate, token, tree, students, enrol, publish, proofFor, claimArgs };
}
