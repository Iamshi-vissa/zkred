// Live-demo enrolment helpers, shared by /api/enrol, the deploy script and tests.
//
// The tree is never stored anywhere except the chain: EnrolmentLog emits one
// Enrolled(index, leaf, root) event per leaf, and rebuildTree replays them.

import { MerkleTree } from "../lib/merkle.js";
import { signRootUpdate } from "../lib/issuer.js";
import { MERKLE_DEPTH } from "../../zkred.config.js";

/** Reads every Enrolled event (from the log's deploy block) in index order. */
export async function enrolledLeaves(log) {
  const fromBlock = Number(await log.deployBlock());
  const events = await log.queryFilter(log.filters.Enrolled(), fromBlock);
  const leaves = events.map((e) => ({ index: e.args.index, leaf: e.args.leaf })).sort((a, b) => (a.index < b.index ? -1 : 1));
  leaves.forEach((l, i) => {
    if (l.index !== BigInt(i)) throw new Error(`EnrolmentLog: missing leaf at index ${i}`);
  });
  return leaves.map((l) => l.leaf);
}

/** Rebuilds the issuer's tree from chain data and checks it against the Registry. */
export async function rebuildTree(log, registry, depth = MERKLE_DEPTH) {
  const tree = await MerkleTree.create({ depth, leaves: await enrolledLeaves(log) });
  if (tree.leaves.length > 0 && tree.root !== (await registry.latestRoot())) {
    throw new Error("tree rebuilt from EnrolmentLog does not match Registry.latestRoot");
  }
  return tree;
}

/**
 * Issuer + relayer side of an enrolment: appends `leaf` to the chain tree,
 * signs the new root with `issuer` and sends one EnrolmentLog.enrol tx from
 * `relayer`. Returns { index, root, receipt }.
 */
export async function enrolLeaf({ log, registry, issuer, relayer, leaf, depth = MERKLE_DEPTH }) {
  const tree = await rebuildTree(log, registry, depth);
  const index = tree.insert(leaf);
  const root = tree.root;
  const epoch = (await registry.epoch()) + 1n;
  const { chainId } = await registry.runner.provider.getNetwork();
  const signature = await signRootUpdate(issuer, { chainId, registry: await registry.getAddress(), root, epoch });
  const receipt = await (await log.connect(relayer).enrol(leaf, root, epoch, signature)).wait();
  return { index: BigInt(index), root, receipt };
}
