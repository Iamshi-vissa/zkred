// Single source of truth for protocol parameters shared by circuits,
// off-chain tooling, contracts and tests.
//
// MERKLE_DEPTH can be overridden for benchmarking, e.g.
//   ZKRED_MERKLE_DEPTH=16 npm test
// Supported values: 10 (default), 16, 20.

const SUPPORTED_DEPTHS = [10, 16, 20];

function readDepth() {
  const raw = process.env.ZKRED_MERKLE_DEPTH;
  if (raw === undefined || raw === "") return 10;
  const depth = Number(raw);
  if (!SUPPORTED_DEPTHS.includes(depth)) {
    throw new Error(
      `ZKRED_MERKLE_DEPTH=${raw} is not supported; use one of ${SUPPORTED_DEPTHS.join(", ")}`,
    );
  }
  return depth;
}

export const MERKLE_DEPTH = readDepth();
export { SUPPORTED_DEPTHS };
