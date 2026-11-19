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

// Powers of Tau (phase 1) from the public PSE Perpetual Powers of Tau ceremony
// (continuation of the Hermez/Zcash ceremony; 80 contributions). The setup
// script picks the smallest power that fits the circuit, downloads it if
// missing, and refuses to use a file whose SHA-256 does not match.
// Depth 10 needs 2^12; depths 16 and 20 need 2^13.
export const PTAU = Object.freeze({
  12: {
    url: "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_12.ptau",
    sha256: "35e163120e724a60853d0dd76ec54037f7c7b00584392255f71a4341d5a05c50",
  },
  13: {
    url: "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_13.ptau",
    sha256: "ccee28086e4b81d81a6e16fdee054d1dbd5276362e2662d4205d31de45cb930f",
  },
});
