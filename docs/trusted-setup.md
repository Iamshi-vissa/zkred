# Trusted setup (Groth16)

Groth16 needs a structured reference string (SRS) generated from secret
randomness ("toxic waste"). Anyone who knows that randomness can forge proofs
for false statements, e.g. "this unregistered person is an adult". The setup
has two phases.

## Phase 1: Powers of Tau (universal)
Source: the **PSE Perpetual Powers of Tau** ceremony, file `ppot_0080_<p>.ptau`
(continuing the Zcash/Hermez ceremony). The file records **62 contributions**,
ending in a random beacon. Phase 1 is secure if **at least one** of those
contributors destroyed their randomness. (`0080` in the file name is the
ceremony's response number, not the contribution count.)

| Power | Used for | SHA-256 (pinned in `zkred.config.js`) |
|---|---|---|
| 2¹² | depth 10 (3,338 constraints) | `35e163120e724a60853d0dd76ec54037f7c7b00584392255f71a4341d5a05c50` |
| 2¹³ | depths 16 and 20 | `ccee28086e4b81d81a6e16fdee054d1dbd5276362e2662d4205d31de45cb930f` |
| 2¹⁴ | lab 01b circuits (`--O0`, 10,936 constraints) | `3ca1149e9349b22b0ee0649399cfb787677129b7b1189d1899fc0d615d9583db` |

The hashes were recorded when the files were first downloaded (trust on first
use). They were then checked independently:

```bash
npx snarkjs powersoftau verify build/ptau/ppot_0080_12.ptau
```

recomputes the whole contribution chain. Result for the 2¹² file: **`Powers of
Tau Ok!`**, with all 62 contributions (#1 to #62) checked. It took well over 30
minutes on a 4-core sandbox, so it is a one-off check, not part of
`npm run setup`. The 2¹⁴ file (`ppot_0080_14.ptau`, used by the lab 01b
circuits) was verified the same way: **`Powers of Tau Ok!`**, 62
contributions. The 2¹³ file is pinned by hash but has not been chain-verified
yet. `npm run setup` downloads the
file if it is missing and refuses to continue if the hash differs.

> The older Hermez URLs (`hermez.s3-eu-west-1.amazonaws.com`,
> `storage.googleapis.com/zkevm/ptau`) now return *AccessDenied* from the
> buckets themselves, which is why the PSE continuation is used (D16).

## Phase 2: circuit-specific
`npm run setup` (`scripts/circuits/setup.js`):
1. `zkey new` from the r1cs and the ptau.
2. **One local contribution** using 64 bytes of fresh randomness. It is never
   written to disk and disappears when the process exits.
3. A random **beacon** (recorded in the manifest) finalises the key.
4. `zkey verify` against the r1cs and ptau, then export of the verification key
   and the Solidity verifier (`contracts/verifiers/CredentialVerifier.sol`).

**Caveat:** phase 2 has a single contributor: the machine that ran setup.
Whoever controls that machine *could* have kept δ. That is acceptable for a
local course demo, but not for production, where phase 2 needs several
independent contributors. Lab 05 demonstrates the forgery a known δ enables.

## Not committed (D15)
`build/` (ptau, zkey, vkey, manifest) and `contracts/verifiers/` are
gitignored. Every machine runs its own setup (`npm test` runs `npm run setup`
first), so each machine has a different verifier contract. Proofs made on one
machine do not verify against another machine's verifier. That is expected.

`build/setup/credential_d<D>_manifest.json` records the r1cs, ptau and zkey
hashes and the beacon. Setup is skipped while the r1cs is unchanged; editing a
circuit automatically triggers a fresh setup. Use `npm run setup -- --force`
to redo it anyway.

## Exception: the frozen demo setup (D27)
The live demo can't use a per-machine setup: the browser needs a proving key,
the Sepolia verifier must match it, and Vercel can't compile circuits. So one
setup is frozen and committed:

| File | Purpose |
|---|---|
| `web/public/circuit/credential.wasm` | witness generator the browser runs |
| `web/public/circuit/credential.zkey` | the demo proving key (about 2 MB) |
| `web/public/circuit/vkey.json` | its verification key |
| `web/public/circuit/manifest.json` | SHA-256 of each file, the circuit's r1cs hash, ptau, beacon |
| `contracts/demo/DemoCredentialVerifier.sol` | the matching Solidity verifier, deployed to Sepolia |

`npm run demo:freeze` creates it from this machine's current setup and refuses
to overwrite an existing set without `--force`, because re-freezing changes the
verification key and the Sepolia verifier would have to be redeployed.
`test/demo/frozen.test.js` checks the hashes, that the circuit hasn't changed
since freezing, that the zkey is a valid Phase 2 for the r1cs and pinned ptau
(`zkey verify`), and that a key from any other Phase 2 doesn't fit.

**Trust caveat.** Phase 2 here had one contributor (whoever ran the freeze) plus
a beacon. If that person kept the contribution's randomness, they could forge
proofs for the demo (lab 05). snarkjs discards it, but you have to trust that.
A real deployment would run a multi-party Phase 2 ceremony.

## Measured (depth 10, this machine)
| Metric | Value |
|---|---|
| Constraints | 3,338 |
| Setup time | ~27 s |
| Proving time (snarkjs, WASM witness) | ~0.75 s |
| `verifyProof` gas (`estimateGas`, includes 21k base) | ~252k |
