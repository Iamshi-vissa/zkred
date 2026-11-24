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

The hashes were recorded when the files were first downloaded (trust on first
use). They were then checked independently:

```bash
npx snarkjs powersoftau verify build/ptau/ppot_0080_12.ptau
```

recomputes the whole contribution chain. Result for the 2¹² file: **`Powers of
Tau Ok!`**, with all 62 contributions (#1 to #62) checked. It took well over 30
minutes on a 4-core sandbox, so it is a one-off check, not part of
`npm run setup`. The 2¹³ file (depths 16/20) is pinned by hash but has not been
chain-verified yet. `npm run setup` downloads the
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

## Measured (depth 10, this machine)
| Metric | Value |
|---|---|
| Constraints | 3,338 |
| Setup time | ~27 s |
| Proving time (snarkjs, WASM witness) | ~0.75 s |
| `verifyProof` gas (`estimateGas`, includes 21k base) | ~252k |
