# ZKred: Zero-Knowledge Student Credentials, Attacked and Hardened

Course project for Cryptography & Blockchain.

## Goal
A university publishes a Merkle root of Poseidon credential commitments to a
Registry contract. Students prove in zero knowledge (Circom + Groth16) that they
hold a valid credential and are over 18, without revealing identity. A nullifier
prevents reuse; the proof is bound to `msg.sender`. Successful claims pay out
`ZKRED` (an OpenZeppelin ERC-20) and emit `Claimed(recipient)`.

## Stack
Circom 2, circomlib, snarkjs (Groth16), Hardhat 3 (ethers + mocha), Solidity,
OpenZeppelin, JavaScript (Python only where it reads better, e.g. lab 04 math).

## Structure
- `circuits/`   Circom circuits (secure versions)
- `contracts/`  Registry, Verifier, App contracts
- `attacks/`    One folder per attack: vulnerable code, exploit, fix, test (see `attacks/README.md`)
- `scripts/`    Issuer tooling, proof generation, deployment; `scripts/lib/` holds the off-chain primitives
- `test/`       Hardhat tests (`test/attacks.test.js` also runs every `attacks/*/test.js`)
- `web/`        Live demo app (Vite + React); `web/public/circuit/` holds the frozen demo setup (D27)
- `docs/`       Design doc, threat model, decisions, report material
- `zkred.config.js`  Protocol parameters shared by everything (e.g. `MERKLE_DEPTH`)

## Attack lab
1. Under-constrained circuit (forged age proof)
2. Proof replay / front-running
3. Double use without nullifier
4. Issuer ECDSA nonce reuse → key recovery → forged Merkle root
5. (Stretch) Trusted-setup toxic waste
6. (Optional) 51% / reorg simulation

## Getting started

Prerequisites: Node.js ≥ 22, and [circom 2.2.x](https://docs.circom.io/getting-started/installation/)
on your `PATH` (`cargo install --git https://github.com/iden3/circom.git --tag v2.2.2 circom`).

```bash
npm install
```

```bash
npm run setup
```

```bash
npm test
```

`npm run setup` compiles the circuit, downloads the pinned Powers of Tau and runs
the circuit-specific setup (about 30 s). `npm test` runs it automatically first;
it is skipped when the circuit hasn't changed.

```bash
npm run check:secrets
```

Run the narrated end-to-end demo (in-process network): the issuer enrols
students and publishes a signed root, a front-run copy of a proof is rejected,
a student claims 100 ZKRED, a second claim is blocked by the nullifier, and a
17-year-old cannot produce a proof:

```bash
npm run demo
```

Deploy to a local node (run each command in its own terminal):

```bash
npx hardhat node
```

```bash
npm run deploy:local
```

The issuer key is generated into `keys/issuer-<chainId>.json` and the addresses
into `build/deployments/<chainId>.json`. Both are gitignored.

Configuration knobs (environment variables):

| Variable | Default | Purpose |
|---|---|---|
| `ZKRED_MERKLE_DEPTH` | `10` | Merkle tree depth; `16` and `20` are supported for benchmarking |
| `ZKRED_SOLC_PATH` | unset | Path to a local solc 0.8.28 binary, for machines that can't reach Hardhat's compiler download host |

## Progress
- [x] Step 1: scaffold, toolchain, off-chain primitives (field, Poseidon, identity/nullifier, Merkle tree), secret scanner
- [x] Step 2: circuits (`credential.circom` + `lib/merkle.circom` + `lib/age.circom`), constraint table in `docs/circuit-constraints.md`
- [x] Step 3: trusted setup (PSE ptau + local phase 2) and verifier export, see `docs/trusted-setup.md`
- [x] Step 4: contracts (Registry, CredentialGate, ZKredToken), see `docs/architecture.md` and `docs/threat-model.md`
- [x] Step 5: end-to-end flow (`npm run demo`, `scripts/deploy.js`)
- [ ] Step 6+: attack lab 01–06 (01 done)
- [ ] Live demo on Sepolia + Vercel, see `docs/live-demo.md` (demo steps 1–2 of 5 done: frozen setup, EnrolmentLog + Sepolia deploy script)
