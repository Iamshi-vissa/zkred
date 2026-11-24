# Design decisions log

| # | Decision | Rationale | Step |
|---|---|---|---|
| D1 | Separate repo `zkred` | Keeps the course project self-contained | 1 |
| D2 | Hardhat 3 with ethers + mocha (`hardhat-toolbox-mocha-ethers`) | Current Hardhat; owner's choice | 1 |
| D3 | `MERKLE_DEPTH` = 10 by default, set in `zkred.config.js`, overridable via `ZKRED_MERKLE_DEPTH` ∈ {10, 16, 20} | Fast tests now, benchmarks later from one parameter | 1 |
| D4 | Reward = OpenZeppelin ERC-20 `ZKRED` payout + `Claimed(recipient)` event | Makes front-running (lab 02) visible as stolen tokens | 4 |
| D5 | Domain-separated Poseidon: `idCommitment = H(1, ns, td)`, `nullifier = H(2, ns, scope)` | Without the tag both are `H(ns, ·)`, so scope == trapdoor would make nullifier == commitment | 1 |
| D6 | Off-chain code rejects values ≥ r instead of reducing them | Reduction lets `x` and `x + r` alias the same field element | 1 |
| D7 | Merkle verification takes a fixed depth | An internal node + shorter path also hashes to the root; the circuit fixes depth, so the library does too | 1 |
| D8 | Leaves (Poseidon arity 4: `H(3, idCommitment, birthDate, credentialType)`) and internal nodes (arity 2) use different arities | Different Poseidon parameter sets, so a node can't be passed off as a leaf | 2 |
| D9 | Attack tests live in `attacks/*/test.js`, loaded by `test/attacks.test.js` | Hardhat's mocha runner takes one test directory | 1 |
| D10 | Optional `ZKRED_SOLC_PATH` local-compiler override | Some environments block Hardhat's compiler download host | 1 |
| D11 | `credentialType` is a public input, checked by the contract | Reveals the credential type (not identity); stops one type being used for another | 2 |
| D12 | Dates are YYYYMMDD integers; age rule `currentDate − birthDate ≥ 180000` | Exact calendar age with no in-circuit calendar logic; the contract converts `block.timestamp` with a vendored BokkyPooBah DateTime library (Step 4) | 2 |
| D13 | Circuits compiled with `--O2` | 7,252 → 3,338 constraints at depth 10 (fits a 2¹² ptau) | 2 |
| D14 | Comparator width 33 bits over 32-bit range-checked dates | `birthDate + 180000 < 2³³`, so comparator inputs are always in range | 2 |
| D15 | Trusted-setup outputs (zkey, vkey, generated verifier) are NOT committed; `npm test` runs `npm run setup` first, which is idempotent | Owner's choice: every machine runs its own setup |
| D16 | Phase 1 = PSE Perpetual Powers of Tau (`ppot_0080`), SHA-256 pinned | Public multi-party ceremony; the Hermez URLs now deny access |
| D17 | Phase 2 = one local contribution + random beacon, then `zkey verify` | Enough for a course demo; the single-contributor risk is documented and explored in lab 05 |
| D18 | Reward: 100 ZKRED minted per claim; `ZKredToken` is deployed by the gate (sole `MINTER_ROLE`, no admin role) | Owner's choice; "only the gate can mint" is enforced by code, not by deploy-script discipline |
| D19 | Registry owner (`Ownable2Step`) can rotate the issuer key and revoke roots, but cannot publish roots | Owner's choice; incident response for lab 04 with minimal extra power |
| D20 | `Claimed(address indexed recipient, uint256 nullifierHash)` | Owner's choice; makes double-use observable |
| D21 | Accepted dates: today or yesterday (UTC), never tomorrow | Tolerates the midnight boundary without allowing claims a day early |
| D22 | Root validity = published within the last 30 epochs and not revoked (O(1) lookup via `rootEpoch`) | Proofs survive a root rotation; constant gas |
| D23 | Strict sequential epochs in signed root updates | Old signatures can't be replayed; pre-signed updates die on rotation |
| D24 | Lab 01b circuits compiled with `--O0`; 2¹⁴ ptau pinned for them | Same wire layout for vulnerable and fixed, so `wtns check` on one patched witness is a fair comparison (O2 differs by one wire) |
| D25 | Lab 01a reuses the secure `CredentialGate` contract with the broken circuit's verifier | Shows the bug is purely in the circuit |
| D26 | `npm run setup` covers every circuit in `scripts/circuits/registry.js` | Lab circuits get their own zkeys/verifiers, generated and gitignored |
