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
