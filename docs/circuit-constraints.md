# Circuit constraints: what each one enforces and why

Circuit: `circuits/credential.circom` → `Credential(MERKLE_DEPTH)`, with
`circuits/lib/merkle.circom` and `circuits/lib/age.circom`. All hashes are
circomlib Poseidon over the BN254 scalar field.

**Public inputs, in this order** (this is the order of the verifier's
`pubSignals`, checked by a test):
`root, nullifierHash, scope, credentialType, currentDate, recipient`

**Private inputs:** `nullifierSecret, trapdoor, birthDate, pathElements[D], pathIndices[D]`

**Size** (depth 10, circom 2.2.2 `--O2`): 3,338 constraints, so a 2¹² Powers of Tau is enough.
The snapshot test fails if this number changes.

| ID | Constraint | Enforces | Attack if missing | Tests |
|----|-----------|----------|-------------------|-------|
| C1 | `idCommitment <== Poseidon(3)(1, nullifierSecret, trapdoor)` | Prover knows the secrets behind the credential | Anyone who learns a leaf's contents can claim it | wrong `nullifierSecret` / wrong `trapdoor` → rejected |
| C2 | `leaf <== Poseidon(4)(3, idCommitment, birthDate, credentialType)` | `birthDate` and `credentialType` are the ones the issuer committed | Prover picks any birth date or type, e.g. a 17-year-old claims 2000-01-01 | lying about `birthDate` / `credentialType` → rejected; tampering either in the witness → R1CS violated |
| C3 | `pathIndices[i] * (1 - pathIndices[i]) === 0` | Every path selector is a bit | Selector `s ∉ {0,1}` turns the mux into arbitrary linear mixes of the two children | Merkle unit test: `s = 2, 3, −1` rejected. **Mutation result:** with C3 deleted, the full-circuit tests still pass, because a non-binary index also breaks the root, so C3 is defence in depth here. Only the Merkle unit test and the constraint snapshot catch its removal. |
| C4 | `MultiMux1` ordering `(left, right)` by the bit | Left/right order matches the leaf's position | Wrong order gives a different root (no proof) or ambiguity in hand-rolled versions | flipped bit → different root / rejected |
| C5 | `Poseidon(2)` per level, then `computedRoot === root` | Leaf is in the tree whose root the issuer published | Prover uses a private tree of their own | wrong sibling, unpublished root, leaf not in tree → rejected; tampering `root` → R1CS violated |
| C6 | `Num2Bits(32)` on `birthDate` and `currentDate` | Both dates are small non-negative integers | Field wrap-around: `birthDate = r − 1` makes `currentDate − birthDate` look like a huge age; the comparator is only sound for inputs `< 2ⁿ` | `r − 1`, `2³²`, a far-future `currentDate` → rejected |
| C7 | `GreaterEqThan(33)(currentDate, birthDate + 180000)` **and** `out === 1` | Calendar age ≥ 18 in YYYYMMDD arithmetic | No age check at all. Lab 01 computes the result with `<--` and never constrains it. | 17-year-old, one day short, 29-Feb on 28-Feb, born in the future → rejected; exactly 18 today and 29-Feb on 1-Mar → accepted |
| C8 | `Poseidon(3)(2, nullifierSecret, scope) === nullifierHash` | Nullifier is deterministic per (student, scope) | Prover submits a fresh random nullifier each time and reuses one credential forever (lab 03) | wrong `nullifierHash`, changed `scope` → rejected; different scope gives a different nullifier; tampering → R1CS violated |
| C9 | `recipientSquare <== recipient * recipient` | `recipient` is explicitly part of the R1CS | Lab 02 (front-running): a proof that doesn't commit to its recipient can be copied from the mempool. Groth16 binds public inputs through the verification equation even when unused, but an unused signal is fragile under refactoring and optimisation. | **Mutation result:** with C9 deleted, tampering `recipient` no longer violates the R1CS. With C9 present, tampering `recipient` or `recipientSquare` is rejected. The full proof-level check (a proof for address A fails for address B) comes in Step 3. |

## Why YYYYMMDD makes the age check exact
With `d = now − birth = 10000·ΔY + (MMDD_now − MMDD_birth)` and
`|MMDD_now − MMDD_birth| < 10000`, `d ≥ 180000` holds exactly when the 18th
birthday has been reached: leap years are handled with no division and no
calendar logic in the circuit. A 29 February birthday turns 18 on 1 March in
non-leap years. `test/lib/dates.test.js` cross-checks the rule against real
calendar arithmetic for every day of 2026.

## What the circuit deliberately does NOT check
| Not checked in circuit | Where it is enforced | Why |
|---|---|---|
| `birthDate` is a real calendar date | Issuer (`credentialLeaf` validates), then fixed inside the leaf | Only the issuer can put leaves in the tree |
| `currentDate` is today | Contract: within ±1 day of `block.timestamp` (Step 4) | The circuit has no clock |
| `scope` is this app's scope | Contract: recomputes `scope` from chain id, address and action (Step 4) | Prevents cross-app and cross-chain replay |
| `recipient == msg.sender` | Contract (Step 4) | The circuit only binds the value. The contract decides what it must be. |
| `root` is a published root | Registry root history (Step 4) | The circuit only proves membership in *some* root |
| `credentialType` is the type this app needs | Contract (Step 4) | Public input by design (D11) |

## How the constraint tests were validated
Mutation testing: each of C3, C7, C8 and C9 was deleted in turn, and the suite
was re-run to confirm the matching tests fail. Results are in the table above.
Witness-tampering tests patch a signal in an honest witness and run
`checkConstraints`. This models an attacker who skips the witness generator
entirely, which is the threat lab 01 exploits.
