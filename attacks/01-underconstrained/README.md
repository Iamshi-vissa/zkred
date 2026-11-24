# Lab 01 · Under-constrained circuit (forged age proof)

> Everything in `vulnerable/` is **DELIBERATELY INSECURE**.

**Goal:** a 17-year-old with a genuine credential collects the 100 ZKRED
reward that is reserved for adults.

**Lesson:** a Groth16 proof only shows that *the R1CS constraints* are
satisfied. Anything the circuit computes but does not constrain is chosen
by the prover. The witness generator (the `.wasm`) is the prover's own
software, so it is not a security boundary.

| Variant | Bug | Exploit |
|---|---|---|
| **01a** | `GreaterEqThan` is wired up but `geq.out === 1` is missing (`vulnerable/credential_01a.circom`) | None needed: the minor runs the **ordinary prover**. Their witness has `geq.out = 0` and satisfies every constraint. The *secure* `CredentialGate` contract pays out, because the bug is purely in the circuit. |
| **01b** | `isAdult <-- geq.out` (assignment, no constraint) exposed as a public output that `AdultFlagGate` requires to be 1 (`vulnerable/credential_01b.circom`) | Compute an honest witness (`isAdult = 0`), overwrite wire 1 with `1` in the `.wtns` (`wtns.js`), run `groth16.prove`. The proof verifies and the gate pays out. |

## Run it
```bash
npm run lab:01
```

```bash
npx hardhat test mocha test/attacks.test.js
```

```bash
npm run lab:01:circomspect
```

`npm run lab:01` runs `exploit.js` on an in-process Hardhat network and prints
the whole attack, including the `snarkjs wtns check` transcripts for the
patched witness. Expected outcome:

| Check | Vulnerable | Secure / fixed |
|---|---|---|
| 01a: minor's ordinary proof | verifies, **claims 100 ZKRED** | witness generation fails: `Assert Failed` (C7) |
| 01b: `snarkjs wtns check` on patched witness | `WITNESS IS CORRECT` | `WITNESS IS NOT CORRECT`, aborting at constraint 36 = `isAdult === geq.out` |
| 01b: proof from patched witness | public `isAdult = 1`, **claims 100 ZKRED** | does not verify; gate reverts `InvalidProof` |

## Files
| Path | What |
|---|---|
| `vulnerable/credential_01a.circom` | 01a: missing `geq.out === 1` |
| `vulnerable/credential_01b.circom` | 01b: `isAdult <-- geq.out` |
| `fixed/credential_01b_fixed.circom` | 01b reference fix: `isAdult <== geq.out` (the only code change) |
| `vulnerable/probes/*.circom` | Disguised variants, used only to test circomspect |
| `AdultFlagGate.sol` | Gate for the 01b circuits (requires public `isAdult == 1`); correct in itself |
| `wtns.js` | Attacker tooling: read/patch `.wtns`, find a wire by name |
| `lab.js` | Setup and both attacks (shared by `exploit.js` and `test.js`) |
| `FIX.md` | The fixes, why they work, and the circomspect results |
| `circomspect/` | Saved circomspect reports (`run.sh` regenerates them) |
| `generated/` | Verifier contracts from `npm run setup` (gitignored) |

## Why 01b is compiled with `--O0`
To run `wtns check` with the **same** patched witness against both circuits,
their wires must line up. With `--O2`, circom merges `geq.out` into `isAdult`
in the fixed circuit (`<==` is a linear equality it can substitute), leaving
3,354 wires against 3,355 in the vulnerable circuit. A witness for one is then
the wrong size for the other, which would prove nothing. With `--O0` both have
**10,951 wires in the same order**, and the fixed circuit has exactly **one
extra constraint** (10,936 vs 10,935). That extra constraint is the one the
check fails on. The cost is a 2¹⁴ Powers of Tau for these two lab circuits only.
