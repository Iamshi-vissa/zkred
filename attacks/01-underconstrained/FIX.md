# Lab 01 · Fixes

## 01a: enforce the result, don't just compute it
Secure code: `circuits/lib/age.circom` (constraint **C7**).

```diff
     component geq = GreaterEqThan(33);
     geq.in[0] <== currentDate;
     geq.in[1] <== birthDate + minYears * 10000;
+    geq.out === 1;
```

`GreaterEqThan` does not *assert* anything. It outputs a bit that is 1 if
the comparison holds and 0 otherwise, and both are valid witnesses. Only
`geq.out === 1` turns the bit into a requirement. With it, a minor's witness
cannot exist: the witness generator aborts with `Assert Failed`, and even a
hand-built witness would violate the R1CS (see the witness-tampering tests in
`test/circuits/credential.circuit.test.js`). The mutation test in
`docs/circuit-constraints.md` (C7 removed) is exactly this lab's bug.

## 01b: `<==`, not `<--`
Reference fix: `fixed/credential_01b_fixed.circom`.

```diff
-    isAdult <-- geq.out;
+    isAdult <== geq.out;
```

| Operator | Witness generator | R1CS |
|---|---|---|
| `<--` | computes the value | **nothing**: the wire is free |
| `===` | checks the equality | adds the constraint |
| `<==` | computes the value | adds the constraint (`<--` plus `===`) |

`<--` is only for values that cannot be expressed quadratically (division,
bit extraction, ternaries), and **every** `<--` must be followed by
constraints that pin the value down, as circomlib's `Num2Bits` does with its
bit checks and sum check. Evidence from the lab run:

```
$ snarkjs wtns check lab01b_d10.r1cs      01b_patched.wtns   # vulnerable
  WITNESS IS CORRECT
$ snarkjs wtns check lab01bFixed_d10.r1cs 01b_patched.wtns   # fixed
  ··· aborting checking process at constraint 36
  WITNESS IS NOT CORRECT
constraint 36 involves: main.isAdult, main.geq.out   # i.e. isAdult === geq.out
```

**Production design.** `circuits/credential.circom` goes one step further and
has no `isAdult` output at all. The circuit enforces the age rule itself
(C7), so there is no flag that the circuit could leave loose or that a
contract could forget to check.

## Static analysis: circomspect v0.9.0
Reports: `circomspect/*.txt` (regenerate with `npm run lab:01:circomspect`).
Only project templates are analysed; circomlib is passed as a library (`-L`).

### The four lab circuits
| Circuit | Relevant finding | Verdict |
|---|---|---|
| **01a vulnerable** | `warning: The output signal 'out' defined by the template 'GreaterEqThan' is not constrained in 'CredentialVuln01a'` (line of `component geq = GreaterEqThan(33)`) | **Caught.** Points straight at the unused comparison result. |
| **01a fixed** (`circuits/credential.circom`) | No finding about the age logic | Clean (noise only, see below) |
| **01b vulnerable** | `warning: Using the signal assignment operator '<--' is not necessary here. The expression assigned to 'isAdult' is quadratic. Consider ... '<=='` | **Caught**, at the exact line, with the exact fix. But note the framing: "not necessary" reads like style advice, not "this output is unconstrained". The second warning on the same line, "`isAdult` is assigned a value, but this value is never read", is misleading: public outputs are never read inside the circuit. |
| **01b fixed** | No finding about `isAdult` | Clean (noise only) |

**Does it catch 01a?** Yes. The *unused-output-signal* pass reports that
`GreaterEqThan`'s `out` is never constrained, which is exactly the bug.

### Disguised variants (`vulnerable/probes/`)
| Probe | Disguise | Relevant finding | Verdict |
|---|---|---|---|
| **P1** (01a laundered) | `signal isAdult <== geq.out;`, and nothing uses `isAdult` | Only `warning: Intermediate signals should typically occur in at least two separate constraints` on `isAdult` | **Effectively missed.** The "unused output" warning disappears because `geq.out` is now consumed. What remains is a generic warning that also fires on the intentional `recipientSquare` (C9) in every circuit, including the secure one, so it is easy to dismiss as noise. |
| **P2** (01b ternary) | `isAdult <-- (currentDate - birthDate >= 180000) ? 1 : 0;` (`<--` is genuinely required here) | `warning: Using the signal assignment operator '<--' does not constrain the assigned signal` | **Caught**, with an even clearer warning than 01b. (It also reports the now-dead `GreaterEqThan` output.) |
| **P3** (01b + bit check) | adds `isAdult * (isAdult - 1) === 0` (looks constrained, but only says "0 or 1") | `warning: Using '<--' is not necessary here` and `warning: The signal 'isAdult' is not constrained by the template` | **Caught.** The boolean check does not fool it. |

### Noise (present in the secure circuit too)
| Finding | Why it is not a bug here |
|---|---|
| `Intermediate signals should typically occur in at least two separate constraints` on `recipientSquare` | C9 is a deliberate single constraint that keeps `recipient` in the R1CS |
| `note: Field element arithmetic could overflow` on `birthDate + 18 * 10000` | Both dates are range-checked to 32 bits (C6) and the comparator is 33 bits wide (D14), so no overflow is possible |
| `note: Field element arithmetic could overflow` on `recipient * recipient` | Intended field multiplication |
| `warning: ... 'isAdult' ... is never read` (01b) | Public outputs are never read inside the circuit |

### What circomspect cannot see, by design
- **Semantic intent.** P1 shows that a result which is computed, copied and
  then ignored looks like ordinary code. The tool flags patterns, not the
  missing `=== 1` the author meant to write.
- **The contract side.** If `AdultFlagGate` forgot to require `isAdult == 1`,
  the circuit would be perfectly constrained and the system still broken.
  Only a review of the circuit **together with its verifier contract**
  (or end-to-end tests like `test.js`) catches that.
- **Soundness in general.** Passing circomspect is evidence, not proof. The
  per-constraint negative tests, the mutation tests and the witness-tampering
  tests remain the primary defence.

**Takeaway for the report:** run circomspect in CI. It caught 4 of the 5 bug
shapes here, at the right line. Treat every `<--` and every "intermediate
signal" warning as a review item rather than noise, and back it with negative
tests, because the one variant it effectively missed (P1) is the one a
"quick fix" for 01a would most naturally produce.
