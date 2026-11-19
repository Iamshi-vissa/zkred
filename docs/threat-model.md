# Threat model (living document)

## Assets
- Student privacy: which student made a claim; birth dates.
- One reward per eligible student per gate.
- Integrity of the credential set (only the university decides who is in it).

## Trust assumptions
| Party | Trusted for | If it misbehaves |
|---|---|---|
| Issuer key | Publishing honest roots | Can enrol fake students → **lab 04**. Mitigation: owner revokes roots and rotates the key. |
| Registry owner | Incident response (rotate the issuer, revoke roots) | Can deny service by revoking good roots or rotating to a bad key. It cannot publish roots or mint. Use a multisig with `Ownable2Step` in practice. |
| Trusted-setup participants | Destroying toxic waste | Whoever knows phase-2 δ can forge proofs → **lab 05**. Phase 2 here has one local contributor. |
| Students | Keeping `nullifierSecret` / `trapdoor` secret | Whoever learns them can claim on the student's behalf (once per gate). |

## Mitigated, with tests
| Threat | Mitigation | Test |
|---|---|---|
| Underage claims | Circuit C6/C7; contract date window (no "tomorrow") | circuit + gate tests |
| Double claims | Nullifier per (student, scope); `nullifier + r` rejected | gate tests |
| Front-running / proof theft | `recipient = msg.sender` public input (C9) | groth16 + gate tests (lab 02 adds the mempool attack) |
| Cross-gate / cross-chain replay | Contract-computed `scope` | gate tests |
| Old or forged roots | Issuer signature, strict epochs, EIP-712 domain, 30-epoch history, revocation | registry + gate tests |
| Signature malleability | OZ `ECDSA` rejects high-s | registry test |
| Unauthorised minting | Token deployed by the gate; no admin role | token tests |

## Known limitations (accepted)
- **Already-minted tokens are not clawed back** after a forged root is revoked.
  Revocation stops *future* claims only. A freeze/clawback would add a
  privileged power over student balances; we prefer the smaller trust surface.
- Claims are linkable to the recipient address by design. Students who care
  should claim to a fresh address (the proof does not require any link
  to their identity).
- The anonymity set is the tree's leaves. With a small tree (e.g. 3 students),
  "anonymous among 3" is weak.
- Timezones: dates are UTC. A student in UTC+14 may have to wait up to 14 h past
  their local 18th birthday.
