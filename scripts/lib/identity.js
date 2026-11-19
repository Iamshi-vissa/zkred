// Student identity and nullifiers.
//
//   idCommitment  = Poseidon(DOMAIN_IDENTITY,  nullifierSecret, trapdoor)
//   nullifierHash = Poseidon(DOMAIN_NULLIFIER, nullifierSecret, scope)
//
// The leading constant is a domain-separation tag: without it both values
// would be Poseidon(nullifierSecret, x), so a scope equal to the trapdoor
// would make the public nullifier equal the identity commitment.
//
// - nullifierSecret/trapdoor are private and never leave the student.
// - idCommitment is hiding (secrets are 254-bit random) and binding
//   (Poseidon collision resistance). The issuer only ever sees idCommitment.
// - nullifierHash is deterministic per (identity, scope): the same student
//   using the same scope twice produces the same value, which the contract
//   rejects; different scopes give unlinkable values.

import { poseidon } from "./poseidon.js";
import { randomFieldElement, toFieldElement } from "./field.js";

export const DOMAIN_IDENTITY = 1n;
export const DOMAIN_NULLIFIER = 2n;

/** Creates a new identity; secrets may be supplied for deterministic tests. */
export async function createIdentity({ nullifierSecret, trapdoor } = {}) {
  const ns = nullifierSecret === undefined ? randomFieldElement() : toFieldElement(nullifierSecret, "nullifierSecret");
  const td = trapdoor === undefined ? randomFieldElement() : toFieldElement(trapdoor, "trapdoor");
  if (ns === 0n || td === 0n) throw new RangeError("identity secrets must be non-zero");
  const commitment = await poseidon([DOMAIN_IDENTITY, ns, td]);
  return Object.freeze({ nullifierSecret: ns, trapdoor: td, commitment });
}

/** nullifierHash for an identity in a given scope (scope is a field element). */
export async function nullifierHash(identity, scope) {
  const s = toFieldElement(scope, "scope");
  return poseidon([DOMAIN_NULLIFIER, identity.nullifierSecret, s]);
}
