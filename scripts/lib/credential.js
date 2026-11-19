// Credential leaves and circuit inputs.
//
//   leaf = Poseidon(DOMAIN_LEAF, idCommitment, birthDate, credentialType)
//
// Arity 4 (vs arity 2 for internal Merkle nodes) means leaves and nodes are
// hashed with different Poseidon parameter sets.

import { poseidon } from "./poseidon.js";
import { toFieldElement } from "./field.js";
import { isValidYYYYMMDD } from "./dates.js";
import { nullifierHash } from "./identity.js";

export const DOMAIN_LEAF = 3n;

/** Known credential types (public input checked by the contract). */
export const CREDENTIAL_TYPES = Object.freeze({ ENROLLED_STUDENT: 1n, GRADUATE: 2n });

/** Leaf the issuer inserts for a student. Validates the birth date. */
export async function credentialLeaf({ idCommitment, birthDate, credentialType }) {
  if (!isValidYYYYMMDD(birthDate)) throw new RangeError(`birthDate ${birthDate} is not a valid YYYYMMDD date`);
  const type = toFieldElement(credentialType, "credentialType");
  if (type === 0n) throw new RangeError("credentialType must be non-zero");
  return poseidon([DOMAIN_LEAF, toFieldElement(idCommitment, "idCommitment"), BigInt(birthDate), type]);
}

/**
 * Builds the full input object for circuits/credential.circom.
 * Public:  root, nullifierHash, scope, credentialType, currentDate, recipient
 * Private: nullifierSecret, trapdoor, birthDate, pathElements, pathIndices
 */
export async function buildCircuitInput({ identity, birthDate, credentialType, tree, leafIndex, scope, currentDate, recipient }) {
  const proof = tree.proof(leafIndex);
  const expectedLeaf = await credentialLeaf({ idCommitment: identity.commitment, birthDate, credentialType });
  if (proof.leaf !== expectedLeaf) throw new Error(`leaf ${leafIndex} does not belong to this identity/credential`);
  return {
    root: proof.root,
    nullifierHash: await nullifierHash(identity, scope),
    scope: toFieldElement(scope, "scope"),
    credentialType: toFieldElement(credentialType, "credentialType"),
    currentDate: BigInt(currentDate),
    recipient: toFieldElement(BigInt(recipient), "recipient"),
    nullifierSecret: identity.nullifierSecret,
    trapdoor: identity.trapdoor,
    birthDate: BigInt(birthDate),
    pathElements: proof.pathElements,
    pathIndices: proof.pathIndices.map(BigInt),
  };
}
