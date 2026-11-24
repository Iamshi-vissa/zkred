// Every circuit that gets a trusted setup. `npm run setup` processes all of
// them; each gets its own zkey, vkey and (optionally) Solidity verifier.
//
// All circuits take the same public inputs (PUBLIC_SIGNALS); lab 01b's
// circuits also have one public output (isAdult), which snarkjs places
// BEFORE the inputs in publicSignals.

export const PUBLIC_SIGNALS = ["root", "nullifierHash", "scope", "credentialType", "currentDate", "recipient"];

const LAB01 = "attacks/01-underconstrained";

export const CIRCUITS = Object.freeze({
  // The production circuit.
  credential: {
    source: "circuits/credential.circom",
    template: "Credential",
    optimization: "O2",
    verifier: { contract: "CredentialVerifier", path: "contracts/verifiers/CredentialVerifier.sol" },
  },
  // Lab 01a: DELIBERATELY INSECURE (age result never enforced).
  lab01a: {
    source: `${LAB01}/vulnerable/credential_01a.circom`,
    template: "CredentialVuln01a",
    optimization: "O2",
    verifier: { contract: "Lab01aVerifier", path: `${LAB01}/generated/Lab01aVerifier.sol` },
  },
  // Lab 01b: DELIBERATELY INSECURE (isAdult assigned with <--).
  // --O0 so that its wires match lab01bFixed exactly (see attacks/01-underconstrained/README.md).
  lab01b: {
    source: `${LAB01}/vulnerable/credential_01b.circom`,
    template: "CredentialVuln01b",
    optimization: "O0",
    verifier: { contract: "Lab01bVerifier", path: `${LAB01}/generated/Lab01bVerifier.sol` },
  },
  // Lab 01b reference fix (isAdult <== geq.out), same wires as lab01b.
  lab01bFixed: {
    source: `${LAB01}/fixed/credential_01b_fixed.circom`,
    template: "CredentialFixed01b",
    optimization: "O0",
    verifier: { contract: "Lab01bFixedVerifier", path: `${LAB01}/generated/Lab01bFixedVerifier.sol` },
  },
});

export function circuitSpec(id) {
  const spec = CIRCUITS[id];
  if (!spec) throw new Error(`unknown circuit id '${id}'; known: ${Object.keys(CIRCUITS).join(", ")}`);
  return spec;
}
