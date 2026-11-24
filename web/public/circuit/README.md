# Frozen demo setup (D27)

These files are the ONE proving/verification key pair used by the live demo.
They are committed on purpose; local development still runs its own setup
(`npm run setup`, D15).

- Made by `npm run demo:freeze` (refuses to overwrite without `--force`).
- `manifest.json` pins the SHA-256 of every file and of the circuit's r1cs.
- The matching verifier is `contracts/demo/DemoCredentialVerifier.sol`.
- Checked by `test/demo/frozen.test.js`.

Trust caveat: one Phase 2 contributor plus a beacon. Fine for a course demo,
not for production (see docs/trusted-setup.md).
