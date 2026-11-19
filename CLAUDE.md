# Working rules for this repository

- Plan before implementing; wait for the owner's approval on designs.
- Build in small steps; every step has tests, including negative tests.
- Explain every circuit constraint and why it is needed (inline comment +
  a row in docs/circuit-constraints.md + a negative test that breaks it).
- Use audited libraries (circomlib, OpenZeppelin) for secure paths; hand-rolled
  or deliberately broken code lives only in attacks/ and must be clearly
  labeled `DELIBERATELY INSECURE`.
- Never commit private keys or .env files; run `npm run check:secrets`.
- Protocol parameters live in zkred.config.js (single source of truth).
- If the solc download host is blocked, set ZKRED_SOLC_PATH to a local solc 0.8.28.
