# Attack lab

> **Everything under `attacks/*/vulnerable/` is DELIBERATELY INSECURE.**
> It exists only to be exploited in a lab. Never import it from `contracts/`,
> `circuits/` or `scripts/`, and never deploy it anywhere except a local
> Hardhat network.

Each attack lives in its own folder:

```
attacks/NN-name/
  README.md     what the bug is, why it is exploitable, how to run the lab
  vulnerable/   the deliberately broken circuit/contract/script
  exploit.js    the attack, runnable on its own against a local network
  FIX.md        points to the secure code in circuits/ or contracts/ and explains the diff
  test.js       asserts: exploit SUCCEEDS on vulnerable/, FAILS on the secure version
```

Hardhat compiles `attacks/**/*.sol` alongside `contracts/` (see
`hardhat.config.js`), and `test/attacks.test.js` loads every `attacks/*/test.js`,
so `npm test` runs the whole lab.

| # | Attack | Status |
|---|--------|--------|
| 01 | Under-constrained circuit (forged age proof): 01a missing `=== 1`, 01b `<--` + witness patching, circomspect study | done |
| 02 | Proof replay / front-running | planned |
| 03 | Double use without nullifier | planned |
| 04 | Issuer ECDSA nonce reuse → key recovery → forged root | planned |
| 05 | (Stretch) Trusted-setup toxic waste | planned |
| 06 | (Optional) 51% / reorg simulation | planned |
