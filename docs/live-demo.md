# Live demo: Sepolia + Vercel

A student connects MetaMask, enrols, proves in the browser, and claims 100
ZKRED on Sepolia. Design approved by the owner (D27, D28).

## Build steps
| # | Step | Status |
|---|---|---|
| 1 | Frozen demo setup: `web/public/circuit/` + `contracts/demo/DemoCredentialVerifier.sol` (`npm run demo:freeze`, `test/demo/frozen.test.js`) | done |
| 2 | `EnrolmentLog` contract + `scripts/deploy-sepolia.js` (Hardhat keystore), `test/demo/enrolment.test.js` | done |
| 3 | `web/api/enrol.js` serverless function (demo issuer + relayer) | |
| 4 | React app with React Bits components: identity, enrol, prove (Web Worker), claim, "try to break it" | |
| 5 | Vercel config, Sepolia deploy, smoke test | |

## How enrolment works on-chain (D29)
`EnrolmentLog.enrol(leaf, newRoot, epoch, issuerSignature)` is called by the
relayer. In ONE transaction it logs `Enrolled(index, leaf, root)` and calls
`Registry.updateRoot`. A bad issuer signature reverts both, so the logged
leaves and the latest root can't disagree. The browser rebuilds the tree from
the `Enrolled` events and refuses to prove if its root differs from
`Registry.latestRoot()`. Only the relayer may enrol; the owner can replace it
(`setRelayer`). Capacity is 2^MERKLE_DEPTH leaves.

## Keys and roles
| Role | What it does | Needs ETH? | Where the key lives |
|---|---|---|---|
| Deployer / owner | Deploys the contracts; owns `Registry` (rotate issuer, revoke roots) | yes, ~0.05 | Hardhat keystore on **your** machine (encrypted) |
| Demo issuer | Signs `RootUpdate(root, epoch)`; never sends transactions | no | Vercel env var `ZKRED_ISSUER_KEY` |
| Relayer | Sends the enrol + `updateRoot` transactions | yes, ~0.05 | Vercel env var `ZKRED_RELAYER_KEY` |

Use **fresh accounts made only for this demo**. Never use a wallet that holds
real funds, and never paste a key into a chat, an issue, or a committed file.
`npm run check:secrets` runs before every commit.

## What you need to set up

### 1. A Sepolia RPC URL (Alchemy or Infura, free tier)
**Alchemy:** sign up at alchemy.com → *Create new app* → chain *Ethereum*,
network *Sepolia* → open the app → *Endpoints* → copy the HTTPS URL. It looks
like `https://eth-sepolia.g.alchemy.com/v2/<your-key>`.

**Infura:** sign up at infura.io → *Create new API key* → enable *Ethereum /
Sepolia* → copy `https://sepolia.infura.io/v3/<your-key>`.

The URL contains your API key, so treat it as a secret: keystore and Vercel
env vars only, never the repo.

### 2. Three fresh accounts
Easiest in MetaMask: *Account menu → Add account* three times and name them
`zkred-deployer`, `zkred-issuer`, `zkred-relayer`. To get a private key:
*account ⋮ → Account details → Show private key*. Copy it straight into the
keystore or Vercel field below, never anywhere else.

You'll also need to tell me the **addresses** (not the keys) of the issuer
and the relayer; addresses are public and go into the deploy.

### 3. About 0.1 Sepolia ETH
Send ~0.05 to the deployer and ~0.05 to the relayer. The issuer needs none.
Faucets (their rules change often; try another if one refuses):
- Google Cloud Web3 faucet (Ethereum Sepolia), with a Google account.
- Alchemy Sepolia faucet (may require a small mainnet balance on the address).
- PoW faucet `sepolia-faucet.pk910.de` (mine in your browser; no account).

The faucet can pay the deployer; then send part of it to the relayer from
MetaMask.

### 4. Put the deployer secrets in the Hardhat keystore (your machine)
From the repo, on your own computer:

```bash
npx hardhat keystore set SEPOLIA_RPC_URL
```

```bash
npx hardhat keystore set SEPOLIA_DEPLOYER_KEY
```

Each command asks for the keystore password (you choose it the first time)
and then the value. It is stored encrypted outside the repo. Step 2 adds the
`sepolia` network to `hardhat.config.js`, reading these two values.

### 5. Deploy to Sepolia (your machine)
Once parts 1–4 are done, with the **addresses** (not keys) of the issuer and
relayer:

```bash
ZKRED_ISSUER_ADDRESS=0x... ZKRED_RELAYER_ADDRESS=0x... npm run deploy:sepolia
```

It asks for the keystore password, refuses to run if the frozen demo setup has
been altered, deploys `Registry`, `DemoCredentialVerifier`, `CredentialGate`
(+ `ZKredToken`) and `EnrolmentLog`, and writes the public addresses to
`web/src/deployments/sepolia.json`. Commit and push that file. Without the
keystore values it stops with `HHE7: Configuration Variable "SEPOLIA_RPC_URL"
not found`.

### 6. Vercel environment variables (after step 3 is built)
Vercel → project `zkred` → *Settings → Environment Variables*. Add each as
*Sensitive*, for the *Production* environment:

| Name | Value |
|---|---|
| `SEPOLIA_RPC_URL` | the URL from part 1 |
| `ZKRED_ISSUER_KEY` | private key of `zkred-issuer` |
| `ZKRED_RELAYER_KEY` | private key of `zkred-relayer` |

Then *Settings → Build and Deployment → Root Directory* = `web`, and redeploy.

### If a key leaks
That is lab 04's scenario. As the owner: `Registry.rotateIssuer(newIssuer)`, then
`Registry.revokeRoot(root)` for every root the attacker published. Swap the
Vercel env var to the new issuer key. For a leaked relayer key:
`EnrolmentLog.setRelayer(newRelayer)` and swap `ZKRED_RELAYER_KEY`.
