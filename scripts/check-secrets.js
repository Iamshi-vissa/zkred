#!/usr/bin/env node
// Fails if a file that git would commit looks like it contains a secret.
//
// Flags:
//  - tracked/untracked-but-not-ignored .env files
//  - PEM private key blocks
//  - 32-byte hex values (0x + 64 hex) on a line that mentions a key/secret/
//    mnemonic/privkey, unless the value is one of Hardhat's public dev-account
//    keys (derived from the well-known "test test ... junk" mnemonic).
//  - a line can opt out with the marker `check-secrets: allow` (used only for
//    deliberately public lab values, and reviewed in code review).
//
// Usage: npm run check:secrets

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";
import { HDNodeWallet, Mnemonic } from "ethers";

const HARDHAT_MNEMONIC = "test test test test test test test test test test test junk";
const KEYWORD = /(priv(ate)?[_ -]?key|secret|mnemonic|seed|signer[_ -]?key|\bpk\b|\bsk\b)/i;
const HEX32 = /0x[0-9a-fA-F]{64}\b/g;
const PEM = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;
const ALLOW_MARKER = "check-secrets: allow";

let devKeys;
function hardhatDevKeys() {
  if (!devKeys) {
    const mnemonic = Mnemonic.fromPhrase(HARDHAT_MNEMONIC);
    devKeys = new Set();
    for (let i = 0; i < 20; i++) {
      const w = HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/0'/0/${i}`);
      devKeys.add(w.privateKey.toLowerCase());
    }
  }
  return devKeys;
}

/** Returns a list of findings `{ file, line, reason }` for one file's text. */
export function scanContent(text, file = "<input>") {
  const findings = [];
  const name = basename(file);
  if (/^\.env(\..+)?$/.test(name) && name !== ".env.example") {
    findings.push({ file, line: 0, reason: ".env file must not be committed" });
  }
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    if (line.includes(ALLOW_MARKER)) return;
    if (PEM.test(line)) findings.push({ file, line: i + 1, reason: "PEM private key" });
    if (!KEYWORD.test(line)) return;
    for (const m of line.matchAll(HEX32)) {
      if (!hardhatDevKeys().has(m[0].toLowerCase())) {
        findings.push({ file, line: i + 1, reason: `possible private key ${m[0].slice(0, 10)}…` });
      }
    }
  });
  return findings;
}

function filesGitWouldCommit() {
  const out = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    encoding: "utf8",
  });
  return out.split("\0").filter(Boolean);
}

function main() {
  const findings = [];
  for (const file of filesGitWouldCommit()) {
    if (file === "package-lock.json") continue;
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue; // deleted in working tree
    }
    findings.push(...scanContent(text, file));
  }
  if (findings.length) {
    for (const f of findings) console.error(`${f.file}:${f.line}: ${f.reason}`);
    console.error(`\ncheck-secrets: ${findings.length} finding(s). Remove the secret or mark a deliberately public value with "${ALLOW_MARKER}".`);
    process.exit(1);
  }
  console.log("check-secrets: no secrets found");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
