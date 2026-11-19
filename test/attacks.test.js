// Loads every attacks/<NN-name>/test.js so `npm test` runs the attack lab.
// (Hardhat's mocha runner takes a single test directory.)
import { readdirSync, existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const ATTACKS = fileURLToPath(new URL("../attacks", import.meta.url));

const labs = readdirSync(ATTACKS, { withFileTypes: true })
  .filter((d) => d.isDirectory() && /^\d\d-/.test(d.name))
  .map((d) => path.join(ATTACKS, d.name, "test.js"))
  .filter(existsSync)
  .sort();

for (const file of labs) await import(pathToFileURL(file).href);
