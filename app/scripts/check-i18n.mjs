// Fails when a t("...") string in src/ has no entry in some language's catalog, an entry is no longer used,
// or a translation doesn't keep the English text's {placeholders}.
// Only plain string literals are recognised, so always pass t() a literal, never a variable.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src/", import.meta.url));
const localesDir = join(root, "locales");
const catalogs = readdirSync(localesDir)
  .filter((name) => name.endsWith(".json"))
  .map((name) => ({ code: name.replace(/\.json$/, ""), entries: JSON.parse(readFileSync(join(localesDir, name), "utf8")) }));
const call = /\bt\(\s*"((?:[^"\\]|\\.)*)"/g;

function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) && name !== "i18n.ts" ? [path] : [];
  });
}

const used = new Set();
for (const file of sources(root)) {
  const code = readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("//"))
    .join("\n");
  for (const m of code.matchAll(call)) used.add(JSON.parse(`"${m[1]}"`));
}

const placeholders = (text) => [...text.matchAll(/\{\w+\}/g)].map((m) => m[0]).sort().join(" ");
const problems = [];
for (const { code, entries } of catalogs) {
  const missing = [...used].filter((k) => !(k in entries));
  const unused = Object.keys(entries).filter((k) => !used.has(k));
  const broken = Object.entries(entries).filter(([en, text]) => placeholders(en) !== placeholders(text)).map(([en]) => en);
  if (missing.length) problems.push(`Missing ${code} entries:\n` + missing.map((k) => `  ${JSON.stringify(k)}`).join("\n"));
  if (unused.length) problems.push(`Unused ${code} entries:\n` + unused.map((k) => `  ${JSON.stringify(k)}`).join("\n"));
  if (broken.length) problems.push(`${code} entries with different placeholders:\n` + broken.map((k) => `  ${JSON.stringify(k)}`).join("\n"));
}
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`i18n: ${used.size} strings, all translated into ${catalogs.length} languages`);
