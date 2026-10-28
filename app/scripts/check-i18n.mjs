// Fails when a t("...") string in src/ has no Simplified Chinese entry, or an entry is no longer used.
// Only plain string literals are recognised, so always pass t() a literal, never a variable.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src/", import.meta.url));
const catalog = JSON.parse(readFileSync(join(root, "locales/zh-Hans.json"), "utf8"));
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

const missing = [...used].filter((k) => !(k in catalog));
const unused = Object.keys(catalog).filter((k) => !used.has(k));
if (missing.length || unused.length) {
  if (missing.length) console.error("Missing zh-Hans entries:\n" + missing.map((k) => `  ${JSON.stringify(k)}`).join("\n"));
  if (unused.length) console.error("Unused zh-Hans entries:\n" + unused.map((k) => `  ${JSON.stringify(k)}`).join("\n"));
  process.exit(1);
}
console.log(`i18n: ${used.size} strings, all translated`);
