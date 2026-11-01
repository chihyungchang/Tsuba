// Writes public/licenses.json: every third-party Rust crate and npm package that ships in Tsuba.app, with its
// license and the license files from its source, for Settings → About.
// MIT, BSD and Apache all require their notices to travel with the binary, so this runs before every build
// instead of being a hand-kept list that goes stale when Cargo.lock changes.
// Rust: the normal and build dependencies of the workspace for both release targets; dev-dependencies don't ship.
// npm: pnpm's production packages, the only ones Vite bundles into the page.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = fileURLToPath(new URL("..", import.meta.url));
const output = join(app, "public", "licenses.json");
const targets = ["aarch64-apple-darwin", "x86_64-apple-darwin"];

// Picks up LICENSE, LICENSE-MIT, LICENCE.txt, COPYING, NOTICE and the like; NOTICE files carry
// attribution Apache-2.0 section 4(d) asks us to keep.
const isLicenseFile = (name) => /^(un)?licen[cs]e|^copying|^notice/i.test(name);

// Identical texts (most Apache-2.0 copies) are stored once and referenced by hash, which keeps the file small.
const texts = {};
function readLicenseFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile() && isLicenseFile(e.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((e) => {
      const text = readFileSync(join(dir, e.name), "utf8").replace(/\r\n/g, "\n").trim();
      const id = createHash("sha256").update(text).digest("hex").slice(0, 16);
      texts[id] = text;
      return id;
    });
}

function rustPackages() {
  const args = ["metadata", "--format-version", "1", "--locked", ...targets.flatMap((t) => ["--filter-platform", t])];
  const meta = JSON.parse(execFileSync("cargo", args, { cwd: app, maxBuffer: 256 * 1024 * 1024, encoding: "utf8" }));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const packages = new Map(meta.packages.map((p) => [p.id, p]));
  const shipped = new Set();
  const walk = (id) => {
    if (shipped.has(id)) return;
    shipped.add(id);
    for (const dep of nodes.get(id).deps) {
      if (dep.dep_kinds.some((k) => k.kind !== "dev")) walk(dep.pkg);
    }
  };
  meta.workspace_members.forEach(walk);
  return [...shipped]
    .filter((id) => !meta.workspace_members.includes(id))
    .map((id) => packages.get(id))
    .map((p) => ({
      name: p.name,
      version: p.version,
      license: p.license ?? (p.license_file ? "Custom" : "Unknown"),
      url: httpsOr(p.repository ?? p.homepage, `https://crates.io/crates/${p.name}`),
      texts: readLicenseFiles(dirname(p.manifest_path)),
    }));
}

function npmPackages() {
  const list = JSON.parse(execFileSync("pnpm", ["licenses", "list", "--prod", "--json"], { cwd: app, encoding: "utf8" }));
  return Object.values(list)
    .flat()
    .flatMap((p) =>
      p.versions.map((version, i) => ({
        name: p.name,
        version,
        license: p.license,
        url: httpsOr(p.homepage, `https://www.npmjs.com/package/${p.name}`),
        texts: readLicenseFiles(p.paths[i]),
      })),
    );
}

// The page opens links through open_link, which only takes https
const httpsOr = (url, fallback) => (url && /^https:\/\//.test(url) ? url : fallback);

const byName = (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true });
const rust = rustPackages().sort(byName);
const npm = npmPackages().sort(byName);

// Many crates in multi-crate repos (objc2, wasmtime, yara-x) keep the license only at the repo root; the page then shows
// the SPDX license and links to the source instead of a text.
const withoutFile = [...rust, ...npm].filter((p) => p.texts.length === 0).length;

mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, JSON.stringify({ rust, npm, texts }));
console.log(`licenses: ${rust.length} crates, ${npm.length} npm packages, ${Object.keys(texts).length} license texts, ${withoutFile} packages without a license file`);
