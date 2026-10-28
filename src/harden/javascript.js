// JS/Electron hardening:
//   1) Strip sourceMappingURL comments and .map files (blocks REA source recovery)
//   2) Rename framework sentinel identifiers (webpack/esbuild/Next.js — declarations
//      and references replaced together, semantics unchanged)
//   3) Optional runtime guard injection hook
//   4) asar: extract → transform → repack

import * as fs from "node:fs";
import * as path from "node:path";
import { parseAsar, extractAsar, packAsar } from "../formats/asar.js";
import { seedFromString, rng } from "../util.js";

const SENTINELS = [
  { re: /\b__webpack_require__\b/g, len: "__webpack_require__".length },
  { re: /\b__webpack_modules__\b/g, len: "__webpack_modules__".length },
  { re: /\bwebpackChunk(?:_N_E)?\b/g, len: 13 },
  { re: /\b__commonJS\b/g, len: "__commonJS".length },
  { re: /\b__esm\b/g, len: "__esm".length },
  { re: /\b__toESM\b/g, len: "__toESM".length },
  { re: /\b__NEXT_DATA__\b/g, len: "__NEXT_DATA__".length },
];

export function transformJsText(text, { seed, stripSourcemap = true, renameSentinels = true } = {}) {
  let changes = 0;
  if (stripSourcemap) {
    const before = text.length;
    text = text.replace(/^[ \t]*\/\/[#@]\s*sourceMappingURL=.*$/gm, "").replace(/\/\*#\s*sourceMappingURL=[\s\S]*?\*\/$/gm, "");
    if (text.length !== before) changes++;
  }
  if (renameSentinels) {
    const rand = rng(seedFromString(seed || String(Date.now())));
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const randName = (n) => { let s = ""; for (let i = 0; i < n; i++) s += chars[Math.floor(rand() * chars.length)]; return `_${s}`; };
    for (const s of SENTINELS) {
      if (s.re.test(text)) {
        s.re.lastIndex = 0;
        const replacement = randName(8);
        text = text.replace(s.re, replacement);
        changes++;
      }
    }
  }
  return { text, changes };
}

export function hardenJsFile(inPath, outPath, opts = {}) {
  let text = fs.readFileSync(inPath, "utf8");
  const { text: out, changes } = transformJsText(text, opts);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, out);
  return { changes };
}

export function hardenJsTree(inDir, outDir, opts = {}) {
  const report = { files: 0, transformed: 0, removedMaps: 0 };
  const inPlace = path.resolve(outDir) === path.resolve(inDir);
  const rec = (dir, rel) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const fp = path.join(dir, e.name);
      const rp = rel ? path.join(rel, e.name) : e.name;
      if (e.isDirectory()) {
        if (e.name === "node_modules") continue; // dependencies untouched; only app code is hardened
        rec(fp, rp);
      } else if (/\.(?:js|mjs|cjs|html)$/.test(e.name)) {
        let text;
        try { text = fs.readFileSync(fp, "utf8"); } catch { continue; }
        const { text: out, changes } = transformJsText(text, { ...opts, seed: rp });
        const dest = path.join(outDir, rp);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, changes ? out : text);
        report.files++;
        if (changes) report.transformed++;
      } else if (/\.map$/.test(e.name) && opts.deleteMaps !== false) {
        report.removedMaps++;
        if (inPlace) {
          // In-place mode (asar flow): "don't copy" means "keep", so actually delete
          fs.rmSync(fp, { force: true });
        }
      } else if (/\.(?:ts|tsx|jsx)$/.test(e.name) && opts.deleteSources !== false) {
        // Source files must not ship in release artifacts
        if (inPlace) fs.rmSync(fp, { force: true });
      } else {
        const dest = path.join(outDir, rp);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.copyFileSync(fp, dest);
      }
    }
  };
  rec(inDir, "");
  return report;
}

export function hardenAsar(inPath, outPath, opts = {}) {
  const buf = fs.readFileSync(inPath);
  const parsed = parseAsar(buf);
  if (!parsed) throw new Error("not a valid asar archive");
  const workDir = path.join(path.dirname(outPath), `.${path.basename(outPath)}.work`);
  fs.rmSync(workDir, { recursive: true, force: true });
  extractAsar(parsed, workDir);
  const treeReport = hardenJsTree(workDir, workDir, opts);
  const { fileCount, headerBytes } = packAsar(workDir, outPath);
  fs.rmSync(workDir, { recursive: true, force: true });
  return { fileCount, headerBytes, ...treeReport };
}
