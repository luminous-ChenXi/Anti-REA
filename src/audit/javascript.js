// JS / Electron / asar audit: targets REA's JavaScript static pipeline
// (babel AST + webpack/esbuild structure recognition + source maps + Wakaru recovery).

import * as fs from "node:fs";
import * as path from "node:path";
import { parseAsar, asarEntries } from "../formats/asar.js";
import { indexOfAll } from "../util.js";

const SENTINELS = [
  { re: /\b__webpack_require__\b|\b__webpack_modules__\b|\bwebpackChunk(?:_\w+)?\b/, id: "JS-WEBPACK", name: "webpack sentinel identifiers" },
  { re: /\b__commonJS\b|\b__esm\b|\b__toESM\b|\b__copyProps\b/, id: "JS-ESBUILD", name: "esbuild runtime helper identifiers" },
  { re: /\b__NEXT_DATA__\b|\bTURBOPACK\b|\bwebpackChunk_N_E\b/, id: "JS-NEXT", name: "Next.js global sentinels" },
];
const ELECTRON_FUSE = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const SECRET_PATTERNS = [
  { re: /\bsk-[A-Za-z0-9_-]{16,}/, name: "OpenAI-style API key" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS AccessKeyId" },
  { re: /\bghp_[A-Za-z0-9]{30,}\b/, name: "GitHub token" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, name: "private key" },
  { re: /\b(?:eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/, name: "JWT" },
];

/** Audit a single JS text buffer. */
export function auditJsText(text, label, { maxStrings = 20 } = {}) {
  const findings = [];
  if (text.includes("sourceMappingURL=")) {
    findings.push({
      id: "JS-SOURCEMAP",
      severity: "high",
      title: `${label}: sourceMappingURL comment present`,
      detail: "REA parses the comment and loads the .map to restore pre-bundle module paths and near-original source (then Wakaru un-minifies).",
      rea: "Source-level recovery",
      fix: "harden strips the comment and .map files; set devtool: false / sourcemap: false at build time",
    });
  }
  for (const s of SENTINELS) {
    const m = text.match(s.re);
    if (m) {
      findings.push({
        id: s.id,
        severity: "high",
        title: `${label}: ${s.name} detected (${m[0]})`,
        detail: "REA's bundler analyzer rebuilds webpack/esbuild module tables from these unrenamed global identifiers, recovering module keys, dependency edges and structural fingerprints.",
        rea: "Module dependency graph reconstruction",
        fix: "harden renames the identifiers consistently (declarations and references together, runtime semantics unchanged)",
        evidence: { sample: m[0] },
      });
    }
  }
  if (text.includes(ELECTRON_FUSE)) {
    findings.push({ id: "JS-ELECTRON-FUSE", severity: "low", title: `${label}: Electron fuse sentinel string in plaintext`, detail: "REA reads fuse configuration to tell whether asar integrity / Node integration are disabled.", rea: "Electron attack-surface assessment", fix: "configure via @electron/fuses as needed (do not alter the sentinel itself — it breaks fuse reading)" });
  }
  const secrets = [];
  for (const p of SECRET_PATTERNS) {
    const m = text.match(p.re);
    if (m) secrets.push({ kind: p.name, sample: m[0].slice(0, 12) + "…" });
  }
  if (secrets.length) {
    findings.push({
      id: "JS-SECRETS",
      severity: "high",
      title: `${label}: suspected plaintext secrets/credentials (${secrets.length} kind(s))`,
      detail: "Any string scan hits these (not just REA). String constants are the first asset to be dumped.",
      rea: "Direct credential theft",
      fix: "Rotate the keys immediately; move to server-side or runtime-derived secrets; harden never rewrites them automatically — manual handling required",
      evidence: { secrets: secrets.slice(0, maxStrings) },
    });
  }
  // API endpoint strings (informational — shows the behavior graph REA can assemble)
  const urls = text.match(/\bhttps?:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._/-]{2,60})?/g) || [];
  if (urls.length >= 3) {
    findings.push({ id: "JS-ENDPOINTS", severity: "medium", title: `${label}: ${urls.length} plaintext URL endpoint(s)`, detail: [...new Set(urls)].slice(0, 8).join(" , "), rea: "Network behavior-surface reconstruction", fix: "Split/encode endpoints or ship via config; dilute with poison decoys" });
  }
  return findings;
}

/** Audit an asar archive: parse the header + audit bundled JS files. */
export function auditAsar(buf, filePath) {
  const parsed = parseAsar(buf);
  if (!parsed) return null;
  const findings = [];
  const entries = asarEntries(parsed);
  findings.push({
    id: "ASAR-INDEX",
    severity: "medium",
    title: `asar archive parseable (${entries.length} entries)`,
    detail: "REA ships its own asar parser and expands it directly (8MiB header budget). asar is packaging, not protection.",
    rea: "Full file inventory + per-file analysis",
    fix: "harden runs the extract-harden-repack flow; move critical logic into native modules",
  });
  let jsAudited = 0;
  for (const e of entries) {
    if (!/\.(?:js|mjs|cjs)$/.test(e.path) || e.unpacked || e.offset === undefined) continue;
    if (jsAudited >= 40) break;
    const start = parsed.dataStart + e.offset;
    const text = parsed.buf.toString("utf8", start, start + e.size);
    findings.push(...auditJsText(text, `asar:${e.path}`));
    jsAudited++;
  }
  return { findings, entries };
}

/** Directory/file entry point. */
export function auditJavascriptPath(p) {
  const findings = [];
  const stat = fs.statSync(p);
  if (stat.isFile()) {
    if (/\.asar$/.test(p)) {
      const r = auditAsar(fs.readFileSync(p), p);
      if (r) findings.push(...r.findings);
    } else if (/\.(?:js|mjs|cjs|html)$/.test(p)) {
      findings.push(...auditJsText(fs.readFileSync(p, "utf8").slice(0, 20 * 1024 * 1024), path.basename(p)));
    }
    return findings;
  }
  const walk = (dir) => {
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) { if (!["node_modules", ".git"].includes(e.name)) walk(fp); continue; }
      if (/\.(?:js|mjs|cjs)$/.test(e.name)) {
        let text = "";
        try { text = fs.readFileSync(fp, "utf8").slice(0, 20 * 1024 * 1024); } catch { continue; }
        findings.push(...auditJsText(text, path.relative(p, fp)));
      } else if (/\.map$/.test(e.name)) {
        findings.push({ id: "JS-MAP-FILE", severity: "high", title: `${path.relative(p, fp)}: source map shipped with the artifact`, detail: "REA / browser devtools restore the original source directly.", rea: "Source-level recovery", fix: "harden removes it (release artifacts must not contain .map)" });
      } else if (/\.(?:ts|tsx|jsx)$/.test(e.name)) {
        findings.push({ id: "JS-TS-SOURCE", severity: "high", title: `${path.relative(p, fp)}: TypeScript source shipped with the artifact`, detail: "Source leaks outright — no reverse engineering required.", rea: "Reads the source directly", fix: "Remove from release artifacts" });
      } else if (/\.asar$/.test(e.name)) {
        try {
          const r = auditAsar(fs.readFileSync(fp), fp);
          if (r) findings.push(...r.findings);
        } catch { /* ignore */ }
      }
    }
  };
  walk(p);
  return findings;
}
