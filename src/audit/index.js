// Audit orchestration: detect artifact type → dispatch to auditors → aggregate report.

import * as fs from "node:fs";
import * as path from "node:path";
import { auditNative } from "./native.js";
import { auditJavascriptPath, auditAsar, auditJsText } from "./javascript.js";
import { auditDotnet } from "./dotnet.js";
import { auditApk } from "./apk.js";
import { walkFiles, readHead, fmtBytes, startsWith, MAGIC } from "../util.js";

/**
 * Rule plugin system: load community/custom detection rules from anti-rea.config.json.
 * Rule format documented in the README. configPath is explicit; otherwise look in
 * cwd, then the target's parent directory.
 */
export function loadCustomRules(configPath, target) {
  const candidates = configPath ? [configPath] : [path.join(process.cwd(), "anti-rea.config.json"), path.join(target, "..", "anti-rea.config.json")];
  for (const c of candidates) {
    try {
      if (!fs.statSync(c).isFile()) continue;
      const cfg = JSON.parse(fs.readFileSync(c, "utf8"));
      const rules = Array.isArray(cfg.rules) ? cfg.rules : [];
      return rules.filter((r) => r && r.id && r.pattern).map((r) => ({
        id: String(r.id),
        severity: ["high", "medium", "low", "info"].includes(r.severity) ? r.severity : "medium",
        title: String(r.title ?? r.id),
        detail: String(r.detail ?? ""),
        rea: String(r.rea ?? "custom rule"),
        fix: String(r.fix ?? "—"),
        appliesTo: Array.isArray(r.appliesTo) ? r.appliesTo.map(String) : ["any"],
        pattern: r.patternIsRegex ? new RegExp(r.pattern, "g") : null,
        literal: r.patternIsRegex ? null : String(r.pattern),
      }));
    } catch { /* missing or broken config → built-in rules still run */ }
  }
  return [];
}

export function applyCustomRules(rules, text, kind) {
  const findings = [];
  for (const r of rules) {
    const kindMatch = r.appliesTo.includes("any") || r.appliesTo.includes(kind) || r.appliesTo.includes("all");
    if (!kindMatch) continue;
    let matched = null;
    try {
      if (r.literal !== null) matched = text.includes(r.literal) ? r.literal : null;
      else { r.pattern.lastIndex = 0; matched = text.match(r.pattern)?.[0] ?? null; }
    } catch { /* skip broken rules */ }
    if (matched) findings.push({ id: r.id, severity: r.severity, title: `${r.title} (match: ${String(matched).slice(0, 40)})`, detail: r.detail, rea: r.rea, fix: r.fix });
  }
  return findings;
}

const MAX_AUDIT_BYTES = 400 * 1024 * 1024; // oversized files: read the head only (memory guard)

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
const SEV_LABEL = { high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };

export function detectFileKind(buf, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (startsWith(buf, MAGIC.elf)) return "elf";
  if (startsWith(buf, MAGIC.wasm)) return "wasm";
  if (startsWith(buf, MAGIC.zip) || startsWith(buf, Buffer.from([0x50, 0x4b, 0x05, 0x06]))) {
    return ext === ".apk" || /\.(?:apk|aab)$/.test(filePath) || buf.includes(Buffer.from("AndroidManifest.xml")) ? "apk" : "zip";
  }
  if (startsWith(buf, MAGIC.mz)) return "pe"; // pe / pe-dotnet
  if (startsWith(buf, MAGIC.macho64le) || startsWith(buf, MAGIC.macho64be) || startsWith(buf, MAGIC.machoFatBe)) return "macho";
  if (ext === ".asar" || (startsWith(buf, Buffer.from([0x04, 0x00, 0x00, 0x00])) && buf.length > 16 && buf[15] === 0x7b)) return "asar";
  if ([".js", ".mjs", ".cjs", ".html"].includes(ext)) return "js";
  return "unknown";
}

export function auditFile(filePath, customRules = []) {
  const { buf, size, truncated } = readHead(filePath, MAX_AUDIT_BYTES);
  // Source/map files: classified without parsing content
  if (/\.(?:map)$/.test(filePath)) {
    return { file: filePath, format: "js", size, truncated, findings: [{ id: "JS-MAP-FILE", severity: "high", title: `${path.basename(filePath)}: source map shipped with the artifact`, detail: "REA / browser devtools restore the original source directly.", rea: "Source-level recovery", fix: "harden removes it (release artifacts must not contain .map)" }] };
  }
  if (/\.(?:ts|tsx|jsx)$/.test(filePath)) {
    return { file: filePath, format: "js", size, truncated, findings: [{ id: "JS-TS-SOURCE", severity: "high", title: `${path.basename(filePath)}: TypeScript source shipped with the artifact`, detail: "Source leaks outright — no reverse engineering required.", rea: "Reads the source directly", fix: "Remove from release artifacts" }] };
  }
  const kind = detectFileKind(buf, filePath);
  let findings = [];
  let format = kind;
  if (kind === "elf" || kind === "pe" || kind === "macho") {
    const r = auditNative(buf, filePath);
    if (r) { findings.push(...r.findings); format = r.format; }
    if (kind === "pe") {
      const dn = auditDotnet(buf);
      if (dn) { findings.push(...dn.findings); format = "pe-dotnet"; }
    }
  } else if (kind === "apk") {
    const r = auditApk(buf);
    if (r) { findings.push(...r.findings); format = "apk"; }
  } else if (kind === "asar") {
    const r = auditAsar(buf, filePath);
    if (r) { findings.push(...r.findings); format = "asar"; }
  } else if (kind === "wasm") {
    findings.push({
      id: "WASM-GENERIC",
      severity: "medium",
      title: "WebAssembly module",
      detail: "REA bundles wabt (wasm2wat/string extraction). wasm restores to readable WAT; export names and string constants are directly readable.",
      rea: "WAT recovery + string extraction",
      fix: "wasm obfuscators / export pruning (--gc-sections, no name section) + string constant encryption",
    });
  } else if (kind === "js") {
    const text = buf.toString("utf8");
    findings.push(...auditJsText(text, path.basename(filePath)));
  }
  // Custom rules: scan text files as utf8, binaries as latin1
  if (customRules.length) {
    const scanText = kind === "js" || kind === "asar" ? buf.toString("utf8") : buf.toString("latin1");
    findings.push(...applyCustomRules(customRules, scanText, kind === "js" ? "js" : kind));
  }
  return { file: filePath, format, size, truncated, findings };
}

export function auditPath(target, { maxFiles = 600, config } = {}) {
  const customRules = loadCustomRules(config, target);
  const stat = fs.statSync(target);
  if (stat.isFile()) {
    const r = auditFile(target, customRules);
    return { target, files: [r], findings: r.findings };
  }
  const files = walkFiles(target, { maxFiles });
  const perFile = [];
  const all = [];
  for (const f of files) {
    try {
      const st = fs.statSync(f);
      if (st.size > MAX_AUDIT_BYTES) continue;
      const ext = path.extname(f).toLowerCase();
      const interesting =
        [".js", ".mjs", ".cjs", ".html", ".map", ".ts", ".tsx", ".jsx", ".asar", ".asar.unpacked"].some((x) => f.endsWith(x)) ||
        [".dll", ".exe", ".so", ".dylib", ".node", ".apk", ".aab", ".wasm", ".bin"].includes(ext);
      if (!interesting) continue;
      const r = auditFile(f, customRules);
      if (r.findings.length || ["elf", "pe", "macho", "apk", "asar", "pe-dotnet"].includes(r.format)) {
        perFile.push(r);
        all.push(...r.findings);
      }
    } catch { /* skip unreadable files */ }
  }
  return { target, files: perFile, findings: all };
}

export function summarize(findings) {
  const bySev = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  return bySev;
}

export function renderReport(result, { json = false } = {}) {
  if (json) {
    return JSON.stringify({ ...result, findings: result.findings, summary: summarize(result.findings) }, null, 2);
  }
  const bySev = summarize(result.findings);
  const lines = [];
  lines.push(`\x1b[1mAnti-REA Audit Report\x1b[0m  Target: ${result.target}`);
  lines.push(`Files scanned: ${result.files.length}    Findings: \x1b[31mhigh ${bySev.high}\x1b[0m / \x1b[33mmedium ${bySev.medium}\x1b[0m / low ${bySev.low} / info ${bySev.info}`);
  lines.push("─".repeat(78));
  const sorted = [...result.findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  for (const f of sorted) {
    const color = f.severity === "high" ? "\x1b[31m" : f.severity === "medium" ? "\x1b[33m" : f.severity === "low" ? "\x1b[36m" : "\x1b[2m";
    lines.push(`${color}[${SEV_LABEL[f.severity]}]\x1b[0m ${f.id}  ${f.title}`);
    if (f.detail) lines.push(`    Detail: ${f.detail}`);
    lines.push(`    REA usage: ${f.rea}`);
    lines.push(`    Fix: ${f.fix}`);
    lines.push("");
  }
  return lines.join("\n");
}
