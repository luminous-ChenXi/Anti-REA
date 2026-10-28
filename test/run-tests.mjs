// Anti-REA test suite: node test/run-tests.mjs
// Covers: format parsers, audit, harden (native/js/asar), poison, guards,
// custom rules, and the MCP server.
// Requires example artifacts under examples/go-app (built with Go when present;
// native cases are skipped gracefully without it).

import * as fs from "node:fs";
import * as path from "node:path";
import * as cp from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "test", "out");
const CLI = path.join(ROOT, "bin", "anti-rea.mjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.error(`  ✗ ${name}`); }
};
const run = (args, opts = {}) => cp.spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", cwd: ROOT, ...opts });

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

console.log("\n[1] CLI basics");
ok("--help exits 0", run(["--help"]).status === 0);

console.log("\n[2] native audit -> harden -> re-audit");
const goExe = path.join(ROOT, "examples", "go-app", "demo-app.exe");
const goElf = path.join(ROOT, "examples", "go-app", "demo-app-linux");
if (fs.existsSync(goExe)) {
  const pre = run(["audit", goExe]);
  ok("pre-harden: high-risk findings present (buildinfo/symtab)", pre.status === 2 && pre.stdout.includes("NAT-"));
  const h = run(["harden", goExe, "--out", path.join(OUT, "demo-app.exe")]);
  ok("harden succeeds", h.status === 0);
  const post = run(["audit", path.join(OUT, "demo-app.exe")]);
  ok("post-harden: high-risk findings cleared", post.status !== 2 && !post.stdout.includes("[HIGH] NAT-"));
  try {
    const r = cp.spawnSync(path.join(OUT, "demo-app.exe"), ["TEST-KEY"], { encoding: "utf8" });
    ok("hardened binary still runs", r.status === 0 && r.stdout.includes("app ok"));
  } catch (e) { ok("hardened binary still runs", false); }
} else {
  console.log("  (Go example artifact missing, skipping PE case)");
}
if (fs.existsSync(goElf)) {
  run(["harden", goElf, "--out", path.join(OUT, "demo-app-linux")]);
  const post = run(["audit", path.join(OUT, "demo-app-linux")]);
  ok("ELF post-harden: findings cleared", post.status !== 2 && !post.stdout.includes("[HIGH] NAT-"));
} else {
  console.log("  (ELF example artifact missing, skipping ELF case)");
}

console.log("\n[3] JS audit -> harden -> run");
const jsDir = path.join(ROOT, "examples", "js-app");
{
  const pre = run(["audit", jsDir]);
  ok("JS: sentinels/sourcemap/secrets detected", pre.stdout.includes("JS-WEBPACK") && pre.stdout.includes("JS-SOURCEMAP") && pre.stdout.includes("JS-SECRETS"));
  ok(".map file detected", pre.stdout.includes("JS-MAP-FILE"));
  const before = cp.spawnSync(process.execPath, [path.join(jsDir, "app.js")], { encoding: "utf8" });
  const h = run(["harden", jsDir, "--out", path.join(OUT, "js-app")]);
  ok("JS harden succeeds and removes the map", h.status === 0 && h.stdout.includes("1 .map removed"));
  const after = cp.spawnSync(process.execPath, [path.join(OUT, "js-app", "app.js")], { encoding: "utf8" });
  ok("runtime output identical before/after", before.stdout === after.stdout && after.stdout.includes("js app ok"));
  const hardenedText = fs.readFileSync(path.join(OUT, "js-app", "app.js"), "utf8");
  ok("sentinels renamed", !hardenedText.includes("__webpack_require__") && !/sourceMappingURL=/.test(hardenedText));
}

console.log("\n[4] asar pack -> harden -> repack/parse");
{
  const { packAsar, parseAsar, asarEntries, extractAsar } = await import(pathToFileURL(path.join(ROOT, "src", "formats", "asar.js")).href);
  const asarPath = path.join(OUT, "app.asar");
  packAsar(jsDir, asarPath);
  const parsed0 = parseAsar(fs.readFileSync(asarPath));
  ok("packed asar parses", !!parsed0);
  const h = run(["harden", asarPath, "--out", path.join(OUT, "app.hardened.asar")]);
  ok("asar harden succeeds", h.status === 0);
  const parsed1 = parseAsar(fs.readFileSync(path.join(OUT, "app.hardened.asar")));
  ok("repacked asar parses and contains no .map", !!parsed1 && !asarEntries(parsed1).some((e) => e.path.endsWith(".map")));
  extractAsar(parsed1, path.join(OUT, "extracted"));
  const text = fs.readFileSync(path.join(OUT, "extracted", "app.js"), "utf8");
  ok("bundled JS transformed", !text.includes("__webpack_require__") && !/sourceMappingURL=/.test(text));
}

console.log("\n[5] poison");
{
  const r1 = run(["poison", "--count", "10", "--seed", "42", "--format", "text"]);
  const r2 = run(["poison", "--count", "10", "--seed", "42", "--format", "text"]);
  ok("same seed reproduces output", r1.stdout === r2.stdout && r1.stdout.split("\n").length >= 10);
  const rj = run(["poison", "--count", "5", "--seed", "7", "--format", "js"]);
  ok("JS format output", rj.stdout.includes("export const RESOURCES"));
}

console.log("\n[6] guards");
{
  ok("guards list", run(["guards", "list"]).stdout.includes("c"));
  const g = run(["guards", "emit", "python", "--out", path.join(OUT, "g")]);
  ok("guards emit python", g.status === 0 && fs.existsSync(path.join(OUT, "g", "anti_rea.py")));
  const py = cp.spawnSync("python", [path.join(OUT, "g", "anti_rea.py")], { encoding: "utf8" });
  ok("clean environment scores 0", py.stdout.trim().startsWith("score=0"));
  const py2 = cp.spawnSync("python", [path.join(OUT, "g", "anti_rea.py")], { encoding: "utf8", env: { ...process.env, REA_PROCESS_RUN_ID: "x" } });
  ok("REA env scores >= 60", /score=(?:6\d|[7-9]\d|100)/.test(py2.stdout));
  // JS guard imports cleanly
  const jsr = cp.spawnSync(process.execPath, ["-e", `import(${JSON.stringify(pathToFileURL(path.join(ROOT, "guards", "js", "anti-rea-guard.mjs")).href)}).then(m => { const r = m.threatScore(); console.log("js-guard-ok", r.score >= 0); })`], { encoding: "utf8" });
  ok("JS guard imports", jsr.stdout.includes("js-guard-ok"));
}

console.log("\n[7] custom rules");
{
  const cfg = path.join(OUT, "cfg.json");
  fs.writeFileSync(cfg, JSON.stringify({ rules: [{ id: "CUSTOM-TEST", appliesTo: ["js"], pattern: "TRIAL_SECRET", severity: "high", title: "t", detail: "d", rea: "r", fix: "f" }] }));
  const r = run(["audit", jsDir, "--config", cfg]);
  ok("custom rule matches", r.stdout.includes("CUSTOM-TEST"));
}

console.log("\n[8] MCP server");
{
  const input = [
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } }),
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "anti_rea_poison", arguments: { count: 3, seed: "mcp" } } }),
  ].join("\n") + "\n";
  const r = cp.spawnSync(process.execPath, [CLI, "mcp"], { input, encoding: "utf8" });
  const lines = r.stdout.trim().split("\n").map((l) => JSON.parse(l));
  const init = lines.find((l) => l.id === 1), list = lines.find((l) => l.id === 2), call = lines.find((l) => l.id === 3);
  ok("initialize replies", init?.result?.serverInfo?.name === "anti-rea");
  ok("tools/list exposes 4 tools", list?.result?.tools?.length === 4);
  ok("tools/call returns decoys", call?.result?.content?.[0]?.text?.includes("#"));
}

console.log(`\nResult: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
