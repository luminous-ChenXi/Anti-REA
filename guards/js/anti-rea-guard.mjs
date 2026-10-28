/**
 * anti-rea-guard.mjs — Anti-REA runtime guard (JavaScript / Node.js / Electron)
 *
 * Detection surface (grounded in REA source recon):
 *  - Node/Electron main process: REA_* environment variables, analyst parent
 *    processes (rea.mjs/frida/gdb/lldb), TMPDIR rea-provider-* /
 *    rea-browser-scenario-*, --inspect debugging, active inspector sessions,
 *    loaded frida-node modules
 *  - Browser/renderer: navigator.webdriver (Playwright/Puppeteer marker),
 *    automation globals, async DevTools/CDP probe
 *
 * Score-based, side-effect-free by default. Example:
 *   import { threatScore, onThreat } from "./anti-rea-guard.mjs";
 *   onThreat((score, findings) => { if (score >= 60) process.exit(1); });
 *   const { score } = threatScore();
 *
 * MIT License — Anti-REA project
 */

const W = {
  envRunId: 60,
  envBridge: 40,
  parentTool: 40,
  ipcDir: 35,
  inspector: 55,
  fridaModule: 70,
  webdriver: 45,
};

const isNode = typeof process !== "undefined" && !!process.versions?.node;
const isBrowser = typeof window !== "undefined" && typeof document !== "undefined";

/** Environment & process checks (Node / Electron main process). */
function nodeChecks(findings) {
  const env = process.env || {};
  if (env.REA_PROCESS_RUN_ID) findings.push({ hit: "REA_PROCESS_RUN_ID", weight: W.envRunId });
  for (const v of ["REA_SOCKET", "REA_TOKEN", "REA_RUN_ID", "REA_TARGET_PATH"])
    if (env[v]) findings.push({ hit: v, weight: W.envBridge });

  // --inspect injected via NODE_OPTIONS (V8 inspector analysis前置)
  if ((env.NODE_OPTIONS || "").includes("--inspect")) findings.push({ hit: "node-inspect", weight: W.inspector });

  // Is an inspector session active?
  try {
    const inspector = globalThis.process?.getBuiltinModule?.("node:inspector") ?? null;
    if (inspector?.url?.()) findings.push({ hit: "inspector-active", weight: W.inspector });
  } catch { /* ignore */ }

  // Loaded frida-node modules (visible in CJS interop only; ESM relies on other vectors)
  try {
    if (globalThis.require?.cache) {
      for (const k of Object.keys(globalThis.require.cache))
        if (k.includes("frida")) findings.push({ hit: "frida-module", weight: W.fridaModule });
    }
  } catch { /* ignore */ }

  // Parent process command line (POSIX)
  try {
    const fs = globalThis.process?.getBuiltinModule?.("node:fs");
    if (fs && process.ppid) {
      const cmdline = fs.readFileSync(`/proc/${process.ppid}/cmdline`, "utf8").replace(/\0/g, " ").toLowerCase();
      for (const marker of ["rea.mjs", "frida", "gdb", "lldb", "ghidra", "ida", "hopper", "rizin", "mitmdump"])
        if (cmdline.includes(marker)) findings.push({ hit: `parent:${marker}`, weight: W.parentTool });
    }
  } catch { /* non-POSIX or unreadable */ }

  // REA traces under TMPDIR
  try {
    const fs = globalThis.process?.getBuiltinModule?.("node:fs");
    const os = globalThis.process?.getBuiltinModule?.("node:os");
    if (fs && os) {
      const tmp = os.tmpdir();
      for (const name of fs.readdirSync(tmp))
        if (name.startsWith("rea-provider-") || name.startsWith("rea-browser-scenario-"))
          findings.push({ hit: "rea-ipc-dir", weight: W.ipcDir });
    }
  } catch { /* ignore */ }
}

/** Browser/renderer checks. */
function browserChecks(findings) {
  const nav = globalThis.navigator || {};
  if (nav.webdriver === true) findings.push({ hit: "navigator.webdriver", weight: W.webdriver });
  // Common headless Chrome traits
  if (!nav.languages || nav.languages.length === 0) findings.push({ hit: "no-languages", weight: 15 });
  // Playwright/Puppeteer/Selenium injected globals
  for (const k of ["__playwright", "__pw_manual", "__selenium_unwrapped", "cdc_adoQpoasnfa76pfcZLmcfl_Array"])
    if (k in globalThis) findings.push({ hit: `automation:${k}`, weight: W.webdriver });
}

/**
 * Async DevTools/CDP probe (browser only):
 * when DevTools is open or CDP is attached, console value serialization
 * triggers getters. Resolves to true when tripped.
 */
export async function detectDevtoolsAsync() {
  if (!isBrowser || !globalThis.console) return false;
  return new Promise((resolve) => {
    let tripped = false;
    const probe = new Image();
    Object.defineProperty(probe, "id", {
      get() {
        tripped = true;
        return "devtools";
      },
    });
    // eslint-disable-next-line no-console
    console.log("%c", probe);
    setTimeout(() => resolve(tripped), 60);
  });
}

export function threatScore() {
  const findings = [];
  if (isNode) nodeChecks(findings);
  if (isBrowser) browserChecks(findings);
  const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
  return { score, findings };
}

const handlers = new Set();
export function onThreat(fn) {
  handlers.add(fn);
  return () => handlers.delete(fn);
}

/** Entry-point self-check: invokes handlers at/above the threshold (default 40). */
export function arm({ threshold = 40, intervalMs = 0 } = {}) {
  const run = () => {
    const { score, findings } = threatScore();
    if (score >= threshold) for (const fn of handlers) fn(score, findings);
    return score;
  };
  const first = run();
  if (intervalMs > 0 && isNode) setInterval(run, intervalMs).unref?.();
  return first;
}

export default { threatScore, onThreat, arm };
