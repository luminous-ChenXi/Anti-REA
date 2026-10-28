// Anti-REA MCP Server — zero-dependency stdio JSON-RPC 2.0 implementing the
// Model Context Protocol. Lets any AI agent (Claude Code / Cursor / Codex /
// Gemini CLI…) call audit / harden / poison / guards directly.
//
// Start: node src/mcp-server.js   (or: anti-rea mcp)

import * as readline from "node:readline";
import * as fs from "node:fs";
import * as path from "node:path";
import { auditPath, summarize } from "./audit/index.js";
import { hardenNative } from "./harden/native.js";
import { hardenJsTree, hardenAsar, hardenJsFile } from "./harden/javascript.js";
import { detectFileKind } from "./audit/index.js";
import { generateDecoys, renderDecoys } from "./poison/index.js";
import { GUARDS } from "./guards.js";

const TOOLS = [
  {
    name: "anti_rea_audit",
    description: "Audit a software artifact (native ELF/PE/Mach-O binary, JS/Electron/asar tree, .NET assembly, or Android APK) and list every leak signal visible to REA (Reverse Engineer Anything) and similar AI-agent reverse-engineering pipelines: symbol tables, DWARF, Go buildinfo, PDB paths, source maps, framework sentinels, plaintext secrets… Each finding carries a severity and a concrete fix. Run this before every release.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File or directory to audit (absolute or relative to cwd)" },
      },
      required: ["path"],
    },
  },
  {
    name: "anti_rea_harden",
    description: "Harden a software artifact (always writes new files, never modifies originals): wipes symbol tables/DWARF/Go buildinfo/PDB paths/Rich header, strips JS source maps and .map files, renames webpack/esbuild/Next.js sentinel identifiers, and repacks asar via extract-harden-repack. After hardening, re-run anti_rea_audit to verify and actually execute the hardened artifact to confirm functionality.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File or directory to harden" },
        out: { type: "string", description: "Output path (defaults to hardened/ or <dir>.hardened)" },
        keepDebug: { type: "boolean", description: "Keep DWARF/debug directory (default false)" },
        keepSymtab: { type: "boolean", description: "Keep symbol tables (default false)" },
        keepGoBuildinfo: { type: "boolean", description: "Keep Go buildinfo (default false)" },
        wipeSwiftRefl: { type: "boolean", description: "Mach-O: wipe Swift reflection metadata (default false)" },
        noRename: { type: "boolean", description: "JS: do not rename framework sentinels (default false)" },
      },
      required: ["path"],
    },
  },
  {
    name: "anti_rea_poison",
    description: "Generate decoy/honeypot constants (fake endpoints, fake license formats, fake feature names, honeypot markers) to mix into artifacts: dilutes the attention of reverse-engineering LLMs and acts as a tripwire when touched. Outputs js/c/csharp/python/json/text.",
    inputSchema: {
      type: "object",
      properties: {
        count: { type: "number", description: "How many decoys (default 40)" },
        format: { type: "string", enum: ["js", "c", "csharp", "python", "json", "text"], description: "Output format (default text)" },
        seed: { type: "string", description: "Random seed (reproducible)" },
        out: { type: "string", description: "Write to file (omit to return text)" },
      },
    },
  },
  {
    name: "anti_rea_guards",
    description: "Emit runtime guard library sources: c (single-header anti_rea.h), dotnet (AntiRea.cs), js (anti-rea-guard.mjs), python (anti_rea.py). Each detects REA environment variables, analyst parent processes, Frida injection and debuggers via a side-effect-free 0-100 score.",
    inputSchema: {
      type: "object",
      properties: {
        language: { type: "string", enum: ["c", "dotnet", "js", "python"], description: "Target language" },
        outDir: { type: "string", description: "Output directory (omit to return the source text directly)" },
      },
      required: ["language"],
    },
  },
];

function callTool(name, args) {
  if (name === "anti_rea_audit") {
    const target = args.path;
    if (!target || !fs.existsSync(target)) return { error: `path does not exist: ${target}` };
    const result = auditPath(target);
    const summary = summarize(result.findings);
    const top = result.findings
      .sort((a, b) => ({ high: 0, medium: 1, low: 2, info: 3 })[a.severity] - ({ high: 0, medium: 1, low: 2, info: 3 })[b.severity])
      .slice(0, 30)
      .map((f) => `[${f.severity}] ${f.id}: ${f.title}\n  REA usage: ${f.rea}\n  Fix: ${f.fix}`);
    return {
      content: [
        {
          type: "text",
          text: `Audit ${target}: high ${summary.high} / medium ${summary.medium} / low ${summary.low} / info ${summary.info}\n\n` + top.join("\n") +
            (result.findings.length > 30 ? `\n…${result.findings.length} findings in total` : "") +
            `\n\nNext steps: call anti_rea_harden for the auto-fixable items; secrets (JS-SECRETS) need manual rotation.`,
        },
      ],
    };
  }
  if (name === "anti_rea_harden") {
    const target = args.path;
    if (!target || !fs.existsSync(target)) return { error: `path does not exist: ${target}` };
    const opts = {
      keepDebug: !!args.keepDebug,
      keepSymtab: !!args.keepSymtab,
      keepGoBuildinfo: !!args.keepGoBuildinfo,
      wipeSwiftRefl: !!args.wipeSwiftRefl,
      renameSentinels: !args.noRename,
    };
    const stat = fs.statSync(target);
    const out = args.out || (stat.isFile() ? path.join(path.dirname(target), "hardened", path.basename(target)) : target + ".hardened");
    let log;
    if (stat.isFile()) {
      const head = Buffer.alloc(64);
      const fd = fs.openSync(target, "r");
      fs.readSync(fd, head, 0, 64, 0);
      fs.closeSync(fd);
      const kind = detectFileKind(head, target);
      fs.mkdirSync(path.dirname(out), { recursive: true });
      if (kind === "elf" || kind === "pe" || kind === "macho") {
        const r = hardenNative(target, out, opts);
        log = r.changes.map((c) => `✓ ${c.id} (${c.bytes}B) ${c.note}`).join("\n") || "(no applicable transforms)";
      } else if (kind === "asar") {
        const r = hardenAsar(target, out, opts);
        log = `✓ asar repacked: ${r.fileCount} file(s), JS transformed ${r.transformed}/${r.files}, ${r.removedMaps} .map removed`;
      } else if (kind === "js") {
        const r = hardenJsFile(target, out, opts);
        log = `✓ JS transforms applied: ${r.changes}`;
      } else return { error: `unsupported type: ${kind}` };
    } else {
      const r = hardenJsTree(target, out, opts);
      log = `✓ JS tree hardened: ${r.transformed}/${r.files} file(s) transformed, ${r.removedMaps} .map removed`;
    }
    return { content: [{ type: "text", text: `Hardened ${target} -> ${out}\n${log}\n\nAlways: 1) run the hardened artifact to verify functionality 2) call anti_rea_audit to re-check` }] };
  }
  if (name === "anti_rea_poison") {
    const decoys = generateDecoys({ count: args.count ?? 40, seed: args.seed ?? "anti-rea" });
    const text = renderDecoys(decoys, args.format ?? "text");
    if (args.out) {
      fs.mkdirSync(path.dirname(args.out), { recursive: true });
      fs.writeFileSync(args.out, text);
      return { content: [{ type: "text", text: `Wrote ${args.out} (${decoys.length} decoys)` }] };
    }
    return { content: [{ type: "text", text }] };
  }
  if (name === "anti_rea_guards") {
    const guard = Object.values(GUARDS).find((g) => g.id === args.language);
    if (!guard) return { error: `unknown language: ${args.language}` };
    if (args.outDir) {
      fs.mkdirSync(args.outDir, { recursive: true });
      for (const [name, content] of Object.entries(guard.files)) fs.writeFileSync(path.join(args.outDir, name), content);
      return { content: [{ type: "text", text: `Emitted to ${args.outDir}\n${guard.usage}` }] };
    }
    const [firstName] = Object.keys(guard.files);
    return { content: [{ type: "text", text: guard.files[firstName] }] };
  }
  return { error: `unknown tool: ${name}` };
}

export function startMcpServer() {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const send = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

  rl.on("line", (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const { id, method, params } = msg;
    if (method === "initialize") {
      send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: params?.protocolVersion ?? "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "anti-rea", version: "0.1.0" },
        },
      });
    } else if (method === "notifications/initialized" || method === "notifications/cancelled") {
      // nothing to answer
    } else if (method === "tools/list") {
      send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    } else if (method === "tools/call") {
      try {
        const result = callTool(params?.name, params?.arguments ?? {});
        send({ jsonrpc: "2.0", id, result });
      } catch (e) {
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `error: ${e.message}` }], isError: true } });
      }
    } else if (method === "ping") {
      send({ jsonrpc: "2.0", id, result: {} });
    } else if (id !== undefined) {
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
    }
  });
  process.stderr.write("[anti-rea] MCP server ready on stdio\n");
}
