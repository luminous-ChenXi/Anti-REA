// Anti-REA CLI: audit / harden / poison / guards / mcp

import * as fs from "node:fs";
import * as path from "node:path";
import { auditPath, renderReport } from "./audit/index.js";
import { hardenNative } from "./harden/native.js";
import { hardenJsTree, hardenAsar, hardenJsFile } from "./harden/javascript.js";
import { detectFileKind } from "./audit/index.js";
import { generateDecoys, renderDecoys } from "./poison/index.js";
import { GUARDS } from "./guards.js";

const HELP = `
Anti-REA v0.1 — anti reverse-engineering hardening toolkit (counters REA and AI-agent RE pipelines)

Usage:
  anti-rea audit  <file-or-dir> [--json]        Audit signals visible to REA; exit code 2 = high-risk findings
  anti-rea harden <file-or-dir> [--out output]  Harden (writes new files, never touches the originals)
      Options: --keep-debug         keep DWARF / debug directory
               --keep-symtab        keep symbol tables
               --keep-go-buildinfo  keep Go buildinfo (if you need runtime version info)
               --wipe-swift-refl    Mach-O: wipe Swift reflection metadata (Mirror degrades)
               --no-rename          JS: do not rename framework sentinel identifiers
  anti-rea poison [--count N] [--format js|c|csharp|python|json|text] [--seed S] [--out file]
                                                Generate decoy/honeypot constants to dilute LLM analysis
  anti-rea guards list                          List runtime guard libraries
  anti-rea guards emit <lang> [--out dir]       Emit a runtime guard library (c|dotnet|js|python)
  anti-rea mcp                                  Run as an MCP server (stdio; plug into any AI agent)

Config: an anti-rea.config.json in the working directory registers custom detection
rules (community-contributable). See the README.

Examples:
  anti-rea audit dist/app.asar
  anti-rea harden myapp.exe --out hardened/myapp.exe
  anti-rea poison --count 60 --format c --out decoys.h
  anti-rea guards emit js --out src/vendor/
`;

function parseArgs(args) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("--") && !FLAGS_BOOL.has(key)) {
        flags[key] = next;
        i++;
      } else flags[key] = true;
    } else positional.push(a);
  }
  return { positional, flags };
}
const FLAGS_BOOL = new Set(["json", "keep-debug", "keep-symtab", "keep-go-buildinfo", "wipe-swift-refl", "no-rename"]);

export async function runCli(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    process.stdout.write(HELP);
    return 0;
  }
  const { positional, flags } = parseArgs(rest);

  try {
    if (cmd === "audit") {
      const target = positional[0];
      if (!target || !fs.existsSync(target)) throw new Error("please provide a file or directory to audit");
      const result = auditPath(target, { config: flags.config });
      process.stdout.write(renderReport(result, { json: !!flags.json }) + "\n");
      return result.findings.some((f) => f.severity === "high") ? 2 : 0; // exit code 2 = high-risk findings
    }

    if (cmd === "harden") {
      const target = positional[0];
      if (!target || !fs.existsSync(target)) throw new Error("please provide a file or directory to harden");
      const opts = {
        keepDebug: !!flags["keep-debug"],
        keepSymtab: !!flags["keep-symtab"],
        keepGoBuildinfo: !!flags["keep-go-buildinfo"],
        wipeSwiftRefl: !!flags["wipe-swift-refl"],
        renameSentinels: !flags["no-rename"],
      };
      const stat = fs.statSync(target);
      const outRoot = flags.out || (stat.isFile() ? path.join(path.dirname(target), "hardened") : target.replace(/[\\/]?$/, "") + ".hardened");
      console.log(`Anti-REA harden: ${target} -> ${outRoot}`);
      let totalChanges = 0;
      if (stat.isFile()) {
        const head = Buffer.alloc(64);
        const fd = fs.openSync(target, "r");
        fs.readSync(fd, head, 0, 64, 0);
        fs.closeSync(fd);
        const kind = detectFileKind(head, target);
        fs.mkdirSync(path.dirname(outRoot), { recursive: true });
        if (kind === "elf" || kind === "pe" || kind === "macho") {
          const r = hardenNative(target, outRoot, opts);
          for (const c of r.changes) console.log(`  ✓ ${c.id}  (${c.bytes} bytes) ${c.note}`);
          totalChanges += r.changes.length;
          if (!r.changes.length) console.log("  (no applicable transforms)");
        } else if (kind === "asar") {
          const r = hardenAsar(target, outRoot, opts);
          console.log(`  ✓ asar repacked: ${r.fileCount} file(s), JS transformed ${r.transformed}/${r.files}, ${r.removedMaps} .map removed`);
        } else if (kind === "js") {
          const r = hardenJsFile(target, outRoot, opts);
          console.log(`  ✓ JS transforms: ${r.changes} applied`);
        } else {
          console.log(`  ✗ unrecognized type (${kind}), skipping.`);
          return 1;
        }
      } else {
        const r = hardenJsTree(target, outRoot, opts);
        console.log(`  ✓ JS tree hardened: ${r.transformed}/${r.files} file(s) transformed, ${r.removedMaps} .map removed`);
      }
      console.log(`Done. Verify with: anti-rea audit ${outRoot} — and run the hardened artifact to confirm it still works.`);
      return 0;
    }

    if (cmd === "poison") {
      const decoys = generateDecoys({ count: Number(flags.count || 40), seed: String(flags.seed || "anti-rea") });
      const text = renderDecoys(decoys, flags.format || "text");
      if (flags.out) {
        fs.mkdirSync(path.dirname(flags.out), { recursive: true });
        fs.writeFileSync(flags.out, text);
        console.log(`Wrote ${flags.out} (${decoys.length} decoys)`);
      } else process.stdout.write(text);
      return 0;
    }

    if (cmd === "guards") {
      const sub = positional[0];
      if (sub === "list" || !sub) {
        console.log("Available runtime guard libraries:");
        for (const g of Object.values(GUARDS)) console.log(`  ${g.id.padEnd(8)} ${g.title}`);
        return 0;
      }
      if (sub === "emit") {
        const lang = positional[1];
        const guard = Object.values(GUARDS).find((g) => g.id === lang || g.aliases.includes(lang || ""));
        if (!guard) throw new Error(`unknown language: ${lang} (choose from ${Object.values(GUARDS).map((g) => g.id).join(", ")})`);
        const outDir = flags.out || ".";
        fs.mkdirSync(outDir, { recursive: true });
        for (const [name, content] of Object.entries(guard.files)) {
          fs.writeFileSync(path.join(outDir, name), content);
          console.log(`  wrote ${path.join(outDir, name)} (${content.length} bytes)`);
        }
        console.log(guard.usage);
        return 0;
      }
      throw new Error("guards subcommands: list | emit <lang>");
    }

    if (cmd === "mcp") {
      const { startMcpServer } = await import("./mcp-server.js");
      startMcpServer();
      return new Promise(() => {}); // long-running
    }

    process.stdout.write(HELP);
    return cmd === "version" || cmd === "--version" ? (console.log("0.1.0"), 0) : 1;
  } catch (e) {
    console.error(`error: ${e.message}`);
    return 1;
  }
}
