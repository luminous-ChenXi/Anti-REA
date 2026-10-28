// Runtime guard library registry: sources under guards/ packaged per language.

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => fs.readFileSync(path.join(root, "guards", rel), "utf8");

export const GUARDS = {
  c: {
    id: "c",
    title: "C/C++ single-header runtime guard (anti_rea.h)",
    aliases: ["cpp", "c++", "native"],
    files: { "anti_rea.h": read("native/anti_rea.h") },
    usage: `Integration: #include "anti_rea.h", then call anti_rea_score(). Call it once early in main and again before critical flows; decide the response (log / degrade / exit / report) from the score.`,
  },
  dotnet: {
    id: "dotnet",
    title: ".NET/C# runtime guard (AntiRea.cs)",
    aliases: ["csharp", "cs"],
    files: { "AntiRea.cs": read("dotnet/AntiRea.cs") },
    usage: `Integration: add AntiRea.cs to your project, then call AntiRea.Check() at startup and before license validation.`,
  },
  js: {
    id: "js",
    title: "JavaScript/Node/Electron runtime guard (anti-rea-guard.mjs)",
    aliases: ["javascript", "node", "electron"],
    files: { "anti-rea-guard.mjs": read("js/anti-rea-guard.mjs") },
    usage: `Integration: import { threatScore, onThreat } from "./anti-rea-guard.mjs"; works in the main process and renderers alike.`,
  },
  python: {
    id: "python",
    title: "Python runtime guard (anti_rea.py)",
    aliases: ["py"],
    files: { "anti_rea.py": read("python/anti_rea.py") },
    usage: `Integration: from anti_rea import threat_score — check at the entry point and inside critical functions.`,
  },
};
