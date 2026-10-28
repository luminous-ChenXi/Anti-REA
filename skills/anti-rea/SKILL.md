---
name: anti-rea
description: Pre-release anti reverse-engineering hardening: audit closed-source software (native binaries/Electron/.NET/APK) for signals visible to REA and similar AI-agent RE pipelines, harden automatically, verify functionality is unchanged, generate decoys and runtime guards. Use when the user wants to release, harden, obfuscate, or protect software from decompilation/reverse engineering/cracking, or mentions REA, anti-reverse-engineering, or software protection.
---

# Anti-REA: pre-release anti reverse-engineering skill

Your job is to help developers harden closed-source software against REA (Reverse Engineer Anything) and similar AI-agent reverse-engineering pipelines. Core principle: **audit → harden → re-audit → run verification** — never skip a step.

## Tool invocation

The CLI lives at the repository root, zero-dependency, run with node (or the global `anti-rea` if installed):

```bash
node bin/anti-rea.mjs audit <path> [--config anti-rea.config.json]   # audit (exit code 2 = high-risk findings)
node bin/anti-rea.mjs harden <path> [--out output] [--keep-debug] ...  # harden (never touches originals)
node bin/anti-rea.mjs poison --count 60 --format c --out decoys.h    # decoy constants
node bin/anti-rea.mjs guards emit js --out src/vendor/               # runtime guard library
node bin/anti-rea.mjs mcp                                           # MCP server mode
```

## Workflow

1. **Audit**: run `audit`, read the report. High-risk items are signals REA directly exploits (symbol tables, DWARF, buildinfo, PDB paths, source maps, framework sentinels, plaintext secrets).
2. **Manual items first**: never auto-rewrite `JS-SECRETS`-class findings — list them and tell the user to rotate the keys immediately.
3. **Harden**: run `harden`; output lands in `hardened/` or `<name>.hardened`. Originals are never modified.
4. **Re-audit**: run `audit` on the output; high-risk findings must be zero.
5. **Run verification (mandatory)**: actually execute the hardened artifact (node, launch the exe, run tests). Functionality must be identical — every transform must be proven non-breaking.
6. **Advanced recommendations** (pick per user scenario):
   - Desktop native: integrate `guards emit c` (anti_rea.h); call `anti_rea_score()` before license checks
   - Electron: `guards emit js`; `arm()` in the main process + `detectDevtoolsAsync()` in renderers
   - .NET: an obfuscator (Obfuscar/BitMono) is required for symbol renaming + string encryption; audit measures but cannot rewrite
   - Android: R8 full mode; never ship mapping.txt; forward APK-* findings to the user
   - Higher obfuscation bar: combine with configs/javascript-obfuscator.preset.json (string array/control-flow flattening)
7. **Decoys**: for high-risk products, generate decoys with `poison` and mix them into resources; pair honeypot markers with guards for tripwires.

## Reporting requirements

The hardening report to the user must include: high-risk counts before vs. after, byte counts per transform, run-verification results, and remaining manual items (secrets / obfuscators / build-time flags).
