<div align="center">

# 🛡️ Anti-REA

**Make your closed-source software invisible to AI-agent reverse engineering.**

A zero-dependency, four-layer hardening toolkit that counters
[REA (Reverse Engineer Anything)](https://github.com/morluto/rea) and similar
AI-agent-driven reverse-engineering pipelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-f4c430.svg?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-339933.svg?style=flat-square&logo=nodedotjs&logoColor=white)](package.json)
[![Tests](https://img.shields.io/badge/tests-26%2F26-2ea44f.svg?style=flat-square)](test/run-tests.mjs)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-5c4ee5.svg?style=flat-square)](CONTRIBUTING.md)

[Why](#why) · [Quick start](#quick-start) · [How it works](#how-it-works) · [MCP](#use-it-from-your-ai-agent-mcp) · [Threat model](#threat-model--honest-limitations) · [FAQ](#faq)

`npx anti-rea audit dist/`

</div>

---

## Why

[REA](https://github.com/morluto/rea) (~400k ⭐) turns any AI coding agent into a reverse engineer: point it at an app and it extracts pseudocode, symbols, strings and dependency lists — with evidence attached — then reimplements your feature. What used to cost an expert a week now costs an end user a minute.

**Anti-REA is the other side of that mirror.** One command audits what such pipelines can see in your software; the next removes, renames or poisons it — without touching your source code or breaking your app.

It is built for individual and enterprise developers protecting closed-source desktop apps (native / Electron / .NET) and mobile apps (Android).

## Quick start

```bash
# 1. Audit — what can REA see in your artifact? (exit code 2 = high-risk findings)
npx anti-rea audit dist/

# 2. Harden — writes NEW files, never touches the originals
npx anti-rea harden dist/ --out dist-hardened/

# 3. Verify — re-audit AND actually run the hardened artifact
npx anti-rea audit dist-hardened/ && node dist-hardened/app.js

# 4. (optional) Runtime guards — detect REA/Frida/debuggers while your app runs
npx anti-rea guards emit c --out src/
```

## How it works

Four composable layers. Each is useful alone; together they push reverse-engineering cost back from "user minutes" toward "expert weeks".

| Layer | Command | What it does |
|---|---|---|
| **Audit** | `audit` | Detects 40+ signals REA's pipelines rely on: Go buildinfo magic, `/rustc/` paths, symbol tables, DWARF, PE COFF symbols, Rich header, PDB paths, source maps, webpack/esbuild/Next.js sentinels, Electron fuses, .NET `#Strings`/`#US` heaps, APK resource tables, plaintext secrets… Every finding states *what REA does with it* and *how to fix it*. |
| **Harden** | `harden` | Content-level transforms only — no structural/address changes: wipes ELF non-ALLOC debug/symbol sections, Go buildinfo magic, PE COFF symbol table, debug directory & Rich header; renames JS framework sentinels (declarations + references together); strips source maps; repacks asar via extract→harden→repack. **Always outputs new files and reminds you to run them.** |
| **Poison** | `poison` | Generates reproducible decoy constants — fake endpoints, fake license formats, fake feature names, honeypot markers — to dilute the attention of analysis LLMs and act as tripwires (a decoy being touched = someone is reverse engineering). |
| **Guards** | `guards` | Four same-shaped runtime libraries (C/C++ · C# · JS · Python) that score the environment 0–100: REA's injected `REA_PROCESS_RUN_ID` env var, `rea-provider-*`/`rea-lease-*` IPC, `rea.mjs`/gdb/ghidra parent chains, Frida gum threads, ptrace/`IsDebuggerPresent`. **Side-effect-free by default** — your code decides the response. |

### Why these specific signals?

Anti-REA is grounded in a source-level study of REA's pipeline (see [docs/REPORT.zh-CN.md](docs/REPORT.zh-CN.md), Chinese, with file-path evidence). Two findings shape the design:

1. **REA has no guessy fallbacks.** When a signal is missing it honestly reports the facet as `unavailable`. So the winning move is *making signals disappear*, not corrupting them (though poisoning its evidence also works).
2. **REA leaks itself at runtime.** Its process harness injects `REA_PROCESS_RUN_ID` into your process environment — an architectural self-exposure your app can trivially detect.

## Use it from your AI agent (MCP)

Anti-REA ships its own zero-dependency MCP server — REA lets agents reverse other people's software; Anti-REA lets agents protect yours.

```json
{
  "mcpServers": {
    "anti-rea": {
      "command": "node",
      "args": ["/path/to/Anti-REA/src/mcp-server.js"]
    }
  }
}
```

Exposes `anti_rea_audit`, `anti_rea_harden`, `anti_rea_poison`, `anti_rea_guards`. Then just ask your agent: *"harden my dist folder and verify it still runs."*

An [agent skill](skills/anti-rea/SKILL.md) (ZCode / Claude Code) is also included, encoding the mandatory audit → harden → re-audit → run-verification workflow.

## Custom rules (community-extensible)

Drop an `anti-rea.config.json` in your project root ([full example](configs/anti-rea.example.config.json)):

```json
{
  "rules": [{
    "id": "CUSTOM-MY-PREFIX",
    "appliesTo": ["js"],
    "pattern": "MySecretPrefix_",
    "patternIsRegex": false,
    "severity": "high",
    "title": "Company-internal string prefix leaked",
    "fix": "Replace with a random prefix via a build plugin"
  }]
}
```

`audit` merges these with built-in rules — reusable rule packs are very welcome PRs.

## Presets & build-time advice

- [`configs/javascript-obfuscator.preset.json`](configs/javascript-obfuscator.preset.json) — a `javascript-obfuscator` config tuned against REA's AST analysis
- **Go**: `-ldflags "-s -w"` at build time + `anti-rea harden` for the buildinfo magic
- **.NET**: audit measures the leak; use Obfuscar/BitMono (or commercial) for symbol renaming + string encryption
- **Android**: R8 full mode; never ship `mapping.txt` (audit flags it if you do)

## Hardening safety model

`harden` is deliberately conservative — it performs **content-level** transforms only:

- never modifies structures, addresses, or loader-required sections
- ELF: only non-`SHF_ALLOC` sections
- PE: keeps the `MZ` header and `e_lfanew`; zeroing the COFF pointer is loader-safe
- JS: sentinel renames are declaration+reference consistent — semantics unchanged
- originals are never modified; output always goes to new files
- **you must run the hardened artifact** — the tool reminds you, our tests prove it

## Verified results

All claims below are reproducible via `npm test` (26 checks):

| Scenario | Before | After | Functionality |
|---|---|---|---|
| Go PE binary (2.7 MB) | 2 high-risk (buildinfo + 2,891-entry COFF symtab) | **0** | runs, identical output ✓ |
| Go ELF binary | buildinfo + DWARF + symtab findings | **0** | structure intact ✓ |
| webpack-style JS | 3 high-risk (sourcemap/sentinels/secrets) | sentinels & maps cleared (secrets → manual) | runs, identical output ✓ |
| asar archive | sentinels + embedded map | cleared & repacked | parses & extracts ✓ |
| Python guard | — | score 0 clean / 60 under `REA_PROCESS_RUN_ID` | — |
| MCP server | — | initialize / tools/list / tools/call ✓ | — |

*C/C++ and C# guards are conservative, standard code but not compiler-verified in this repo yet — CI contributions welcome.*

## Threat model & honest limitations

- **This cannot make software "unreversible."** Nothing can. The goal is cost restoration: *user minutes → expert weeks*.
- **Runtime fingerprints drift.** REA is open source; an attacker can strip `REA_PROCESS_RUN_ID` from a fork. Treat guards as one layer among several, and keep rules updated (the plugin system exists for exactly this).
- **Some signals need build-time tools.** .NET metadata tables, ObjC/Swift runtime-required metadata and wasm name sections cannot be blindly wiped post-build; `audit` detects them and points to the right tool.
- **Server-side beats everything.** If a secret or check can live server-side, it should. Client-side hardening is for what must ship.
- **REA will evolve.** All signatures come from REA `main` @ `40b9c03` (2026-10-28). Community rule packs keep this current.

## FAQ

**Will hardening break my app?**
The transforms are chosen so it can't — and we verify by running the output. If your tooling depends on unrenamed framework globals (e.g. webpack HMR), that's why hardening targets *release artifacts only*, and `--no-rename` exists.

**Is this legal?**
Protecting your own software is legitimate — same category as VMProtect, OLLVM or javascript-obfuscator. Don't use it to shield malware from analysis, and respect local law when reverse engineering anything that isn't yours.

**Why "Anti-REA" when it defends against more than REA?**
REA is the tool that made AI-assisted RE mainstream, so it gets the name. The techniques and rules generalize to any agent-driven RE pipeline — see the [roadmap](docs/REPORT.zh-CN.md).

**Does it work on packed/encrypted binaries?**
Audit honestly reports what it can parse; packers that hide everything already defeat static analysis (that's their point). Guards still apply at runtime.

## Contributing

Issues and PRs welcome — especially: new detection rules, new language guards, new decoy classes, compiler/CI verification for the C and C# guards, and WASM support. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a vulnerability in Anti-REA itself (e.g. a harden transform that corrupts binaries)? Please follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Anti-REA contributors

## Acknowledgments

- [morluto/rea](https://github.com/morluto/rea) — studying its source made this toolkit possible; the best defense is knowing the offense
- The obfuscation research lineage: Collberg et al.'s *A Taxonomy of Obfuscating Transformations*, OLLVM & descendants, and the javascript-obfuscator community
