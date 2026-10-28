# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-10-28

Initial release.

### Added
- **audit** command: 40+ detection rules across ELF/PE/Mach-O (Go buildinfo, `/rustc/` paths, `.dep-v0`, DWARF, symbol tables, Rich header, PDB paths, COFF symbols, ObjC/Swift metadata), JS/Electron/asar (source maps, webpack/esbuild/Next.js sentinels, Electron fuses, plaintext secrets, endpoints), .NET (#Strings/#US heaps, Unity detection), APK (dex, resources.arsc, hot-load code, mapping leaks), wasm; custom rule plugins via `anti-rea.config.json`; JSON output.
- **harden** command: content-level transforms with output-to-new-files safety model — ELF non-ALLOC section wiping + same-length section renames, Go buildinfo magic wipe, PE COFF symbol table / debug directory / Rich header wipe, JS sentinel renaming + sourcemap stripping, asar extract-harden-repack, optional Swift reflection wipe.
- **poison** command: reproducible decoy generation (endpoints, license formats, API keys, feature names, config entries, honeypot markers) in js/c/csharp/python/json/text.
- **guards** command: runtime guard libraries for C/C++ (single header), .NET/C#, JavaScript/Node/Electron, Python — REA `REA_PROCESS_RUN_ID` / bridge env vars, `rea-provider-*`/`rea-lease-*` IPC, analyst parent chains, Frida traces, debugger detection; score-based, side-effect-free.
- **mcp** mode: zero-dependency stdio MCP server exposing audit/harden/poison/guards to any AI agent.
- Agent skill (`skills/anti-rea`) encoding the audit → harden → re-audit → run-verification workflow.
- Test suite: 26 checks covering parsers, all four layers, custom rules and MCP.
- Research report (Chinese, with REA source-path evidence): `docs/REPORT.zh-CN.md`.
