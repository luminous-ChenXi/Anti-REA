# Contributing to Anti-REA

Thanks for helping push reverse-engineering costs back up! Contributions of every size are welcome.

## Ways to contribute

1. **Detection rules** — new built-in signals or community rule packs (`anti-rea.config.json` format). If you find a leak in your own release artifacts, generalize it into a rule.
2. **Runtime guards** — new languages (Rust? Go? Swift?), new detection vectors, and especially **compiler/CI verification** for the existing C/C++ and C# guards (not yet compiler-tested in this repo).
3. **Decoy classes** — new poison formats (fake protobuf schemas, fake RPC interfaces…).
4. **Hardening transforms** — post-build transforms that stay inside the safety model (content-level only, no structural changes, no broken artifacts).
5. **Evidence** — REA and similar tools evolve. PRs updating signatures with file-path evidence from new versions are gold.

## Ground rules

- **Defensive use only.** Anything that helps malware evade analysis will be rejected.
- **Evidence-based.** New detection rules should cite where the signal comes from (tool source path, observed artifact, etc.).
- **Safety model is non-negotiable.** Harden transforms must never: change program structure or addresses, touch loader-required sections, or modify the original input file.
- **Tests required.** `npm test` must stay green; new features need a test case. Native examples: `cd examples/go-app && go build -o demo-app.exe . && GOOS=linux go build -o demo-app-linux .`

## Dev setup

```bash
git clone <your-fork> && cd Anti-REA
npm test        # 26 checks; native cases skip gracefully without Go-built examples
node bin/anti-rea.mjs --help
```

Zero runtime dependencies by design — please keep it that way.

## Style

- Plain modern JavaScript (ESM, Node ≥ 18), no build step, no TypeScript-for-its-own-sake
- Comments explain *constraints and evidence*, not narrate the obvious
- User-facing strings in English

## Reporting bugs

Open an issue with: target artifact type (ELF/PE/JS/asar/APK…), command line, full output, and — if a harden transform corrupted something — how you verified breakage.
