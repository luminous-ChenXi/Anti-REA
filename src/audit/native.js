// Native binary audit: enumerates every signal the REA static pipeline relies on.
// Signal mapping is grounded in the recon report (see docs/REPORT.zh-CN.md, section 2).

import { parseElf } from "../formats/elf.js";
import { parsePe as parsePeFmt } from "../formats/pe.js";
import { parseMacho as parseMachoFmt } from "../formats/macho.js";
import { indexOfAll } from "../util.js";

const GO_MAGIC = Buffer.from("\xff\x20Go buildinf:", "binary");
const RUSTC_PATH = Buffer.from("/rustc/", "utf8");
const GO_BUILDID_NOTE = Buffer.from("Go build ID:", "utf8");
const IL2CPP_MAGIC_LE = Buffer.from([0xaf, 0x1b, 0xb1, 0xfa]); // 0xFAB11BAF LE

export function auditNative(buf, filePath) {
  const findings = [];
  const elf = buf[0] === 0x7f && buf[1] === 0x45 ? parseElf(buf) : null;
  const pe = !elf && buf[0] === 0x4d && buf[1] === 0x5a ? parsePeFmt(buf) : null;
  const macho = !elf && !pe ? parseMachoFmt(buf) : null;
  if (!elf && !pe && !macho) return null;

  // ---- Cross-container language fingerprints (REA's first-priority signals) ----
  const goHits = indexOfAll(buf, GO_MAGIC, { limit: 50 });
  if (goHits.length > 0) {
    findings.push({
      id: "NAT-GO-BUILDINFO",
      severity: "high",
      title: `Go buildinfo magic found (${goHits.length} occurrence(s))`,
      detail: "REA's GoBinaryProvider reads the \\xff\\x20\"Go buildinf:\" magic to dump the Go version and the full module dependency list; it falls back to a whole-segment scan when the named section is missing.",
      rea: "Identifies language/dependency stack → narrows analysis scope, matches known library fingerprints",
      fix: "harden wipes the magic (only debug.ReadBuildInfo is affected, runtime unaffected); or build with -ldflags \"-s -w\" plus harden",
      evidence: { offsets: goHits.slice(0, 5) },
    });
  }
  if (indexOfAll(buf, GO_BUILDID_NOTE, { limit: 1 }).length > 0) {
    findings.push({ id: "NAT-GO-BUILDID", severity: "low", title: "\"Go build ID:\" string found", detail: "Go build id note exposes a build fingerprint.", rea: "Build fingerprint correlation", fix: "harden wipes it, or build with -ldflags -buildid=" });
  }
  const rustHits = indexOfAll(buf, RUSTC_PATH, { limit: 200 });
  if (rustHits.length > 0) {
    findings.push({
      id: "NAT-RUST-PATHS",
      severity: "medium",
      title: `${rustHits.length} plaintext /rustc/ path(s) found`,
      detail: "REA's RustBinaryImage scans plaintext /rustc/ paths (panic locations etc.) to infer the rustc version and dependencies.",
      rea: "Identifies Rust toolchain version → matches known crate fingerprints",
      fix: "harden wipes them in place (only affects panic message readability)",
      evidence: { count: rustHits.length },
    });
  }
  const il2cpp = indexOfAll(buf, IL2CPP_MAGIC_LE, { limit: 10 });
  if (il2cpp.length > 0) {
    findings.push({
      id: "NAT-IL2CPP-MAGIC",
      severity: "medium",
      title: "Suspected IL2CPP metadata magic 0xFAB11BAF found",
      detail: "If a global-metadata.dat ships alongside, REA can fully recover Unity type/method names and feed them to Ghidra as function seeds.",
      rea: "Recovers the Unity type system and function names",
      fix: "Encrypt the metadata (commercial Unity solution or a custom encrypted loader), decrypt at runtime",
    });
  }

  // ---- ELF specific ----
  if (elf && elf.sections.length) {
    // Treat a section as wiped when its leading bytes are all zero — mitigated
    // findings are no longer reported as high risk.
    const sectionZeroed = (sec) => {
      if (!sec || sec.sh_offset + sec.sh_size > buf.length) return false;
      const n = Math.min(sec.sh_size, 64);
      for (let i = 0; i < n; i++) if (buf[sec.sh_offset + i] !== 0) return false;
      return true;
    };
    if (elf.symtab && !sectionZeroed(elf.strtab ?? elf.symtab)) {
      findings.push({
        id: "NAT-ELF-SYMTAB",
        severity: "high",
        title: `ELF static symbol table present (~${elf.symbolCount} symbols)`,
        detail: "objdump -t lists every function name; Ghidra auto-names functions from symbols, dramatically improving pseudocode readability.",
        rea: "Function names are semantics: license/crypto functions stand out immediately",
        fix: "strip --strip-all at build time, or harden wipes .symtab/.strtab contents",
        evidence: { symbolCount: elf.symbolCount },
      });
    }
    if (elf.debugSections.length && elf.debugSections.some((s) => !sectionZeroed(s))) {
      findings.push({
        id: "NAT-ELF-DWARF",
        severity: "high",
        title: `${elf.debugSections.length} DWARF debug section(s) present`,
        detail: "REA runs objdump -W by default: source paths, line numbers, types and variable names all leak.",
        rea: "Recovers source-level structure (files/lines/types)",
        fix: "objcopy --strip-debug / -ldflags \"-s -w\" at build time, or harden wipes them",
        evidence: { sections: elf.debugSections.map((s) => s.name).slice(0, 10) },
      });
    }
    const comment = elf.sections.find((s) => s.name === ".comment");
    if (comment && comment.sh_size > 0) {
      const text = buf.toString("utf8", comment.sh_offset, Math.min(comment.sh_offset + comment.sh_size, comment.sh_offset + 256));
      findings.push({ id: "NAT-ELF-COMMENT", severity: "medium", title: ".comment section leaks compiler versions", detail: text.replace(/\0+/g, " ").trim().slice(0, 120), rea: "Toolchain fingerprint", fix: "harden wipes it, or strip at build time" });
    }
    const depv0 = elf.sections.find((s) => s.name === ".dep-v0");
    if (depv0) findings.push({ id: "NAT-RUST-DEP", severity: "medium", title: ".dep-v0 section present (cargo auditable)", detail: "Contains the full Rust dependency list as JSON.", rea: "Reads the dependency list directly", fix: "harden wipes it (non-ALLOC section)" });
    const gobi = elf.sections.find((s) => s.name === ".go.buildinfo");
    if (gobi && goHits.length === 0) findings.push({ id: "NAT-ELF-GOBI-SEC", severity: "high", title: ".go.buildinfo named section present", detail: "REA locates buildinfo by section name first.", fix: "harden wipes both the section name and the magic" });
  }

  // ---- PE specific ----
  if (pe) {
    if (pe.symbolTable && pe.symbolTable.numberOfSymbols > 0) {
      findings.push({
        id: "NAT-PE-SYMTAB",
        severity: "high",
        title: `COFF symbol table present (${pe.symbolTable.numberOfSymbols} entries)`,
        detail: "Go/MinGW toolchains keep the COFF symbol table by default; function names are fully readable.",
        rea: "Locates key logic by function name",
        fix: "harden zeroes the table pointer and contents (or build with -ldflags \"-s -w\")",
        evidence: pe.symbolTable,
      });
    }
    if (pe.rich) {
      findings.push({ id: "NAT-PE-RICH", severity: "medium", title: "Rich header present", detail: "Leaks MSVC toolchain component versions and the build environment.", rea: "Toolchain fingerprint", fix: "harden wipes the DOS stub region (MZ header and PE offset preserved)" });
    }
    if (pe.pdbPath) {
      findings.push({
        id: "NAT-PE-PDB",
        severity: "high",
        title: `Debug directory leaks PDB path: ${pe.pdbPath}`,
        detail: "PDB paths often contain build-machine usernames/project paths; combined with a symbol server the structure can be nearly restored.",
        rea: "Locates modules and the development environment",
        fix: "harden zeroes the debug directory; release builds should never carry PDB paths",
        evidence: { pdbPath: pe.pdbPath },
      });
    }
    if (pe.importDlls.length) {
      findings.push({ id: "NAT-PE-IMPORTS", severity: "info", title: `Imports ${pe.importDlls.length} DLL(s)`, detail: pe.importDlls.slice(0, 12).join(", "), rea: "Behavior-surface inference", fix: "No action needed (informational)" });
    }
  }

  // ---- Mach-O specific ----
  if (macho && !macho.fat) {
    const objc = macho.segments.find((s) => s.section === "__objc_classlist" || s.section.startsWith("__objc_"));
    if (objc) {
      findings.push({
        id: "NAT-MACHO-OBJC",
        severity: "medium",
        title: "Objective-C metadata sections present",
        detail: "REA recovers the full class/method/ivar/protocol inventory from __objc_classlist — the largest semantic leak on Apple platforms.",
        rea: "Recovers the entire ObjC interface surface",
        fix: "strip -x at build time + ObjC obfuscation tools; dead-strip runtime metadata you don't need",
      });
    }
    const swift5 = macho.segments.filter((s) => s.section.startsWith("__swift5_"));
    if (swift5.length) {
      findings.push({
        id: "NAT-MACHO-SWIFT",
        severity: "medium",
        title: `Swift metadata sections present (${swift5.length}, incl. types/reflection)`,
        detail: "REA reads __swift5_types to recover nominal types, then swift-demangle restores readable names.",
        rea: "Recovers the Swift type system",
        fix: "harden --wipe-swift-refl wipes reflection metadata in releases (Mirror reflection degrades); handle type sections at build time",
        evidence: { sections: swift5.map((s) => s.section).slice(0, 10) },
      });
    }
    if (macho.symtab && macho.symtab.nsyms > 0) {
      findings.push({ id: "NAT-MACHO-SYMTAB", severity: "high", title: `Symbol table present (${macho.symtab.nsyms} entries)`, detail: "Local symbols are not stripped; function names are directly enumerable.", rea: "Function names are semantics", fix: "strip -x at build time (v0.1 does not rewrite Mach-O, see docs)" });
    }
  }

  return { format: elf ? "elf" : pe ? "pe" : "macho", findings };
}
