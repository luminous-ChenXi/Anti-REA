// Native binary hardening: content-level transforms only (no structural changes,
// no address changes, no touching ALLOC sections). Every transform has a whitelist
// precondition + bounds checks; a failing step is skipped and logged, never fatal.

import * as fs from "node:fs";
import { parseElf, zeroSection, renameSectionInShstrtab } from "../formats/elf.js";
import { parsePe, wipeDosStub, wipeCoffSymbolTable, wipeDebugDirectory } from "../formats/pe.js";
import { parseMacho, wipeSwiftReflection } from "../formats/macho.js";
import { indexOfAll, rng, seedFromString } from "../util.js";

const GO_MAGIC = Buffer.from("\xff\x20Go buildinf:", "binary");
const RUSTC_PATH = Buffer.from("/rustc/", "utf8");
const GO_BUILDID_NOTE = Buffer.from("Go build ID:", "utf8");

export function hardenNative(inPath, outPath, opts = {}) {
  const buf = fs.readFileSync(inPath);
  const changes = [];
  const notes = [];
  const add = (id, bytes, note) => changes.push({ id, bytes, note: note || "" });

  const isElf = buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
  const isPe = buf[0] === 0x4d && buf[1] === 0x5a;
  const macho = !isElf && !isPe ? parseMacho(buf) : null;

  // ---- Cross-container: language fingerprint wiping ----
  if (!opts.keepGoBuildinfo) {
    let zeroed = 0;
    for (const off of indexOfAll(buf, GO_MAGIC, { limit: 64 })) {
      buf.fill(0, off, off + GO_MAGIC.length);
      zeroed += GO_MAGIC.length;
    }
    for (const off of indexOfAll(buf, GO_BUILDID_NOTE, { limit: 64 })) {
      buf.fill(0, off, off + GO_BUILDID_NOTE.length);
      zeroed += GO_BUILDID_NOTE.length;
    }
    if (zeroed) add("wipe-go-buildinfo", zeroed, "Go buildinfo/buildid magic wiped (debug.ReadBuildInfo returns empty; runtime unaffected)");
  }
  if (!opts.keepRustPaths) {
    let zeroed = 0;
    for (const off of indexOfAll(buf, RUSTC_PATH, { limit: 2000 })) {
      buf.fill(0, off, off + RUSTC_PATH.length);
      zeroed += RUSTC_PATH.length;
    }
    if (zeroed) add("wipe-rust-paths", zeroed, `/rustc/ paths wiped, ${zeroed} bytes (path info gone from panic messages)`);
  }

  // ---- ELF ----
  if (isElf) {
    const elf = parseElf(buf);
    if (elf) {
      if (!opts.keepDebug) {
        let z = 0;
        for (const sec of elf.debugSections) z += zeroSection(buf, sec);
        if (z) add("wipe-dwarf", z, "DWARF debug section contents wiped (section headers kept, structure intact)");
      }
      if (!opts.keepSymtab) {
        let z = 0;
        if (elf.strtab) z += zeroSection(buf, elf.strtab); // wipe the string table first
        if (elf.symtab) z += zeroSection(buf, elf.symtab);
        if (z) add("wipe-symtab", z, ".symtab/.strtab contents wiped (symbol count preserved, names unreadable)");
      }
      const comment = elf.sections.find((s) => s.name === ".comment");
      if (comment) {
        const z = zeroSection(buf, comment);
        if (z) add("wipe-comment", z, ".comment compiler versions wiped");
      }
      const dep = elf.sections.find((s) => s.name === ".dep-v0");
      if (dep) {
        const z = zeroSection(buf, dep);
        if (z) add("wipe-dep-v0", z, "cargo auditable dependency list wiped");
      }
      // Rename the .go.buildinfo section (same-length random name) to break REA's
      // "locate by section name first" heuristic.
      const gobiIdx = elf.sections.findIndex((s) => s.name === ".go.buildinfo");
      if (gobiIdx >= 0 && elf.shstrtabSection) {
        const rand = rng(seedFromString(outPath));
        const chars = "abcdefghijklmnopqrstuvwxyz";
        let name = ".";
        for (let i = 0; i < 12; i++) name += chars[Math.floor(rand() * 26)];
        try {
          if (renameSectionInShstrtab(buf, elf, gobiIdx, name)) add("rename-go-buildinfo-sec", name.length, `section renamed to ${name}`);
        } catch { /* length mismatch etc. — skip */ }
      }
      // Same-length rename of non-runtime sections: .symtab/.strtab names randomized too
      if (!opts.keepSymtab) {
        for (const secName of [".symtab", ".strtab", ".debug_info"]) {
          const idx = elf.sections.findIndex((s) => s.name === secName);
          if (idx >= 0) {
            const rand = rng(seedFromString(outPath + secName));
            const chars = "zyxwvu";
            let name = secName.split("").map(() => chars[Math.floor(rand() * 6)]).join("");
            try { renameSectionInShstrtab(buf, elf, idx, name); } catch { /* skip */ }
          }
        }
      }
    }
  }

  // ---- PE ----
  if (isPe) {
    const pe = parsePe(buf);
    if (pe) {
      if (!opts.keepSymtab && pe.symbolTable) {
        const z = wipeCoffSymbolTable(buf, pe);
        if (z) add("wipe-coff-symtab", z, "COFF symbol table header fields zeroed + contents wiped");
      }
      if (pe.rich) {
        const z = wipeDosStub(buf, pe);
        if (z) add("wipe-rich-header", z, "DOS stub/Rich header wiped (MZ header and PE offset preserved)");
      }
      if (!opts.keepDebug && pe.debugEntries.length) {
        const z = wipeDebugDirectory(buf, pe);
        if (z) add("wipe-debug-dir", z, "debug directory and PDB path wiped");
      }
    }
  }

  // ---- Mach-O (optional: Swift reflection metadata) ----
  if (macho && !macho.fat && opts.wipeSwiftRefl) {
    const z = wipeSwiftReflection(buf, macho);
    if (z) add("wipe-swift-reflection", z, "Swift reflection metadata wiped (Mirror reflection degrades)");
  }

  fs.writeFileSync(outPath, buf);
  return { inPath, outPath, size: buf.length, changes, notes };
}
