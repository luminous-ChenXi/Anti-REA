// ELF parser (64-bit primary, 32-bit read support).
// Read-only parsing + controlled write-back (used by harden). All write-backs
// are bounds-checked.

const SHT_SYMTAB = 2;
const SHF_ALLOC = 0x2;

export function parseElf(buf) {
  if (buf.length < 64) return null;
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return null;
  const eiClass = buf[4]; // 1=32, 2=64
  const eiData = buf[5]; // 1=LE, 2=BE
  if (eiData !== 1) return null; // little-endian only (covers mainstream targets)
  const is64 = eiClass === 2;
  const u16 = (o) => buf.readUInt16LE(o);
  const u32 = (o) => buf.readUInt32LE(o);
  const u64 = (o) => Number(buf.readBigUInt64LE(o));

  const e_shoff = is64 ? u64(0x28) : u32(0x20);
  const e_shentsize = is64 ? u16(0x3a) : u16(0x2e);
  const e_shnum = is64 ? u16(0x3c) : u16(0x30);
  const e_shstrndx = is64 ? u16(0x3e) : u16(0x32);
  if (e_shoff <= 0 || e_shentsize < (is64 ? 64 : 40)) return { kind: "elf", sections: [], warning: "bad-shdr" };

  const sh = [];
  for (let i = 0; i < e_shnum; i++) {
    const o = e_shoff + i * e_shentsize;
    if (o + e_shentsize > buf.length) break;
    sh.push({
      index: i,
      sh_name: u32(o),
      sh_type: u32(o + 4),
      sh_flags: is64 ? u64(o + 8) : u32(o + 4 + 4),
      sh_offset: is64 ? u64(o + 0x18) : u32(o + 0x10),
      sh_size: is64 ? u64(o + 0x20) : u32(o + 0x14),
      _hdrOffset: o,
    });
  }

  // Section name string table
  const strtabSec = sh[e_shstrndx];
  const nameOf = (sec) => {
    if (!strtabSec) return "";
    const start = strtabSec.sh_offset + sec.sh_name;
    if (start >= buf.length) return "";
    const end = buf.indexOf(0, start);
    if (end === -1 || end > strtabSec.sh_offset + strtabSec.sh_size) return "";
    return buf.toString("utf8", start, end);
  };
  for (const s of sh) s.name = nameOf(s);

  const symtab = sh.find((s) => s.sh_type === SHT_SYMTAB);
  const strtab = sh.find((s) => s.name === ".strtab");
  return {
    kind: "elf",
    is64,
    sections: sh,
    shstrtabSection: strtabSec,
    symtab,
    strtab,
    debugSections: sh.filter((s) => s.name.startsWith(".debug_") || s.name.startsWith(".zdebug_")),
    symbolCount: symtab ? Math.floor(symtab.sh_size / (is64 ? 24 : 16)) : 0,
  };
}

/**
 * Zero out a section's contents in place (non-ALLOC sections only, so the
 * runtime image is never touched). Returns bytes written; 0 when preconditions fail.
 */
export function zeroSection(buf, sec) {
  if (!sec || sec.sh_flags & SHF_ALLOC) return 0;
  if (sec.sh_offset + sec.sh_size > buf.length) return 0;
  buf.fill(0, sec.sh_offset, sec.sh_offset + sec.sh_size);
  return sec.sh_size;
}

/**
 * Rename a section inside shstrtab to a same-length name (only safe for sections
 * with no runtime dependency on their name — callers keep the whitelist).
 */
export function renameSectionInShstrtab(buf, elf, secIndex, newName) {
  const sec = elf.sections[secIndex];
  const st = elf.shstrtabSection;
  if (!sec || !st) return false;
  const start = st.sh_offset + sec.sh_name;
  const end = buf.indexOf(0, start);
  if (end === -1) return false;
  const len = end - start;
  if (newName.length !== len) throw new Error(`renameSectionInShstrtab: length must match (${len})`);
  buf.write(newName, start, len, "utf8");
  sec.name = newName;
  return true;
}
