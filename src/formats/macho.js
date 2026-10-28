// Mach-O parser (64-bit LE/BE + fat-binary detection). v0.1 is audit-focused;
// write-back is limited to optional Swift reflection metadata wiping
// (--wipe-swift-refl).

const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;

export function parseMacho(buf) {
  if (buf.length < 32) return null;
  const magicLE = buf.readUInt32LE(0);
  const magicBE = buf.readUInt32BE(0);
  let le = false;
  let is64 = false;
  if (magicLE === 0xfeedfacf) { le = true; is64 = true; }
  else if (magicBE === 0xfeedfacf) { le = false; is64 = true; }
  else if (magicLE === 0xfeedface) { le = true; is64 = false; }
  else if (magicBE === 0xfeedface) { le = false; is64 = false; }
  else if (magicBE === 0xcafebabe) {
    return { kind: "macho", fat: true, slices: buf.readUInt32BE(4) };
  } else return null;

  const u32 = le ? (o) => buf.readUInt32LE(o) : (o) => buf.readUInt32BE(o);
  const ncmds = u32(16);
  let off = is64 ? 32 : 28;
  const segments = [];
  let symtab = null;
  for (let i = 0; i < ncmds && off + 8 <= buf.length; i++) {
    const cmd = u32(off);
    const cmdsize = u32(off + 4);
    if (cmdsize <= 0 || off + cmdsize > buf.length) break;
    if (cmd === LC_SEGMENT_64 && cmdsize >= 72) {
      const segName = buf.toString("ascii", off + 8, off + 24).replace(/\0+$/, "");
      const nsects = u32(off + 64);
      const sectBase = off + 72;
      for (let s = 0; s < nsects; s++) {
        const so = sectBase + s * 80;
        if (so + 80 > off + cmdsize) break;
        segments.push({
          segment: segName,
          section: buf.toString("ascii", so, so + 16).replace(/\0+$/, ""),
          offset: le ? buf.readUInt32LE(so + 40) : buf.readUInt32BE(so + 40),
          size: le ? buf.readUInt32LE(so + 32) : buf.readUInt32BE(so + 32),
        });
      }
    } else if (cmd === LC_SYMTAB && cmdsize >= 24) {
      symtab = {
        symoff: u32(off + 8),
        nsyms: u32(off + 12),
        stroff: u32(off + 16),
        strsize: u32(off + 20),
      };
    }
    off += cmdsize;
  }
  return { kind: "macho", fat: false, is64, le, segments, symtab };
}

/** Wipe Swift reflection metadata sections (opt-in hardening; Mirror reflection degrades). */
export function wipeSwiftReflection(buf, macho) {
  const targets = ["__swift5_reflstr", "__swift5_typeref", "__swift5_fieldmd", "__swift5_assocty", "__swift5_builtin", "__swift5_mpenum"];
  let zeroed = 0;
  for (const s of macho.segments) {
    if (targets.includes(s.section) && s.offset > 0 && s.offset + s.size <= buf.length) {
      buf.fill(0, s.offset, s.offset + s.size);
      zeroed += s.size;
    }
  }
  return zeroed;
}
