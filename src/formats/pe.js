// PE/COFF parser: DOS header, NT headers, section table, data directories,
// COFF symbol table, debug directory, Rich header, CLI (.NET) header.

const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
const IMAGE_DIRECTORY_ENTRY_COMHEADER = 14; // .NET CLI header

export function parsePe(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return null; // "MZ"
  const e_lfanew = buf.readUInt32LE(0x3c);
  if (e_lfanew <= 0 || e_lfanew + 24 > buf.length) return null;
  if (buf.readUInt32LE(e_lfanew) !== 0x00004550) return null; // "PE\0\0"

  const coff = e_lfanew + 4;
  const machine = buf.readUInt16LE(coff);
  const numberOfSections = buf.readUInt16LE(coff + 2);
  const pointerToSymbolTable = buf.readUInt32LE(coff + 8);
  const numberOfSymbols = buf.readUInt32LE(coff + 12);
  const sizeOfOptionalHeader = buf.readUInt16LE(coff + 16);

  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  const isPe32Plus = magic === 0x20b;
  const numberOfRvaAndSizes = buf.readUInt32LE(opt + (isPe32Plus ? 108 : 92));
  const dataDirBase = opt + (isPe32Plus ? 112 : 96);

  const dataDirectories = [];
  for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
    const o = dataDirBase + i * 8;
    if (o + 8 > buf.length) break;
    dataDirectories.push({ rva: buf.readUInt32LE(o), size: buf.readUInt32LE(o + 4), _fileOffset: o });
  }

  // Section table
  const secBase = opt + sizeOfOptionalHeader;
  const sections = [];
  for (let i = 0; i < numberOfSections; i++) {
    const o = secBase + i * 40;
    if (o + 40 > buf.length) break;
    sections.push({
      name: buf.toString("ascii", o, o + 8).replace(/\0+$/, ""),
      virtualSize: buf.readUInt32LE(o + 8),
      virtualAddress: buf.readUInt32LE(o + 12),
      sizeOfRawData: buf.readUInt32LE(o + 16),
      pointerToRawData: buf.readUInt32LE(o + 20),
    });
  }

  const rvaToOffset = (rva) => {
    for (const s of sections) {
      if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData)) {
        return s.pointerToRawData + (rva - s.virtualAddress);
      }
    }
    return null;
  };

  // Rich header (between the DOS stub and the PE signature) — presence check only
  let rich = null;
  const richIdx = buf.indexOf("Rich", 0x40, "ascii");
  if (richIdx > 0 && richIdx < e_lfanew) rich = { offset: 0x40, end: e_lfanew };

  // Debug directory
  const debugDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG];
  const debugEntries = [];
  if (debugDir && debugDir.rva > 0) {
    const off = rvaToOffset(debugDir.rva);
    if (off !== null && debugDir.size >= 28) {
      const n = Math.floor(debugDir.size / 28);
      for (let i = 0; i < n; i++) {
        const o = off + i * 28;
        if (o + 28 > buf.length) break;
        debugEntries.push({
          type: buf.readUInt32LE(o + 12), // 2=CODEVIEW
          pointerToRawData: buf.readUInt32LE(o + 24),
          sizeOfData: buf.readUInt32LE(o + 16),
          _fileOffset: o,
        });
      }
    }
  }

  // CodeView PDB path
  let pdbPath = null;
  for (const e of debugEntries) {
    if (e.type === 2 && e.pointerToRawData > 0 && e.pointerToRawData + e.sizeOfData <= buf.length) {
      if (buf.toString("ascii", e.pointerToRawData, e.pointerToRawData + 4) === "RSDS") {
        const end = buf.indexOf(0, e.pointerToRawData + 24);
        if (end > 0 && end - (e.pointerToRawData + 24) < 1024) {
          pdbPath = buf.toString("utf8", e.pointerToRawData + 24, end);
        }
      }
    }
  }

  // .NET CLI header
  const cliDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_COMHEADER];
  const isDotnet = !!(cliDir && cliDir.rva > 0);

  // Import DLL names (informational)
  const importDlls = [];
  const impDir = dataDirectories[1];
  if (impDir && impDir.rva > 0) {
    let off = rvaToOffset(impDir.rva);
    if (off !== null) {
      for (let i = 0; i < 64; i++) {
        if (off + 20 > buf.length) break;
        const nameRva = buf.readUInt32LE(off + 12);
        if (nameRva === 0) break;
        const nameOff = rvaToOffset(nameRva);
        if (nameOff === null) break;
        const end = buf.indexOf(0, nameOff);
        importDlls.push(buf.toString("ascii", nameOff, Math.min(end, nameOff + 64)));
        off += 20;
      }
    }
  }

  return {
    kind: "pe",
    e_lfanew,
    coffOffset: coff,
    machine,
    sections,
    dataDirectories,
    rvaToOffset,
    rich,
    debugDir,
    debugEntries,
    pdbPath,
    isDotnet,
    cliDir,
    importDlls,
    symbolTable: pointerToSymbolTable > 0 ? { pointerToSymbolTable, numberOfSymbols } : null,
  };
}

/** Wipe the DOS stub (keeps the first 0x40 bytes and the e_lfanew pointer); kills the Rich header. */
export function wipeDosStub(buf, pe) {
  const start = 0x40;
  const end = pe.e_lfanew;
  if (end <= start || end > buf.length) return 0;
  buf.fill(0, start, end);
  return end - start;
}

/** Wipe the COFF symbol table: zero the header fields + the symbol/string table region. */
export function wipeCoffSymbolTable(buf, pe) {
  if (!pe.symbolTable) return 0;
  const { pointerToSymbolTable, numberOfSymbols } = pe.symbolTable;
  let zeroed = 0;
  const symEnd = pointerToSymbolTable + numberOfSymbols * 18;
  // String table: right after the symbol table, starts with a 4-byte size
  if (symEnd + 4 <= buf.length) {
    const strSize = buf.readUInt32LE(symEnd);
    const totalEnd = symEnd + (strSize > 0 && strSize < buf.length - symEnd ? strSize : 0);
    if (totalEnd <= buf.length) {
      buf.fill(0, pointerToSymbolTable, totalEnd);
      zeroed = totalEnd - pointerToSymbolTable;
    }
  }
  if (zeroed === 0 && symEnd <= buf.length) {
    buf.fill(0, pointerToSymbolTable, symEnd);
    zeroed = symEnd - pointerToSymbolTable;
  }
  buf.writeUInt32LE(0, pe.coffOffset + 8);
  buf.writeUInt32LE(0, pe.coffOffset + 12);
  return zeroed;
}

/** Wipe the debug directory: zero the data-directory entry + every entry and its target (PDB path leak). */
export function wipeDebugDirectory(buf, pe) {
  let zeroed = 0;
  for (const e of pe.debugEntries) {
    if (e.pointerToRawData > 0 && e.pointerToRawData + e.sizeOfData <= buf.length) {
      buf.fill(0, e.pointerToRawData, e.pointerToRawData + e.sizeOfData);
      zeroed += e.sizeOfData;
    }
    buf.fill(0, e._fileOffset, e._fileOffset + 28);
    zeroed += 28;
  }
  const dir = pe.debugDir;
  if (dir) {
    buf.writeUInt32LE(0, dir._fileOffset);
    buf.writeUInt32LE(0, dir._fileOffset + 4);
  }
  return zeroed;
}
