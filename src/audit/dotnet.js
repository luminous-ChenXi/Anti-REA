// .NET assembly audit: REA uses its own PE/CLI metadata parser (#Strings/#US/#Blob heaps
// + metadata tables) to recover type/method names and every string literal without ever
// loading the assembly. This module implements equivalent read access to size the leak.

import { parsePe } from "../formats/pe.js";

function readCompressedUInt(buf, off) {
  const b0 = buf[off];
  if (b0 === undefined) return null;
  if ((b0 & 0x80) === 0) return { value: b0, next: off + 1 };
  if ((b0 & 0x40) === 0) return { value: ((b0 & 0x3f) << 8) | buf[off + 1], next: off + 2 };
  return { value: ((b0 & 0x1f) << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3], next: off + 4 };
}

/** Parse the #US (user strings) heap: returns up to `limit` strings. */
function parseUserStrings(buf, start, size, limit = 10) {
  const end = start + size;
  const out = [];
  let off = start + 1; // the heap's first byte is the mandatory empty string at index 0
  while (off < end && out.length < limit + 40) {
    const len = readCompressedUInt(buf, off);
    if (!len || len.next >= end) break;
    off = len.next;
    if (len.value === 0) continue;
    const strBytes = len.value - 1; // trailing 1 byte is the flag
    if (strBytes <= 0 || off + strBytes > end) break;
    out.push(buf.toString("utf16le", off, off + strBytes));
    off += strBytes;
  }
  return out;
}

export function auditDotnet(buf) {
  const pe = parsePe(buf);
  if (!pe || !pe.isDotnet) return null;
  const findings = [];
  const cliOff = pe.rvaToOffset(pe.cliDir.rva);
  if (cliOff === null || cliOff + 8 > buf.length) return { findings: [{ id: "DN-UNPARSED", severity: "info", title: ".NET CLI header unparseable", detail: "", fix: "" }] };
  const metaRva = buf.readUInt32LE(cliOff + 8);
  const metaSize = buf.readUInt32LE(cliOff + 12);
  const metaOff = pe.rvaToOffset(metaRva);
  if (metaOff === null || buf.toString("ascii", metaOff, metaOff + 4) !== "BSJB") {
    return { findings: [{ id: "DN-NO-METADATA", severity: "info", title: "BSJB metadata root not found", detail: "Possibly already hardened or packed.", fix: "" }] };
  }

  // Stream headers: [offset u32][size u32][name\0 padded to 4-byte alignment]
  const verLen = buf.readUInt32LE(metaOff + 12);
  let off = metaOff + 16 + verLen + 2;
  const streams = {};
  for (let guard = 0; guard < 8 && off + 8 <= buf.length; guard++) {
    const sOff = buf.readUInt32LE(off);
    const sSize = buf.readUInt32LE(off + 4);
    const nameStart = off + 8;
    const nameEnd = buf.indexOf(0, nameStart);
    if (nameEnd === -1 || nameEnd > nameStart + 32) break;
    const name = buf.toString("ascii", nameStart, nameEnd);
    const nameLen = nameEnd - nameStart + 1;
    streams[name] = { offset: metaOff + sOff, size: sSize };
    off = nameStart + ((nameLen + 3) & ~3);
    if (sOff === 0 && sSize === 0) break;
  }
  const usStream = streams["#US"];
  const stringsStream = streams["#Strings"];

  if (usStream && usStream.size > 2) {
    const strs = parseUserStrings(buf, usStream.offset, usStream.size);
    const sample = strs.slice(0, 8).map((s) => (s.length > 40 ? s.slice(0, 40) + "…" : s));
    findings.push({
      id: "DN-USER-STRINGS",
      severity: "high",
      title: `#US string heap readable (≥${strs.length} literals)`,
      detail: `REA resolves every ldstr token against the #US heap and obtains all string constants. Samples: ${JSON.stringify(sample)}`,
      rea: "License logic / UI text / error messages directly readable",
      fix: "Apply obfuscator string encryption (Obfuscar/BitMono/commercial), or decrypt key strings at runtime",
      evidence: { count: strs.length },
    });
  }
  if (stringsStream && stringsStream.size > 2) {
    // Count readable identifiers
    let count = 0;
    const s = stringsStream;
    for (let i = 1; i < s.size && count < 5000; i++) if (buf[s.offset + i] === 0) count++;
    findings.push({
      id: "DN-IDENTIFIERS",
      severity: "high",
      title: `#Strings heap holds ~${count} unobfuscated identifiers`,
      detail: "Type/method/field names are fully preserved; REA's ManagedStaticProvider enumerates the metadata tables to rebuild the type system.",
      rea: "Type/method semantic recovery — equivalent to leaking the public API structure",
      fix: "Obfuscator symbol renaming (Obfuscar/BitMono); disable InternalsVisibleTo in releases",
      evidence: { count },
    });
  }
  const tfm = buf.indexOf(".NETCoreApp,", metaOff, "ascii") >= 0 || buf.indexOf(".NETFramework,", metaOff, "ascii") >= 0;
  if (tfm) findings.push({ id: "DN-TFM", severity: "low", title: "TargetFrameworkAttribute in plaintext", detail: "REA uses it to pick the runtime family.", fix: "Harmless (low-value info)" });
  const unity = buf.indexOf("UnityEngine", metaOff, "ascii") >= 0;
  if (unity) findings.push({ id: "DN-UNITY", severity: "medium", title: "UnityEngine assembly reference detected", detail: "REA classifies the artifact as unity-mono and switches strategy.", fix: "Harmless for detection; for Mono consider IL2CPP + metadata encryption" });
  return { findings };
}
