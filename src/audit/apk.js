// APK audit: parses the ZIP central directory (zero-dependency) and maps REA's
// apktool → JADX → JNI static-binding pipeline.

import * as zlib from "node:zlib";

export function parseZipCentralDir(buf) {
  // Locate the EOCD from the tail
  const minEocd = Math.max(0, buf.length - 65557);
  let eocd = -1;
  for (let i = buf.length - 22; i >= minEocd; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const entries = [];
  let off = cdOffset;
  for (let i = 0; i < count && off + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOffset = buf.readUInt32LE(off + 42);
    entries.push({
      name: buf.toString("utf8", off + 46, off + 46 + nameLen),
      localOffset,
    });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Read the (stored or deflated) data a local header points at — small text scans only. */
export function readZipEntry(buf, entry) {
  const lo = entry.localOffset;
  if (lo + 30 > buf.length || buf.readUInt32LE(lo) !== 0x04034b50) return null;
  const nameLen = buf.readUInt16LE(lo + 26);
  const extraLen = buf.readUInt16LE(lo + 28);
  const method = buf.readUInt16LE(lo + 8);
  const compSize = buf.readUInt32LE(lo + 18);
  const dataStart = lo + 30 + nameLen + extraLen;
  if (dataStart + compSize > buf.length) return null;
  const raw = buf.subarray(dataStart, dataStart + compSize);
  if (method === 0) return Buffer.from(raw);
  if (method === 8) {
    return zlib.inflateRawSync(raw);
  }
  return null;
}

export function auditApk(buf) {
  const entries = parseZipCentralDir(buf);
  if (!entries || !entries.some((e) => /\.dex$/.test(e.name) || e.name === "AndroidManifest.xml" || e.name === "resources.arsc")) return null;
  const findings = [];
  const dex = entries.filter((e) => /^classes\d*\.dex$/.test(e.name));
  findings.push({
    id: "APK-DEX",
    severity: "info",
    title: `APK contains ${dex.length} dex file(s)`,
    detail: "REA decompiles to Java via JADX (dexlib2 + jadx-java); without an R8 mapping the obfuscated names still enter the call graph, only flagged unmapped.",
    rea: "Full Java-layer decompilation",
    fix: "Enable R8 full mode + keep mapping private; move core logic to native with string encryption",
  });
  const arsc = entries.find((e) => e.name === "resources.arsc");
  if (arsc) findings.push({ id: "APK-ARSC", severity: "medium", title: "resources.arsc plaintext resource string tables", detail: "apktool decodes every resource string (<8MiB per-table budget).", rea: "UI text/config/hidden feature enumeration", fix: "Resource obfuscation (resguard-style tools); encrypt sensitive config" });
  const hotCode = entries.filter((e) => /^assets\/.+\.(?:dex|js|jar|so)$/.test(e.name));
  if (hotCode.length) findings.push({ id: "APK-HOTCODE", severity: "medium", title: `${hotCode.length} hot-load code file(s) under assets/`, detail: hotCode.slice(0, 5).map((e) => e.name).join(", "), rea: "Dynamically loaded logic located", fix: "Encrypt + decrypt at load time; pair with integrity checks" });
  const mapping = entries.find((e) => /(?:^|\/)(?:mapping\.txt|.*\.pro$)/.test(e.name));
  if (mapping) findings.push({ id: "APK-MAPPING-LEAK", severity: "high", title: `mapping/proguard file shipped in the APK: ${mapping.name}`, detail: "With a mapping, REA automatically restores obfuscated names to the originals.", fix: "Remove it from the APK immediately; keep it internal only" });
  const sos = entries.filter((e) => /^lib\/.+\.so$/.test(e.name));
  if (sos.length) findings.push({ id: "APK-NATIVE", severity: "medium", title: `${sos.length} native library(ies) under lib/`, detail: "REA runs JNI static binding analysis on every .so (runtime-built tables / encrypted strings are not recovered).", rea: "JNI boundary reconstruction", fix: "Run anti-rea audit/harden on the .so files; switch JNI registration to runtime-built tables" });
  // manifest strings
  const manifest = entries.find((e) => e.name === "AndroidManifest.xml");
  if (manifest) {
    const data = readZipEntry(buf, manifest);
    if (data) {
      // Binary XML string pools are UTF-16
      const text = data.toString("utf16le");
      const urls = text.match(/\bhttps?:\/\/[A-Za-z0-9./_-]{4,80}/g) || [];
      if (urls.length) findings.push({ id: "APK-MANIFEST-URLS", severity: "low", title: `Manifest leaks ${urls.length} URL(s)`, detail: [...new Set(urls)].slice(0, 6).join(" , "), rea: "Network behavior surface", fix: "Move to runtime config where possible" });
    }
  }
  return { findings };
}
