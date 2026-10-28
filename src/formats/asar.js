// Electron asar archive: parsing (audit) + repacking (harden's extract-transform-repack).
// Format (aligned with REA's src/artifacts/AsarHeader.ts):
//   [0:4]  u32 = 4                     — outer pickle payload size
//   [4:8]  u32 = headerBytes
//   [8:12] u32 = payloadBytes = headerBytes - 4
//   [12:16] u32 = jsonBytes
//   [16:16+jsonBytes] JSON index
//   4-byte alignment padding after the JSON, then the file data area
//   (data starts at 8 + headerBytes).

import * as fs from "node:fs";
import * as path from "node:path";

const align4 = (n) => (n + 3) & ~3;

export function parseAsar(buf) {
  if (buf.length < 16) return null;
  if (buf.readUInt32LE(0) !== 4) return null;
  const headerBytes = buf.readUInt32LE(4);
  const payloadBytes = buf.readUInt32LE(8);
  const jsonBytes = buf.readUInt32LE(12);
  if (headerBytes < 8 || payloadBytes !== headerBytes - 4 || jsonBytes > payloadBytes - 4) return null;
  const dataStart = 8 + headerBytes;
  if (dataStart > buf.length) return null;
  let index;
  try {
    index = JSON.parse(buf.toString("utf8", 16, 16 + jsonBytes));
  } catch {
    return null;
  }
  if (typeof index !== "object" || index === null) return null;
  return { kind: "asar", headerBytes, jsonBytes, dataStart, index, buf };
}

/** Flatten the index: {path, offset, size, unpacked} */
export function asarEntries(parsed) {
  const out = [];
  const rec = (node, prefix) => {
    if (node.files) {
      for (const [name, child] of Object.entries(node.files)) rec(child, prefix ? `${prefix}/${name}` : name);
    } else {
      // offset/size are strings in the asar spec — always coerce to numbers
      out.push({
        path: prefix,
        offset: node.offset !== undefined ? Number(node.offset) : undefined,
        size: node.size !== undefined ? Number(node.size) : 0,
        unpacked: node.unpacked === true,
      });
    }
  };
  rec(parsed.index, "");
  return out;
}

export function extractAsar(parsed, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  for (const e of asarEntries(parsed)) {
    const dest = path.join(outDir, e.path);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    if (e.unpacked || e.offset === undefined) continue; // unpacked files live outside the archive
    const start = parsed.dataStart + e.offset;
    const end = start + e.size;
    if (end > parsed.buf.length) throw new Error(`asar entry out of bounds: ${e.path}`);
    fs.writeFileSync(dest, parsed.buf.subarray(start, end));
  }
}

/**
 * Repack a directory into an asar. Relative paths under filesRoot become index
 * paths. Original ordering is unknowable (not stored), so entries are written
 * alphabetically — asar consumers don't depend on order.
 */
export function packAsar(filesRoot, outFile) {
  const files = [];
  const rec = (dir, prefix) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, ent.name);
      const rel = prefix ? `${prefix}/${ent.name}` : ent.name;
      if (ent.isDirectory()) rec(p, rel);
      else files.push({ abs: p, rel, size: fs.statSync(p).size });
    }
  };
  rec(filesRoot, "");

  const index = { files: {} };
  let cursor = 0;
  const chunks = [];
  for (const f of files) {
    index.files[f.rel] = { size: String(f.size), offset: String(cursor) };
    const data = fs.readFileSync(f.abs);
    chunks.push(data);
    cursor += f.size;
  }
  const json = Buffer.from(JSON.stringify(index), "utf8");
  const jsonBytes = json.length;
  const payloadBytes = 4 + align4(jsonBytes);
  const headerBytes = payloadBytes + 4;
  const head = Buffer.alloc(16 + align4(jsonBytes));
  head.writeUInt32LE(4, 0);
  head.writeUInt32LE(headerBytes, 4);
  head.writeUInt32LE(payloadBytes, 8);
  head.writeUInt32LE(jsonBytes, 12);
  json.copy(head, 16);
  const out = [head, ...chunks];
  fs.writeFileSync(outFile, Buffer.concat(out));
  return { fileCount: files.length, headerBytes };
}
