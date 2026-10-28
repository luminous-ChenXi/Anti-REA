// Shared utilities: no external dependencies.
import * as fs from "node:fs";
import * as path from "node:path";

export const MB = 1024 * 1024;

/** Reproducible PRNG (mulberry32), used by the poison generator. */
export function rng(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function seedFromString(s) {
  let h = 2166136261 >>> 0;
  for (const ch of Buffer.from(s, "utf8")) {
    h ^= ch;
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function randomIdent(rand) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let s = "";
  for (let i = 0; i < 6; i++) s += alphabet[Math.floor(rand() * alphabet.length)];
  return s;
}

/** Find all occurrences of needle in buf (plain scan, safe on large buffers). */
export function indexOfAll(buf, needle, { limit = 10000, from = 0 } = {}) {
  const out = [];
  if (!needle || needle.length === 0) return out;
  let pos = from;
  while (out.length < limit) {
    const i = buf.indexOf(needle, pos);
    if (i === -1) break;
    out.push(i);
    pos = i + 1;
  }
  return out;
}

/** Read at most maxBytes from a file (audit truncation for huge files). */
export function readHead(filePath, maxBytes) {
  const fd = fs.openSync(filePath, "r");
  try {
    const stat = fs.fstatSync(fd);
    const len = Math.min(stat.size, maxBytes);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, 0);
    return { buf, size: stat.size, truncated: stat.size > len };
  } finally {
    fs.closeSync(fd);
  }
}

/** Magic-prefix checks. */
export const MAGIC = {
  elf: Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
  mz: Buffer.from([0x4d, 0x5a]),
  macho64le: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]),
  macho64be: Buffer.from([0xfe, 0xed, 0xfa, 0xcf]),
  machoFatBe: Buffer.from([0xca, 0xfe, 0xba, 0xbe]),
  wasm: Buffer.from([0x00, 0x61, 0x73, 0x6d]),
  zip: Buffer.from([0x50, 0x4b, 0x03, 0x04]),
};

export function startsWith(buf, magic) {
  return buf.length >= magic.length && magic.compare(buf, 0, magic.length) === 0;
}

export function fmtBytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < MB) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / MB).toFixed(1)}MB`;
}

export function walkFiles(root, { maxFiles = 4000, maxDepth = 12 } = {}) {
  const out = [];
  const skipDirs = new Set([".git", "node_modules", "__pycache__"]);
  const rec = (dir, depth) => {
    if (out.length >= maxFiles || depth > maxDepth) return;
    let ents;
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      if (out.length >= maxFiles) return;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!skipDirs.has(e.name)) rec(p, depth + 1);
      } else if (e.isFile()) {
        out.push(p);
      }
    }
  };
  if (fs.statSync(root).isFile()) out.push(root);
  else rec(root, 0);
  return out;
}

export function jsonSafe(o) {
  return JSON.parse(JSON.stringify(o, (k, v) => (typeof v === "bigint" ? Number(v) : v)));
}
