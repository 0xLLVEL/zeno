// Generates src-tauri/icons/icon.ico (256x256, PNG-encoded ICO) for Zeno.
// No dependencies: builds raw RGBA, deflates with zlib, wraps in ICO + PNG.
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const S = 256;
const px = Buffer.alloc(S * S * 4);

const A = [124, 92, 255];
const B = [58, 34, 150];

function blend(x, y, r, g, b, a) {
  const i = (y * S + x) * 4;
  const inv = 1 - a / 255;
  px[i] = Math.round(r * a + px[i] * inv);
  px[i + 1] = Math.round(g * a + px[i + 1] * inv);
  px[i + 2] = Math.round(b * a + px[i + 2] * inv);
  px[i + 3] = Math.round(255 * a + px[i + 3] * inv);
}

const radius = 56;
function inside(x, y) {
  const cx = Math.min(Math.max(x, radius), S - 1 - radius);
  const cy = Math.min(Math.max(y, radius), S - 1 - radius);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= radius * radius;
}

for (let y = 0; y < S; y++) {
  for (let x = 0; x < S; x++) {
    if (!inside(x, y)) continue;
    const t = (x + y) / (2 * S);
    blend(x, y, A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t, 1);
  }
}

// Z glyph: two horizontal bars + diagonal
const thick = 26;
function bar(x0, x1, y0, y1) {
  for (let y = y0; y < y1; y++)
    for (let x = x0; x < x1; x++) if (inside(x, y)) blend(x, y, 255, 255, 255, 0.97);
}
bar(72, 184, 66, 66 + thick);
bar(72, 184, 190 - thick, 190);
for (let y = 66 + thick; y < 190 - thick; y++) {
  const t = (y - (66 + thick)) / (190 - thick - (66 + thick));
  const cx = 176 - t * 104;
  bar(Math.round(cx - thick / 2), Math.round(cx + thick / 2), y, y + 1);
}

// --- PNG encode ---
function crc32(buf) {
  let c;
  const table = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

const raw = Buffer.alloc(S * (S * 4 + 1));
for (let y = 0; y < S; y++) {
  raw[y * (S * 4 + 1)] = 0;
  px.copy(raw, y * (S * 4 + 1) + 1, y * S * 4, (y + 1) * S * 4);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(S, 0);
ihdr.writeUInt32BE(S, 4);
ihdr[8] = 8;
ihdr[9] = 6;
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk("IHDR", ihdr),
  chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);

const ico = Buffer.alloc(6);
ico.writeUInt16LE(0, 0);
ico.writeUInt16LE(1, 2);
ico.writeUInt16LE(1, 4);
const dir = Buffer.alloc(16);
dir[0] = 0;
dir[1] = 0;
dir.writeUInt16LE(1, 4);
dir.writeUInt16LE(32, 6);
dir.writeUInt32LE(png.length, 8);
dir.writeUInt32LE(22, 12);
const out = Buffer.concat([ico, dir, png]);

const dirPath = path.join(__dirname, "..", "src-tauri", "icons");
fs.mkdirSync(dirPath, { recursive: true });
fs.writeFileSync(path.join(dirPath, "icon.ico"), out);
fs.writeFileSync(path.join(dirPath, "icon.png"), png);
console.log(`icon.ico ${out.length} bytes · icon.png ${png.length} bytes`);
