// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// ZIP の最小の読み書き (外部依存なし。node:zlib だけ)。Word (.docx) と Excel (.xlsx) の中身を読むため・規程を .docx で書き出すために使う。
//   読む: 中央ディレクトリから名前と位置を拾い、無圧縮 (0) と deflate (8) だけ展開する。暗号化・分割・ZIP64 は扱わない (規程の文書には要らない)
import zlib from 'node:zlib';
import { HttpError } from '../util.js';

const MAX_ENTRY = 64 << 20; // 展開後 64MB まで (ZIP 爆弾よけ)
export function unzip(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 22) throw new HttpError(400, 'bad_zip', 'ZIP の形ではありません');
  let eocd = -1; for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new HttpError(400, 'bad_zip', 'ZIP の終わりの印が見つかりません');
  const count = buf.readUInt16LE(eocd + 10); let p = buf.readUInt32LE(eocd + 16); const out = new Map();
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw new HttpError(400, 'bad_zip', 'ZIP の目次が壊れています');
    const flags = buf.readUInt16LE(p + 8), method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), elen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), lho = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nlen).toString(flags & 0x800 ? 'utf8' : 'latin1'); p += 46 + nlen + elen + clen;
    if (name.endsWith('/')) continue; if (flags & 1) throw new HttpError(400, 'encrypted_zip', 'パスワードのかかった文書は読めません');
    if (usize > MAX_ENTRY) throw new HttpError(413, 'too_large', `${name} が大きすぎます`);
    if (buf.readUInt32LE(lho) !== 0x04034b50) throw new HttpError(400, 'bad_zip', 'ZIP の中身の位置が壊れています');
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28); const raw = buf.subarray(start, start + csize);
    out.set(name, () => (method === 0 ? Buffer.from(raw) : method === 8 ? zlib.inflateRawSync(raw, { maxOutputLength: MAX_ENTRY }) : (() => { throw new HttpError(400, 'bad_zip', `${name}: 扱えない圧縮 (${method})`); })()));
  }
  return { names: [...out.keys()], has: (n) => out.has(n), read: (n) => { const f = out.get(n); if (!f) throw new HttpError(400, 'bad_zip', `${n} がありません`); return f(); }, text: (n) => out.has(n) ? out.get(n)().toString('utf8') : null };
}

// files: [{ name, data: Buffer|string }]。deflate で詰め、日時は固定 (同じ中身なら同じバイト列になる)
export function zip(files) {
  const locals = []; const central = []; let off = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8'); const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(String(f.data), 'utf8');
    const comp = zlib.deflateRawSync(data); const crc = zlib.crc32(data);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x800, 6); lh.writeUInt16LE(8, 8); lh.writeUInt16LE(0, 10); lh.writeUInt16LE(0x5a21, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26); lh.writeUInt16LE(0, 28);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x800, 8); ch.writeUInt16LE(8, 10); ch.writeUInt16LE(0, 12); ch.writeUInt16LE(0x5a21, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, comp); central.push(ch, name); off += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(central); const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

// XML の文字参照を戻す (&amp; &#13; など)
export const xmlText = (s) => String(s).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e.toLowerCase()]);
export const xmlEsc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
