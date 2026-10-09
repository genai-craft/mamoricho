// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳のパッケージ内で使う小さな補助 (外部依存なし)。言箱 OS の src/util.js と同じ振る舞いだが、パッケージは OS の中を import しない (OSS として単体で成り立つため)
import crypto from 'node:crypto';

export function nowIso() { return new Date().toISOString(); }
export function id(prefix) { return `${prefix}_${crypto.randomBytes(8).toString('hex')}`; }
export function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
export function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
export const sleep = (ms) => new Promise(r => setTimeout(r, ms));
// キーの順序を固定した JSON 直列化 (ハッシュ・署名の対象に使う)
// undefined の値は JSON.stringify と同じく「無いもの」として扱う (保存した JSON と読み戻した値でハッシュが変わらないように)
export function canonicalJson(v) {
  if (v === undefined || typeof v === 'function') return 'null';
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(x => (x === undefined || typeof x === 'function' ? 'null' : canonicalJson(x))).join(',') + ']';
  return '{' + Object.keys(v).filter(k => v[k] !== undefined && typeof v[k] !== 'function').sort().map(k => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}
// HTTP の誤り。status / code / message / extra の形は OS と同じ (OS 側は instanceof ではなく、この形で判定する)
export class HttpError extends Error {
  constructor(status, code, message, extra = {}) { super(message); this.status = status; this.code = code; this.extra = extra; }
}
// 記録やログに出してはいけない値を伏せる (鍵名が秘密らしいもの・秘密に見える値)
const SECRET_KEY_RE = /(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)/i;
const SECRET_VALUE_RE = /\b(sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[A-Fa-f0-9]{40,})\b/g;
export function redact(v, depth = 0) {
  if (depth > 12) return '[depth]';
  if (typeof v === 'string') return v.replace(SECRET_VALUE_RE, '[REDACTED]');
  if (Array.isArray(v)) return v.map(x => redact(x, depth + 1));
  if (v && typeof v === 'object') { const out = {}; for (const [k, val] of Object.entries(v)) out[k] = SECRET_KEY_RE.test(k) ? '[REDACTED]' : redact(val, depth + 1); return out; }
  return v;
}
// JSON 列の読み書き
export const J = { parse: (s, fb = null) => { if (s == null) return fb; try { return JSON.parse(s); } catch { return fb; } }, str: (v) => (v === undefined ? null : JSON.stringify(v)) };
