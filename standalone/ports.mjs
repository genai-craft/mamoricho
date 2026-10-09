// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 単体版のポート: ローカルの利用者とセッション・改ざん検知つきの監査ログ・画面内の承認・ローカルの金庫 (AES-256-GCM)・記録の署名鍵 (ed25519)・通知。
//   組み込み先 (言箱 OS など) が無いときに、ports.js が求めるものをこの 1 ファイルで満たす。SQLite は node:sqlite (Node 22.13+)。
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { HttpError, id, nowIso, sha256, redact, canonicalJson, randomToken, J } from '../util.js';
import { createLlm } from '../llm/providers.js';

export const RANK = { viewer: 0, operator: 1, admin: 2, owner: 3 };
const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, display_name TEXT, role TEXT, password_hash TEXT, status TEXT DEFAULT \'active\', created_at TEXT, updated_at TEXT)',
  'CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT, token_hash TEXT UNIQUE, created_at TEXT, expires_at TEXT, revoked_at TEXT, ip TEXT, user_agent TEXT)',
  'CREATE TABLE IF NOT EXISTS audit_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, time TEXT, actor_id TEXT, actor_name TEXT, action TEXT, target TEXT, result TEXT, detail TEXT, ip TEXT, prev_hash TEXT, hash TEXT)',
  'CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, action TEXT, summary TEXT, detail TEXT, requested_by TEXT, approver_id TEXT, state TEXT, created_at TEXT, expires_at TEXT, decided_at TEXT, reason TEXT)',
  'CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, provider TEXT, name TEXT, scope TEXT, owner_id TEXT, ciphertext TEXT, iv TEXT, tag TEXT, expires_at TEXT, created_at TEXT)',
  'CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, kind TEXT, severity TEXT, title TEXT, body TEXT, dedupe_key TEXT, link TEXT, created_at TEXT, read_at TEXT)',
  'CREATE TABLE IF NOT EXISTS login_failures (key TEXT PRIMARY KEY, count INTEGER, first_at TEXT, last_at TEXT)',
];
const scrypt = (pw, salt) => crypto.scryptSync(String(pw), salt, 64).toString('hex');
export const hashPassword = (pw) => { const salt = crypto.randomBytes(16).toString('hex'); return `scrypt$${salt}$${scrypt(pw, salt)}`; };
export const verifyPassword = (pw, stored) => { const [, salt, h] = String(stored || '').split('$'); if (!salt || !h) return false; const a = Buffer.from(scrypt(pw, salt), 'hex'), b = Buffer.from(h, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const keyFile = (dir, name, make) => { const p = path.join(dir, name); if (!fs.existsSync(p)) { fs.writeFileSync(p, make(), { mode: 0o600 }); } return fs.readFileSync(p); };

// dataDir に DB・鍵・設定を置く。config: { llm: {...}, tls: {...}, brand: {...}, session_hours, docker_image }
export function createStandalone(dataDir, config = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'mamoricho.sqlite')); db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;'); for (const s of SCHEMA) db.exec(s);
  const masterKey = keyFile(dataDir, 'vault.key', () => crypto.randomBytes(32)); // 金庫の鍵 (32 バイト)。この箱から出さない
  const signPem = keyFile(dataDir, 'signing.key', () => crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' })).toString();
  const signingKey = crypto.createPrivateKey(signPem);
  const reauthTokens = new Map(); const sessionHours = Number(config.session_hours) || 24;
  const llm = config.llm === false ? null : createLlm(config.llm || {});

  // ---- 監査ログ (前の hash を含めて連鎖) ----
  function audit({ actor, action, target, result = 'ok', detail = null, ip = null }) {
    const last = db.prepare('SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1').get(); const prev = last ? last.hash : 'GENESIS';
    const ev = { id: id('aud'), time: nowIso(), actor_id: actor?.id || 'system', actor_name: actor?.username || actor?.name || 'system', action, target: typeof target === 'string' ? target : JSON.stringify(target ?? null), result, detail: redact(detail), ip };
    const hash = sha256(prev + canonicalJson(ev));
    db.prepare('INSERT INTO audit_events(id,time,actor_id,actor_name,action,target,result,detail,ip,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(ev.id, ev.time, ev.actor_id, ev.actor_name, ev.action, ev.target, ev.result, J.str(ev.detail), ip, prev, hash);
    return { ...ev, prev_hash: prev, hash };
  }
  function listAudit({ limit = 100, since = null, action = null } = {}) {
    const where = []; const args = []; if (since) { where.push('time>=?'); args.push(since); } if (action) { where.push('action LIKE ?'); args.push(action + '%'); }
    return db.prepare(`SELECT * FROM audit_events ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY seq DESC LIMIT ?`).all(...args, limit).map(r => ({ ...r, detail: J.parse(r.detail) }));
  }
  function verifyAuditChain() { let prev = 'GENESIS'; for (const r of db.prepare('SELECT * FROM audit_events ORDER BY seq').all()) { const ev = { id: r.id, time: r.time, actor_id: r.actor_id, actor_name: r.actor_name, action: r.action, target: r.target, result: r.result, detail: J.parse(r.detail), ip: r.ip }; if (r.prev_hash !== prev || sha256(prev + canonicalJson(ev)) !== r.hash) return { ok: false, broken_at: r.seq }; prev = r.hash; } return { ok: true, head: prev }; }

  // ---- 利用者・セッション ----
  const requireRole = (actor, role) => { if (!actor || (RANK[actor.role] ?? -1) < RANK[role]) throw new HttpError(403, 'forbidden', `この操作には ${role} 以上の権限が要ります`); };
  const userOut = (u) => u && { id: u.id, username: u.username, display_name: u.display_name, role: u.role, status: u.status, tenant_id: 'local', created_at: u.created_at, mfa_factors: 0 };
  function createUser(actor, { username, password, role = 'viewer', display_name = '' }) {
    if (actor) requireRole(actor, 'admin'); if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username || '')) throw new HttpError(400, 'bad_username', 'ユーザー名は 3〜32 文字の英数字'); if (String(password || '').length < 8) throw new HttpError(400, 'weak_password', 'パスワードは 8 文字以上');
    if (!RANK[role] && role !== 'viewer') throw new HttpError(400, 'bad_role', 'role は owner / admin / operator / viewer'); const now = nowIso(); const u = { id: id('usr'), username, display_name: display_name || username, role, password_hash: hashPassword(password), status: 'active', created_at: now, updated_at: now };
    db.prepare('INSERT INTO users(id,username,display_name,role,password_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(u.id, u.username, u.display_name, u.role, u.password_hash, u.status, now, now);
    audit({ actor, action: actor ? 'user.create' : 'setup.owner_created', target: u.id, detail: { username, role } }); return userOut(u);
  }
  function setPassword(username, password) { const u = db.prepare('SELECT * FROM users WHERE username=?').get(username); if (!u) throw new HttpError(404, 'not_found', '利用者が見つかりません'); if (String(password || '').length < 8) throw new HttpError(400, 'weak_password', 'パスワードは 8 文字以上'); db.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').run(hashPassword(password), nowIso(), u.id); audit({ actor: null, action: 'auth.password_changed', target: u.id }); return userOut(u); }
  function login({ username, password, ip, userAgent }) {
    const key = `${username}@${ip || '-'}`; const f = db.prepare('SELECT * FROM login_failures WHERE key=?').get(key);
    if (f && f.count >= 5 && Date.now() - Date.parse(f.last_at) < 10 * 60e3) { audit({ actor: null, action: 'auth.login_locked', target: username, ip, result: 'denied' }); throw new HttpError(429, 'locked', 'ログインの失敗が続いたので、10 分ほど待ってください'); }
    const u = db.prepare('SELECT * FROM users WHERE username=? AND status=\'active\'').get(username);
    if (!u || !verifyPassword(password, u.password_hash)) { db.prepare('INSERT INTO login_failures(key,count,first_at,last_at) VALUES(?,1,?,?) ON CONFLICT(key) DO UPDATE SET count=count+1, last_at=excluded.last_at').run(key, nowIso(), nowIso()); audit({ actor: null, action: 'auth.login_failed', target: username, ip, result: 'denied' }); throw new HttpError(401, 'bad_login', 'ユーザー名かパスワードが違います'); }
    db.prepare('DELETE FROM login_failures WHERE key=?').run(key); const token = randomToken(32); const sid = id('ses');
    db.prepare('INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at,ip,user_agent) VALUES(?,?,?,?,?,?,?)').run(sid, u.id, sha256(token), nowIso(), new Date(Date.now() + sessionHours * 3600e3).toISOString(), ip, userAgent || null);
    const actor = { ...userOut(u), session_id: sid }; audit({ actor, action: 'auth.login', target: u.id, ip }); return { token, session_id: sid, user: userOut(u) };
  }
  function sessionActor(token) { if (!token) return null; const s = db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(sha256(token)); if (!s || s.revoked_at || s.expires_at < nowIso()) return null; const u = db.prepare('SELECT * FROM users WHERE id=? AND status=\'active\'').get(s.user_id); return u ? { ...userOut(u), session_id: s.id } : null; }
  function logout(actor) { if (actor?.session_id) { db.prepare('UPDATE sessions SET revoked_at=? WHERE id=?').run(nowIso(), actor.session_id); audit({ actor, action: 'auth.logout', target: actor.id }); } }
  function reauth(actor, password) { const u = db.prepare('SELECT password_hash FROM users WHERE id=?').get(actor.id); if (!u || !verifyPassword(password, u.password_hash)) { audit({ actor, action: 'auth.reauth_failed', target: actor.id, result: 'denied' }); throw new HttpError(401, 'reauth_failed', 'パスワードが違います'); } const token = randomToken(24); reauthTokens.set(token, { user_id: actor.id, expires: Date.now() + 5 * 60e3 }); audit({ actor, action: 'auth.reauth', target: actor.id }); return { reauth_token: token, expires_in_sec: 300 }; }
  function requireReauth(actor, token) { const r = token && reauthTokens.get(token); if (!r || r.user_id !== actor.id || r.expires < Date.now()) throw new HttpError(403, 'reauth_required', 'この操作にはパスワードの再入力が必要です'); reauthTokens.delete(token); }

  // ---- 金庫 (AES-256-GCM、鍵はこの箱のファイル) ----
  const vault = {
    store(actor, { provider, name, secret, scope = 'probe', expires_at = null }) { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', masterKey, iv); const ct = Buffer.concat([c.update(String(secret), 'utf8'), c.final()]); const cid = id('cred'); db.prepare('INSERT INTO credentials(id,provider,name,scope,owner_id,ciphertext,iv,tag,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(cid, provider, name, scope, actor?.id || null, ct.toString('base64'), iv.toString('base64'), c.getAuthTag().toString('base64'), expires_at, nowIso()); audit({ actor, action: 'vault.store', target: cid, detail: { provider, name, scope, expires_at } }); return { id: cid, provider, name, scope, expires_at }; },
    use(cid) { const r = db.prepare('SELECT * FROM credentials WHERE id=?').get(cid); if (!r) throw new HttpError(404, 'not_found', '資格情報が見つかりません'); if (r.expires_at && r.expires_at < nowIso()) throw new HttpError(410, 'expired', '資格情報の期限が切れています'); const d = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(r.iv, 'base64')); d.setAuthTag(Buffer.from(r.tag, 'base64')); return Buffer.concat([d.update(Buffer.from(r.ciphertext, 'base64')), d.final()]).toString('utf8'); },
    delete(actor, cid) { const n = db.prepare('DELETE FROM credentials WHERE id=?').run(cid).changes; if (!n) throw new HttpError(404, 'not_found', '資格情報が見つかりません'); audit({ actor, action: 'vault.delete', target: cid }); return { ok: true }; },
    purgeExpired() { return db.prepare('DELETE FROM credentials WHERE expires_at IS NOT NULL AND expires_at < ?').run(nowIso()).changes; },
  };
  // ---- 承認 (画面の中で。probe:authz は admin 以上) ----
  const apOut = (r) => r && { ...r, detail: J.parse(r.detail, {}) };
  const approvals = {
    create({ action, summary, detail = {}, requested_by, ttl_min = 60 }) { const ap = { id: id('apv'), action, summary, detail: J.str(redact(detail)), requested_by: requested_by?.id || 'system', state: 'pending', created_at: nowIso(), expires_at: new Date(Date.now() + ttl_min * 60e3).toISOString() }; db.prepare('INSERT INTO approvals(id,action,summary,detail,requested_by,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)').run(ap.id, ap.action, ap.summary, ap.detail, ap.requested_by, ap.state, ap.created_at, ap.expires_at); audit({ actor: requested_by, action: 'approval.request', target: ap.id, detail: { action, summary } }); return approvals.get(ap.id); },
    get(apId) { return apOut(db.prepare('SELECT * FROM approvals WHERE id=?').get(apId)); },
    list({ state = null, limit = 50 } = {}) { return (state ? db.prepare('SELECT * FROM approvals WHERE state=? ORDER BY created_at DESC LIMIT ?').all(state, limit) : db.prepare('SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?').all(limit)).map(apOut); },
    decide(actor, apId, decision, reason = null) { requireRole(actor, 'operator'); const ap = approvals.get(apId); if (!ap) throw new HttpError(404, 'not_found', '承認要求が見つかりません'); if (ap.state !== 'pending') throw new HttpError(409, 'already_decided', 'この承認要求は処理済みです'); if (ap.expires_at < nowIso()) { db.prepare("UPDATE approvals SET state='expired' WHERE id=?").run(apId); throw new HttpError(410, 'expired', '承認要求の期限が切れています'); } if (/^(admin|probe:authz)/.test(ap.action)) requireRole(actor, 'admin'); const state = decision === 'approve' ? 'approved' : 'rejected'; db.prepare('UPDATE approvals SET state=?, approver_id=?, decided_at=?, reason=? WHERE id=?').run(state, actor.id, nowIso(), reason, apId); audit({ actor, action: 'approval.' + decision, target: apId, detail: { action: ap.action, reason } }); return approvals.get(apId); },
  };
  const notify = ({ kind, severity = 'info', title, body = '', dedupe_key = null, link = null }) => { if (dedupe_key && db.prepare('SELECT 1 FROM notifications WHERE dedupe_key=? AND read_at IS NULL').get(dedupe_key)) return; db.prepare('INSERT INTO notifications(id,kind,severity,title,body,dedupe_key,link,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id('ntf'), kind, severity, title, body, dedupe_key, link, nowIso()); };
  const notifications = { list({ limit = 50 } = {}) { return db.prepare('SELECT * FROM notifications ORDER BY created_at DESC LIMIT ?').all(limit); }, markRead(nid) { db.prepare('UPDATE notifications SET read_at=? WHERE id=?').run(nowIso(), nid); } };
  // ---- 自己点検 (単体版で機械的に分かるものだけ) ----
  const dockerOk = () => { try { return spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8', timeout: 8000 }).status === 0; } catch { return false; } };
  const selfChecks = async () => [
    { id: 'self.https', label: 'https で画面を出している', item: 'leak.encrypt', ok: !!config.tls?.cert, detail: config.tls?.cert ? 'https' : 'http のまま (前段のリバースプロキシで https にするか、config.tls を設定)', level: 'check' },
    { id: 'self.login_lock', label: 'ログイン失敗が続くとロックする', item: 'entry.lockout', ok: true, detail: '同じ名前+接続元で 5 回失敗すると 10 分ロック', level: 'check' },
    { id: 'self.llm_local', label: 'AI が手元 (社内) にある', item: null, ok: !llm || llm.local, detail: llm ? `${llm.provider} ${llm.base_url}${llm.local ? '' : ' — 社外のサービスです (データが外に出ます)'}` : 'AI なし (規則と記録だけで動きます)', level: 'check' },
    { id: 'self.docker', label: 'docker が使える (調査の使い捨てコンテナ)', item: null, ok: dockerOk(), detail: dockerOk() ? 'docker あり' : 'docker が無い・使えない (調査は実行できません。点検と記録は使えます)', level: 'check' },
  ];
  const ports = {
    db: () => db, audit, listAudit, requireRole,
    users: { list: () => db.prepare('SELECT * FROM users ORDER BY created_at').all().map(userOut), firstTenant: () => 'local' },
    sharedWorkspace: () => null, apiKeys: () => [], vault, approvals, signer: { privateKey: () => signingKey }, notify, selfChecks,
    externalAi: () => !!llm && llm.local === false, brand: { product: 'まもり帳', os: 'まもり帳', os_en: 'Mamoricho', vendor: 'genai-craft', ua: 'Mamoricho', image: config.docker_image || 'mamoricho-probe:1', user: 'mamoricho', ai: llm ? `ローカルの AI (${llm.provider})` : 'AI (未設定)', store: 'まもり帳の保存先 (この箱)', ...(config.brand || {}) },
    llm, akigrid: null, nas: null, netops: null, rag: null,
  };
  return { ports, db, auth: { createUser, setPassword, login, logout, sessionActor, reauth, requireReauth, users: () => db.prepare('SELECT * FROM users ORDER BY created_at').all().map(userOut) }, approvals, notifications, verifyAuditChain, llm, config };
}
