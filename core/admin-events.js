// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳の管理者監視 — イベントの正規化 (docs/MAMORICHO_DESIGN.md「管理者監視」)。
//   既存の調査の出力 (last・lastb・auth.log / journal・getent・authorized_keys・sudoers) と、言箱 OS 自身の監査ログを、相関分析のための 1 つの形 (イベント) に直す。
//   新しいコマンドは増やさない (読むのは既存の型の出力だけ)。原本 (probe_runs の出力・audit_events) はそのまま残し、イベントは原本への参照 (run_id / 監査の id) と行のハッシュを持つ (たどれる)。
//   資格情報・セッション・鍵の中身は持たない (鍵は種類と注釈とハッシュだけ)。
import { sha256 } from '../util.js';
import { NO_OUTPUT, STDERR_MARK } from './output.js';

const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
// 'Thu Oct  8 10:00:00 2026' (last -F / lastb -F) → ISO。対象の時刻帯は分からないので、箱の時刻帯とみなす (差分と相関には十分)
export function parseLastDate(s) {
  const m = String(s || '').match(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+(\d{4})$/); if (!m || !(m[1] in MON)) return null;
  const d = new Date(Number(m[6]), MON[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])); return isNaN(d) ? null : d.toISOString();
}
// 'Oct  8 10:00:01' (syslog) / 'Oct 08 10:00:01' (journal) / '2026-10-08T10:00:01+09:00' (short-iso) → ISO。年が無い形は、未来になるなら去年
export function parseSyslogDate(s, now = new Date()) {
  const str = String(s || '').trim();
  if (/^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d/.test(str)) { const d = new Date(str.replace(' ', 'T').replace(/([+-]\d\d)(\d\d)$/, '$1:$2')); return isNaN(d) ? null : d.toISOString(); }
  const m = str.match(/^(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)$/); if (!m || !(m[1] in MON)) return null;
  let d = new Date(now.getFullYear(), MON[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])); if (d.getTime() > now.getTime() + 86400e3) d = new Date(now.getFullYear() - 1, MON[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
  return isNaN(d) ? null : d.toISOString();
}

// 共通のイベント (docs の 2.4)。id は中身から決める (同じ行は何度読んでも同じ id → 重複しない)
export function makeEvent({ source, target_id, timestamp, actor_id = null, actor_role = null, actor_ip = null, action, result = 'success', details = {}, run_id = null, source_ref = null, raw = null }) {
  const hash = raw != null ? 'sha256:' + sha256(String(raw)) : null;
  const e = { id: null, source, target_id, timestamp, actor: { id: actor_id, role: actor_role, ip: actor_ip, device_id: null }, action, result, details, evidence: { probe_run_id: run_id, snapshot_id: null, source_ref, hash } };
  e.id = 'aev_' + sha256([source, target_id, timestamp, action, actor_id, actor_ip, hash || JSON.stringify(details)].join('|')).slice(0, 20);
  return e;
}
// 画面と AI 向けの、動作の日本語
export const ACTION_JA = {
  'auth.login_success': 'ログイン成功', 'auth.login_failed': 'ログイン失敗', 'auth.login_locked': 'ログインのロック', 'auth.mfa_enrolled': '多要素認証を登録', 'auth.mfa_removed': '多要素認証を外した', 'auth.mfa_reset': '多要素認証をリセット',
  'auth.password_changed': 'パスワードを変えた', 'auth.key_added': '鍵 (ログイン手段) が増えた', 'auth.method_added': 'ログインの入口を足した', 'auth.method_removed': 'ログインの入口を外した', 'auth.sessions_revoked': '全セッションを切った',
  'account.created': 'アカウントを作った', 'account.removed': 'アカウントを消した', 'account.status': 'アカウントの状態を変えた', 'admin.user_added': '管理者が増えた', 'admin.user_removed': '管理者が減った', 'admin.role_changed': '役割を変えた',
  'privilege.escalation': '権限を上げた', 'privilege.sudo': 'sudo で実行', 'privilege.sudo_failed': 'sudo の認証に失敗', 'token.created': 'API キー・トークンを作った', 'token.revoked': 'API キー・トークンを消した', 'data.bulk_export': '大量のデータ取得',
};
export const fmtEvent = (e) => `${String(e.timestamp || '').slice(0, 16).replace('T', ' ')} ${e.actor?.id || '?'}${e.actor?.ip ? '@' + e.actor.ip : ''}: ${ACTION_JA[e.action] || e.action}${e.details?.subject ? ' → ' + e.details.subject : ''}${e.details?.note ? ' (' + String(e.details.note).slice(0, 80) + ')' : ''}`;

// ---- Linux (SSH の対象): 既存の型の出力から ----
const stdoutOf = (x) => String(x?.output || '').split(STDERR_MARK)[0];
const linesOf = (x) => stdoutOf(x).split('\n').map(l => l.replace(/\r$/, '')).filter(l => l.trim() && l.trim() !== NO_OUTPUT);
const stepsOf = (sections, tid, pick) => (sections.find(s => s.template_id === tid)?.results || sections.find(s => s.template_id === tid)?.steps || []).filter(x => !pick || pick(x));
const readable = (x) => x && !x.error && !x.needs_root && !x.stale_sudoers && (x.exit_code === 0 || x.partial);
const SKIP_USERS = new Set(['reboot', 'shutdown', 'runlevel', 'wtmp', 'btmp']);
const LAST_RE = /^(\S+)\s+(.*?)\s+((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\d{4})/;
// last -F / lastb -F の行 → { user, tty, ip, at, raw }
export function parseLast(lines) {
  const out = [];
  for (const l of lines) {
    const m = l.match(LAST_RE); if (!m || SKIP_USERS.has(m[1]) || /^(wtmp|btmp) begins/.test(l)) continue;
    const mid = m[2].trim().split(/\s+/); const at = parseLastDate(m[3]); if (!at) continue;
    out.push({ user: m[1], tty: mid[0] || null, ip: mid.length > 1 ? mid[mid.length - 1] : null, at, raw: l });
  }
  return out;
}
const SYSLOG_RE = /^(\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:?\d\d|Z)?)\s+(\S+)\s+([A-Za-z0-9_./-]+?)(?:\[\d+\])?:\s+(.*)$/;
// auth.log / journalctl -u ssh の行 → イベントの材料 (sshd の Accepted / Failed・sudo・useradd / usermod / userdel・passwd)
export function parseAuthLog(lines, { now = new Date(), skipUser = 'mamoricho' } = {}) {
  const out = []; const push = (o, l, at) => out.push({ ...o, at, raw: l });
  for (const l of lines) {
    const m = l.match(SYSLOG_RE); if (!m) continue; const at = parseSyslogDate(m[1], now); if (!at) continue; const prog = m[3].replace(/^.*\//, ''); const body = m[4]; let x;
    if (/^sshd/.test(prog)) {
      if ((x = body.match(/^Accepted (\w+) for (\S+) from (\S+) port \d+/))) push({ action: 'auth.login_success', user: x[2], ip: x[3], note: x[1] }, l, at);
      else if ((x = body.match(/^Failed (\w+) for (?:invalid user )?(\S+) from (\S+) port/))) push({ action: 'auth.login_failed', user: x[2], ip: x[3], note: x[1], result: 'failure' }, l, at);
      else if ((x = body.match(/^Invalid user (\S*) from (\S+)/))) push({ action: 'auth.login_failed', user: x[1] || '(空)', ip: x[2], note: 'invalid user', result: 'failure' }, l, at);
    } else if (prog === 'sudo') {
      if ((x = body.match(/^\s*(\S+) : TTY=.*?COMMAND=(.*)$/))) { if (x[1] !== skipUser) push({ action: 'privilege.sudo', user: x[1], note: x[2].slice(0, 120) }, l, at); }
      else if (/pam_unix\(sudo:auth\): authentication failure/.test(body) && (x = body.match(/user=(\S+)/))) { if (x[1] !== skipUser) push({ action: 'privilege.sudo_failed', user: x[1], result: 'failure' }, l, at); }
    } else if (prog === 'useradd' && (x = body.match(/new user: name=([^,\s]+)/))) { if (x[1] !== skipUser) push({ action: 'account.created', subject: x[1] }, l, at); }
    else if (prog === 'usermod' && (x = body.match(/add '([^']+)' to (?:shadow )?group '(sudo|wheel|admin|root|docker)'/))) { if (x[1] !== skipUser) push({ action: 'privilege.escalation', subject: x[1], note: `group ${x[2]}` }, l, at); }
    else if (prog === 'userdel' && (x = body.match(/delete user '([^']+)'/))) push({ action: 'account.removed', subject: x[1] }, l, at);
    else if ((prog === 'passwd' || prog === 'chpasswd' || /^su|^sudo/.test(prog)) && (x = body.match(/password changed for (\S+)/))) push({ action: 'auth.password_changed', subject: x[1] }, l, at);
  }
  return out;
}
const KEY_RE = /^(?:(\S+?):)?(?:[\w-]+(?:="[^"]*")?,)*(?:[\w-]+(?:="[^"]*")?\s+)?(ssh-[\w-]+|ecdsa-[\w-]+|sk-[\w-]+@[\w.]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$/;
// authorized_keys の行 → { file, type, comment, fp }。鍵の中身は持たない (ハッシュだけ)
export function parseKeyLine(line, defaultFile = null) {
  const m = String(line).trim().match(KEY_RE); if (!m) return null;
  return { file: m[1] || defaultFile, type: m[2], comment: (m[4] || '').trim().slice(0, 80), fp: sha256(m[3]).slice(0, 16) };
}
const keyKey = (k) => `${k.file || '?'}|${k.type}|${k.fp}`;
// 管理者の状態 (差分の基準): 管理者と同じ権限のアカウント・鍵でのログインの許可・sudo の決まり
export function linuxAdminState(sections) {
  const admins = new Set(); const keys = new Map(); const sudoers = new Set(); let covered = false;
  for (const x of stepsOf(sections, 'linux.rootusers', readable)) { if (x.argv?.[0] === 'awk') for (const l of linesOf(x)) { const u = l.split(':')[0]; if (u) admins.add(u); covered = true; } }
  for (const x of [...stepsOf(sections, 'linux.users', readable), ...stepsOf(sections, 'linux.rootusers', readable)]) {
    if (x.argv?.[0] !== 'getent') continue;
    if (x.argv[1] === 'passwd') for (const l of linesOf(x)) { const f = l.split(':'); if (f[2] === '0') admins.add(f[0]); covered = true; }
    if (x.argv[1] === 'group' && ['sudo', 'wheel', 'admin', 'root'].includes(x.argv[2])) for (const l of linesOf(x)) { const f = l.split(':'); for (const u of String(f[3] || '').split(',')) if (u.trim()) admins.add(u.trim()); covered = true; }
  }
  for (const x of stepsOf(sections, 'linux.authkeys', readable)) for (const l of linesOf(x)) { const k = parseKeyLine(l); if (k) keys.set(keyKey(k), k); }
  for (const x of stepsOf(sections, 'linux.ssh', readable)) if (x.argv?.[0] === 'cat' && /authorized_keys$/.test(x.argv[1] || '')) for (const l of linesOf(x)) { const k = parseKeyLine(l, x.argv[1]); if (k) keys.set(keyKey(k), k); }
  for (const x of stepsOf(sections, 'linux.sudoers', readable)) for (const l of linesOf(x)) { const body = l.replace(/^\/etc\/sudoers(?:\.d\/[^:]+)?:/, '').trim(); if (!body || body.startsWith('#') || /^Defaults/.test(body) || /mamoricho/.test(l)) continue; if (/NOPASSWD|ALL\s*=\s*\(ALL/.test(body)) sudoers.add(body.replace(/\s+/g, ' ')); }
  return { covered, admins: [...admins].sort(), keys: [...keys.values()].sort((a, b) => keyKey(a).localeCompare(keyKey(b))), sudoers: [...sudoers].sort() };
}
// 2 つの状態の差 (増えた・減った)
export function stateDiff(prev, cur) {
  const d = (a, b, key = (x) => x) => { const A = new Set((a || []).map(key)); const B = new Map((b || []).map(x => [key(x), x])); return { added: [...B].filter(([k]) => !A.has(k)).map(([, v]) => v), removed: (a || []).filter(x => !B.has(key(x))) }; };
  const admins = d(prev?.admins, cur?.admins), keys = d(prev?.keys, cur?.keys, keyKey), sudoers = d(prev?.sudoers, cur?.sudoers), methods = d(prev?.methods, cur?.methods);
  return { admins_added: admins.added, admins_removed: admins.removed, keys_added: keys.added, keys_removed: keys.removed, sudoers_added: sudoers.added, sudoers_removed: sudoers.removed, methods_added: methods.added, methods_removed: methods.removed };
}
// Linux の対象 1 つ: 既存の型の出力 (sections) → 状態・イベント・取れた範囲 (coverage)。prevState があれば、状態の差分も「検知した時刻」のイベントにする
export function linuxAdmin(sections, { target_id, now = new Date(), prevState = null, detected_at = null } = {}) {
  const state = linuxAdminState(sections); const events = []; const src = 'linux-ssh';
  const logins = stepsOf(sections, 'linux.logins', readable).filter(x => x.argv?.[0] === 'last'); const auth = [...stepsOf(sections, 'linux.logs_auth', readable)];
  for (const x of logins) for (const r of parseLast(linesOf(x))) events.push(makeEvent({ source: src, target_id, timestamp: r.at, actor_id: r.user, actor_role: state.admins.includes(r.user) ? 'administrator' : 'user', actor_ip: r.ip, action: 'auth.login_success', details: { tty: r.tty }, run_id: x.run_id || null, raw: r.raw }));
  for (const x of auth) {
    if (x.argv?.[0] === 'last' || x.argv?.[2]?.endsWith('/last')) for (const r of parseLast(linesOf(x))) events.push(makeEvent({ source: src, target_id, timestamp: r.at, actor_id: r.user, actor_role: state.admins.includes(r.user) ? 'administrator' : 'user', actor_ip: r.ip, action: 'auth.login_success', details: { tty: r.tty }, run_id: x.run_id || null, raw: r.raw }));
    else if (x.argv?.[2]?.endsWith('/lastb') || x.argv?.[0] === 'lastb') for (const r of parseLast(linesOf(x))) events.push(makeEvent({ source: src, target_id, timestamp: r.at, actor_id: r.user, actor_ip: r.ip, action: 'auth.login_failed', result: 'failure', details: { tty: r.tty }, run_id: x.run_id || null, raw: r.raw }));
    else for (const r of parseAuthLog(linesOf(x), { now })) events.push(makeEvent({ source: 'linux-auth', target_id, timestamp: r.at, actor_id: r.user || null, actor_role: r.user && state.admins.includes(r.user) ? 'administrator' : null, actor_ip: r.ip || null, action: r.action, result: r.result || 'success', details: { ...(r.subject ? { subject: r.subject } : {}), ...(r.note ? { note: r.note } : {}) }, run_id: x.run_id || null, raw: r.raw }));
  }
  // 状態の差分 → 検知した時刻のイベント (原本は今回の run)。時刻は「気づいた時刻」であって起きた時刻ではないので detected_by: 'diff' を付け、時間の相関 (ADMIN-05/06/10) には使わない
  if (prevState && state.covered) {
    const at = detected_at || now.toISOString(); const d = stateDiff(prevState, state); const runOf = (tid) => stepsOf(sections, tid)[0]?.run_id || null; const D = { detected_by: 'diff', note: '前回の記録との差分' };
    for (const u of d.admins_added) events.push(makeEvent({ source: src, target_id, timestamp: at, action: 'admin.user_added', details: { subject: u, ...D }, run_id: runOf('linux.rootusers') || runOf('linux.users'), raw: `admin+${u}` }));
    for (const u of d.admins_removed) events.push(makeEvent({ source: src, target_id, timestamp: at, action: 'admin.user_removed', details: { subject: u, ...D }, run_id: runOf('linux.rootusers') || runOf('linux.users'), raw: `admin-${u}` }));
    for (const k of d.keys_added) events.push(makeEvent({ source: src, target_id, timestamp: at, action: 'auth.key_added', details: { subject: `${k.file || ''} ${k.type} ${k.comment || ''}`.trim(), ...D, fp: k.fp }, run_id: runOf('linux.authkeys') || runOf('linux.ssh'), raw: `key+${keyKey(k)}` }));
    for (const s of d.sudoers_added) events.push(makeEvent({ source: src, target_id, timestamp: at, action: 'privilege.escalation', details: { subject: s.slice(0, 120), ...D, note: 'sudo の決まりが増えた (前回の記録との差分)' }, run_id: runOf('linux.sudoers'), raw: `sudoers+${s}` }));
  }
  const coverage = { state: state.covered, logins: logins.some(readable) || auth.some(x => readable(x) && (x.argv?.[0] === 'last' || x.argv?.[2]?.endsWith('/last'))), authlog: auth.some(x => readable(x) && !(x.argv?.[0] === 'last' || x.argv?.[2]?.endsWith('/last'))), mfa: false, tokens: false, bulk: false };
  const uniq = new Map(); for (const e of events) uniq.set(e.id, e);
  return { state, events: [...uniq.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp)), coverage };
}

// ---- 言箱 OS 自身: 監査ログ (audit_events) と利用者・API キーの一覧から ----
const ADMIN_ROLES = new Set(['owner', 'admin']);
const OS_MAP = {
  'auth.login': 'auth.login_success', 'auth.login_gpu_box': 'auth.login_success', 'auth.login_failed': 'auth.login_failed', 'auth.login_locked': 'auth.login_locked', 'auth.login_mfa_missing': 'auth.login_failed',
  'auth.mfa_enrolled': 'auth.mfa_enrolled', 'auth.mfa_removed': 'auth.mfa_removed', 'auth.mfa_reset': 'auth.mfa_reset', 'auth.mfa_recovery_regenerated': 'auth.mfa_reset', 'auth.mfa_trusted_cleared': 'auth.mfa_reset',
  'auth.password_changed': 'auth.password_changed', 'user.password_reset': 'auth.password_changed', 'auth.owner_recovered': 'privilege.escalation', 'auth.revoke_all_sessions': 'auth.sessions_revoked',
  'user.create': 'account.created', 'user.role_change': 'admin.role_changed', 'user.status_change': 'account.status', 'setup.owner_created': 'admin.user_added',
  'apikey.create': 'token.created', 'apikey.revoke': 'token.revoked', 'remote.enable': 'auth.method_added', 'remote.issue': 'auth.method_added', 'remote.disable': 'auth.method_removed',
};
export const OS_AUDIT_ACTIONS = Object.keys(OS_MAP);
const FAIL = new Set(['auth.login_failed', 'auth.login_locked', 'auth.login_mfa_missing']);
export function osAuditEvents(rows, { users = [] } = {}) {
  const roleOf = new Map(users.map(u => [u.id, u.role])); const nameOf = new Map(users.map(u => [u.id, u.username]));
  const out = [];
  for (const r of rows) {
    let action = OS_MAP[r.action]; if (!action) continue; const d = r.detail && typeof r.detail === 'object' ? r.detail : {};
    const to = String(d.role || d.to || d.new_role || ''); if (r.action === 'user.create' && ADMIN_ROLES.has(to)) action = 'admin.user_added'; if (r.action === 'user.role_change' && ADMIN_ROLES.has(to)) action = 'privilege.escalation';
    const subject = typeof r.target === 'string' && !/^null$/.test(r.target) ? (nameOf.get(r.target) || d.username || r.target) : (d.username || null);
    const note = r.action === 'user.role_change' ? `${d.from || d.previous || '?'} → ${to || '?'}` : r.action === 'apikey.create' ? String(d.name || '') : r.action === 'user.status_change' ? String(d.status || '') : (r.result && r.result !== 'ok' ? String(r.result) : '');
    out.push(makeEvent({ source: 'os-audit', target_id: 'self', timestamp: r.time, actor_id: r.actor_name || r.actor_id, actor_role: ADMIN_ROLES.has(roleOf.get(r.actor_id)) ? 'administrator' : (r.actor_id === 'system' ? 'system' : 'user'), actor_ip: r.ip || null, action, result: FAIL.has(r.action) || (r.result && r.result !== 'ok') ? 'failure' : 'success', details: { ...(subject ? { subject: String(subject).slice(0, 80) } : {}), ...(note ? { note: note.slice(0, 120) } : {}) }, source_ref: r.id, raw: `${r.id}|${r.hash || ''}` }));
  }
  return out.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}
export function osAdminState({ users = [], apiKeys = [], remote = null } = {}) {
  const admins = users.filter(u => ADMIN_ROLES.has(u.role) && (u.status || 'active') === 'active');
  return { covered: true, admins: admins.map(u => u.username).sort(), mfa_missing: admins.filter(u => !u.mfa_factors).map(u => u.username).sort(), keys: apiKeys.filter(k => !k.revoked_at).map(k => ({ file: 'apikey', type: 'apikey', comment: String(k.name || k.prefix || k.id).slice(0, 80), fp: sha256(String(k.id)).slice(0, 16) })), sudoers: [], methods: remote?.hostname ? [`公開 URL ${remote.hostname}`] : [] };
}
