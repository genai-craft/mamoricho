// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳の調査の仕組み (段階 1、docs/MAMORICHO_DESIGN.md 5)。壊さずに、承認・vault・監査に直結して調べる。
//   対象の台帳 (probe_targets) に載せた機械だけを調べる。どの機械につなぐか (host/port/user) は OS が台帳から決め、
//   テンプレートや AI は「何を読むか」(対象の機械で動かすコマンド) だけを決める → ほかの機械へはつなげない。
//   実行は使い捨てのコンテナ (読み取り専用・権限を落とす・非 root・時間と出力の上限)。出力は伏せ字にして箱の中 (AI NAS) に保存。
//   コマンドの判定は src/probe/classify.js: read は実行、change は Owner の承認と理由、forbidden は実行しない。
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { HttpError, id, nowIso, sha256, redact, randomToken, J } from '../util.js';
import { classifyCommand, llmJudge } from '../core/classify.js';
import { sudoersLines } from '../core/rootsteps.js';
import { OUTPUT_KEEP, NO_OUTPUT, STDERR_MARK } from '../core/output.js';
export { OUTPUT_KEEP, NO_OUTPUT, STDERR_MARK };

const KINDS = ['ssh', 'network', 'web']; // winrm・local-script は後の版で
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$|^(\d{1,3}\.){3}\d{1,3}$|^[0-9A-Fa-f:]+$/;
const CONTAINER_RUN = ['run', '--rm', '-i', '--network', 'bridge', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '256m', '--cpus', '1', '--tmpfs', '/tmp:size=16m', '--tmpfs', '/home/probe:size=16m,uid=10002'];

const PROBE_TIMEOUT_MS = 90000;
const OUT_MAX = 2 * 1024 * 1024;
// 公開 HP の調査で名乗る名前 (検索エンジン名義は、乗っ取られた HP が検索エンジンにだけ別の内容を見せる「偽装 (クローキング)」を確かめるため。自社の HP にだけ使う)
const WEB_UA = { default: 'Mamoricho', googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', browser: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', mobile: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1' };
const DIG_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CAA'];
const sq = (x) => `'${String(x).replace(/'/g, "'\\''")}'`;
// 公開 HP の対象で動かすコマンドを組む (読むだけ)。curl: -I (ヘッダだけ) -v (証明書の情報) -L (転送を 5 回まで追う) --plain-http (http:// で見る) -A <googlebot|browser|mobile> と、/ で始まるパス。dig: +short <A|AAAA|MX|TXT|NS|CAA> <対象の名前 ({host} / {apex} / _dmarc.{apex})>
export function webScript(t, argv, defaultUa = WEB_UA.default) {
  const apex = String(t.host).replace(/^www\./, '');
  if (argv[0] === 'dig') {
    const type = String(argv[2] || '').toUpperCase(); const name = String(argv[3] || '').replace('{host}', t.host).replace('{apex}', apex);
    const allowed = new Set([t.host, apex, `_dmarc.${t.host}`, `_dmarc.${apex}`]);
    if (argv.length !== 4 || argv[1] !== '+short' || !DIG_TYPES.includes(type) || !allowed.has(name)) throw new HttpError(400, 'bad_dig', 'DNS の調査は dig +short <A|AAAA|MX|TXT|NS|CAA> <対象の名前> だけです (ほかの名前は引けません)');
    return `exec dig +short +time=5 +tries=1 ${type} ${sq(name)}`;
  }
  if (argv[0] !== 'curl') throw new HttpError(400, 'bad_program', '公開 HP の調査は curl (見に行く) と dig (DNS を引く) だけです');
  let head = false, verbose = false, follow = false, plain = false, ua = defaultUa, pathArg = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-I' || a === '--head') head = true; else if (a === '-v') verbose = true; else if (a === '-L') follow = true; else if (a === '--plain-http') plain = true;
    else if (a === '-A') { const k = argv[++i]; if (!WEB_UA[k] || k === 'default') throw new HttpError(400, 'bad_flag', '-A は googlebot / browser / mobile のどれかです'); ua = WEB_UA[k]; }
    else if (a.startsWith('-')) throw new HttpError(400, 'bad_flag', `web の調査で使える指定は -I -v -L --plain-http -A だけです (${a})`);
    else if (pathArg === null) pathArg = a; else throw new HttpError(400, 'bad_path', 'パスは 1 つだけです');
  }
  pathArg = pathArg || '/';
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*$/.test(pathArg)) throw new HttpError(400, 'bad_path', 'web の調査はパス (/ で始まる) だけ指定できます');
  if (plain && Number(t.port) !== 443) throw new HttpError(400, 'bad_flag', 'http:// で見るのは、https が 443 の対象だけです');
  const url = plain ? `http://${t.host}${pathArg}` : `https://${t.host}:${t.port}${pathArg}`;
  // -sS: 進み具合の表示 (毎回変わる) を出さず、エラーだけ出す
  return `exec curl${head ? ' -I' : ''}${verbose ? ' -v' : ''}${follow ? ' -L --max-redirs 5' : ''} -sS --max-time 20 --max-filesize 2000000 -A ${sq(ua)} ${sq(url)}`;
}
// ---- 対話で調べる: 利用者が持ってきた公開のアドレスを 1 回だけ読む (社内・自分自身の住所は読まない) ----
export function isPrivateIp(ip) {
  const v = String(ip || '').toLowerCase().replace(/^\[|\]$/g, '');
  const m = v.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) { const a = Number(m[1]), b = Number(m[2]); return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224; }
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v.startsWith('64:ff9b:');
}
export async function checkPublicUrl(url, resolve = (h) => lookup(h, { all: true })) {
  let u; try { u = new URL(String(url || '').trim()); } catch { throw new HttpError(400, 'bad_url', 'アドレスの形が違います (https://… の形で)'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new HttpError(400, 'bad_url', '読めるのは http(s) のアドレスだけです (利用者名やパスワード入りは不可)');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host === 'localhost' || /\.(localhost|local|internal|lan|home|arpa|corp|intranet)$/.test(host)) throw new HttpError(400, 'private_host', '社内や自分自身の住所は読みません');
  let addrs; if (net.isIP(host)) addrs = [host]; else { try { addrs = (await resolve(host)).map(x => x.address); } catch { throw new HttpError(400, 'bad_host', `${host} の住所が引けません`); } }
  if (!addrs.length || addrs.some(isPrivateIp)) throw new HttpError(400, 'private_host', '社内や自分自身の住所 (またはそこへ向く名前) は読みません');
  return { host, url: u.toString(), addrs };
}
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', hellip: '…', mdash: '—', ndash: '–', laquo: '«', raquo: '»' };
const decodeEntities = (s) => String(s).replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d))).replace(/&([a-z]+);/gi, (m, n) => ENT[n.toLowerCase()] ?? m);
// HTML から読む文章だけを取り出す (script/style は捨て、段落で改行)
export function htmlToText(html) {
  const s = String(html || '');
  const title = decodeEntities((s.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i)?.[1] || '')).replace(/\s+/g, ' ').trim();
  let t = s.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<svg[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<(?:br|hr)\b[^>]*>|<\/(?:p|div|h[1-6]|li|tr|table|section|article|header|footer|blockquote|pre|dd|dt|figcaption|nav|aside|main)\b[^>]*>/gi, '\n').replace(/<[^>]+>/g, ' ');
  t = decodeEntities(t).replace(/[ \t　\r]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  return { title, text: t };
}
// シェル用の引用 (単一引用符)。ssh は引数の引用を保たず、空白でつないだ 1 本の文字列を対象の sh に渡す。
// そのため「対象の sh 向けに引用した 1 本の文字列」を作り、それをもう一度コンテナの sh 向けに引用する (二重の引用)。
// これを怠ると $3 や * が対象側で展開される (2026-10-08 に awk '$3==0{print}' が壊れていた)
export const shq = (a) => `'${String(a).replace(/'/g, "'\\''")}'`;
export const remoteCommand = (argv) => argv.map(shq).join(' ');

// 出力の伏せ字: 秘密に見える値・KEY=値 / key: 値 (鍵名が秘密)・秘密鍵のブロック
const SECRET_LINE = /^(\s*[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)[A-Za-z0-9_.-]*\s*[:=]\s*)(.+)$/i;
export function redactText(s) {
  const out = []; let inKey = false;
  for (const line of String(s).split('\n')) {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(line)) inKey = true;
    if (inKey) { out.push('[REDACTED PRIVATE KEY]'); if (/-----END [A-Z ]*PRIVATE KEY-----/.test(line)) inKey = false; continue; }
    out.push(redact(line.replace(SECRET_LINE, (_, k) => k + '[REDACTED]')));
  }
  return out.join('\n');
}

export class Probe {
  constructor(cfg, ports) { this.cfg = cfg; this.ports = ports; this.nas = ports.nas; this.akigrid = ports.akigrid; this.netops = ports.netops; this.image = ports.brand.image; this._image = null; }
  db() { return this.ports.db(); }
  imageExists() { return this._dk(['image', 'inspect', this.image]).status === 0; }

  // ---- 対象の台帳 ----
  // enrolled = 1 行の登録 (鍵は箱が作った)。borrowed = 人が入れた資格情報 (社外から預かった一時的な権限など) → 「預かった権限を返した」はこれにだけ意味がある
  rowOut(r) { if (!r) return null; const { credential_id, host_keys, enroll_token_hash, ...rest } = r; const v = J.parse(r.verify, null); return { ...rest, has_credential: !!credential_id, credential_expires_at: r.credential_expires_at || null, host_keys: J.parse(host_keys, []).length, excluded: !!r.excluded, verify: v ? { root_read: !!v.root_read } : null, root_read: !!v?.root_read, state: r.state || 'ready', pending: (r.state || 'ready') === 'pending', attested: !!r.attested_by, enrolled: !!v?.public_key, borrowed: !!credential_id && !v?.public_key }; }
  listTargets(actor) { this.ports.requireRole(actor, 'operator'); return this.db().prepare('SELECT * FROM probe_targets ORDER BY created_at').all().map(r => this.rowOut(r)); }
  getTarget(tid) { return this.db().prepare('SELECT * FROM probe_targets WHERE id=?').get(tid) || null; }

  // ssh の公開鍵を拾う (TOFU)。つなぐ前に 1 回。あとで変わっていたら拒否する (なりすまし・経路のすり替え)
  scanHostKeys(host, port = 22) {
    const r = spawnSync('ssh-keyscan', ['-T', '5', '-p', String(port), host], { encoding: 'utf8', timeout: 15000 });
    return (r.stdout || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  }

  async addTarget(actor, { name, kind, host, port, username, secret, secret_kind = 'password', verify = null, notes = '', credential_expires_at = null } = {}) {
    this.ports.requireRole(actor, 'admin');
    if (!KINDS.includes(kind)) throw new HttpError(400, 'bad_kind', `kind は ${KINDS.join(' / ')}`);
    if (!HOST_RE.test(String(host || ''))) throw new HttpError(400, 'bad_host', 'host は名前か IP アドレス');
    const p = port ? Number(port) : (kind === 'web' ? 443 : 22);
    if (!(p >= 1 && p <= 65535)) throw new HttpError(400, 'bad_port', 'port が不正です');
    // 公開 HP は、自社 (または調査を頼まれた) のサイトだと申告してもらう (他人のサイトを勝手に調べない。誰が申告したかを残す)
    const attested = kind === 'web' ? !!arguments[1]?.attested : true;
    if (kind === 'web' && !attested) throw new HttpError(400, 'attest_required', 'この公開 HP が自社のもの (または調査を頼まれたもの) であることを確かめてから、申告にチェックしてください');
    let credential_id = null;
    if (secret) { const c = this.ports.vault.store(actor, { provider: `probe:${kind}`, name: `まもり帳 ${name || host}`, secret: secret_kind === 'key' ? secret : `${secret_kind}:${secret}`, scope: 'probe', expires_at: credential_expires_at }); credential_id = c.id; }
    let host_keys = [];
    if (kind === 'ssh' || kind === 'network') { host_keys = this.scanHostKeys(host, p); if (!host_keys.length) throw new HttpError(502, 'no_host_key', `${host}:${p} の鍵を取れません (届かない・SSH が無い・ポートが違う)。この対象は追加しませんでした`); }
    const tid = id('ptgt'); const t = nowIso();
    this.db().prepare(`INSERT INTO probe_targets(id,name,kind,host,port,username,credential_id,credential_expires_at,host_keys,verify,excluded,notes,created_by,created_at,updated_at,state,attested_by)
      VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,'ready',?)`).run(tid, String(name || host).slice(0, 80), kind, host, p, username || null, credential_id, credential_expires_at, J.str(host_keys), J.str(verify), String(notes).slice(0, 500), actor.id, t, t, kind === 'web' ? actor.id : null);
    this.ports.audit({ actor, action: 'probe.target_add', target: tid, detail: { kind, host, port: p, username, host_keys: host_keys.length, credential: !!credential_id, credential_expires_at } });
    return this.rowOut(this.getTarget(tid));
  }
  updateTarget(actor, tid, patch = {}) {
    this.ports.requireRole(actor, 'admin'); const t = this.getTarget(tid); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    const set = []; const args = [];
    if (patch.excluded !== undefined) { set.push('excluded=?'); args.push(patch.excluded ? 1 : 0); }
    if (patch.notes !== undefined) { set.push('notes=?'); args.push(String(patch.notes).slice(0, 500)); }
    if (patch.rescan_host_keys && (t.kind === 'ssh' || t.kind === 'network')) { const hk = this.scanHostKeys(t.host, t.port); if (hk.length) { set.push('host_keys=?'); args.push(J.str(hk)); } }
    if (set.length) { set.push('updated_at=?'); args.push(nowIso()); this.db().prepare(`UPDATE probe_targets SET ${set.join(',')} WHERE id=?`).run(...args, tid); }
    this.ports.audit({ actor, action: 'probe.target_update', target: tid, detail: redact(patch) });
    return this.rowOut(this.getTarget(tid));
  }
  // 社外の一時的な権限: 調査が終わったら、先方に取り消しを頼み、取り消した日を記録する
  markRevoked(actor, tid, { requested = false, revoked = false } = {}) {
    this.ports.requireRole(actor, 'admin'); const t = this.getTarget(tid); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    const now = nowIso();
    if (requested) this.db().prepare('UPDATE probe_targets SET revoke_requested_at=? WHERE id=?').run(now, tid);
    if (revoked) { this.db().prepare('UPDATE probe_targets SET revoked_at=?, excluded=1 WHERE id=?').run(now, tid); if (t.credential_id) { try { this.ports.vault.delete(actor, t.credential_id); } catch { /* 無ければよい */ } this.db().prepare('UPDATE probe_targets SET credential_id=NULL WHERE id=?').run(tid); } }
    this.ports.audit({ actor, action: 'probe.target_revoke', target: tid, detail: { requested, revoked } });
    return this.rowOut(this.getTarget(tid));
  }
  removeTarget(actor, tid, { purge_runs = false } = {}) {
    this.ports.requireRole(actor, 'admin'); const t = this.getTarget(tid); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    if (t.credential_id) { try { this.ports.vault.delete(actor, t.credential_id); } catch { /* ignore */ } }
    this.db().prepare('DELETE FROM probe_targets WHERE id=?').run(tid);
    if (purge_runs) this.db().prepare('DELETE FROM probe_runs WHERE target_id=?').run(tid);
    this.ports.audit({ actor, action: 'probe.target_remove', target: tid, detail: { purge_runs } });
    return { ok: true };
  }

  // ---- 登録 (enroll): 箱が鍵を作り、対象の機械で 1 行を実行すると、機械の側から言箱へ「つながった」と知らせてくる ----
  //   利用者が打つのは名前だけ。IP アドレスは知らせの接続元から分かり、公開鍵は秘密鍵ごと箱の金庫に入る (画面には出ない)。
  //   対象には読み取り専用のユーザー mamoricho (sudo なし・ポート転送なし・端末なし) ができる
  enrollStart(actor, { name = '', kind = 'ssh', notes = '', root_read = true } = {}) {
    this.ports.requireRole(actor, 'admin'); if (!['ssh', 'network'].includes(kind)) throw new HttpError(400, 'bad_kind', '1 行での登録は SSH の対象 (サーバー・PC・ネットワーク機器) だけです');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'enroll-')); let priv, pub;
    try { const r = spawnSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-q', '-f', path.join(dir, 'k'), '-C', `mamoricho@${this.ports.brand.os_en.toLowerCase()}`], { encoding: 'utf8' }); if (r.status !== 0) throw new HttpError(500, 'keygen', '鍵を作れませんでした'); priv = fs.readFileSync(path.join(dir, 'k'), 'utf8'); pub = fs.readFileSync(path.join(dir, 'k.pub'), 'utf8').trim(); }
    finally { fs.rmSync(dir, { recursive: true, force: true }); }
    const c = this.ports.vault.store(actor, { provider: `probe:${kind}`, name: `まもり帳 ${name || '(登録中)'}`, secret: priv, scope: 'probe' });
    const token = randomToken(24); const tid = id('ptgt'); const t = nowIso(); const exp = new Date(Date.now() + 24 * 3600e3).toISOString();
    this.db().prepare(`INSERT INTO probe_targets(id,name,kind,host,port,username,credential_id,host_keys,verify,excluded,notes,created_by,created_at,updated_at,state,enroll_token_hash,enroll_expires_at)
      VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?,?,'pending',?,?)`).run(tid, String(name || '登録中の機械').slice(0, 80), kind, '', 22, 'mamoricho', c.id, J.str([]), J.str({ public_key: pub, root_read: !!root_read }), String(notes).slice(0, 500), actor.id, t, t, sha256(token), exp);
    this.ports.audit({ actor, action: 'probe.enroll_start', target: tid, detail: { kind, name, root_read: !!root_read } });
    return { target_id: tid, token, expires_at: exp, public_key: pub };
  }
  // 期限切れ・紛失のとき、1 行を出し直す (鍵はそのまま、token だけ新しく)
  // 1 行を出し直す。登録中の対象のほか、登録済みの対象でも (同じ機械で実行すると、ユーザーと鍵はそのままに root の読むだけの手順 = sudoers が今の版に更新される)
  enrollRenew(actor, tid) {
    this.ports.requireRole(actor, 'admin'); const t = this.getTarget(tid); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    const v = J.parse(t.verify, null); const reenroll = t.state === 'ready';
    if (t.state !== 'pending' && !(reenroll && v?.public_key)) throw new HttpError(400, 'not_enrollable', 'この対象は 1 行での登録ではないので、やり直しはできません (鍵を手で登録した対象)');
    const token = randomToken(24); const exp = new Date(Date.now() + 24 * 3600e3).toISOString(); const now = nowIso();
    this.db().prepare('UPDATE probe_targets SET enroll_token_hash=?, enroll_expires_at=?, updated_at=? WHERE id=?').run(sha256(token), exp, now, tid);
    return { target_id: tid, token, expires_at: exp, reenroll, wait_key: now };
  }
  _pendingByToken(token) {
    const t = this.db().prepare("SELECT * FROM probe_targets WHERE enroll_token_hash=? AND state IN ('pending','ready')").get(sha256(String(token || '')));
    if (!t) throw new HttpError(404, 'not_found', 'この登録は見つかりません (もう使われたか、消されました)');
    if (t.enroll_expires_at < nowIso()) throw new HttpError(410, 'expired', 'この登録の期限 (24 時間) が切れました。まもり帳で 1 行を出し直してください');
    return t;
  }
  // 対象の機械で実行する 1 行の中身 (sh)。root で: 読み取り専用のユーザーを作り、箱の公開鍵を制限つきで置き、箱へ知らせる
  enrollScript(token, baseUrl) {
    const B = this.ports.brand; const t = this._pendingByToken(token); const v = J.parse(t.verify, {}); const pub = v.public_key || '';
    const done = `${baseUrl}/api/v1/probe/enroll/${token}/done`;
    // root の読み取り (登録時に許したときだけ): 決まったコマンドだけを sudoers に完全一致で書く。visudo で確かめ、だめなら消す
    const sudoBlock = v.root_read ? `if command -v sudo >/dev/null 2>&1; then
  printf '%s\n' ${sudoersLines('mamoricho', `${B.os} ${B.product}`).map(l => `'${l.replace(/'/g, "'\\''")}'`).join(' ')} > /etc/sudoers.d/mamoricho.tmp
  chmod 440 /etc/sudoers.d/mamoricho.tmp
  if command -v visudo >/dev/null 2>&1 && ! visudo -cf /etc/sudoers.d/mamoricho.tmp >/dev/null 2>&1; then rm -f /etc/sudoers.d/mamoricho.tmp; echo "注意: sudoers を書けませんでした (root でしか読めないものは読めません)"; else mv -f /etc/sudoers.d/mamoricho.tmp /etc/sudoers.d/mamoricho; fi
else echo "注意: sudo が無いので、root でしか読めないものは読めません"; fi
` : '';
    return `#!/bin/sh
# ${B.os} (${B.os_en}) ${B.product}: この機械を「読むだけ」で調べられるようにする。root で実行してください。
#   作るもの: ユーザー mamoricho (ログインシェル /bin/sh)、その authorized_keys に${B.os}の公開鍵 (ポート転送・端末なし)。
#   ${v.root_read ? 'root の読み取り: /etc/sudoers.d/mamoricho に、読むだけの決まったコマンド (完全一致) だけを書く。任意のコマンドは動かない' : 'sudo は付けない'}
#   消すとき: userdel -r mamoricho; rm -f /etc/sudoers.d/mamoricho
set -e
U=mamoricho
KEY='${pub.replace(/'/g, '')}'
if ! id "$U" >/dev/null 2>&1; then useradd -m -s /bin/sh -c "${B.os_en} Mamoricho (read-only)" "$U" 2>/dev/null || adduser -D -s /bin/sh "$U"; fi
H=$(getent passwd "$U" | cut -d: -f6); mkdir -p "$H/.ssh"; chmod 700 "$H/.ssh"
grep -qF "$KEY" "$H/.ssh/authorized_keys" 2>/dev/null || printf '%s %s\\n' 'no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty' "$KEY" >> "$H/.ssh/authorized_keys"
chmod 600 "$H/.ssh/authorized_keys"; chown -R "$U" "$H/.ssh"
# パスワードは無し (鍵だけ)。"!" のままだと PAM の無い OS (Alpine など) で鍵のログインも拒まれるので "*" にする
sed -i "s|^\\($U\\):!*:|\\1:*:|" /etc/shadow 2>/dev/null || true
for g in adm systemd-journal docker; do getent group "$g" >/dev/null 2>&1 && usermod -aG "$g" "$U" 2>/dev/null || true; done
${sudoBlock}command -v sshd >/dev/null 2>&1 || echo "注意: SSH サーバー (openssh-server) が入っていないようです。入れて起動してください"
B="{\\"hostname\\":\\"$(hostname)\\"}"
if command -v curl >/dev/null 2>&1; then
  R=$(curl -sS -m 15 -X POST "${done}" -H 'content-type: application/json' -d "$B" -w '\n%{http_code}' 2>&1); C=$(printf '%s' "$R" | tail -n 1); BODY=$(printf '%s' "$R" | sed '$d')
  case "$C" in 2*) printf '%s\n' "$BODY";; *) MSG=$(printf '%s' "$BODY" | sed -n 's/.*"message":"\\([^"]*\\)".*/\\1/p'); echo "${B.os}に受け付けられませんでした (HTTP \${C:-なし}): \${MSG:-$BODY}"; [ -n "$MSG" ] || echo "(${baseUrl} に届かないときは、${B.product}で IP アドレスを入れて登録してください)"; exit 2;; esac
elif command -v wget >/dev/null 2>&1; then wget -qO- --timeout=15 --post-data="$B" --header='content-type: application/json' "${done}" || { echo "${B.os}に受け付けられませんでした (${baseUrl} に届かないか、拒まれました)。${B.product}の画面で理由を確かめてください"; exit 2; }
else echo "curl も wget もありません。入れてからやり直してください"; exit 2; fi
echo; echo "${B.os}につながりました。${B.product}の画面に戻ってください。"
`;
  }
  // 対象の機械からの知らせ。接続元の IP がその機械の住所。公開鍵を拾い、つながったことにする (token は 1 回きり)
  enrollDone(token, { hostname = '' } = {}, remoteIp) {
    const t = this._pendingByToken(token); const host = String(remoteIp || '').replace('::ffff:', '');
    if (!HOST_RE.test(host) || host === '127.0.0.1' || host === '::1') throw new HttpError(400, 'bad_host', '接続元の住所が分かりません');
    let keys = []; for (let i = 0; i < 3 && !keys.length; i++) { keys = this.scanHostKeys(host, t.port || 22); if (!keys.length) spawnSync('sleep', ['2']); }
    if (!keys.length) throw new HttpError(502, 'no_host_key', `${host}:${t.port || 22} の SSH に届きません (SSH サーバーが動いているか、ポートが空いているか)`);
    const hn = String(hostname || '').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 64);
    if (t.state === 'ready') {
      // 登録のやり直し: 同じ機械かを SSH の公開鍵で確かめる (違う機械からの実行は拒む。住所が変わっただけなら更新する)
      // ssh-keyscan の行は「住所 種類 鍵」。住所は変わりうるので、種類と鍵だけで比べる
      const kp = (k) => String(k).trim().split(/\s+/).slice(-2).join(' '); const prev = J.parse(t.host_keys, []).map(kp);
      if (prev.length && !keys.some(k => prev.includes(kp(k)))) throw new HttpError(409, 'different_host', '登録済みの機械と SSH の公開鍵が違います (別の機械で実行されました)。新しい機械は「対象を追加」で登録してください');
      this.db().prepare("UPDATE probe_targets SET host=?, host_keys=?, enroll_token_hash=NULL, enroll_expires_at=NULL, enrolled_hostname=?, updated_at=? WHERE id=?").run(host, J.str(keys), hn || t.enrolled_hostname || null, nowIso(), t.id);
      this.ports.audit({ actor: null, action: 'probe.reenroll_done', target: t.id, ip: host, detail: { hostname: hn, host_keys: keys.length, host_changed: host !== t.host } });
      return { ok: true, target_id: t.id, host, name: t.name, reenroll: true };
    }
    const name = t.name === '登録中の機械' && hn ? hn : t.name;
    this.db().prepare("UPDATE probe_targets SET host=?, host_keys=?, state='ready', enroll_token_hash=NULL, enroll_expires_at=NULL, enrolled_hostname=?, name=?, updated_at=? WHERE id=?").run(host, J.str(keys), hn || null, name, nowIso(), t.id);
    this.ports.audit({ actor: null, action: 'probe.enroll_done', target: t.id, ip: host, detail: { hostname: hn, host_keys: keys.length } });
    return { ok: true, target_id: t.id, host, name };
  }
  // 業者や担当者に渡す文面 (何をする 1 行か、消し方まで)
  vendorMessage({ name, scriptUrl }) {
    const B = this.ports.brand; return `お世話になります。情報セキュリティの点検のため、サーバー「${name}」で次の 1 行を root で実行していただけますか。

  curl -fsSL '${scriptUrl}' | sh

この 1 行は、読み取り専用のユーザー mamoricho (ポート転送なし) を作り、当社の点検用サーバー (${B.os}) の公開鍵を置きます。root でしか読めないもの (root の鍵・sudo の設定・認証ログ) は、あらかじめ決めた読むだけのコマンドだけを sudoers に完全一致で書いて読めるようにします。設定の変更や削除はしません。
実行する前に中身を確認したい場合は、同じ URL をブラウザで開くと内容を読めます。
点検が終わったら、userdel -r mamoricho と rm -f /etc/sudoers.d/mamoricho で消せます。期限は 24 時間です。よろしくお願いいたします。`;
  }

  // ---- 発見 (discover): 同じネットワークの機械を見つけて、選べるようにする (NetOps の台帳 + 近くの機械の表 + ポートの応答) ----
  async discover(actor) {
    this.ports.requireRole(actor, 'operator'); const seen = new Map(); const mine = new Set(Object.values(os.networkInterfaces()).flat().map(i => i?.address).filter(Boolean));
    const registered = new Set(this.db().prepare('SELECT host FROM probe_targets').all().map(r => r.host));
    const priv = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
    const add = (ip, extra) => { if (!ip || mine.has(ip) || !priv(ip)) return; const cur = seen.get(ip) || { host: ip, sources: [] }; Object.assign(cur, extra, { sources: [...new Set([...cur.sources, extra.source])] }); seen.set(ip, cur); };
    try { for (const d of this.netops?.listDevices?.() || []) if (d.mgmt_ip) add(d.mgmt_ip, { source: 'netops', name: d.name, vendor: d.vendor || d.meta?.vendor || null, kind_hint: 'network' }); } catch { /* 無ければよい */ }
    const r = spawnSync('ip', ['-4', 'neigh', 'show'], { encoding: 'utf8', timeout: 5000 });
    for (const l of (r.stdout || '').split('\n')) { const m = /^(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr \S+ (\w+)/.exec(l); if (m && !['FAILED', 'INCOMPLETE'].includes(m[3])) add(m[1], { source: 'neigh', dev: m[2] }); }
    const list = [...seen.values()].slice(0, 64);
    const probePort = (host, port) => new Promise(res => { const s = net.connect({ host, port, timeout: 600 }); s.once('connect', () => { s.destroy(); res(true); }); s.once('timeout', () => { s.destroy(); res(false); }); s.once('error', () => res(false)); });
    await Promise.all(list.map(async (c) => {
      const [ssh, https, http] = await Promise.all([probePort(c.host, 22), probePort(c.host, 443), probePort(c.host, 80)]);
      c.ports = { ssh, https, http }; c.kind_hint = c.kind_hint || (ssh ? 'ssh' : https || http ? 'web' : null);
      if (!c.name) { const g = spawnSync('getent', ['hosts', c.host], { encoding: 'utf8', timeout: 2000 }); const nm = (g.stdout || '').trim().split(/\s+/)[1]; if (nm) c.name = nm; }
      c.registered = registered.has(c.host);
    }));
    return list.sort((a, b) => (b.ports?.ssh - a.ports?.ssh) || a.host.localeCompare(b.host, undefined, { numeric: true }));
  }
  // つながるか確かめる (読むだけ 1 つ)。結果はふつうの言葉で
  async testTarget(actor, tid) {
    this.ports.requireRole(actor, 'operator'); const t = this.getTarget(tid); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    const argv = t.kind === 'web' ? ['curl', '-I', '/'] : t.kind === 'network' ? ['show', 'version'] : ['uname', '-a'];
    try { const r = await this.run(actor, { target_id: tid, argv, explanation: 'つながるかの確認' }); const ok = r.exit_code === 0; return { ok, message: ok ? 'つながりました。読み取りができます' : `つながりましたが、確認のコマンドが失敗しました (終了 ${r.exit_code})`, output: r.output.slice(0, 400) }; }
    catch (e) { return { ok: false, message: e.message, output: '' }; }
  }

  // ---- コマンドの判定 (実行しない。画面で見せる・承認の材料) ----
  async classifyPreview(actor, { target_id, argv, explanation = '' } = {}) {
    this.ports.requireRole(actor, 'operator'); const t = this.getTarget(target_id); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    const cls = classifyCommand(argv, { target_kind: t.kind });
    const ai = this.akigrid ? await llmJudge(argv, { akigrid: this.akigrid, head: this.cfg?.probe?.decision_head || null, explanation }) : { probabilities: null, via: 'none' };
    return { classification: cls, ai, target: { id: t.id, name: t.name, kind: t.kind, host: t.host } };
  }

  // ---- 1 回の調査 ----
  // read: 実行する。change: Owner の承認と理由が要る (approval を作って止める)。forbidden: 実行しない
  async run(actor, { target_id, argv, template_id = null, explanation = '', reason = '', approval_id = null } = {}) {
    this.ports.requireRole(actor, 'operator'); const t = this.getTarget(target_id); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    if (t.revoked_at) throw new HttpError(409, 'revoked', 'この対象は権限を取り消し済みです');
    if (t.excluded) throw new HttpError(409, 'excluded', 'この対象は調査から外されています');
    if ((t.state || 'ready') !== 'ready') throw new HttpError(409, 'pending', 'この対象はまだつながっていません (対象の機械で 1 行を実行してください)');
    if (!Array.isArray(argv) || !argv.length) throw new HttpError(400, 'bad_argv', 'argv が要ります');
    const cls = classifyCommand(argv, { target_kind: t.kind });
    if (cls.class === 'forbidden') { this.ports.audit({ actor, action: 'probe.refused', target: target_id, detail: { argv: redact(argv), reasons: cls.reasons } }); throw new HttpError(403, 'forbidden_command', `このコマンドは実行できません: ${cls.reasons.join(' / ')}`); }
    if (cls.class === 'change') {
      if (!approval_id) {
        if (!String(reason || '').trim()) throw new HttpError(400, 'reason_required', '状態を変えるおそれのあるコマンドには理由が要ります');
        const ap = this.ports.approvals.create({ action: 'probe:change', summary: `まもり帳: ${t.name} で「${argv.join(' ').slice(0, 120)}」(状態を変えるおそれ)`, detail: { target_id, argv: redact(argv), reasons: cls.reasons, explanation, reason }, requested_by: actor, ttl_min: 120 });
        const run = this._record(t, { argv, template_id, explanation, reason, cls, state: 'awaiting_approval', approval_id: ap.id, requested_by: actor.id });
        throw new HttpError(202, 'approval_required', 'このコマンドは状態を変えるおそれがあります。Owner の承認が要ります', { approval_id: ap.id, run_id: run.id });
      }
      const ap = this.ports.approvals.get(approval_id);
      if (!ap || ap.state !== 'approved' || ap.action !== 'probe:change') throw new HttpError(403, 'not_approved', '承認されていません');
    }
    // 実行 (read、または承認済みの change)
    const run = this._record(t, { argv, template_id, explanation, reason, cls, state: 'running', approval_id, requested_by: actor.id, approved_by: approval_id ? this.ports.approvals.get(approval_id)?.approver_id : null });
    this.db().prepare("UPDATE probe_runs SET started_at=? WHERE id=?").run(nowIso(), run.id);
    this.ports.audit({ actor, action: 'probe.run', target: target_id, detail: { run_id: run.id, class: cls.class, argv: redact(argv), approval_id } });
    try {
      const { exitCode, output } = await this._exec(t, argv);
      const red = redactText(output).slice(0, OUT_MAX);
      let outPath = null; const buf = Buffer.from(red, 'utf8');
      // 保存先は、この組織の共有ワークスペース (まもり帳の記録はみんなのもの)。無ければ保存は飛ばす (hash は記録に残る)
      const ws = this.ports.sharedWorkspace(actor);
      if (this.nas && ws) { try { const a = await this.nas.ingest({ ...actor, kind: 'user' }, { workspace_id: ws, name: `${t.name}-${run.id}.txt`, buffer: buf, folder: `まもり帳/${t.name}`, tags: ['まもり帳', t.kind], origin: `probe:${run.id}` }); outPath = a?.id || null; } catch { /* 保存できなくても記録は残す */ } }
      this.db().prepare("UPDATE probe_runs SET state='done', finished_at=?, exit_code=?, output_path=?, output_sha256=?, output_bytes=?, output=? WHERE id=?").run(nowIso(), exitCode, outPath, sha256(buf), buf.length, red.slice(0, OUTPUT_KEEP), run.id);
      return { run_id: run.id, class: cls.class, exit_code: exitCode, output: red, output_sha256: sha256(buf), asset_id: outPath };
    } catch (e) {
      this.db().prepare("UPDATE probe_runs SET state='error', finished_at=?, error=? WHERE id=?").run(nowIso(), String(e.message || e).slice(0, 300), run.id);
      throw e instanceof HttpError ? e : new HttpError(502, 'probe_failed', `調査を実行できませんでした: ${String(e.message || e).slice(0, 200)}`);
    }
  }
  _record(t, { argv, template_id, explanation, reason, cls, state, approval_id = null, requested_by, approved_by = null }) {
    const rid = id('prun');
    this.db().prepare(`INSERT INTO probe_runs(id,target_id,template_id,argv,explanation,reason,class,classification,ai,approval_id,state,requested_by,approved_by,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(rid, t.id, template_id, J.str(argv), String(explanation).slice(0, 1000), String(reason).slice(0, 500), cls.class, J.str(cls), null, approval_id, state, requested_by, approved_by, nowIso());
    return { id: rid };
  }
  listRuns(actor, { target_id = null, limit = 50 } = {}) {
    this.ports.requireRole(actor, 'operator');
    const rows = target_id ? this.db().prepare('SELECT * FROM probe_runs WHERE target_id=? ORDER BY created_at DESC LIMIT ?').all(target_id, limit) : this.db().prepare('SELECT * FROM probe_runs ORDER BY created_at DESC LIMIT ?').all(limit);
    return rows.map(({ output, ...r }) => ({ ...r, argv: J.parse(r.argv, []), classification: J.parse(r.classification, null), has_output: !!output }));
  }
  // 同じ対象・同じ型・同じコマンドの、1 つ前の成功した出力 (差分の基準)。無ければ null
  previousOutput(target_id, template_id, argv, exceptRunId = null) {
    const r = this.db().prepare("SELECT id, output, created_at FROM probe_runs WHERE target_id=? AND template_id=? AND argv=? AND state='done' AND id<>? ORDER BY created_at DESC LIMIT 1").get(target_id, template_id, J.str(argv), exceptRunId || '');
    return r ? { run_id: r.id, output: r.output || '', at: r.created_at } : null;
  }
  runOutput(actor, runId) { this.ports.requireRole(actor, 'operator'); const r = this.db().prepare('SELECT id, target_id, argv, state, created_at, output FROM probe_runs WHERE id=?').get(runId); if (!r) throw new HttpError(404, 'not_found', '見つかりません'); return { ...r, argv: J.parse(r.argv, []) }; }

  // ---- 実行器 (使い捨てのコンテナ)。どの機械につなぐかは OS が台帳から組み立てる (argv は対象の機械で動かす中身) ----
  async ensureImage() {
    if (this._image) return this.image;
    if (this._dk(['image', 'inspect', this.image]).status === 0) { this._image = true; return this.image; }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-img-'));
    fs.writeFileSync(path.join(dir, 'Dockerfile'), 'FROM alpine:3.20\nRUN apk add --no-cache openssh-client curl ca-certificates bind-tools >/dev/null && adduser -D -u 10002 probe\nUSER probe\nENTRYPOINT ["/bin/sh","-c"]\n');
    const r = this._dk(['build', '-q', '-t', this.image, dir]); fs.rmSync(dir, { recursive: true, force: true });
    if (r.status !== 0) throw new HttpError(502, 'image_build', `調査用のコンテナを作れませんでした: ${String(r.stderr || '').slice(0, 200)}`);
    this._image = true; return this.image;
  }
  _dk(args, opts = {}) { let r = spawnSync('docker', args, { encoding: 'utf8', timeout: 180000, ...opts }); if (r.error && /EACCES|permission/i.test(String(r.error.message)) || /permission denied/i.test(String(r.stderr || ''))) r = spawnSync('sg', ['docker', '-c', ['docker', ...args].map(a => `'${String(a).replace(/'/g, "'\\''")}'`).join(' ')], { encoding: 'utf8', timeout: 180000, ...opts }); return r; }

  // 対象ごとに、コンテナで動かすスクリプトと、持ち込む秘密を組み立てる。host/port/user は OS が台帳から入れる (ほかの機械へはつなげない)
  // 使い捨てのコンテナで script (sh -c) を 1 回動かす。標準出力とエラー出力は分けて集め、エラー出力は末尾に見出しつき
  async _runScript(script, env = {}, timeoutMs = PROBE_TIMEOUT_MS) {
    await this.ensureImage();
    const envArgs = Object.keys(env).flatMap(k => ['-e', k]);
    return new Promise((resolve) => {
      const ch = spawn('docker', [...CONTAINER_RUN, ...envArgs, this.image, script], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
      const outs = [], errs = []; let n = 0; ch.stdout.on('data', (d) => { n += d.length; if (n <= OUT_MAX) outs.push(d); }); ch.stderr.on('data', (d) => { n += d.length; if (n <= OUT_MAX) errs.push(d); });
      const timer = setTimeout(() => { try { ch.kill('SIGKILL'); } catch { /* ignore */ } }, timeoutMs);
      ch.on('close', (code) => { clearTimeout(timer); const out = Buffer.concat(outs).toString('utf8'), err = Buffer.concat(errs).toString('utf8'); resolve({ exitCode: code, output: (out + (err ? `${out && !out.endsWith('\n') ? '\n' : ''}${STDERR_MARK}\n${err}` : '')) || NO_OUTPUT }); });
      ch.on('error', (e) => { clearTimeout(timer); resolve({ exitCode: -1, output: `コンテナを起動できません: ${e.message}` }); });
    });
  }
  // 利用者が持ってきた公開のアドレスを、使い捨てのコンテナの curl で 1 回だけ読む。転送は 3 回まで、各回 checkPublicUrl で社内でないことを確かめる
  async fetchPublic(actor, url, { maxHops = 3 } = {}) {
    this.ports.requireRole(actor, 'operator');
    let cur = String(url || '').trim(); const hops = [];
    for (let i = 0; i <= maxHops; i++) {
      const { host } = await checkPublicUrl(cur);
      const script = `exec curl -sS --max-time 20 --max-filesize 2000000 -A ${sq(this.ports.brand.ua + ' (news reader)')} -w '\\n<<mamoricho-meta>> %{http_code} %{content_type} %{redirect_url}' ${sq(cur)}`;
      const r = await this._runScript(script, {}, 30000);
      const out = r.output.split(STDERR_MARK)[0]; const mi = out.lastIndexOf('<<mamoricho-meta>>');
      if (mi < 0) throw new HttpError(502, 'fetch_failed', `読めませんでした: ${(r.output.split(STDERR_MARK)[1] || r.output).trim().slice(0, 200)}`);
      const meta = out.slice(mi + '<<mamoricho-meta>>'.length).trim().split(/\s+/); const status = Number(meta[0]) || 0; const ctype = meta[1] || ''; const redir = meta[2] || '';
      const body = out.slice(0, mi);
      this.ports.audit({ actor, action: 'probe.fetch_public', detail: { url: cur.slice(0, 300), host, status } });
      if ([301, 302, 303, 307, 308].includes(status) && redir) { hops.push(cur); cur = new URL(redir, cur).toString(); continue; }
      if (!status || status >= 400) throw new HttpError(502, 'fetch_failed', `読めませんでした (HTTP ${status || '応答なし'})`);
      const isHtml = /html|xml/i.test(ctype) || /^\s*</.test(body);
      const { title, text } = isHtml ? htmlToText(body) : { title: null, text: body };
      return { url: String(url || '').trim(), final_url: cur, hops, status, content_type: ctype, title: title || null, text: String(text || '').slice(0, 60000) };
    }
    throw new HttpError(502, 'too_many_redirects', '転送が多すぎます (3 回まで)');
  }
  async _exec(t, argv) {
    await this.ensureImage();
    const run = CONTAINER_RUN;
    let script, env = {};
    if (t.kind === 'ssh' || t.kind === 'network') {
      const kh = J.parse(t.host_keys, []); if (!kh.length) throw new HttpError(409, 'no_host_key', 'この対象は公開鍵が記録されていません (追加し直してください)');
      const remote = remoteCommand(argv); // 対象の機械でそのまま動かす中身 (判定済み)。下で 1 本の文字列として ssh に渡す
      const sshOpts = `-o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/probe/known_hosts -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=10 -o PasswordAuthentication=${t.credential_id ? 'yes' : 'no'} -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey,password -p ${t.port}`;
      let auth = '', secretLine = '';
      if (t.credential_id) {
        const raw = this.ports.vault.use(t.credential_id); const isKey = !raw.startsWith('password:');
        if (isKey) { env.PK = raw; secretLine = 'printf %s "$PK" > /home/probe/key && chmod 600 /home/probe/key; '; auth = '-i /home/probe/key'; }
        else { env.SSHPASS = raw.slice('password:'.length); secretLine = ''; } // sshpass はイメージに無いので、鍵認証を基本にする
      }
      // known_hosts を書き、ssh で対象の機械の中身を動かす。host は台帳の値 (固定)
      const khData = kh.join('\n').replace(/'/g, "'\\''");
      script = `printf '%s\\n' '${khData}' > /home/probe/known_hosts; ${secretLine}exec ssh ${sshOpts} ${auth} ${t.username ? `'${t.username}'@` : ''}'${t.host}' -- ${shq(remote)}`;
    } else if (t.kind === 'web') {
      script = webScript(t, argv, this.ports.brand.ua); // host は台帳のものに固定 (OS が URL を組む)。path・少しの指定・DNS だけ argv から
    } else throw new HttpError(400, 'bad_kind', 'この kind の実行はまだありません');
    const envArgs = Object.keys(env).flatMap(k => ['-e', k]);
    const r = await new Promise((resolve) => {
      const ch = spawn('docker', [...run, ...envArgs, this.image, script], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
      // 標準出力とエラー出力は分けて集める (混ぜると行の途中で割り込み、前回との差分に偽の行が出る)。エラー出力は末尾に見出しつきで
      // 断片 (Buffer) のまま集めて最後に 1 回で文字にする (断片ごとに文字にすると、日本語が断片の境目で化ける)
      const outs = [], errs = []; let n = 0; const grab = (d) => { n += d.length; if (n <= OUT_MAX) outs.push(d); }; const grabErr = (d) => { n += d.length; if (n <= OUT_MAX) errs.push(d); };
      ch.stdout.on('data', grab); ch.stderr.on('data', grabErr);
      const timer = setTimeout(() => { try { ch.kill('SIGKILL'); } catch { /* ignore */ } }, PROBE_TIMEOUT_MS);
      ch.on('close', (code) => { clearTimeout(timer); const out = Buffer.concat(outs).toString('utf8'), err = Buffer.concat(errs).toString('utf8'); const o = out + (err ? `${out && !out.endsWith('\n') ? '\n' : ''}${STDERR_MARK}\n${err}` : ''); resolve({ exitCode: code, output: o || NO_OUTPUT }); });
      ch.on('error', (e) => { clearTimeout(timer); resolve({ exitCode: -1, output: `コンテナを起動できません: ${e.message}` }); });
    });
    return r;
  }
}
