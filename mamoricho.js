// まもり帳 (docs/MAMORICHO_DESIGN.md)。平時の点検 = 聞き取り → 確かめる → 記録 → 宿題 → 定期の見直し。
//   骨格はルール: 点検の項目 (checklist.js) は固定、言箱自身の自己点検は機械的、記録は 1 件ごとに前のハッシュを含めて箱の鍵で署名 (後から書き換えると分かる)。
//   AI は「利用者の答えを状態に翻訳して提案する」役だけ (interview)。状態を決めるのは人。「安全」とは言わせない。
import crypto from 'node:crypto';
import { getDb, J, metaGet } from '../db.js';
import { HttpError, id, nowIso, sha256, redact } from '../util.js';
import { audit } from '../audit.js';
import { requireRole, listUsers } from '../auth.js';
import { ensureLocalPublisherKey } from '../signing.js';
import { notify } from '../notify.js';
import * as mfa from '../mfa.js';
import { timeStatus } from '../timesync.js';
import { ITEMS, CATEGORIES, BASELINE, STATUSES, byId } from './checklist.js';
import { ROOT_STEPS } from '../probe/rootsteps.js';
import { OUTPUT_KEEP, NO_OUTPUT } from '../probe/probe.js';

export const TEMPLATES = [
  // 読むだけの調査の型。OS の版と一緒に配られる (= 署名つき)。各 step は probe の判定 (read) を通ったものだけ使う
  { id: 'linux.basic', kind: ['ssh'], label: '基本 (OS・起動時間・ログイン中)', steps: [['uname', '-a'], ['uptime'], ['who'], ['cat', '/etc/os-release']] },
  { id: 'linux.ports', kind: ['ssh'], label: '待ち受けているポート', steps: [['ss', '-tlnpH'], ['ss', '-ulnH'], ['netstat', '-tln']] },
  { id: 'linux.logins', kind: ['ssh'], label: '最近のログイン', steps: [['last', '-n', '30', '-F'], ['lastlog']] },
  { id: 'linux.users', kind: ['ssh'], label: 'アカウントと管理者', steps: [['getent', 'passwd'], ['getent', 'group', 'sudo'], ['getent', 'group', 'wheel'], ['getent', 'group', 'docker']] },
  { id: 'linux.autostart', kind: ['ssh'], label: '自動で動くもの (タイマー・cron)', steps: [['systemctl', 'list-timers', '--all', '--no-pager'], ['crontab', '-l'], ['ls', '-la', '/etc/cron.d', '/etc/cron.daily'], ['cat', '/etc/crontab']] },
  { id: 'linux.updates', kind: ['ssh'], label: '更新の状況', steps: [['apt', 'list', '--upgradable'], ['ls', '-la', '--time-style=long-iso', '/var/log/apt'], ['tail', '-n', '40', '/var/log/apt/history.log'], ['cat', '/etc/apt/apt.conf.d/20auto-upgrades']] },
  { id: 'linux.ssh', kind: ['ssh'], label: 'SSH の設定', steps: [['cat', '/etc/ssh/sshd_config'], ['ls', '-la', '/etc/ssh/sshd_config.d'], ['cat', '/root/.ssh/authorized_keys']] },
  { id: 'linux.firewall', kind: ['ssh'], label: 'ファイアウォール', steps: [['ufw', 'status', 'verbose'], ['iptables', '-L', '-n', '--line-numbers'], ['nft', 'list', 'ruleset']] },
  { id: 'linux.docker', kind: ['ssh'], label: 'コンテナ', steps: [['docker', 'ps', '-a'], ['docker', 'images']] },
  { id: 'linux.webroot', kind: ['ssh'], label: '公開フォルダで最近変わったファイル (7 日)', steps: [['find', '/var/www', '-type', 'f', '-mtime', '-7', '-newer', '/etc/hostname'], ['find', '/var/www', '-type', 'f', '-name', '*.php', '-mtime', '-7']] },
  { id: 'linux.backup', kind: ['ssh'], label: 'バックアップの実態 (最終更新)', steps: [['ls', '-la', '--time-style=long-iso', '/backup'], ['ls', '-la', '--time-style=long-iso', '/mnt/backup'], ['ls', '-la', '--time-style=long-iso', '/var/backups'], ['df', '-h']] },
  { id: 'web.head', kind: ['web'], label: '応答とヘッダ (証明書・セキュリティヘッダ)', steps: [['curl', '-I', '/']] },
  { id: 'web.exposed', kind: ['web'], label: '出てはいけないファイル', steps: [['curl', '-I', '/.git/HEAD'], ['curl', '-I', '/.env'], ['curl', '-I', '/wp-config.php.bak'], ['curl', '-I', '/backup.zip'], ['curl', '-I', '/phpinfo.php'], ['curl', '-I', '/.DS_Store'], ['curl', '-I', '/wp-login.php'], ['curl', '-I', '/administrator/'], ['curl', '-I', '/phpmyadmin/']] },
  { id: 'web.robots', kind: ['web'], label: 'robots と目印', steps: [['curl', '/robots.txt'], ['curl', '-I', '/readme.html'], ['curl', '-I', '/wp-json/']] },
  { id: 'network.show', kind: ['network'], label: 'ネットワーク機器の版と設定 (show)', steps: [['show', 'version'], ['show', 'running-config']] },
  // ---- 初動 (有事) 向け。消えやすい順に読む。平時の記録があれば、前回との差分が出る
  { id: 'linux.processes', kind: ['ssh'], label: '動いているプロセス', incident: true, steps: [['ps', 'auxww']] },
  { id: 'linux.connections', kind: ['ssh'], label: '通信の相手 (つながっている先)', incident: true, steps: [['ss', '-tnpH', 'state', 'established'], ['netstat', '-tn']] },
  { id: 'linux.rootusers', kind: ['ssh'], label: '管理者と同じ権限 (UID 0) のアカウント', incident: true, steps: [['awk', '-F:', '$3==0{print}', '/etc/passwd'], ['getent', 'group', 'sudo'], ['getent', 'group', 'wheel']] },
  { id: 'linux.authkeys', kind: ['ssh'], label: '鍵でのログインが許されている先 (authorized_keys)', incident: true, steps: [['find', '/home', '/etc/ssh', '-name', 'authorized_keys', '-type', 'f']] },
  { id: 'linux.sudoers', kind: ['ssh'], label: 'sudo の設定', incident: true, steps: [['ls', '-la', '/etc/sudoers.d']] },
  { id: 'linux.preload', kind: ['ssh'], label: '仕込みに使われる場所 (ld.so.preload・rc.local・profile.d)', incident: true, steps: [['cat', '/etc/ld.so.preload'], ['cat', '/etc/rc.local'], ['ls', '-la', '--time-style=long-iso', '/etc/profile.d']] },
  { id: 'linux.suid', kind: ['ssh'], label: '特権で動くプログラム (SUID)', incident: true, steps: [['find', '/', '-xdev', '-perm', '-4000', '-type', 'f']] },
  { id: 'linux.integrity', kind: ['ssh'], label: 'パッケージの改ざん確認 (dpkg -V / rpm -Va)', incident: true, steps: [['dpkg', '-V'], ['rpm', '-Va']] },
  { id: 'linux.recent_etc', kind: ['ssh'], label: '3 日以内に変わった設定・プログラム', incident: true, steps: [['find', '/etc', '/usr/bin', '/usr/sbin', '/usr/local/bin', '-xdev', '-type', 'f', '-mtime', '-3']] },
  { id: 'linux.logs_auth', kind: ['ssh'], label: 'ログインのログ (直近)', incident: true, steps: [['last', '-n', '30', '-F']] },
];
// 初動セット: 消えやすいものから順に (メモリの中身 → 通信 → ログイン → 仕込まれやすい場所 → ログ)
export const INCIDENT_SET = ['linux.processes', 'linux.connections', 'linux.logins', 'linux.rootusers', 'linux.users', 'linux.authkeys', 'linux.sudoers', 'linux.autostart', 'linux.preload', 'linux.ports', 'linux.suid', 'linux.integrity', 'linux.recent_etc', 'linux.webroot', 'linux.docker', 'linux.logs_auth'];

// 行の差分 (順序は問わない): 増えた行と消えた行。時刻や PID のような毎回変わる値は、荒く正規化して比べる
// 手順の半分以上 (3 つ以上) に同じ「増えた行」(または「消えた行」) があれば、それは 1 つの手順の変化ではなく機械全体の異常 (壊れた preload が全コマンドに出す ERROR など)。
// 抜き出して返し、各手順の差分からは外す (steps の diff を書き換える)。増えた側が警告、消えた側は「前回の異常が消えた」の知らせ
export function splitCommonLines(steps) {
  const out = { added: [], removed: [] };
  if (steps.length < 3) return out;
  for (const side of ['added', 'removed']) {
    const count = new Map();
    for (const x of steps) for (const l of new Set(x.diff[side])) count.set(l, (count.get(l) || 0) + 1);
    const common = [...count].filter(([, n]) => n >= Math.max(3, Math.ceil(steps.length * 0.5))).map(([l]) => l);
    if (common.length) for (const x of steps) { x.diff[side] = x.diff[side].filter(l => !common.includes(l)); x.diff[`${side}_count`] = x.diff[side].length; }
    out[side] = common;
  }
  return out;
}
export const splitCommonAdded = (steps) => splitCommonLines(steps).added;
export function diffLines(prev, cur) {
  const norm = (l) => l.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, '<時刻>').replace(/\b\d{1,2}:\d{2}(:\d{2})?\b/g, '<時刻>').replace(/\b(pid=|users:\(\("[^"]+",pid=)\d+/g, '$1<pid>').replace(/\s+/g, ' ').trim();
  // 「(出力なし)」は出力が無かった目印で、行ではない (前回が空・今回にエラー行だけ、で「消えた 1」と出ていた)
  const a = new Map(); for (const l of String(prev || '').split('\n')) { const k = norm(l); if (k && k !== NO_OUTPUT) a.set(k, (a.get(k) || 0) + 1); }
  const b = new Map(); for (const l of String(cur || '').split('\n')) { const k = norm(l); if (k && k !== NO_OUTPUT) b.set(k, (b.get(k) || 0) + 1); }
  const added = [], removed = [];
  for (const [k, n] of b) if (!a.has(k)) added.push(k); for (const [k, n] of a) if (!b.has(k)) removed.push(k);
  return { added: added.slice(0, 200), removed: removed.slice(0, 200), added_count: added.length, removed_count: removed.length };
}

const SELF_CHECKS = [
  { id: 'self.mfa_remote', label: '外からのログインに多要素認証を求めている', item: 'entry.mfa_remote' },
  { id: 'self.mfa_admins', label: 'Owner・管理者の全員が多要素認証を登録している', item: 'entry.mfa_admin' },
  { id: 'self.login_lock', label: 'ログイン失敗が続くとロックする', item: 'entry.lockout' },
  { id: 'self.updates_auto', label: '更新を自動で当てている (配信元の設定あり)', item: 'patch.updates' },
  { id: 'self.audit_retention', label: '監査ログを 1 年以上保管する設定', item: 'detect.logs' },
  { id: 'self.backup_recent', label: '2 日以内にバックアップが取れている', item: 'backup.exists' },
  { id: 'self.backup_offsite', label: '外部保管先があり、最後の保管が成功している', item: 'backup.offline' },
  { id: 'self.ntp', label: '時刻が合っている (NTP)', item: null },
  { id: 'self.https', label: 'https で画面を出している', item: 'leak.encrypt' },
  { id: 'self.remote_url', label: '公開 URL (インターネットからの入口) の有無', item: null },
];

export class Mamoricho {
  constructor(cfg, { probe = null, llm = null, rag = null, backup = null, updates = null, remote = null } = {}) {
    Object.assign(this, { cfg, probe, llm, rag, backup, updates, remote }); this.timer = null;
  }
  db() { return getDb(); }

  // ---- 点検の項目と答え ----
  checklist(actor) {
    requireRole(actor, 'viewer');
    const answers = Object.fromEntries(this.db().prepare('SELECT * FROM mamoricho_answers').all().map(a => [a.item_id, { ...a, evidence: J.parse(a.evidence, []) }]));
    return { baseline: BASELINE, statuses: STATUSES, categories: CATEGORIES, items: ITEMS.map(i => ({ ...i, answer: answers[i.id] || null })) };
  }
  // 状態を決めるのは人 (operator 以上)。AI の提案はここに来る前に画面で見せる
  answer(actor, { item_id, status, note = '', evidence = null } = {}) {
    requireRole(actor, 'operator');
    const item = byId[item_id]; if (!item) throw new HttpError(404, 'not_found', '点検の項目が見つかりません');
    if (!STATUSES[status]) throw new HttpError(400, 'bad_status', `status は ${Object.keys(STATUSES).join(' / ')}`);
    const prev = this.db().prepare('SELECT * FROM mamoricho_answers WHERE item_id=?').get(item_id);
    const ev = Array.isArray(evidence) ? evidence.slice(0, 20).map(e => ({ kind: String(e.kind || 'note').slice(0, 20), ref: String(e.ref || '').slice(0, 200), label: String(e.label || '').slice(0, 120) })) : (prev ? J.parse(prev.evidence, []) : []);
    const t = nowIso();
    this.db().prepare('INSERT INTO mamoricho_answers(item_id,status,note,evidence,updated_by,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(item_id) DO UPDATE SET status=excluded.status, note=excluded.note, evidence=excluded.evidence, updated_by=excluded.updated_by, updated_at=excluded.updated_at')
      .run(item_id, status, String(note).slice(0, 2000), J.str(ev), actor.id, t);
    const rec = this.record(actor, 'answer', { item_id, status, note: String(note).slice(0, 2000), evidence: ev, previous: prev ? { status: prev.status, updated_at: prev.updated_at } : null });
    audit({ actor, action: 'mamoricho.answer', target: item_id, detail: { status, previous: prev?.status || null, record: rec.id } });
    return { item_id, status, note, evidence: ev, updated_at: t, record_id: rec.id };
  }

  // ---- 記録の連鎖 (1 件ごとに前の hash を含め、箱の鍵で署名) ----
  record(actor, kind, payload) {
    const db = this.db(); const last = db.prepare('SELECT hash FROM mamoricho_records ORDER BY seq DESC LIMIT 1').get();
    const rec = { id: id('mrec'), kind, payload: J.str(payload), by_id: actor?.id || 'system', by_name: actor?.display_name || actor?.username || 'system', at: nowIso(), prev_hash: last?.hash || '', baseline: BASELINE.id };
    rec.hash = sha256([rec.id, rec.kind, rec.payload, rec.by_id, rec.at, rec.prev_hash, rec.baseline].join('\n'));
    try { const { privateKey } = ensureLocalPublisherKey(); rec.sig = crypto.sign(null, Buffer.from(rec.hash), privateKey).toString('base64'); } catch { rec.sig = null; }
    db.prepare('INSERT INTO mamoricho_records(id,kind,payload,by_id,by_name,at,prev_hash,hash,sig,baseline) VALUES(?,?,?,?,?,?,?,?,?,?)').run(rec.id, rec.kind, rec.payload, rec.by_id, rec.by_name, rec.at, rec.prev_hash, rec.hash, rec.sig, rec.baseline);
    return rec;
  }
  records(actor, { limit = 200, kind = null } = {}) {
    requireRole(actor, 'viewer');
    const rows = kind ? this.db().prepare('SELECT * FROM mamoricho_records WHERE kind=? ORDER BY seq DESC LIMIT ?').all(kind, limit) : this.db().prepare('SELECT * FROM mamoricho_records ORDER BY seq DESC LIMIT ?').all(limit);
    return rows.map(r => ({ ...r, payload: J.parse(r.payload, {}) }));
  }
  // 連鎖を最初から確かめる: hash のつながりと署名
  verify(actor) {
    requireRole(actor, 'viewer');
    const rows = this.db().prepare('SELECT * FROM mamoricho_records ORDER BY seq').all(); let prev = ''; let pub = null;
    try { pub = crypto.createPublicKey(ensureLocalPublisherKey().privateKey); } catch { /* 署名は確かめられない */ }
    for (const r of rows) {
      const h = sha256([r.id, r.kind, r.payload, r.by_id, r.at, r.prev_hash, r.baseline].join('\n'));
      if (r.prev_hash !== prev) return { ok: false, count: rows.length, broken_at: r.seq, reason: '前の記録とのつながりが切れています (消された・差し替えられた記録があります)' };
      if (h !== r.hash) return { ok: false, count: rows.length, broken_at: r.seq, reason: '記録の中身が書き換えられています' };
      if (pub && r.sig && !crypto.verify(null, Buffer.from(r.hash), pub, Buffer.from(r.sig, 'base64'))) return { ok: false, count: rows.length, broken_at: r.seq, reason: '署名が合いません' };
      prev = r.hash;
    }
    return { ok: true, count: rows.length, head: prev || null, signed: !!pub };
  }

  // ---- 言箱自身の自己点検 (機械的) ----
  async selfCheck(actor, { save = false } = {}) {
    requireRole(actor, 'viewer');
    const pol = mfa.policy(this.cfg); const out = [];
    const push = (id_, ok, detail, level = 'check') => out.push({ ...SELF_CHECKS.find(s => s.id === id_), ok, detail, level });
    push('self.mfa_remote', pol.require_remote, pol.require_remote ? '外からのログインは多要素認証が必須' : '外からのログインに多要素認証を求めていません (System › 設定)');
    const admins = (actor.tenant_id ? listUsers(actor.tenant_id) : []).filter(u => ['owner', 'admin'].includes(u.role) && u.status === 'active');
    const missing = admins.filter(u => !u.mfa_factors).map(u => u.username);
    push('self.mfa_admins', admins.length > 0 && !missing.length, missing.length ? `未登録: ${missing.join(', ')}` : `${admins.length} 人とも登録済み`);
    push('self.login_lock', true, `同じ名前+接続元で ${this.cfg.security?.login_max_failures ?? 5} 回、名前だけで ${this.cfg.security?.login_max_failures_user ?? 20} 回でロック`);
    const us = this.updates?.status?.(); push('self.updates_auto', !!(us?.auto_apply && us?.url), us ? `自動更新 ${us.auto_apply ? 'あり' : 'なし'}・配信元 ${us.url || '未設定'}・いまの版 ${us.current || '-'}` : '更新の状態を読めません');
    const days = Number(this.cfg.audit?.retention_days ?? 0); push('self.audit_retention', days === 0 || days >= 365, days === 0 ? '無期限' : `${days} 日`);
    const bs = this.backup?.status?.(); const lastAt = bs?.last_at ? Date.parse(bs.last_at) : 0; push('self.backup_recent', !!lastAt && Date.now() - lastAt < 2 * 86400e3, bs?.last_at ? `最後: ${bs.last_at} (${bs.count} 世代)` : 'まだ取っていません (System › デバイス › バックアップ)');
    push('self.backup_offsite', !!(bs?.remote && bs?.offsite_last?.ok), bs?.remote ? (bs.offsite_last?.ok ? `外部保管 ${bs.offsite_last.target || ''} (${bs.offsite_last.at})` : `外部保管先はあるが最後は失敗: ${bs.offsite_last?.error || '未実施'}`) : '外部保管先が未設定 (切り離した写しがありません)');
    let ts = null; try { ts = timeStatus(); } catch { /* timedatectl なし */ } push('self.ntp', !!ts?.synchronized, ts?.synchronized ? `合っている (${ts.server || ts.address || '-'})` : '時刻合わせができていません (System › 設定 › 時刻合わせ)');
    push('self.https', this.cfg.server?.https !== false, this.cfg.server?.https !== false ? `https :${this.cfg.server?.https_port || 7443}` : 'https を切っています');
    const rs = this.remote?.state?.(); push('self.remote_url', true, rs?.hostname ? `公開 URL あり: ${rs.hostname} (外からの入口。多要素認証が必須か確かめる)` : '公開 URL なし (社内だけ)', 'info');
    const summary = { ok: out.filter(x => x.level === 'check' && x.ok).length, total: out.filter(x => x.level === 'check').length, at: nowIso() };
    if (save) { const rec = this.record(actor, 'selfcheck', { checks: out.map(({ id: cid, ok, detail }) => ({ id: cid, ok, detail })), summary }); summary.record_id = rec.id; }
    return { checks: out, summary };
  }

  // ---- まとめ (ホーム) ----
  async summary(actor) {
    requireRole(actor, 'viewer');
    const { items } = this.checklist(actor); const counts = { ok: 0, partial: 0, no: 0, unknown: 0, na: 0, unanswered: 0 };
    for (const i of items) counts[i.answer?.status || 'unanswered']++;
    const answered = items.length - counts.unanswered; const scoreBase = items.length - counts.na;
    const score = scoreBase ? Math.round(((counts.ok + counts.partial * 0.5) / scoreBase) * 100) : 0;
    const homework = items.filter(i => !i.answer || ['no', 'unknown', 'partial'].includes(i.answer.status)).sort((a, b) => (b.weight - a.weight) || a.id.localeCompare(b.id)).slice(0, 8)
      .map(i => ({ id: i.id, cat: i.cat, q: i.q, status: i.answer?.status || 'unanswered', min: i.min }));
    const lastFull = this.db().prepare("SELECT at FROM mamoricho_records WHERE kind='review' ORDER BY seq DESC LIMIT 1").get()?.at || null;
    const nextReview = lastFull ? new Date(Date.parse(lastFull) + 91 * 86400e3).toISOString() : null;
    const self = await this.selfCheck(actor);
    const settings = this.settings();
    return { baseline: BASELINE, counts, answered, total: items.length, score, homework, last_review_at: lastFull, next_review_at: nextReview, self: self.summary, self_failed: self.checks.filter(c => c.level === 'check' && !c.ok).map(c => c.label),
      chain: this.verify(actor), emergency_ready: !!(settings.contacts?.lead && settings.contacts?.it), targets: this.probe ? this.probe.listTargets({ ...actor, role: actor.role === 'viewer' ? 'operator' : actor.role }).length : 0 };
  }
  // 四半期の見直しを「終えた」と記録する (全部答えたとき)
  closeReview(actor, { note = '' } = {}) {
    requireRole(actor, 'operator'); const s = this.db().prepare('SELECT COUNT(*) c FROM mamoricho_answers').get().c;
    if (s < ITEMS.length) throw new HttpError(409, 'incomplete', `まだ答えていない項目が ${ITEMS.length - s} 個あります`);
    const rec = this.record(actor, 'review', { note: String(note).slice(0, 1000), answers: this.db().prepare('SELECT item_id,status FROM mamoricho_answers').all() });
    audit({ actor, action: 'mamoricho.review_closed', target: rec.id }); return { record_id: rec.id, at: rec.at };
  }

  // ---- 対話: 利用者の答えを状態に翻訳して提案する (決めるのは人) ----
  async interview(actor, { item_id, text = '', history = [] } = {}) {
    requireRole(actor, 'operator'); const item = byId[item_id]; if (!item) throw new HttpError(404, 'not_found', '点検の項目が見つかりません');
    if (!this.llm) return { proposal: null, note: 'AI が使えません。状態を自分で選んでください' };
    const sys = `あなたは中小企業の情報セキュリティの点検を手伝う担当者です。利用者の答えを読んで、点検項目の状態を 1 つ提案し、理由を 1 文で書き、曖昧なら確認の質問を 1 つだけします。
状態は ok (できている) / partial (一部できている) / no (できていない) / unknown (分からない) / na (対象外) のどれか。
断定を避け、「安全」「問題なし」とは書かない。できていない点は責めず、最低ラインを 1 つ示す。
必ず次の JSON だけを返す: {"status":"ok|partial|no|unknown|na","confidence":0.0-1.0,"note":"記録に残す 1 文 (40 字以内)","follow_up":"確認の質問 (無ければ空)","tip":"最低ラインに向けた一言 (無ければ空)"}`;
    const user = `点検項目: ${item.q}\n基準の最低ライン: ${item.min}\n推奨: ${item.rec}\n背景: ${item.why}\n\nこれまでのやりとり:\n${history.slice(-6).map(h => `${h.role === 'assistant' ? 'AI' : '利用者'}: ${String(h.text).slice(0, 300)}`).join('\n')}\n利用者の答え: ${String(text).slice(0, 1200)}`;
    try {
      const r = await this.llm.chat([{ role: 'system', content: sys }, { role: 'user', content: user }], { temperature: 0.1, max_tokens: 400 });
      const m = /\{[\s\S]*\}/.exec(r?.content || ''); const p = m ? JSON.parse(m[0]) : null;
      if (!p || !STATUSES[p.status]) return { proposal: null, note: 'AI の答えを読めませんでした。状態を自分で選んでください' };
      return { proposal: { status: p.status, confidence: Math.max(0, Math.min(1, Number(p.confidence) || 0)), note: String(p.note || '').slice(0, 200), follow_up: String(p.follow_up || '').slice(0, 300), tip: String(p.tip || '').slice(0, 300) } };
    } catch (e) { return { proposal: null, note: `AI に聞けませんでした: ${String(e.message || e).slice(0, 120)}` }; }
  }
  // 相談 (安全の文脈に絞る)。社内の文書を読み込んでいれば、その内容を根拠に添える (ragnarok)
  async consult(actor, { question = '', workspace_id = null } = {}) {
    requireRole(actor, 'viewer'); const q = String(question || '').trim(); if (!q) throw new HttpError(400, 'empty', '相談の内容を入れてください');
    let docs = null; if (this.rag && workspace_id) { try { docs = await this.rag.ask(actor, { workspace_id, question: q, k: 4, answer: false }); } catch { docs = null; } }
    if (!this.llm) return { answer: 'AI が使えません。', sources: [] };
    const ctx = docs?.hits?.length ? `社内の文書からの抜粋:\n${docs.hits.slice(0, 4).map((h, i) => `[${i + 1}] ${h.name || h.asset_name || ''}: ${String(h.text || h.snippet || '').slice(0, 500)}`).join('\n')}\n` : '';
    const sys = `あなたは中小企業の情報セキュリティの相談相手です。個人情報保護委員会の 2026-10-07 の注意喚起 (アクセス制御・識別と認証・不正アクセスの防止・漏えいの防止・検知、不要な個人データの消去) と WARNING の 9 事例を基準に、ふつうの言葉で、まず何をすべきかを順番に答えます。
断定を避け「安全」「問題なし」とは書かない。手に負えない事案 (侵入の疑い・大量の漏えい) は、ネットワークからの切り離しと専門家への連絡、委員会への速報 (おおむね 3〜5 日) を先に伝える。社内の文書の抜粋があれば、それを根拠に引く。400 字以内。`;
    try { const r = await this.llm.chat([{ role: 'system', content: sys }, { role: 'user', content: `${ctx}相談: ${q}` }], { temperature: 0.2, max_tokens: 700 }); return { answer: r?.content || '', sources: (docs?.hits || []).slice(0, 4).map(h => ({ name: h.name || h.asset_name || '', asset_id: h.asset_id || h.id || null })) }; }
    catch (e) { return { answer: `AI に聞けませんでした: ${String(e.message || e).slice(0, 120)}`, sources: [] }; }
  }

  // ---- 調査の型 (読むだけ) を対象に流す。各 step は probe の判定を通る (forbidden/change が混じれば止める) ----
  templates() { return TEMPLATES.map(({ id: tid, kind, label, steps, incident }) => ({ id: tid, kind, label, steps, incident: !!incident })); }
  async runTemplate(actor, { target_id, template_id, item_id = null, record = true } = {}) {
    requireRole(actor, 'operator'); if (!this.probe) throw new HttpError(503, 'no_probe', '調査の仕組みがありません');
    const tpl = TEMPLATES.find(t => t.id === template_id); if (!tpl) throw new HttpError(404, 'not_found', '調査の型が見つかりません');
    const t = this.probe.getTarget(target_id); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    if (!tpl.kind.includes(t.kind)) throw new HttpError(400, 'bad_kind', `この型は ${tpl.kind.join('/')} の対象向けです`);
    const results = [];
    const rootSteps = ROOT_STEPS[template_id] || []; const rootRead = !!J.parse(t.verify, {})?.root_read;
    // root で同じコマンドを読むなら、一般ユーザー側の同じ手順は省く (dpkg -V を 2 回走らせない)
    const cmdKey = (a) => [String(a[0]).replace(/^.*\//, ''), ...a.slice(1)].join(' '); const rootKeys = new Set(rootRead ? rootSteps.map(cmdKey) : []);
    const plan = [...tpl.steps.filter(a => !rootKeys.has(cmdKey(a))).map(a => ({ argv: a })), ...rootSteps.map(a => rootRead ? { argv: ['sudo', '-n', ...a], root: true } : { argv: a, needs_root: true })];
    for (const { argv, root, needs_root } of plan) {
      if (needs_root) { results.push({ argv, needs_root: true, error: 'root の権限が要ります (登録時に「root の読み取りも許す」を選んだ対象だけ読めます)' }); continue; }
      try {
        const prev = this.probe.previousOutput(target_id, template_id, argv); // 走らせる前に「前回」を取る (今回を混ぜない)
        const r = await this.probe.run(actor, { target_id, argv, template_id, explanation: tpl.label });
        // 前回は記録に残した長さ (OUTPUT_KEEP) で切れているので、今回も同じ長さで比べる (全文と比べると切れた先が全部「増えた」になる)
        const truncated = r.output.length > OUTPUT_KEEP;
        const diff = prev ? { ...diffLines(prev.output, r.output.slice(0, OUTPUT_KEEP)), previous_at: prev.at, ...(truncated ? { truncated: true } : {}) } : null;
        results.push({ argv, exit_code: r.exit_code, output: r.output.slice(0, 20000), run_id: r.run_id, diff, root: !!root });
      }
      catch (e) { results.push({ argv, error: e.message, code: e.code }); if (e.code === 'forbidden_command' || e.code === 'approval_required') break; }
    }
    const rec = record ? this.record(actor, 'probe', { target_id, target_name: t.name, template_id, item_id, runs: results.map(r => ({ argv: r.argv, exit_code: r.exit_code ?? null, run_id: r.run_id || null, error: r.error || null, added: r.diff?.added_count ?? null, removed: r.diff?.removed_count ?? null })) }) : null;
    if (record && item_id && byId[item_id]) {
      const prev = this.db().prepare('SELECT evidence FROM mamoricho_answers WHERE item_id=?').get(item_id); const ev = prev ? J.parse(prev.evidence, []) : [];
      ev.push({ kind: 'probe', ref: rec.id, label: `${t.name}: ${tpl.label} (${new Date().toLocaleDateString('ja-JP')})` });
      this.db().prepare('INSERT INTO mamoricho_answers(item_id,status,note,evidence,updated_by,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(item_id) DO UPDATE SET evidence=excluded.evidence, updated_at=excluded.updated_at').run(item_id, 'unknown', '', J.str(ev.slice(-20)), actor.id, nowIso());
    }
    return { record_id: rec?.id || null, target: { id: t.id, name: t.name, kind: t.kind }, template: tpl.label, results };
  }
  // 初動セット: 消えやすい順に型を流し、前回 (平時の記録) との差分をまとめる。1 つの記録 (incident_probe) に残す
  async runIncident(actor, { target_id } = {}) {
    requireRole(actor, 'operator'); if (!this.probe) throw new HttpError(503, 'no_probe', '調査の仕組みがありません');
    const t = this.probe.getTarget(target_id); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    if (t.kind !== 'ssh') throw new HttpError(400, 'bad_kind', '初動セットはサーバー・PC (SSH) の対象向けです');
    const sections = []; let baseline = false;
    for (const tid of INCIDENT_SET) {
      const tpl = TEMPLATES.find(x => x.id === tid); if (!tpl) continue;
      try { const r = await this.runTemplate(actor, { target_id, template_id: tid, record: false }); for (const x of r.results) if (x.diff) baseline = true; sections.push({ template_id: tid, label: tpl.label, results: r.results }); }
      catch (e) { sections.push({ template_id: tid, label: tpl.label, error: e.message, results: [] }); }
    }
    // どの手順にも出る「増えた行」は、1 つの手順の変化ではなく機械全体の異常 (例: 壊れた ld.so.preload が全コマンドに出す ERROR)。1 か所にまとめ、各手順からは外す
    const common = splitCommonLines(sections.flatMap(sec => sec.results.filter(x => x.diff)));
    const summary = sections.map(sec => ({ template_id: sec.template_id, label: sec.label, steps: sec.results.length, ok: sec.results.filter(x => x.exit_code === 0).length, needs_root: sec.results.filter(x => x.needs_root).length, failed: sec.results.filter(x => !x.needs_root && (x.error || (x.exit_code != null && x.exit_code !== 0))).length, added: sec.results.reduce((n, x) => n + (x.diff?.added_count || 0), 0), removed: sec.results.reduce((n, x) => n + (x.diff?.removed_count || 0), 0) }));
    const rec = this.record(actor, 'incident_probe', { target_id, target_name: t.name, baseline, common_added: common.added.slice(0, 20), common_removed: common.removed.slice(0, 20), sections: summary, run_ids: sections.flatMap(sec => sec.results.map(x => x.run_id).filter(Boolean)) });
    audit({ actor, action: 'mamoricho.incident_run', target: target_id, detail: { record: rec.id, baseline, added: summary.reduce((n, x) => n + x.added, 0) } });
    return { record_id: rec.id, target: { id: t.id, name: t.name }, baseline, common_added: common.added.slice(0, 20), common_removed: common.removed.slice(0, 20), sections, summary, note: baseline ? '前回の記録と比べました。「増えた」ものを先に見てください' : 'この対象には前回の記録がありません。今回が基準になります (次回から差分が出ます)' };
  }
  // 速報の下書き: 初動の記録・初動の調査・連絡先から、委員会への速報の形に (箱の AI。無ければ材料だけ並べる)。「安全」「原因は特定」とは書かせない
  async draftReport(actor, { discovered_at = null, summary = '' } = {}) {
    requireRole(actor, 'operator');
    const notes = this.records(actor, { kind: 'incident_note', limit: 100 }).reverse(); const probes = this.records(actor, { kind: 'incident_probe', limit: 3 });
    const st = this.settings(); const dl = discovered_at ? this.deadlines(discovered_at) : null;
    const material = `発覚日: ${dl?.discovered || '(未入力)'}\n報告の期限: ${dl ? `速報 ${dl.prompt_report.from}〜${dl.prompt_report.to} / 確報 ${dl.final_report.to} (不正の目的のおそれ ${dl.final_report_malicious.to})` : '(発覚日を入れると出ます)'}\n責任者: ${st.contacts?.lead || '(未設定)'} / 担当: ${st.contacts?.it || '(未設定)'}\n概要 (担当者の言葉): ${String(summary).slice(0, 1000) || '(未入力)'}\n\n初動の記録 (時系列):\n${notes.map(n => `- ${n.at.slice(0, 16).replace('T', ' ')} ${n.by_name}: ${n.payload.text}`).join('\n') || '- (まだありません)'}\n\n初動の調査:\n${probes.map(p => `- ${p.at.slice(0, 16).replace('T', ' ')} ${p.payload.target_name}: ${p.payload.baseline ? '前回と比べて ' + p.payload.sections.reduce((n, x) => n + x.added, 0) + ' 行増・' + p.payload.sections.reduce((n, x) => n + x.removed, 0) + ' 行減' : '基準を作成'}${p.payload.sections.filter(x => x.added > 0).map(x => `（${x.label}: +${x.added}）`).join('')}`).join('\n') || '- (まだありません)'}`;
    const skeleton = `【個人情報保護委員会への速報 (下書き)】\n1. 発生・発覚の日時\n2. 事案の概要\n3. 漏えい等が発生し、またはそのおそれがある個人データの項目・件数 (分からなければ「調査中」)\n4. 原因 (分からなければ「調査中」)\n5. 二次被害またはそのおそれの有無\n6. 本人への対応の実施状況\n7. 公表の実施状況\n8. 再発防止のための措置\n9. その他参考となる事項\n\n--- 材料 ---\n${material}`;
    if (!this.llm) return { draft: skeleton, material, llm: false };
    try {
      const heads = ['1. 発生・発覚の日時', '2. 事案の概要', '3. 漏えい等が発生し、またはそのおそれがある個人データの項目・件数', '4. 原因', '5. 二次被害またはそのおそれの有無', '6. 本人への対応の実施状況', '7. 公表の実施状況', '8. 再発防止のための措置', '9. その他参考となる事項'];
      const r = await this.llm.chat([{ role: 'system', content: `中小企業の担当者に代わって、個人情報保護委員会への「速報」の下書きを日本語で書く。見出しは次の 9 つを **この文言のまま、この順で** 使い、増やしたり変えたりしない:\n${heads.join('\n')}\n各見出しの下に 1〜3 文。分からないことは「調査中」と書き、推測で断定しない。「安全」「問題なし」「原因を特定した」とは書かない。材料に無いことは書かない。最後に「※ 速報は分かっている範囲で早めに出し、確報で補う」と添える。` }, { role: 'user', content: `材料:\n${material}\n\n上の材料で 1〜9 を埋めてください。` }], { temperature: 0.1, max_tokens: 1200 });
      return { draft: r?.content || skeleton, material, llm: true };
    } catch (e) { return { draft: skeleton, material, llm: false, note: `AI に聞けませんでした: ${String(e.message || e).slice(0, 120)}` }; }
  }

  // ---- 安全の仕組み (調査が安全である理由を、ふつうの言葉で、生きている状態つきで) ----
  safety() {
    const image = this.probe ? this.probe._dk(['image', 'inspect', 'kotohako-probe:1']).status === 0 : false;
    const chain = this.db().prepare('SELECT COUNT(*) c FROM mamoricho_records').get().c;
    return { items: [
      { id: 'readonly', title: '読むだけのコマンドしか動かさない', body: 'コマンドは 1 つずつ「読むだけ / 変えるおそれ / 使えない」に機械的に判定します。消す・止める・入れる・権限を変える・別の機械へつなぐものは実行しません。知らないものは「変えるおそれ」側に倒し、Owner の承認と理由が要ります。', ok: true, detail: '判定の決まりは OS の版と一緒に配られ、調査の型 (16 + 15) はすべて「読むだけ」で固定' },
      { id: 'noshell', title: 'シェルを通さず、記号も通さない', body: 'パイプ・リダイレクト・つなぎ (| ; & > < $( `) は受け付けません。遠隔のコマンドは 1 本ずつ、対象の機械で展開されないように引用して渡します。', ok: true },
      { id: 'ledger', title: 'つなぐ先は台帳で固定', body: 'どの機械につなぐか (住所・ポート・利用者) は、まもり帳の台帳の値だけを使います。調査の型や AI は「その機械で何を読むか」しか決められず、台帳に無い機械へはつなげません。初めてつないだときの公開鍵を覚え、次から変わっていれば拒否します (なりすまし・経路のすり替え)。', ok: true },
      { id: 'container', title: '使い捨てのコンテナから', body: '調査は、読み取り専用・権限を落とした・root でないコンテナ (kotohako-probe) から行い、1 回ごとに消します。時間 (90 秒)・メモリ (256MB)・出力 (2MB) に上限があります。言箱本体のファイルや鍵には触れません。', ok: image, detail: image ? 'コンテナの材料はこの箱にあります' : 'コンテナの材料はまだありません (初回の調査で自動で用意します)' },
      { id: 'account', title: '対象には読み取り専用のユーザーだけ', body: '1 行の登録で作る mamoricho ユーザーは、パスワード無し・鍵だけ・ポート転送なし・端末なしです。root でしか読めないもの (root の鍵・sudo の設定・認証ログ) は、登録時に許した対象でだけ、あらかじめ決めた読むだけのコマンドを sudoers に完全一致で書いて読みます。任意のコマンドは root で動かせません。消し方は userdel -r mamoricho と rm -f /etc/sudoers.d/mamoricho の 2 つだけ。', ok: true },
      { id: 'secrets', title: '鍵や秘密は箱の金庫に、出力は伏せ字に', body: '秘密鍵・パスワードは箱の金庫 (暗号化) に入り、画面には出ません。調査の出力は、パスワードや鍵に見える行を伏せ字にしてから箱の中 (AI NAS の「まもり帳」フォルダ) に保存します。', ok: true },
      { id: 'inside', title: 'データは外に出ない', body: '調査の結果も、相談も、速報の下書きも、箱の中の AI (Akigrid) だけで処理します。箱の外の AI には送りません。外に出すのは、管理者が自分で書き出したときだけです。', ok: this.cfg.security?.external_ai !== 'enabled', detail: this.cfg.security?.external_ai === 'enabled' ? '注意: 箱の設定で外部 AI が有効です (System › 設定)' : '外部 AI は無効' },
      { id: 'records', title: '記録は書き換えられない', body: 'すべての答え・調査・初動の記録は、1 件ごとに前の記録のハッシュを含めて箱の鍵で署名しています。消したり書き換えたりすると「記録」の画面で分かります。実行は監査ログにも残ります。', ok: true, detail: `いまの記録 ${chain} 件` },
      { id: 'approval', title: '人が決める', body: 'AI の提案も、変えるおそれのあるコマンドも、最後に決めるのは人です。調査を始める前には毎回「これからやること / やらないこと」を示し、確認してから動きます。', ok: true },
    ], not_doing: ['設定を書き換えない', 'ファイルを消さない・作らない (対象の機械では mamoricho ユーザーと sudoers の 1 ファイル以外)', 'サービスの停止・再起動をしない', 'ソフトを入れない', '台帳に無い機械へつながない', 'データを箱の外へ送らない'] };
  }

  // ---- もしものときのカード (連絡先・体制) と初動の時系列 ----
  settings() { const r = this.db().prepare("SELECT value FROM mamoricho_settings WHERE key='emergency'").get(); return r ? J.parse(r.value, {}) : {}; }
  saveSettings(actor, patch = {}) {
    requireRole(actor, 'admin'); const cur = this.settings(); const next = { ...cur, ...redact(patch) };
    for (const k of Object.keys(next)) if (typeof next[k] === 'string') next[k] = next[k].slice(0, 500);
    if (next.contacts && typeof next.contacts === 'object') for (const k of Object.keys(next.contacts)) next.contacts[k] = String(next.contacts[k] ?? '').slice(0, 200);
    this.db().prepare("INSERT INTO mamoricho_settings(key,value) VALUES('emergency',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(J.str(next));
    this.record(actor, 'emergency_card', { contacts: next.contacts || {}, notes: next.notes || '' }); audit({ actor, action: 'mamoricho.emergency_card', target: 'emergency' });
    return next;
  }
  // 発覚日から、委員会への報告と本人通知の期限を出す (速報 3〜5 日・確報 30 日・不正の目的のおそれは 60 日)
  deadlines(discovered_at) {
    const d = Date.parse(discovered_at); if (!d) throw new HttpError(400, 'bad_date', '発覚した日を入れてください');
    const add = (n) => new Date(d + n * 86400e3).toISOString().slice(0, 10);
    return { discovered: new Date(d).toISOString().slice(0, 10), prompt_report: { from: add(3), to: add(5), label: '速報 (おおむね 3〜5 日以内)' }, final_report: { to: add(30), label: '確報 (30 日以内)' }, final_report_malicious: { to: add(60), label: '確報 (不正アクセスなど不正の目的のおそれがあるとき: 60 日以内)' }, notify_subjects: '本人への通知は事態の状況に応じて速やかに' };
  }
  addIncidentNote(actor, { text = '', at = null } = {}) {
    requireRole(actor, 'operator'); const s = String(text).trim(); if (!s) throw new HttpError(400, 'empty', '記録する内容を入れてください');
    const rec = this.record(actor, 'incident_note', { text: s.slice(0, 2000), observed_at: at || nowIso() }); audit({ actor, action: 'mamoricho.incident_note', target: rec.id }); return { record_id: rec.id, at: rec.at };
  }

  // ---- 定期の見直しの知らせ (1 日 1 回見る)。四半期の見直し期限・権限の棚卸し・自己点検の落ち ----
  start() { this.stop(); this.timer = setInterval(() => this.tick().catch(() => {}), 6 * 3600e3); setTimeout(() => this.tick().catch(() => {}), 60e3); }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }
  async tick() {
    const day = new Date().toDateString(); if (metaGet('mamoricho.tick_day') === day) return; this.db().prepare("INSERT INTO meta(key,value) VALUES('mamoricho.tick_day',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(day);
    const sys = { id: 'system', username: 'system', role: 'owner', tenant_id: this.db().prepare('SELECT id FROM tenants ORDER BY created_at LIMIT 1').get()?.id || null, display_name: 'まもり帳' };
    const s = await this.summary(sys);
    if (s.next_review_at && Date.parse(s.next_review_at) < Date.now()) notify({ kind: 'mamoricho', severity: 'warning', title: 'まもり帳: 四半期の見直しの時期です', body: `前回の見直しから 3 か月たちました。点検を見直し、アクセス権の棚卸しをしてください`, dedupe_key: 'mamoricho.review', link: 'mamoricho:check' });
    if (s.self_failed.length) notify({ kind: 'mamoricho', severity: 'warning', title: `まもり帳: 言箱の自己点検で ${s.self_failed.length} 件が未達`, body: s.self_failed.slice(0, 3).join(' / '), dedupe_key: 'mamoricho.self', link: 'mamoricho:home' });
    if (!s.answered) notify({ kind: 'mamoricho', severity: 'info', title: 'まもり帳: 最初の点検を始めましょう', body: '15 分ほどで、基本の対策ができているかを記録に残せます', dedupe_key: 'mamoricho.start', link: 'mamoricho:check' });
  }
}
