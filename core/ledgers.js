// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 台帳 (一覧で把握する・記録を残す): SCS 評価制度の「把握するための仕組みを整備すること」「記録を保管すること」を、1 つの汎用の表で持つ。
//   種類ごとに列が決まっている (LEDGER_KINDS)。行の追加・変更・削除はすべて記録の鎖に残す。診断の結果や箱 (OS) の利用者から「候補」を出せる (足すのは人)
import { HttpError, id, nowIso, J } from '../util.js';

// cols: [key, 見出し, 型 (text / date / num / bool / long / select:a|b), 必須]
export const LEDGER_KINDS = [
  { id: 'pcs', label: 'パソコン', note: 'シンクライアントを含む。機種ごとに 1 行でかまいません', criteria: ['3-1-1-1', '3-1-1-7'], cols: [['maker', '製造元', 'text', true], ['model', '機種', 'text'], ['os', 'OS', 'text', true], ['count', '台数', 'num', true], ['users', '使う部署・人', 'text'], ['notes', '備考', 'text']] },
  { id: 'servers', label: 'サーバー', note: '仮想サーバー・ハイパーバイザ・クラウドのサーバーを含む。管理者と責任者も', criteria: ['3-1-1-2', '3-1-1-6', '3-1-1-7', '4-1-2-1'], cols: [['name', '名前', 'text', true], ['maker', '製造元・種類', 'text'], ['os', 'OS', 'text', true], ['count', '台数', 'num'], ['purpose', '用途', 'text'], ['admin', 'システム管理者', 'text', true], ['owner', '責任者', 'text', true], ['config', '設定の控えの場所', 'text'], ['notes', '備考', 'text']] },
  { id: 'smart', label: 'スマートデバイス', note: '会社のスマートフォン・タブレット (★4)', criteria: ['3-1-1-5', '3-1-1-7'], cols: [['maker', '製造元', 'text', true], ['os', 'OS', 'text', true], ['count', '台数', 'num', true], ['users', '使う部署・人', 'text'], ['notes', '備考', 'text']] },
  { id: 'networks', label: 'ネットワーク', note: '拠点ごと・用途ごとに。ネットワーク図の置き場も', criteria: ['3-1-2-1', '3-1-2-3', '3-1-2-4'], cols: [['name', '名前', 'text', true], ['place', '所在地', 'text', true], ['purpose', '用途', 'text', true], ['range', '住所の範囲 (例: 192.168.1.0/24)', 'text'], ['diagram', 'ネットワーク図の置き場', 'text'], ['notes', '備考', 'text']] },
  { id: 'netdevices', label: 'ネットワーク機器', note: 'ルーター・UTM・スイッチ・無線 LAN。インターネットとの境目の機器には印を', criteria: ['3-1-2-2', '4-1-2-1', '4-4-4-3', '4-5-1-1'], cols: [['name', '名前', 'text', true], ['maker', '製造元', 'text', true], ['model', '型番', 'text', true], ['firmware', 'OS・ファームウェアの版', 'text'], ['vendor', '保守の会社', 'text', true], ['admin', 'システム管理者', 'text'], ['owner', '責任者', 'text'], ['edge', 'インターネットとの境目', 'bool'], ['notes', '備考', 'text']] },
  { id: 'services', label: '外部のサービス', note: 'クラウドのメール・ファイル共有・会計など。機密情報を扱うものは要件の確認と合意を', criteria: ['3-1-3-1', '3-1-3-2', '4-1-3-2', '2-1-1-1'], cols: [['name', 'サービス名', 'text', true], ['provider', '提供事業者', 'text', true], ['purpose', '用途', 'text'], ['secret', '機密情報を扱う', 'bool'], ['checked_at', 'セキュリティの条件を確かめた日', 'date'], ['agreement', '機密情報の扱いの合意 (契約・規約)', 'text'], ['mfa', '多要素認証', 'select:必須|任意|無し|分からない'], ['notes', '備考', 'text']] },
  { id: 'partners', label: '取引先・子会社', note: '機密情報を共有する相手、自社のシステムがつながる相手', criteria: ['2-1-1-1', '2-1-1-2', '2-1-1-3', '2-1-2-1', '2-1-3-1', '2-1-4-1'], cols: [['name', '会社名', 'text', true], ['kind', '関係', 'select:顧客|仕入れ先|委託先|子会社・関係会社|クラウドの事業者|その他'], ['systems', 'つながっているシステム', 'text'], ['means', 'やり取りの手段', 'text'], ['info', '受け渡す機密情報とその扱い', 'long'], ['agreement', '機密情報の取り決め (文書・日付)', 'text'], ['incident_roles', 'インシデント時の役割の取り決め', 'text'], ['important', '重要な取引先 (★4)', 'bool'], ['checked_at', '対策の状況を確かめた日 (★4)', 'date'], ['notes', '備考', 'text']] },
  { id: 'secrets', label: '重要な機密情報', note: '情報ごとに 1 行。管理者・保管場所・保管期限・開示先', criteria: ['3-1-4-3', '3-1-4-4'], cols: [['name', '情報の名前', 'text', true], ['level', '機密区分', 'text', true], ['manager', '管理者', 'text', true], ['dept', '部署', 'text', true], ['place', '保管場所', 'text', true], ['until', '保管期限', 'text', true], ['disclosed', '開示先', 'text'], ['contact', '管理者の連絡先', 'text', true]] },
  { id: 'admins', label: '管理者 ID', note: 'サーバー・ネットワーク機器・クラウド・箱の管理者。付与の承認と最後の確認も', criteria: ['4-1-2-2', '4-1-2-3', '4-1-2-5', '4-1-2-6', '4-1-2-7', '4-1-2-8'], cols: [['system', 'システム・機器', 'text', true], ['account', 'ID', 'text', true], ['holder', '持っている人', 'text', true], ['purpose', '用途・権限の範囲', 'text'], ['shared', '共有している', 'bool'], ['approved', '付与の承認 (日付・承認者)', 'text'], ['last_checked', '最後に確かめた日', 'date']] },
  { id: 'software', label: '使ってよいソフト', note: '会社のパソコン・サーバーで許可するソフトの一覧 (★4 では必須)', criteria: ['4-4-1-1', '5-1-2-1', '5-1-2-2'], cols: [['name', 'ソフト名', 'text', true], ['purpose', '用途', 'text'], ['scope', '対象 (パソコン・サーバー)', 'text'], ['update', '更新の方法', 'text'], ['notes', '備考', 'text']] },
  { id: 'tools', label: 'セキュリティの道具', note: 'UTM・EDR・ウイルス対策・メールや Web の検査。お助け隊サービスなどの監視サービスもここに', criteria: ['4-4-5-1', '4-4-5-2', '4-4-5-3', '4-4-5-4', '4-4-5-5', '5-1-1-1', '5-1-1-3', '5-1-2-3'], cols: [['kind', '種類', 'select:UTM (ネットワークの監視)|EDR (端末の監視)|ウイルス対策ソフト|メールの検査|Web の閲覧の制限|監視サービス|その他'], ['product', '製品・サービス', 'text', true], ['provider', '提供事業者', 'text'], ['scope', '対象 (台数・範囲)', 'text'], ['scan', '検査の範囲と頻度', 'text'], ['alert_to', '警告の知らせ先', 'text'], ['until', '契約の期限', 'date'], ['notes', '備考', 'text']] },
  { id: 'backups', label: 'バックアップ', note: '対象ごとに頻度・保管期間・離れた場所の写し・戻し方の手順書', criteria: ['4-3-4-1', '4-3-4-2', '4-3-4-3', '7-1-1-2'], cols: [['target', '対象', 'text', true], ['freq', '頻度', 'text', true], ['keep', '保管期間', 'text', true], ['where', '保存先', 'text'], ['remote', '離れた場所の写し', 'text'], ['restore_doc', 'リストアの手順書', 'text'], ['restore_test', '最後に戻せると確かめた日', 'date'], ['rto', '目標の時間・時点 (★4)', 'text']] },
  { id: 'trainings', label: '教育・訓練の記録', note: '内容・やり方・時期・受講した人。受講は「全員に知らせる」の確認でも集められます', criteria: ['4-2-1-1', '4-2-1-3', '4-2-1-4', '4-2-2-1', '4-2-2-2'], cols: [['date', '日付', 'date', true], ['title', '題目', 'text', true], ['method', 'やり方', 'select:資料の配布・掲示|e ラーニング|集合教育|訓練 (演習)|その他'], ['topic', '内容', 'long'], ['audience', '対象', 'text'], ['attendance', '受講の状況 (人数・名前)', 'long']] },
  { id: 'retrievals', label: '退職時の回収', note: '印刷物・記憶媒体・パソコン・スマートデバイス・ID・鍵 (★4)', criteria: ['3-1-4-5', '3-1-4-6'], cols: [['date', '日付', 'date', true], ['person', '退職・任期満了の人', 'text', true], ['items', '回収したもの', 'long', true], ['ids', '止めた ID', 'text'], ['checker', '確かめた人', 'text', true]] },
  { id: 'disposals', label: '抹消の記録', note: '捨てた・返した機器のデータを戻せないように消した記録 (★4)', criteria: ['3-1-4-7', '3-1-4-8'], cols: [['date', '日付', 'date', true], ['device', '機器', 'text', true], ['method', '消し方', 'text', true], ['by', '実施した人・会社', 'text', true], ['proof', '証明書など', 'text']] },
  { id: 'entry_log', label: 'サーバー室の入退室', note: '日時と氏名を 6 か月以上 (★4)', criteria: ['4-1-8-4'], cols: [['at', '日時', 'text', true], ['person', '氏名', 'text', true], ['purpose', '目的', 'text'], ['out_at', '退室', 'text']] },
  { id: 'vulns', label: '脆弱性への対応', note: '集めた脆弱性・脅威の情報と、判断・対応・完了 (★4。毎月の点検)', criteria: ['3-2-1-5', '3-2-1-4'], cols: [['date', '知った日', 'date', true], ['source', '情報源', 'text'], ['title', '内容 (CVE など)', 'text', true], ['target', '対象の機器・ソフト', 'text'], ['decision', '判断 (対応する・しない・理由)', 'text', true], ['action', '対応', 'text'], ['done_at', '完了日', 'date']] },
  { id: 'cases', label: 'インシデント事例の共有', note: '社内外の事例と対応策を、年 1 回以上と大きな事案のときに', criteria: ['6-1-1-6'], cols: [['date', '日付', 'date', true], ['case', '事例', 'long', true], ['measure', '対応策', 'long'], ['shared_to', '共有した先', 'text']] },
];
export const LEDGER_BY_ID = Object.fromEntries(LEDGER_KINDS.map(k => [k.id, k]));

const cell = (type, v) => {
  if (v == null || v === '') return '';
  if (type === 'num') { const n = Number(v); return Number.isFinite(n) ? n : ''; }
  if (type === 'bool') return v === true || v === 'true' || v === '1' || v === 1 || v === 'はい';
  if (type === 'date') { const s = String(v).slice(0, 10); return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ''; }
  return String(v).slice(0, type === 'long' ? 4000 : 400);
};

export class Ledgers {
  constructor(ports, { mm = null, probe = null } = {}) { Object.assign(this, { ports, mm, probe }); }
  db() { return this.ports.db(); }
  kinds() { return LEDGER_KINDS; }
  kind(k) { const d = LEDGER_BY_ID[k]; if (!d) throw new HttpError(404, 'not_found', '台帳の種類が見つかりません'); return d; }
  list(actor, kind) {
    this.ports.requireRole(actor, 'viewer'); const d = this.kind(kind);
    const rows = this.db().prepare('SELECT * FROM mm_ledger WHERE kind=? AND deleted_at IS NULL ORDER BY created_at').all(kind).map(r => ({ id: r.id, data: J.parse(r.data, {}), source: r.source, updated_by: r.updated_by, updated_at: r.updated_at, created_at: r.created_at }));
    return { kind: d, rows, reviewed_at: this.reviewedAt(kind) };
  }
  counts() { return Object.fromEntries(this.db().prepare('SELECT kind, COUNT(*) n, MAX(updated_at) at FROM mm_ledger WHERE deleted_at IS NULL GROUP BY kind').all().map(r => [r.kind, { n: r.n, at: r.at }])); }
  reviewedAt(kind) { return J.parse(this.db().prepare("SELECT value FROM mamoricho_settings WHERE key='ledger_reviewed'").get()?.value, {})[kind] || null; }
  upsert(actor, { kind, id: rid = null, data = {}, source = 'manual' } = {}) {
    this.ports.requireRole(actor, 'operator'); const d = this.kind(kind);
    const clean = {}; for (const [k, , type] of d.cols) clean[k] = cell(type, data[k]);
    const miss = d.cols.filter(([k, , , req]) => req && (clean[k] === '' || clean[k] == null)).map(([, l]) => l); if (miss.length) throw new HttpError(400, 'missing', `入れてください: ${miss.join('・')}`);
    const t = nowIso(); const prev = rid ? this.db().prepare('SELECT * FROM mm_ledger WHERE id=? AND kind=? AND deleted_at IS NULL').get(rid, kind) : null;
    if (rid && !prev) throw new HttpError(404, 'not_found', '台帳の行が見つかりません');
    const rowId = prev?.id || id('led');
    if (prev) this.db().prepare('UPDATE mm_ledger SET data=?, updated_by=?, updated_at=? WHERE id=?').run(J.str(clean), actor.id, t, rowId);
    else this.db().prepare('INSERT INTO mm_ledger(id,kind,data,source,created_by,created_at,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(rowId, kind, J.str(clean), String(source).slice(0, 20), actor.id, t, actor.id, t);
    const rec = this.mm?.record(actor, 'ledger', { kind, kind_label: d.label, row_id: rowId, op: prev ? 'update' : 'add', data: clean, previous: prev ? J.parse(prev.data, {}) : null });
    this.ports.audit({ actor, action: 'mamoricho.ledger', target: `${kind}:${rowId}`, detail: { op: prev ? 'update' : 'add', record: rec?.id || null } });
    return { id: rowId, data: clean, updated_at: t, record_id: rec?.id || null };
  }
  remove(actor, { kind, id: rid } = {}) {
    this.ports.requireRole(actor, 'operator'); const d = this.kind(kind);
    const prev = this.db().prepare('SELECT * FROM mm_ledger WHERE id=? AND kind=? AND deleted_at IS NULL').get(rid, kind); if (!prev) throw new HttpError(404, 'not_found', '台帳の行が見つかりません');
    this.db().prepare('UPDATE mm_ledger SET deleted_at=?, updated_by=? WHERE id=?').run(nowIso(), actor.id, rid); // 消した行も残す (記録の鎖から追える)
    const rec = this.mm?.record(actor, 'ledger', { kind, kind_label: d.label, row_id: rid, op: 'remove', previous: J.parse(prev.data, {}) });
    this.ports.audit({ actor, action: 'mamoricho.ledger', target: `${kind}:${rid}`, detail: { op: 'remove', record: rec?.id || null } });
    return { ok: true };
  }
  // 「一覧を見直した」(年 1 回の点検の材料)。中身の写しのハッシュも記録に残す
  markReviewed(actor, { kind, note = '' } = {}) {
    this.ports.requireRole(actor, 'operator'); const d = this.kind(kind); const at = nowIso();
    const cur = J.parse(this.db().prepare("SELECT value FROM mamoricho_settings WHERE key='ledger_reviewed'").get()?.value, {}); cur[kind] = at;
    this.db().prepare("INSERT INTO mamoricho_settings(key,value) VALUES('ledger_reviewed',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(J.str(cur));
    const rows = this.list(actor, kind).rows; const rec = this.mm?.record(actor, 'ledger_review', { kind, kind_label: d.label, rows: rows.length, note: String(note).slice(0, 500) });
    return { kind, reviewed_at: at, rows: rows.length, record_id: rec?.id || null };
  }
  // 診断・箱の利用者から出す候補 (まだ台帳に無いものだけ)。足すかどうかは人が決める
  suggest(actor, kind, facts = null) {
    this.ports.requireRole(actor, 'operator'); this.kind(kind);
    const have = this.list(actor, kind).rows.map(r => JSON.stringify(r.data).toLowerCase()); const has = (s) => !!s && have.some(h => h.includes(String(s).toLowerCase()));
    const out = [];
    if (kind === 'servers' && facts) for (const f of facts.targets.filter(t => t.kind === 'ssh')) if (!has(f.name)) out.push({ name: f.name, os: f.os || '', purpose: f.host || '', count: 1, admin: '', owner: '', notes: `まもり帳の対象 (${f.host})` });
    if (kind === 'netdevices' && facts) for (const f of facts.targets.filter(t => t.kind === 'network')) if (!has(f.name)) out.push({ name: f.name, maker: f.vendor || '', model: f.model || '', firmware: f.version || '', vendor: '', edge: false, notes: `まもり帳の対象 (${f.host})` });
    if (kind === 'admins') {
      const tenant = actor.tenant_id || this.ports.users.firstTenant(); const users = tenant ? this.ports.users.list(tenant) : [];
      for (const u of users.filter(u => ['owner', 'admin'].includes(u.role) && u.status !== 'disabled')) if (!has(u.username)) out.push({ system: this.ports.brand.os, account: u.username, holder: u.display_name || u.username, purpose: u.role === 'owner' ? 'Owner (すべて)' : 'Admin (管理)', shared: false, approved: '', last_checked: '' });
      if (facts) for (const f of facts.targets.filter(t => t.kind === 'ssh')) for (const a of f.admins || []) if (!has(`${f.name}`) || !has(a)) out.push({ system: f.name, account: a, holder: '', purpose: 'sudo (管理者権限)', shared: false, approved: '', last_checked: '' });
    }
    return { kind, suggestions: out.slice(0, 50) };
  }
  csv(actor, kind) {
    const { kind: d, rows } = this.list(actor, kind);
    const q = (v) => { const s = typeof v === 'boolean' ? (v ? 'はい' : '') : String(v ?? ''); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    return '﻿' + [d.cols.map(c => q(c[1])).join(','), ...rows.map(r => d.cols.map(c => q(r.data[c[0]])).join(','))].join('\r\n') + '\r\n';
  }
}
